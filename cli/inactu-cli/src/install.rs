use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use inactu_verifier::{
    compute_manifest_hash, enforce_capability_ceiling, parse_manifest_json, parse_policy_document,
    parse_signatures_json, sha256_prefixed, verify_signatures,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tar::Archive;
use url::Url;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::constants::{MAX_JSON_BYTES, MAX_SKILL_ARCHIVE_BYTES, MAX_WASM_BYTES};
use crate::fileio::{read_file_limited, write_file};
use crate::keys::{parse_public_keys, verify_keys_digest};

const EXPERIMENTAL_SCHEMA_VERSION: &str = "1.0.0-draft";

#[derive(Debug, Clone, Copy)]
pub enum SignatureMode {
    Optional,
    Required,
}

pub struct InstallRequest<'a> {
    pub artifact: &'a str,
    pub keys_path: Option<&'a Path>,
    pub keys_digest: Option<&'a str>,
    pub policy_path: Option<&'a Path>,
    pub allow_experimental: bool,
    pub allow_insecure_http: bool,
    pub signature_mode: SignatureMode,
}

#[derive(Debug, Serialize, Deserialize)]
struct Index {
    schema_version: String,
    entries: Vec<IndexEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexEntry {
    skill: String,
    source: String,
    store: String,
    installed_at: u64,
    manifest_name: String,
    manifest_version: String,
}

#[derive(Debug)]
struct Package {
    manifest_raw: Vec<u8>,
    wasm_raw: Vec<u8>,
    signatures_raw: Option<Vec<u8>>,
    sbom_raw: Option<Vec<u8>>,
    sigstore_bundle_raw: Option<Vec<u8>>,
}

pub fn install(request: InstallRequest<'_>) -> Result<String, String> {
    if is_network_artifact_source(request.artifact)
        && matches!(request.signature_mode, SignatureMode::Optional)
    {
        return Err(
            "remote artifacts require --require-signatures with --keys and --keys-digest"
                .to_string(),
        );
    }

    let archive_raw = load_artifact(request.artifact, request.allow_insecure_http)?;
    let archive_digest = sha256_prefixed(&archive_raw);
    let package = unpack_archive(&archive_raw)?;

    let manifest = parse_manifest_json(&package.manifest_raw).map_err(|e| e.to_string())?;
    require_manifest_schema_allowed(&manifest, request.allow_experimental)?;
    let actual_wasm = sha256_prefixed(&package.wasm_raw);
    if manifest.artifact != actual_wasm {
        return Err(format!(
            "manifest.artifact must match bundled skill.wasm digest (expected {}, got {})",
            actual_wasm, manifest.artifact
        ));
    }

    if let Some(policy_path) = request.policy_path {
        let policy_raw = read_file_limited(policy_path, MAX_JSON_BYTES, "policy")?;
        let policy = parse_policy_document(&policy_raw).map_err(|e| e.to_string())?;
        enforce_capability_ceiling(&manifest.capabilities, &policy).map_err(|e| e.to_string())?;
    }

    validate_signatures(
        &package,
        &manifest,
        request.keys_path,
        request.keys_digest,
        request.signature_mode,
    )?;

    let inactu_home = resolve_inactu_home()?;
    let store_dir = persist_to_store(
        &inactu_home,
        &archive_digest,
        request.artifact,
        &package,
        &manifest.name,
        &manifest.version,
    )?;
    update_index(
        &inactu_home,
        &archive_digest,
        request.artifact,
        &store_dir,
        &manifest.name,
        &manifest.version,
    )?;

    Ok(format!(
        "OK install skill={} store={} source={}",
        archive_digest,
        store_dir.display(),
        request.artifact
    ))
}

fn load_artifact(source: &str, allow_insecure_http: bool) -> Result<Vec<u8>, String> {
    if source.starts_with("oci://") {
        return Err(
            "OCI refs are not supported in v0 install yet; use file path, file://, or http(s) URL"
                .to_string(),
        );
    }
    if source.starts_with("http://") {
        if !allow_insecure_http {
            return Err(
                "http:// artifacts are disabled by default; pass --allow-insecure-http only for local development"
                    .to_string(),
            );
        }
        let response = ureq::get(source)
            .call()
            .map_err(|e| format!("failed to fetch artifact from {source}: {e}"))?;
        let mut reader = response.into_body().into_reader();
        return read_limited(&mut reader, MAX_SKILL_ARCHIVE_BYTES, "artifact");
    }
    if source.starts_with("https://") {
        let response = ureq::get(source)
            .call()
            .map_err(|e| format!("failed to fetch artifact from {source}: {e}"))?;
        let mut reader = response.into_body().into_reader();
        return read_limited(&mut reader, MAX_SKILL_ARCHIVE_BYTES, "artifact");
    }
    if source.starts_with("file://") {
        let url = Url::parse(source).map_err(|e| format!("invalid file URL: {e}"))?;
        let path = url
            .to_file_path()
            .map_err(|_| "file:// URL must resolve to a local path".to_string())?;
        return read_file_limited(&path, MAX_SKILL_ARCHIVE_BYTES, "artifact");
    }
    read_file_limited(Path::new(source), MAX_SKILL_ARCHIVE_BYTES, "artifact")
}

fn unpack_archive(bytes: &[u8]) -> Result<Package, String> {
    let decoder = ZstdDecoder::new(Cursor::new(bytes))
        .map_err(|e| format!("artifact is not valid zstd stream: {e}"))?;
    let mut archive = Archive::new(decoder);

    let mut package = Package {
        manifest_raw: Vec::new(),
        wasm_raw: Vec::new(),
        signatures_raw: None,
        sbom_raw: None,
        sigstore_bundle_raw: None,
    };
    for entry in archive
        .entries()
        .map_err(|e| format!("artifact tar read failed: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("artifact tar entry failed: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("artifact tar path failed: {e}"))?;
        let normalized = normalize_path(&path.to_string_lossy())?;
        let mut raw = Vec::new();
        entry
            .read_to_end(&mut raw)
            .map_err(|e| format!("artifact entry read failed ({normalized}): {e}"))?;
        match normalized.as_str() {
            "manifest.json" => package.manifest_raw = raw,
            "skill.wasm" => package.wasm_raw = raw,
            "signatures.json" => package.signatures_raw = Some(raw),
            "sbom.spdx.json" => package.sbom_raw = Some(raw),
            "sigstore.bundle.json" => package.sigstore_bundle_raw = Some(raw),
            _ => {
                return Err(format!(
                    "unexpected archive entry: {normalized} (expected top-level skill package files only)"
                ));
            }
        }
    }

    if package.manifest_raw.is_empty() {
        return Err("artifact missing required file manifest.json".to_string());
    }
    if package.wasm_raw.is_empty() {
        return Err("artifact missing required file skill.wasm".to_string());
    }
    if package.wasm_raw.len() as u64 > MAX_WASM_BYTES {
        return Err(format!(
            "skill.wasm exceeds maximum size ({} bytes > {} bytes)",
            package.wasm_raw.len(),
            MAX_WASM_BYTES
        ));
    }
    Ok(package)
}

fn normalize_path(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim_start_matches("./");
    if trimmed.is_empty()
        || trimmed.contains("../")
        || trimmed.starts_with('/')
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err(format!("invalid archive path: {raw}"));
    }
    Ok(trimmed.to_string())
}

fn require_manifest_schema_allowed(
    manifest: &inactu_verifier::Manifest,
    allow_experimental: bool,
) -> Result<(), String> {
    if manifest.schema_version.as_deref() == Some(EXPERIMENTAL_SCHEMA_VERSION)
        && !allow_experimental
    {
        return Err(format!(
            "manifest schema_version '{EXPERIMENTAL_SCHEMA_VERSION}' requires --allow-experimental"
        ));
    }
    Ok(())
}

fn validate_signatures(
    package: &Package,
    manifest: &inactu_verifier::Manifest,
    keys_path: Option<&Path>,
    keys_digest: Option<&str>,
    signature_mode: SignatureMode,
) -> Result<(), String> {
    let Some(signatures_raw) = package.signatures_raw.as_ref() else {
        if matches!(signature_mode, SignatureMode::Required) || keys_path.is_some() {
            return Err("signatures.json is required for this install mode".to_string());
        }
        return Ok(());
    };
    let signatures = parse_signatures_json(signatures_raw).map_err(|e| e.to_string())?;
    let manifest_hash = compute_manifest_hash(manifest).map_err(|e| e.to_string())?;
    if signatures.artifact != manifest.artifact {
        return Err("manifest.artifact must equal signatures.artifact".to_string());
    }
    if signatures.manifest_hash != manifest_hash {
        return Err("signatures.manifest_hash must equal canonical manifest hash".to_string());
    }

    if let Some(path) = keys_path {
        let Some(digest) = keys_digest else {
            return Err("--keys-digest is required when --keys is set".to_string());
        };
        let keys_raw = read_file_limited(path, MAX_JSON_BYTES, "public-keys.json")?;
        verify_keys_digest(&keys_raw, digest)?;
        let public_keys = parse_public_keys(&keys_raw)?;
        verify_signatures(&signatures, &public_keys).map_err(|e| e.to_string())?;
    } else if matches!(signature_mode, SignatureMode::Required) {
        return Err(
            "--keys and --keys-digest are required when --require-signatures is set".to_string(),
        );
    }
    Ok(())
}

fn resolve_inactu_home() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("INACTU_HOME") {
        return Ok(PathBuf::from(path));
    }
    let Some(home) = std::env::var_os("HOME") else {
        return Err("could not resolve home directory; set INACTU_HOME".to_string());
    };
    Ok(PathBuf::from(home).join(".inactu"))
}

fn persist_to_store(
    inactu_home: &Path,
    archive_digest: &str,
    source: &str,
    package: &Package,
    manifest_name: &str,
    manifest_version: &str,
) -> Result<PathBuf, String> {
    let suffix = archive_digest
        .strip_prefix("sha256:")
        .unwrap_or(archive_digest);
    let store_dir = inactu_home.join("store").join("sha256").join(suffix);
    fs::create_dir_all(&store_dir)
        .map_err(|e| format!("failed to create store path {}: {e}", store_dir.display()))?;

    write_file(&store_dir.join("manifest.json"), &package.manifest_raw)?;
    write_file(&store_dir.join("skill.wasm"), &package.wasm_raw)?;
    if let Some(raw) = &package.signatures_raw {
        write_file(&store_dir.join("signatures.json"), raw)?;
    }
    if let Some(raw) = &package.sbom_raw {
        write_file(&store_dir.join("sbom.spdx.json"), raw)?;
    }
    if let Some(raw) = &package.sigstore_bundle_raw {
        write_file(&store_dir.join("sigstore.bundle.json"), raw)?;
    }

    let installed_at = unix_now_secs()?;
    let meta = json!({
        "schema_version": "1.0.0",
        "skill": archive_digest,
        "source": source,
        "manifest_name": manifest_name,
        "manifest_version": manifest_version,
        "installed_at": installed_at
    });
    let meta_bytes =
        serde_json::to_vec_pretty(&meta).map_err(|e| format!("meta JSON encode failed: {e}"))?;
    write_file(&store_dir.join("meta.json"), &meta_bytes)?;
    Ok(store_dir)
}

fn update_index(
    inactu_home: &Path,
    archive_digest: &str,
    source: &str,
    store_dir: &Path,
    manifest_name: &str,
    manifest_version: &str,
) -> Result<(), String> {
    fs::create_dir_all(inactu_home).map_err(|e| {
        format!(
            "failed to create inactu home {}: {e}",
            inactu_home.display()
        )
    })?;
    let index_path = inactu_home.join("index.json");
    let mut index = if index_path.exists() {
        let raw = read_file_limited(&index_path, MAX_JSON_BYTES, "index.json")?;
        serde_json::from_slice::<Index>(&raw)
            .map_err(|e| format!("index.json parse failed: {e}"))?
    } else {
        Index {
            schema_version: "1.0.0".to_string(),
            entries: Vec::new(),
        }
    };

    let installed_at = unix_now_secs()?;
    let store = store_dir.display().to_string();
    if let Some(existing) = index.entries.iter_mut().find(|e| e.skill == archive_digest) {
        existing.source = source.to_string();
        existing.store = store;
        existing.installed_at = installed_at;
        existing.manifest_name = manifest_name.to_string();
        existing.manifest_version = manifest_version.to_string();
    } else {
        index.entries.push(IndexEntry {
            skill: archive_digest.to_string(),
            source: source.to_string(),
            store,
            installed_at,
            manifest_name: manifest_name.to_string(),
            manifest_version: manifest_version.to_string(),
        });
        index.entries.sort_by(|a, b| a.skill.cmp(&b.skill));
    }
    let raw =
        serde_json::to_vec_pretty(&index).map_err(|e| format!("index JSON encode failed: {e}"))?;
    write_file(&index_path, &raw)?;
    Ok(())
}

fn unix_now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock error: {e}"))
}

fn read_limited<R: Read>(
    reader: &mut R,
    max_bytes: u64,
    logical_name: &str,
) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read {logical_name}: {e}"))?;
    if buf.len() as u64 > max_bytes {
        return Err(format!(
            "{logical_name} exceeds maximum size ({} bytes > {} bytes)",
            buf.len(),
            max_bytes
        ));
    }
    Ok(buf)
}

pub(crate) fn is_network_artifact_source(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}
