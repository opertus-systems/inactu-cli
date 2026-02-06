use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use inactu_verifier::{
    compute_manifest_hash, parse_manifest_json, parse_signatures_json, verify_artifact_hash,
};
use tar::{Builder, Header};
use zstd::stream::write::Encoder as ZstdEncoder;

use crate::constants::{MAX_JSON_BYTES, MAX_WASM_BYTES};
use crate::fileio::read_file_limited;

pub fn create_skill_archive(bundle_dir: &Path, output_path: &Path) -> Result<(), String> {
    let manifest_raw = read_file_limited(&bundle_dir.join("manifest.json"), MAX_JSON_BYTES, "manifest.json")?;
    let wasm_raw = read_file_limited(&bundle_dir.join("skill.wasm"), MAX_WASM_BYTES, "skill.wasm")?;
    let manifest = parse_manifest_json(&manifest_raw).map_err(|e| e.to_string())?;
    verify_artifact_hash(&wasm_raw, &manifest.artifact).map_err(|e| e.to_string())?;

    let signatures_raw = read_optional_file(bundle_dir, "signatures.json")?;
    if let Some(raw) = signatures_raw.as_ref() {
        let signatures = parse_signatures_json(raw).map_err(|e| e.to_string())?;
        if signatures.artifact != manifest.artifact {
            return Err("manifest.artifact must equal signatures.artifact".to_string());
        }
        let manifest_hash = compute_manifest_hash(&manifest).map_err(|e| e.to_string())?;
        if signatures.manifest_hash != manifest_hash {
            return Err("signatures.manifest_hash must equal canonical manifest hash".to_string());
        }
    }
    let sbom_raw = read_optional_file(bundle_dir, "sbom.spdx.json")?;
    let sigstore_bundle_raw = read_optional_file(bundle_dir, "sigstore.bundle.json")?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create output directory {}: {e}", parent.display()))?;
    }

    let output_file =
        File::create(output_path).map_err(|e| format!("{}: {e}", output_path.display()))?;
    let encoder =
        ZstdEncoder::new(output_file, 19).map_err(|e| format!("zstd encoder init failed: {e}"))?;
    let mut tar = Builder::new(encoder);

    // Canonical archive order for deterministic package identity.
    append_entry(&mut tar, "manifest.json", 0o644, &manifest_raw)?;
    append_entry(&mut tar, "skill.wasm", 0o755, &wasm_raw)?;
    if let Some(raw) = sbom_raw.as_ref() {
        append_entry(&mut tar, "sbom.spdx.json", 0o644, raw)?;
    }
    if let Some(raw) = sigstore_bundle_raw.as_ref() {
        append_entry(&mut tar, "sigstore.bundle.json", 0o644, raw)?;
    }
    if let Some(raw) = signatures_raw.as_ref() {
        append_entry(&mut tar, "signatures.json", 0o644, raw)?;
    }
    tar.finish()
        .map_err(|e| format!("tar finish failed for {}: {e}", output_path.display()))?;

    let mut encoder = tar
        .into_inner()
        .map_err(|e| format!("tar encoder extraction failed: {e}"))?;
    encoder
        .flush()
        .map_err(|e| format!("zstd flush failed for {}: {e}", output_path.display()))?;
    let _ = encoder
        .finish()
        .map_err(|e| format!("zstd finish failed for {}: {e}", output_path.display()))?;
    Ok(())
}

fn append_entry<W: std::io::Write>(
    builder: &mut Builder<W>,
    name: &str,
    mode: u32,
    bytes: &[u8],
) -> Result<(), String> {
    let mut header = Header::new_ustar();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_username("")
        .map_err(|e| format!("failed to set username for {name}: {e}"))?;
    header.set_groupname("")
        .map_err(|e| format!("failed to set groupname for {name}: {e}"))?;
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .map_err(|e| format!("failed to append {name}: {e}"))?;
    Ok(())
}

fn read_optional_file(bundle_dir: &Path, file_name: &str) -> Result<Option<Vec<u8>>, String> {
    let path = bundle_dir.join(file_name);
    if !path.exists() {
        return Ok(None);
    }
    let max = if file_name.ends_with(".wasm") {
        MAX_WASM_BYTES
    } else {
        MAX_JSON_BYTES
    };
    read_file_limited(&path, max, file_name).map(Some)
}
