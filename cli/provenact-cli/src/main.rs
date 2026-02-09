mod agentskills;
mod archive;
mod constants;
mod fileio;
mod flags;
mod install;
mod keys;
mod preflight;
mod runtime_exec;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use agentskills::{export_agentskills, Agent, ExportRequest, Scope};
use archive::create_skill_archive;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer as _;
use provenact_verifier::{
    compute_bundle_hash, compute_manifest_hash, compute_policy_hash, compute_receipt_hash,
    compute_receipt_v1_draft_hash, compute_result_digest_v1, compute_runtime_version_digest_v1,
    enforce_capability_ceiling, parse_manifest_json, parse_manifest_v1_draft_json,
    parse_policy_document, parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed,
    verify_receipt_hash, verify_receipt_v1_draft_hash, verify_registry_entry_artifact,
    verify_signatures, verify_trusted_signers, ExecutionReceipt, ExecutionReceiptV1Draft,
    ExecutionResultV1Draft, Manifest, RegistryEntry, RuntimeV1Draft, SignatureEntry, Signatures,
};
use serde_json::{json, Value};

use constants::{MAX_INPUT_BYTES, MAX_JSON_BYTES, MAX_SECRET_KEY_BYTES, MAX_WASM_BYTES};
use fileio::{read_file_limited, write_file};
use flags::{
    has_switch, optional_string, parse_flags, parse_flags_with_switches, required_path,
    required_string,
};
use install::{install, is_network_artifact_source, InstallRequest, SignatureMode};
use keys::{parse_public_keys, parse_signing_key, verify_keys_digest};
use preflight::{load_verified_bundle, read_manifest_and_signatures};
use runtime_exec::execute_wasm;

const USAGE: &str = "usage:\n  provenact-cli verify --bundle <bundle-dir> --keys <public-keys.json> --keys-digest <sha256:...> [--require-cosign --oci-ref <oci-ref>] [--allow-experimental]\n  provenact-cli inspect --bundle <bundle-dir> [--allow-experimental]\n  provenact-cli pack --bundle <bundle-dir> --wasm <skill.wasm> --manifest <manifest.json> [--allow-experimental]\n  provenact-cli archive --bundle <bundle-dir> --output <skill.tar.zst>\n  provenact-cli sign --bundle <bundle-dir> --signer <signer-id> --secret-key <ed25519-secret-key-file> [--allow-experimental]\n  provenact-cli install --artifact <path|file://...|http(s)://...|oci://...> [--keys <public-keys.json> --keys-digest <sha256:...>] [--policy <policy.{json|yaml}>] [--require-signatures] [--allow-insecure-http] [--allow-experimental]\n  provenact-cli export agentskills --agent <claude|codex|cursor> --scope <user|repo|admin>\n  provenact-cli run --bundle <bundle-dir> --keys <public-keys.json> --keys-digest <sha256:...> --policy <policy.{json|yaml}> --input <input-file> --receipt <receipt.json> [--receipt-format <v0|v1-draft>] [--require-cosign --oci-ref <oci-ref>] [--allow-experimental]\n  provenact-cli verify-receipt --receipt <receipt.json>\n  provenact-cli verify-registry-entry --artifact <artifact-bytes-file> --sha256 <sha256:...> --md5 <32-lowercase-hex>\n  provenact-cli experimental-validate-manifest-v1 --manifest <manifest.json>\n  provenact-cli experimental-validate-receipt-v1 --receipt <receipt.json>";
const EXPERIMENTAL_SCHEMA_VERSION: &str = "1.0.0-draft";
const BUNDLE_META_SCHEMA_VERSION: &str = "1.0.0";
const RECEIPT_TIMESTAMP_STRATEGY_LOCAL: &str = "local_untrusted_unix_seconds";

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("command failed: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ReceiptFormat {
    V0,
    V1Draft,
}

fn parse_receipt_format(value: Option<&str>) -> Result<ReceiptFormat, String> {
    match value.unwrap_or("v0") {
        "v0" => Ok(ReceiptFormat::V0),
        "v1-draft" => Ok(ReceiptFormat::V1Draft),
        _ => Err("unsupported --receipt-format; expected v0 or v1-draft".to_string()),
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("unknown");
    let started = Instant::now();
    let result = match args.first().map(String::as_str) {
        Some("verify") => run_verify(&args[1..]),
        Some("inspect") => run_inspect(&args[1..]),
        Some("pack") => run_pack(&args[1..]),
        Some("archive") => run_archive(&args[1..]),
        Some("sign") => run_sign(&args[1..]),
        Some("install") => run_install(&args[1..]),
        Some("export") => run_export(&args[1..]),
        Some("run") => run_execute(&args[1..]),
        Some("verify-receipt") => run_verify_receipt_cmd(&args[1..]),
        Some("verify-registry-entry") => run_verify_registry_entry_cmd(&args[1..]),
        Some("experimental-validate-manifest-v1") => run_validate_manifest_v1_cmd(&args[1..]),
        Some("experimental-validate-receipt-v1") => run_validate_receipt_v1_cmd(&args[1..]),
        _ => Err(USAGE.to_string()),
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(()) => emit_obs(
            "provenact.command",
            vec![
                ("command", json!(command)),
                ("status", json!("ok")),
                ("duration_ms", json!(duration_ms)),
            ],
        ),
        Err(err) => emit_obs(
            "provenact.command",
            vec![
                ("command", json!(command)),
                ("status", json!("error")),
                ("duration_ms", json!(duration_ms)),
                ("error", json!(err)),
            ],
        ),
    }
    result
}

fn run_export(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err(USAGE.to_string());
    };
    if subcommand != "agentskills" {
        return Err(USAGE.to_string());
    }
    let parsed = parse_flags(&args[1..], &["--agent", "--scope"], USAGE)?;
    let agent = Agent::parse(&required_string(&parsed, "--agent", USAGE)?)?;
    let scope = Scope::parse(&required_string(&parsed, "--scope", USAGE)?)?;
    let line = export_agentskills(ExportRequest { agent, scope })?;
    println!("{line}");
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(
        args,
        &["--bundle", "--keys", "--keys-digest", "--oci-ref"],
        &["--allow-experimental", "--require-cosign"],
        USAGE,
    )?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let keys_path = required_path(&parsed, "--keys", USAGE)?;
    let keys_digest = required_string(&parsed, "--keys-digest", USAGE)?;
    let oci_ref = optional_string(&parsed, "--oci-ref");
    let require_cosign = has_switch(&parsed, "--require-cosign");
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    verify_bundle(
        &bundle_dir,
        &keys_path,
        &keys_digest,
        require_cosign,
        oci_ref.as_deref(),
        allow_experimental,
    )
}

fn run_inspect(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(args, &["--bundle"], &["--allow-experimental"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    inspect_bundle(&bundle_dir, allow_experimental)
}

fn run_pack(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(
        args,
        &["--bundle", "--wasm", "--manifest"],
        &["--allow-experimental"],
        USAGE,
    )?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let wasm_path = required_path(&parsed, "--wasm", USAGE)?;
    let manifest_path = required_path(&parsed, "--manifest", USAGE)?;
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    pack_bundle(&bundle_dir, &wasm_path, &manifest_path, allow_experimental)
}

fn run_archive(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--bundle", "--output"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let output_path = required_path(&parsed, "--output", USAGE)?;
    create_skill_archive(&bundle_dir, &output_path)?;
    println!(
        "OK archive bundle={} output={}",
        bundle_dir.display(),
        output_path.display()
    );
    Ok(())
}

fn run_sign(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(
        args,
        &["--bundle", "--signer", "--secret-key"],
        &["--allow-experimental"],
        USAGE,
    )?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let signer_id = required_string(&parsed, "--signer", USAGE)?;
    let secret_key_path = required_path(&parsed, "--secret-key", USAGE)?;
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    sign_bundle(
        &bundle_dir,
        &signer_id,
        &secret_key_path,
        allow_experimental,
    )
}

fn run_install(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(
        args,
        &["--artifact", "--keys", "--keys-digest", "--policy"],
        &[
            "--require-signatures",
            "--allow-insecure-http",
            "--allow-experimental",
        ],
        USAGE,
    )?;
    let artifact = required_string(&parsed, "--artifact", USAGE)?;
    let keys_path = optional_string(&parsed, "--keys").map(std::path::PathBuf::from);
    let keys_digest = optional_string(&parsed, "--keys-digest");
    if keys_path.is_some() ^ keys_digest.is_some() {
        return Err("--keys and --keys-digest must be provided together".to_string());
    }
    let policy_path = optional_string(&parsed, "--policy").map(std::path::PathBuf::from);
    let requested_signature_mode = if has_switch(&parsed, "--require-signatures") {
        SignatureMode::Required
    } else {
        SignatureMode::Optional
    };
    let remote_source = is_network_artifact_source(&artifact);
    if remote_source && keys_path.is_none() {
        return Err(
            "remote artifacts require --keys and --keys-digest (or use a local file source)"
                .to_string(),
        );
    }
    let signature_mode = if remote_source {
        SignatureMode::Required
    } else {
        requested_signature_mode
    };
    let allow_insecure_http = has_switch(&parsed, "--allow-insecure-http");
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    let line = install(InstallRequest {
        artifact: &artifact,
        keys_path: keys_path.as_deref(),
        keys_digest: keys_digest.as_deref(),
        policy_path: policy_path.as_deref(),
        allow_experimental,
        allow_insecure_http,
        signature_mode,
    })?;
    println!("{line}");
    Ok(())
}

fn run_execute(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags_with_switches(
        args,
        &[
            "--bundle",
            "--keys",
            "--keys-digest",
            "--oci-ref",
            "--policy",
            "--input",
            "--receipt",
            "--receipt-format",
        ],
        &["--allow-experimental", "--require-cosign"],
        USAGE,
    )?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let keys_path = required_path(&parsed, "--keys", USAGE)?;
    let keys_digest = required_string(&parsed, "--keys-digest", USAGE)?;
    let oci_ref = optional_string(&parsed, "--oci-ref");
    let require_cosign = has_switch(&parsed, "--require-cosign");
    let policy_path = required_path(&parsed, "--policy", USAGE)?;
    let input_path = required_path(&parsed, "--input", USAGE)?;
    let receipt_path = required_path(&parsed, "--receipt", USAGE)?;
    let receipt_format =
        parse_receipt_format(optional_string(&parsed, "--receipt-format").as_deref())?;
    let allow_experimental = has_switch(&parsed, "--allow-experimental");
    run_bundle(RunBundleArgs {
        bundle_dir,
        keys_path,
        keys_digest,
        require_cosign,
        oci_ref,
        policy_path,
        input_path,
        receipt_path,
        receipt_format,
        allow_experimental,
    })
}

fn run_verify_receipt_cmd(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--receipt"], USAGE)?;
    let receipt_path = required_path(&parsed, "--receipt", USAGE)?;
    verify_receipt_file(&receipt_path)
}

fn run_verify_registry_entry_cmd(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--artifact", "--sha256", "--md5"], USAGE)?;
    let artifact_path = required_path(&parsed, "--artifact", USAGE)?;
    let expected_sha256 = required_string(&parsed, "--sha256", USAGE)?;
    let expected_md5 = required_string(&parsed, "--md5", USAGE)?;
    verify_registry_entry_file(&artifact_path, &expected_sha256, &expected_md5)
}

fn run_validate_manifest_v1_cmd(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--manifest"], USAGE)?;
    let manifest_path = required_path(&parsed, "--manifest", USAGE)?;
    validate_manifest_v1_file(&manifest_path)
}

fn run_validate_receipt_v1_cmd(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--receipt"], USAGE)?;
    let receipt_path = required_path(&parsed, "--receipt", USAGE)?;
    validate_receipt_v1_file(&receipt_path)
}

fn verify_bundle(
    bundle_dir: &Path,
    keys_path: &Path,
    keys_digest: &str,
    require_cosign: bool,
    oci_ref: Option<&str>,
    allow_experimental: bool,
) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let preflight_started = Instant::now();
        let bundle = load_verified_bundle(bundle_dir)?;
        require_manifest_schema_allowed(&bundle.manifest, allow_experimental)?;
        let preflight_ms = preflight_started.elapsed().as_millis() as u64;

        let trust_started = Instant::now();
        let keys_raw = read_file_limited(keys_path, MAX_JSON_BYTES, "public-keys.json")?;
        verify_keys_digest(&keys_raw, keys_digest)?;
        let public_keys = parse_public_keys(&keys_raw)?;
        verify_signatures(&bundle.signatures, &public_keys).map_err(|e| e.to_string())?;
        if require_cosign || oci_ref.is_some() {
            let Some(ref_value) = oci_ref else {
                return Err("--oci-ref is required when --require-cosign is set".to_string());
            };
            verify_cosign_oci_ref(ref_value)?;
        }
        let trust_ms = trust_started.elapsed().as_millis() as u64;

        println!(
            "OK verify artifact={} signers={}",
            bundle.manifest.artifact,
            bundle.signatures.signatures.len()
        );
        Ok((
            bundle.manifest.artifact,
            bundle.signatures.signatures.len() as u64,
            preflight_ms,
            trust_ms,
        ))
    })();

    match result {
        Ok((artifact, signer_count, preflight_ms, trust_ms)) => {
            emit_obs(
                "provenact.verify",
                vec![
                    ("status", json!("ok")),
                    ("artifact", json!(artifact)),
                    ("signer_count", json!(signer_count)),
                    ("preflight_ms", json!(preflight_ms)),
                    ("trust_ms", json!(trust_ms)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.verify",
                vec![
                    ("status", json!("error")),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn inspect_bundle(bundle_dir: &Path, allow_experimental: bool) -> Result<(), String> {
    let (manifest, signatures) = read_manifest_and_signatures(bundle_dir)?;
    require_manifest_schema_allowed(&manifest, allow_experimental)?;
    let bundle_meta_path = bundle_dir.join("bundle-meta.json");
    let bundle_meta_present = bundle_meta_path.is_file();
    let mut bundle_meta_artifact = String::new();
    let mut bundle_meta_manifest_hash = String::new();
    let mut bundle_meta_schema_version = String::new();
    if bundle_meta_present {
        let bundle_meta_raw = read_file_limited(&bundle_meta_path, MAX_JSON_BYTES, "bundle-meta")?;
        let bundle_meta_json: Value =
            serde_json::from_slice(&bundle_meta_raw).map_err(|e| format!("bundle-meta: {e}"))?;
        bundle_meta_artifact = bundle_meta_json
            .get("artifact")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        bundle_meta_manifest_hash = bundle_meta_json
            .get("manifest_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        bundle_meta_schema_version = bundle_meta_json
            .get("schema_version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    }
    let mut capabilities = manifest
        .capabilities
        .iter()
        .map(|c| format!("{}:{}", c.kind, c.value))
        .collect::<Vec<_>>();
    capabilities.sort();
    let mut manifest_signers = manifest.signers.clone();
    manifest_signers.sort();
    let mut signature_signers = signatures
        .signatures
        .iter()
        .map(|s| s.signer.clone())
        .collect::<Vec<_>>();
    signature_signers.sort();

    println!("name={}", manifest.name);
    println!("version={}", manifest.version);
    println!("entrypoint={}", manifest.entrypoint);
    println!("manifest_artifact={}", manifest.artifact);
    println!("signatures_artifact={}", signatures.artifact);
    println!("signatures_manifest_hash={}", signatures.manifest_hash);
    println!("bundle_meta_present={bundle_meta_present}");
    if bundle_meta_present {
        println!("bundle_meta_schema_version={bundle_meta_schema_version}");
        println!("bundle_meta_artifact={bundle_meta_artifact}");
        println!("bundle_meta_manifest_hash={bundle_meta_manifest_hash}");
    }
    println!("capabilities={}", capabilities.len());
    for (idx, cap) in capabilities.iter().enumerate() {
        println!("capability[{idx}]={cap}");
    }
    println!("signers={}", manifest_signers.len());
    for (idx, signer) in manifest_signers.iter().enumerate() {
        println!("signer[{idx}]={signer}");
    }
    println!("signature_count={}", signatures.signatures.len());
    for (idx, signer) in signature_signers.iter().enumerate() {
        println!("signature_signer[{idx}]={signer}");
    }
    Ok(())
}

fn pack_bundle(
    bundle_dir: &Path,
    wasm_path: &Path,
    manifest_path: &Path,
    allow_experimental: bool,
) -> Result<(), String> {
    let wasm = read_file_limited(wasm_path, MAX_WASM_BYTES, "skill.wasm")?;
    let manifest_raw = read_file_limited(manifest_path, MAX_JSON_BYTES, "manifest.json")?;
    let manifest = parse_manifest_json(&manifest_raw).map_err(|e| e.to_string())?;
    require_manifest_schema_allowed(&manifest, allow_experimental)?;
    let artifact = sha256_prefixed(&wasm);
    if manifest.artifact != artifact {
        return Err(format!(
            "manifest.artifact must match skill.wasm digest (expected {artifact}, got {})",
            manifest.artifact
        ));
    }

    fs::create_dir_all(bundle_dir).map_err(|e| format!("{}: {e}", bundle_dir.display()))?;
    write_file(&bundle_dir.join("skill.wasm"), &wasm)?;

    let manifest_out = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("manifest JSON encode failed: {e}"))?;
    write_file(&bundle_dir.join("manifest.json"), &manifest_out)?;

    let signatures = Signatures {
        artifact: manifest.artifact.clone(),
        manifest_hash: compute_manifest_hash(&manifest).map_err(|e| e.to_string())?,
        signatures: Vec::new(),
    };
    let bundle_meta = json!({
        "schema_version": BUNDLE_META_SCHEMA_VERSION,
        "artifact": manifest.artifact,
        "manifest_hash": signatures.manifest_hash,
    });
    let signatures_out = serde_json::to_vec_pretty(&signatures)
        .map_err(|e| format!("signatures JSON encode failed: {e}"))?;
    write_file(&bundle_dir.join("signatures.json"), &signatures_out)?;
    let bundle_meta_out = serde_json::to_vec_pretty(&bundle_meta)
        .map_err(|e| format!("bundle-meta JSON encode failed: {e}"))?;
    write_file(&bundle_dir.join("bundle-meta.json"), &bundle_meta_out)?;

    println!("OK pack bundle={}", bundle_dir.display());
    Ok(())
}

fn sign_bundle(
    bundle_dir: &Path,
    signer_id: &str,
    secret_key_path: &Path,
    allow_experimental: bool,
) -> Result<(), String> {
    let (manifest, mut signatures) = read_manifest_and_signatures(bundle_dir)?;
    require_manifest_schema_allowed(&manifest, allow_experimental)?;
    if manifest.artifact != signatures.artifact {
        return Err("manifest.artifact must equal signatures.artifact".to_string());
    }
    let manifest_hash = compute_manifest_hash(&manifest).map_err(|e| e.to_string())?;
    if signatures.manifest_hash != manifest_hash {
        return Err("signatures.manifest_hash must equal canonical manifest hash".to_string());
    }
    if !manifest.signers.iter().any(|s| s == signer_id) {
        return Err(format!(
            "signer is not declared in manifest.signers: {signer_id}"
        ));
    }

    let signing_key = parse_signing_key(&read_file_limited(
        secret_key_path,
        MAX_SECRET_KEY_BYTES,
        "secret-key",
    )?)?;
    let signature = signing_key.sign(signatures.manifest_hash.as_bytes());
    let encoded_signature = STANDARD.encode(signature.to_bytes());

    if let Some(existing) = signatures
        .signatures
        .iter_mut()
        .find(|entry| entry.signer == signer_id)
    {
        existing.algorithm = "ed25519".to_string();
        existing.signature = encoded_signature;
    } else {
        signatures.signatures.push(SignatureEntry {
            signer: signer_id.to_string(),
            algorithm: "ed25519".to_string(),
            signature: encoded_signature,
        });
    }
    signatures
        .signatures
        .sort_by(|a, b| a.signer.cmp(&b.signer).then(a.algorithm.cmp(&b.algorithm)));

    let signatures_out = serde_json::to_vec_pretty(&signatures)
        .map_err(|e| format!("signatures JSON encode failed: {e}"))?;
    write_file(&bundle_dir.join("signatures.json"), &signatures_out)?;

    println!(
        "OK sign bundle={} signer={} signatures={}",
        bundle_dir.display(),
        signer_id,
        signatures.signatures.len()
    );
    Ok(())
}

struct RunBundleArgs {
    bundle_dir: PathBuf,
    keys_path: PathBuf,
    keys_digest: String,
    require_cosign: bool,
    oci_ref: Option<String>,
    policy_path: PathBuf,
    input_path: PathBuf,
    receipt_path: PathBuf,
    receipt_format: ReceiptFormat,
    allow_experimental: bool,
}

fn run_bundle(args: RunBundleArgs) -> Result<(), String> {
    let RunBundleArgs {
        bundle_dir,
        keys_path,
        keys_digest,
        require_cosign,
        oci_ref,
        policy_path,
        input_path,
        receipt_path,
        receipt_format,
        allow_experimental,
    } = args;
    let started = Instant::now();
    let result = (|| {
        if matches!(receipt_format, ReceiptFormat::V1Draft) && !allow_experimental {
            return Err("receipt format 'v1-draft' requires --allow-experimental".to_string());
        }

        let run_started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();

        let verify_started = Instant::now();
        let bundle = load_verified_bundle(&bundle_dir)?;
        require_manifest_schema_allowed(&bundle.manifest, allow_experimental)?;
        let keys_raw = read_file_limited(&keys_path, MAX_JSON_BYTES, "public-keys.json")?;
        verify_keys_digest(&keys_raw, &keys_digest)?;
        let policy_raw = read_file_limited(&policy_path, MAX_JSON_BYTES, "policy")?;
        let input_bytes = read_file_limited(&input_path, MAX_INPUT_BYTES, "input")?;

        let public_keys = parse_public_keys(&keys_raw)?;
        verify_signatures(&bundle.signatures, &public_keys).map_err(|e| e.to_string())?;
        if require_cosign || oci_ref.is_some() {
            let Some(ref_value) = oci_ref.as_deref() else {
                return Err("--oci-ref is required when --require-cosign is set".to_string());
            };
            verify_cosign_oci_ref(ref_value)?;
        }

        let policy = parse_policy_document(&policy_raw).map_err(|e| e.to_string())?;
        verify_trusted_signers(&bundle.manifest, &bundle.signatures, &policy)
            .map_err(|e| e.to_string())?;
        enforce_capability_ceiling(&bundle.manifest.capabilities, &policy)
            .map_err(|e| e.to_string())?;
        let verify_ms = verify_started.elapsed().as_millis() as u64;

        let execute_started = Instant::now();
        let inputs_hash = sha256_prefixed(&input_bytes);
        let execution = execute_wasm(
            &bundle.wasm,
            &bundle.manifest.entrypoint,
            &input_bytes,
            &bundle.manifest.capabilities,
        )?;
        let outputs = execution.outputs;
        let outputs_hash = sha256_prefixed(&outputs);
        let execute_ms = execute_started.elapsed().as_millis() as u64;

        let receipt_started = Instant::now();
        let caps_used = execution.caps_used;
        let finished_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();
        let receipt_json = match receipt_format {
            ReceiptFormat::V0 => {
                let receipt_hash = compute_receipt_hash(
                    &bundle.manifest.artifact,
                    &inputs_hash,
                    &outputs_hash,
                    &caps_used,
                    finished_at,
                )
                .map_err(|e| format!("receipt hash computation failed: {e}"))?;
                let receipt = ExecutionReceipt {
                    artifact: bundle.manifest.artifact.clone(),
                    inputs_hash: inputs_hash.clone(),
                    outputs_hash: outputs_hash.clone(),
                    caps_used: caps_used.clone(),
                    timestamp: finished_at,
                    receipt_hash,
                };
                verify_receipt_hash(&receipt)
                    .map_err(|e| format!("receipt self-verification failed: {e}"))?;
                serde_json::to_vec_pretty(&receipt)
                    .map_err(|e| format!("receipt JSON encode failed: {e}"))?
            }
            ReceiptFormat::V1Draft => {
                let mut caps_requested = bundle
                    .manifest
                    .capabilities
                    .iter()
                    .map(|c| format!("{}:{}", c.kind, c.value))
                    .collect::<Vec<_>>();
                caps_requested.sort();
                let caps_granted = caps_requested.clone();
                let manifest_hash = bundle.signatures.manifest_hash.clone();
                let policy_hash = compute_policy_hash(&policy)
                    .map_err(|e| format!("policy hash computation failed: {e}"))?;
                let bundle_hash = compute_bundle_hash(
                    &bundle.manifest.artifact,
                    &manifest_hash,
                    &bundle.signatures,
                )
                .map_err(|e| format!("bundle hash computation failed: {e}"))?;
                let result = ExecutionResultV1Draft {
                    status: "success".to_string(),
                    code: "ok".to_string(),
                    message: None,
                };
                let runtime = RuntimeV1Draft {
                    name: "provenact-cli".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    profile: Some("wasmtime36-hostabi-v0".to_string()),
                };
                let runtime_version_digest = compute_runtime_version_digest_v1(&runtime)
                    .map_err(|e| format!("runtime version digest failed: {e}"))?;
                let result_digest = compute_result_digest_v1(&result, &outputs_hash, &caps_used)
                    .map_err(|e| format!("result digest computation failed: {e}"))?;

                let mut receipt = ExecutionReceiptV1Draft {
                    schema_version: EXPERIMENTAL_SCHEMA_VERSION.to_string(),
                    artifact: bundle.manifest.artifact.clone(),
                    manifest_hash,
                    policy_hash,
                    bundle_hash,
                    inputs_hash: inputs_hash.clone(),
                    outputs_hash: outputs_hash.clone(),
                    runtime_version_digest,
                    result_digest,
                    caps_requested,
                    caps_granted,
                    caps_used: caps_used.clone(),
                    result,
                    runtime,
                    started_at: run_started_at,
                    finished_at,
                    timestamp_strategy: RECEIPT_TIMESTAMP_STRATEGY_LOCAL.to_string(),
                    attestations: None,
                    receipt_hash: String::new(),
                };
                let receipt_hash = compute_receipt_v1_draft_hash(&receipt)
                    .map_err(|e| format!("receipt hash computation failed: {e}"))?;
                receipt.receipt_hash = receipt_hash;
                verify_receipt_v1_draft_hash(&receipt)
                    .map_err(|e| format!("receipt self-verification failed: {e}"))?;
                serde_json::to_vec_pretty(&receipt)
                    .map_err(|e| format!("receipt JSON encode failed: {e}"))?
            }
        };

        if let Some(parent) = receipt_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
        }
        write_file(&receipt_path, &receipt_json)?;
        let receipt_ms = receipt_started.elapsed().as_millis() as u64;

        println!(
            "OK run artifact={} receipt={}",
            bundle.manifest.artifact,
            receipt_path.display()
        );
        Ok((
            bundle.manifest.artifact,
            bundle.manifest.capabilities.len() as u64,
            verify_ms,
            execute_ms,
            receipt_ms,
        ))
    })();

    match result {
        Ok((artifact, capability_count, verify_ms, execute_ms, receipt_ms)) => {
            emit_obs(
                "provenact.run",
                vec![
                    ("status", json!("ok")),
                    ("artifact", json!(artifact)),
                    ("capability_count", json!(capability_count)),
                    ("verify_ms", json!(verify_ms)),
                    ("execute_ms", json!(execute_ms)),
                    ("receipt_ms", json!(receipt_ms)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.run",
                vec![
                    ("status", json!("error")),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn verify_receipt_file(receipt_path: &Path) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let receipt_raw = read_file_limited(receipt_path, MAX_JSON_BYTES, "receipt.json")?;
        if let Ok(receipt) = parse_receipt_json(&receipt_raw) {
            verify_receipt_hash(&receipt).map_err(|e| e.to_string())?;
            println!(
                "OK verify-receipt artifact={} receipt={}",
                receipt.artifact,
                receipt_path.display()
            );
            return Ok(receipt.artifact);
        }

        let receipt = parse_receipt_v1_draft_json(&receipt_raw).map_err(|e| e.to_string())?;
        verify_receipt_v1_draft_hash(&receipt).map_err(|e| e.to_string())?;
        println!(
            "OK verify-receipt artifact={} receipt={} schema={}",
            receipt.artifact,
            receipt_path.display(),
            receipt.schema_version
        );
        Ok(receipt.artifact)
    })();

    match result {
        Ok(artifact) => {
            emit_obs(
                "provenact.verify_receipt",
                vec![
                    ("status", json!("ok")),
                    ("artifact", json!(artifact)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.verify_receipt",
                vec![
                    ("status", json!("error")),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn verify_registry_entry_file(
    artifact_path: &Path,
    expected_sha256: &str,
    expected_md5: &str,
) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let artifact_bytes = read_file_limited(artifact_path, MAX_WASM_BYTES, "artifact")?;
        let entry = RegistryEntry {
            sha256: expected_sha256.to_string(),
            md5: expected_md5.to_string(),
        };
        verify_registry_entry_artifact(&artifact_bytes, &entry).map_err(|e| e.to_string())?;
        println!(
            "OK verify-registry-entry sha256={} md5={} artifact={}",
            expected_sha256,
            expected_md5,
            artifact_path.display()
        );
        Ok(())
    })();

    match result {
        Ok(()) => {
            emit_obs(
                "provenact.verify_registry_entry",
                vec![
                    ("status", json!("ok")),
                    ("sha256", json!(expected_sha256)),
                    ("md5", json!(expected_md5)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.verify_registry_entry",
                vec![
                    ("status", json!("error")),
                    ("sha256", json!(expected_sha256)),
                    ("md5", json!(expected_md5)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn validate_manifest_v1_file(manifest_path: &Path) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let raw = read_file_limited(manifest_path, MAX_JSON_BYTES, "manifest.json")?;
        let manifest = parse_manifest_v1_draft_json(&raw).map_err(|e| e.to_string())?;
        println!(
            "OK experimental-validate-manifest-v1 id={} version={}",
            manifest.id, manifest.version
        );
        Ok(manifest.id)
    })();

    match result {
        Ok(manifest_id) => {
            emit_obs(
                "provenact.experimental_validate_manifest_v1",
                vec![
                    ("status", json!("ok")),
                    ("manifest_id", json!(manifest_id)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.experimental_validate_manifest_v1",
                vec![
                    ("status", json!("error")),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn validate_receipt_v1_file(receipt_path: &Path) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let raw = read_file_limited(receipt_path, MAX_JSON_BYTES, "receipt.json")?;
        let receipt = parse_receipt_v1_draft_json(&raw).map_err(|e| e.to_string())?;
        println!(
            "OK experimental-validate-receipt-v1 artifact={} status={}",
            receipt.artifact, receipt.result.status
        );
        Ok(receipt.artifact)
    })();

    match result {
        Ok(artifact) => {
            emit_obs(
                "provenact.experimental_validate_receipt_v1",
                vec![
                    ("status", json!("ok")),
                    ("artifact", json!(artifact)),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                ],
            );
            Ok(())
        }
        Err(err) => {
            emit_obs(
                "provenact.experimental_validate_receipt_v1",
                vec![
                    ("status", json!("error")),
                    ("duration_ms", json!(started.elapsed().as_millis() as u64)),
                    ("error", json!(err)),
                ],
            );
            Err(err)
        }
    }
}

fn require_manifest_schema_allowed(
    manifest: &Manifest,
    allow_experimental: bool,
) -> Result<(), String> {
    if manifest.schema_version.as_deref() == Some(EXPERIMENTAL_SCHEMA_VERSION)
        && !allow_experimental
    {
        return Err(format!(
            "manifest schema_version '{}' requires --allow-experimental",
            EXPERIMENTAL_SCHEMA_VERSION
        ));
    }
    Ok(())
}

fn obs_enabled() -> bool {
    matches!(
        env::var("PROVENACT_OBS_JSON")
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn emit_obs(event: &str, fields: Vec<(&str, Value)>) {
    if !obs_enabled() {
        return;
    }

    let mut record = serde_json::Map::new();
    record.insert("event".to_string(), json!(event));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    record.insert("timestamp".to_string(), json!(timestamp));
    for (key, value) in fields {
        record.insert(key.to_string(), value);
    }
    eprintln!("{}", Value::Object(record));
}

fn verify_cosign_oci_ref(oci_ref: &str) -> Result<(), String> {
    let output = Command::new("cosign")
        .args(["verify", oci_ref])
        .output()
        .map_err(|e| format!("cosign verify invocation failed: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(format!("cosign verify failed for {oci_ref}"));
        }
        return Err(format!("cosign verify failed for {oci_ref}: {stderr}"));
    }
    Ok(())
}
