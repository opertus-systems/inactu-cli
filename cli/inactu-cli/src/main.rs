mod constants;
mod fileio;
mod flags;
mod keys;
mod preflight;
mod runtime_exec;

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer as _;
use inactu_verifier::{
    compute_manifest_hash, compute_receipt_hash, enforce_capability_ceiling, parse_manifest_json,
    parse_policy_document, parse_receipt_json, sha256_prefixed, verify_receipt_hash,
    verify_signatures, verify_trusted_signers, ExecutionReceipt, SignatureEntry, Signatures,
};
use serde_json::{json, Value};

use constants::{MAX_INPUT_BYTES, MAX_JSON_BYTES, MAX_SECRET_KEY_BYTES, MAX_WASM_BYTES};
use fileio::{read_file_limited, write_file};
use flags::{optional_string, parse_flags, required_path, required_string};
use keys::{parse_public_keys, parse_signing_key, verify_keys_digest};
use preflight::{load_verified_bundle, read_manifest_and_signatures};
use runtime_exec::execute_wasm;

const USAGE: &str = "usage:\n  inactu-cli verify --bundle <bundle-dir> --keys <public-keys.json> [--keys-digest <sha256:...>]\n  inactu-cli inspect --bundle <bundle-dir>\n  inactu-cli pack --bundle <bundle-dir> --wasm <skill.wasm> --manifest <manifest.json>\n  inactu-cli sign --bundle <bundle-dir> --signer <signer-id> --secret-key <ed25519-secret-key-file>\n  inactu-cli run --bundle <bundle-dir> --keys <public-keys.json> [--keys-digest <sha256:...>] --policy <policy.{json|yaml}> --input <input-file> --receipt <receipt.json>\n  inactu-cli verify-receipt --receipt <receipt.json>";

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("command failed: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("unknown");
    let started = Instant::now();
    let result = match args.first().map(String::as_str) {
        Some("verify") => run_verify(&args[1..]),
        Some("inspect") => run_inspect(&args[1..]),
        Some("pack") => run_pack(&args[1..]),
        Some("sign") => run_sign(&args[1..]),
        Some("run") => run_execute(&args[1..]),
        Some("verify-receipt") => run_verify_receipt_cmd(&args[1..]),
        _ => Err(USAGE.to_string()),
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(()) => emit_obs(
            "inactu.command",
            vec![
                ("command", json!(command)),
                ("status", json!("ok")),
                ("duration_ms", json!(duration_ms)),
            ],
        ),
        Err(err) => emit_obs(
            "inactu.command",
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

fn run_verify(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--bundle", "--keys", "--keys-digest"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let keys_path = required_path(&parsed, "--keys", USAGE)?;
    let keys_digest = optional_string(&parsed, "--keys-digest");
    verify_bundle(&bundle_dir, &keys_path, keys_digest.as_deref())
}

fn run_inspect(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--bundle"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    inspect_bundle(&bundle_dir)
}

fn run_pack(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--bundle", "--wasm", "--manifest"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let wasm_path = required_path(&parsed, "--wasm", USAGE)?;
    let manifest_path = required_path(&parsed, "--manifest", USAGE)?;
    pack_bundle(&bundle_dir, &wasm_path, &manifest_path)
}

fn run_sign(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--bundle", "--signer", "--secret-key"], USAGE)?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let signer_id = required_string(&parsed, "--signer", USAGE)?;
    let secret_key_path = required_path(&parsed, "--secret-key", USAGE)?;
    sign_bundle(&bundle_dir, &signer_id, &secret_key_path)
}

fn run_execute(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(
        args,
        &[
            "--bundle",
            "--keys",
            "--keys-digest",
            "--policy",
            "--input",
            "--receipt",
        ],
        USAGE,
    )?;
    let bundle_dir = required_path(&parsed, "--bundle", USAGE)?;
    let keys_path = required_path(&parsed, "--keys", USAGE)?;
    let keys_digest = optional_string(&parsed, "--keys-digest");
    let policy_path = required_path(&parsed, "--policy", USAGE)?;
    let input_path = required_path(&parsed, "--input", USAGE)?;
    let receipt_path = required_path(&parsed, "--receipt", USAGE)?;
    run_bundle(
        &bundle_dir,
        &keys_path,
        keys_digest.as_deref(),
        &policy_path,
        &input_path,
        &receipt_path,
    )
}

fn run_verify_receipt_cmd(args: &[String]) -> Result<(), String> {
    let parsed = parse_flags(args, &["--receipt"], USAGE)?;
    let receipt_path = required_path(&parsed, "--receipt", USAGE)?;
    verify_receipt_file(&receipt_path)
}

fn verify_bundle(
    bundle_dir: &Path,
    keys_path: &Path,
    keys_digest: Option<&str>,
) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let preflight_started = Instant::now();
        let bundle = load_verified_bundle(bundle_dir)?;
        let preflight_ms = preflight_started.elapsed().as_millis() as u64;

        let trust_started = Instant::now();
        let keys_raw = read_file_limited(keys_path, MAX_JSON_BYTES, "public-keys.json")?;
        verify_keys_digest(&keys_raw, keys_digest)?;
        let public_keys = parse_public_keys(&keys_raw)?;
        verify_signatures(&bundle.signatures, &public_keys).map_err(|e| e.to_string())?;
        let trust_ms = trust_started.elapsed().as_millis() as u64;

        println!(
            "OK artifact={} signers={}",
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
                "inactu.verify",
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
                "inactu.verify",
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

fn inspect_bundle(bundle_dir: &Path) -> Result<(), String> {
    let (manifest, signatures) = read_manifest_and_signatures(bundle_dir)?;
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

fn pack_bundle(bundle_dir: &Path, wasm_path: &Path, manifest_path: &Path) -> Result<(), String> {
    let wasm = read_file_limited(wasm_path, MAX_WASM_BYTES, "skill.wasm")?;
    let manifest_raw = read_file_limited(manifest_path, MAX_JSON_BYTES, "manifest.json")?;
    let manifest = parse_manifest_json(&manifest_raw).map_err(|e| e.to_string())?;
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
    let signatures_out = serde_json::to_vec_pretty(&signatures)
        .map_err(|e| format!("signatures JSON encode failed: {e}"))?;
    write_file(&bundle_dir.join("signatures.json"), &signatures_out)?;

    println!("OK packed bundle={}", bundle_dir.display());
    Ok(())
}

fn sign_bundle(bundle_dir: &Path, signer_id: &str, secret_key_path: &Path) -> Result<(), String> {
    let (manifest, mut signatures) = read_manifest_and_signatures(bundle_dir)?;
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
        "OK signed bundle={} signer={} signatures={}",
        bundle_dir.display(),
        signer_id,
        signatures.signatures.len()
    );
    Ok(())
}

fn run_bundle(
    bundle_dir: &Path,
    keys_path: &Path,
    keys_digest: Option<&str>,
    policy_path: &Path,
    input_path: &Path,
    receipt_path: &Path,
) -> Result<(), String> {
    let started = Instant::now();
    let result = (|| {
        let verify_started = Instant::now();
        let bundle = load_verified_bundle(bundle_dir)?;
        let keys_raw = read_file_limited(keys_path, MAX_JSON_BYTES, "public-keys.json")?;
        verify_keys_digest(&keys_raw, keys_digest)?;
        let policy_raw = read_file_limited(policy_path, MAX_JSON_BYTES, "policy")?;
        let input_bytes = read_file_limited(input_path, MAX_INPUT_BYTES, "input")?;

        let public_keys = parse_public_keys(&keys_raw)?;
        verify_signatures(&bundle.signatures, &public_keys).map_err(|e| e.to_string())?;

        let policy = parse_policy_document(&policy_raw).map_err(|e| e.to_string())?;
        verify_trusted_signers(&bundle.manifest, &bundle.signatures, &policy)
            .map_err(|e| e.to_string())?;
        enforce_capability_ceiling(&bundle.manifest.capabilities, &policy)
            .map_err(|e| e.to_string())?;
        let verify_ms = verify_started.elapsed().as_millis() as u64;

        let execute_started = Instant::now();
        let inputs_hash = sha256_prefixed(&input_bytes);
        let outputs = execute_wasm(&bundle.wasm, &bundle.manifest.entrypoint)?;
        let outputs_hash = sha256_prefixed(&outputs);
        let execute_ms = execute_started.elapsed().as_millis() as u64;

        let receipt_started = Instant::now();
        let mut caps_used = bundle
            .manifest
            .capabilities
            .iter()
            .map(|cap| format!("{}:{}", cap.kind, cap.value))
            .collect::<Vec<_>>();
        caps_used.sort();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs();
        let receipt_hash = compute_receipt_hash(
            &bundle.manifest.artifact,
            &inputs_hash,
            &outputs_hash,
            &caps_used,
            timestamp,
        )
        .map_err(|e| format!("receipt hash computation failed: {e}"))?;
        let receipt = ExecutionReceipt {
            artifact: bundle.manifest.artifact.clone(),
            inputs_hash,
            outputs_hash,
            caps_used,
            timestamp,
            receipt_hash,
        };
        verify_receipt_hash(&receipt)
            .map_err(|e| format!("receipt self-verification failed: {e}"))?;

        if let Some(parent) = receipt_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
        }
        let receipt_json = serde_json::to_vec_pretty(&receipt)
            .map_err(|e| format!("receipt JSON encode failed: {e}"))?;
        write_file(receipt_path, &receipt_json)?;
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
                "inactu.run",
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
                "inactu.run",
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
        let receipt = parse_receipt_json(&receipt_raw).map_err(|e| e.to_string())?;
        verify_receipt_hash(&receipt).map_err(|e| e.to_string())?;
        println!(
            "OK receipt artifact={} receipt={}",
            receipt.artifact,
            receipt_path.display()
        );
        Ok(receipt.artifact)
    })();

    match result {
        Ok(artifact) => {
            emit_obs(
                "inactu.verify_receipt",
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
                "inactu.verify_receipt",
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

fn obs_enabled() -> bool {
    matches!(
        env::var("INACTU_OBS_JSON")
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
