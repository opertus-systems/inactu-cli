mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, wasm_with_i32_entrypoint, write};
use ed25519_dalek::SigningKey;
use provenact_verifier::sha256_prefixed;
use serde_json::Value;

fn make_receipt() -> PathBuf {
    let root = temp_dir("verify_receipt");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 42);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());

    let pack = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(pack.status.success(), "{:?}", pack);

    let signing_key = SigningKey::from_bytes(&[33u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());
    let policy = r#"{
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{}"#);

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);
    receipt_path
}

fn make_receipt_v1_draft() -> PathBuf {
    let root = temp_dir("verify_receipt_v1");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.json");

    let wasm = wasm_with_i32_entrypoint("run", 42);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());

    let pack = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(pack.status.success(), "{:?}", pack);

    let signing_key = SigningKey::from_bytes(&[34u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());
    let policy = r#"{
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{}"#);

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .args(["--receipt-format", "v1-draft", "--allow-experimental"])
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);
    receipt_path
}

#[test]
fn verify_receipt_succeeds_for_valid_receipt() {
    let receipt_path = make_receipt();
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_fails_for_tampered_receipt() {
    let receipt_path = make_receipt();
    let raw = fs::read(&receipt_path).expect("receipt should exist");
    let mut value: Value = serde_json::from_slice(&raw).expect("receipt json should parse");
    value["outputs_hash"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&value).expect("receipt json should serialize"),
    )
    .expect("tamper write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_succeeds_for_valid_v1_draft_receipt() {
    let receipt_path = make_receipt_v1_draft();
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(output.status.success(), "{:?}", output);
}
