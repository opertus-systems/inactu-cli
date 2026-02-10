mod common;

use std::fs;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{
    temp_dir, wasm_with_i32_entrypoint, wasm_with_infinite_loop, wasm_with_memory_growth_trap,
    write,
};
use ed25519_dalek::SigningKey;
use provenact_verifier::{
    parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed, verify_receipt_hash,
    verify_receipt_v1_draft_hash,
};

#[test]
fn run_emits_valid_receipt_after_verification_and_policy_check() {
    let root = temp_dir("run_ok");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 7);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[{{\"kind\":\"env\",\"value\":\"HOME\"}}],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
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
        "env": ["HOME"],
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{"msg":"hello"}"#);

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

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.artifact, artifact);
    assert_eq!(receipt.inputs_hash, sha256_prefixed(br#"{"msg":"hello"}"#));
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"7"));
}

#[test]
fn run_denies_capability_outside_policy_ceiling() {
    let root = temp_dir("run_policy_deny");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.yaml");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 1);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[{{\"kind\":\"net\",\"value\":\"https://example.com/api\"}}],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[22u8; 32]);
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
    let policy = r#"
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  net: ["https://api.open-meteo.com"]
  exec: false
  time: false
"#;
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
    assert!(!run.status.success(), "{:?}", run);

    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("capability denied"), "stderr was: {stderr}");
    assert!(!receipt_path.exists(), "receipt should not exist on deny");
}

#[test]
fn run_fails_when_require_cosign_without_cert_identity() {
    let root = temp_dir("run_require_cosign_no_cert_identity");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let cosign_pub_path = root.join("cosign.pub");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 9);
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

    let signing_key = SigningKey::from_bytes(&[31u8; 32]);
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
    write(&cosign_pub_path, b"dummy cosign public key");

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
        .args(["--oci-ref", "ghcr.io/acme/echo:0.1.0"])
        .args(["--cosign-key"])
        .arg(&cosign_pub_path)
        .arg("--require-cosign")
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr
            .contains("--cosign-cert-identity is required when cosign verification is configured"),
        "stderr was: {stderr}"
    );
    assert!(
        !receipt_path.exists(),
        "receipt should not exist on failed run"
    );
}

#[test]
fn run_stops_infinite_loop_on_fuel_exhaustion() {
    let root = temp_dir("run_fuel_exhaustion");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_infinite_loop("run");
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"loop.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[23u8; 32]);
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
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("fuel exhausted"), "stderr was: {stderr}");
    assert!(!receipt_path.exists(), "receipt should not exist on trap");
}

#[test]
fn run_stops_memory_growth_abuse() {
    let root = temp_dir("run_memory_limit");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_memory_growth_trap("run", 1024);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"memory.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[24u8; 32]);
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
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("wasm execution failed"),
        "stderr was: {stderr}"
    );
    assert!(!receipt_path.exists(), "receipt should not exist on trap");
}

#[test]
fn run_emits_v1_draft_receipt_with_security_digests() {
    let root = temp_dir("run_v1_draft_ok");
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

    let signing_key = SigningKey::from_bytes(&[25u8; 32]);
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

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_v1_draft_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_v1_draft_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.schema_version, "1.0.0-draft");
    assert_eq!(receipt.timestamp_strategy, "local_untrusted_unix_seconds");
    assert_eq!(receipt.artifact, artifact);
}

#[test]
fn run_rejects_v1_draft_receipt_without_allow_experimental() {
    let root = temp_dir("run_v1_draft_gate");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.json");

    let wasm = wasm_with_i32_entrypoint("run", 1);
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

    let signing_key = SigningKey::from_bytes(&[26u8; 32]);
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
        .args(["--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("requires --allow-experimental"),
        "stderr was: {stderr}"
    );
}

#[test]
fn run_rejects_keys_digest_mismatch() {
    let root = temp_dir("run_keys_digest_mismatch");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 3);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"keys.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[25u8; 32]);
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
        .args([
            "--keys-digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("public keys digest mismatch"),
        "stderr was: {stderr}"
    );
    assert!(
        !receipt_path.exists(),
        "receipt should not exist on digest mismatch"
    );
}

#[test]
fn run_requires_keys_digest_flag() {
    let root = temp_dir("run_keys_digest_required");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 5);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"digest.required\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[27u8; 32]);
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
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}
