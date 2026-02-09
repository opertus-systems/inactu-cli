use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::SigningKey;
use provenact_verifier::sha256_prefixed;
use wat::parse_str as wat_parse_str;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .canonicalize()
        .expect("test-vectors dir should exist")
}

fn temp_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "provenact-cli-{test_name}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn write(path: &PathBuf, bytes: &[u8]) {
    fs::write(path, bytes).expect("write should succeed");
}

fn wasm_with_i32_entrypoint(entrypoint: &str, value: i32) -> Vec<u8> {
    let wat = format!(
        r#"(module
  (func (export "{entrypoint}") (result i32)
    i32.const {value})
)"#
    );
    wat_parse_str(&wat).expect("wat should compile")
}

#[test]
fn gate_tampered_artifact_is_rejected() {
    let root = vectors_root();
    let bundle = root.join("bad/hash-mismatch");
    let keys = bundle.join("public-keys.json");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys).expect("keys should exist"),
        ))
        .output()
        .expect("verify should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn gate_bad_signature_is_rejected() {
    let root = vectors_root();
    let bundle = root.join("bad/bad-signature");
    let keys = bundle.join("public-keys.json");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys).expect("keys should exist"),
        ))
        .output()
        .expect("verify should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn gate_unauthorized_capability_is_denied() {
    let root = temp_dir("threat_cap_deny");
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

    let signing_key = SigningKey::from_bytes(&[44u8; 32]);
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
    assert!(
        !receipt_path.exists(),
        "receipt must not exist on denied run"
    );
}

#[test]
fn gate_successful_run_produces_auditable_receipt() {
    let root = temp_dir("threat_receipt_ok");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 99);
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

    let signing_key = SigningKey::from_bytes(&[45u8; 32]);
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
    assert!(receipt_path.exists(), "receipt should exist");

    let verify_receipt = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(verify_receipt.status.success(), "{:?}", verify_receipt);
}
