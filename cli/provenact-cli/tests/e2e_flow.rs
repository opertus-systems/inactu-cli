mod common;

use std::fs;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, vectors_root};
use ed25519_dalek::SigningKey;
use provenact_verifier::{parse_receipt_json, sha256_prefixed, verify_receipt_hash};
use serde_json::{Map, Value};
use wat::parse_str as wat_parse_str;

#[test]
fn e2e_fixture_verify_run_verify_receipt() {
    let fixture = vectors_root().join("good/verify-run-verify-receipt");
    let temp = temp_dir("e2e_fixture");
    let bundle_dir = temp.join("bundle");
    let wasm_path = temp.join("skill.wasm");
    let manifest_path = temp.join("manifest.json");
    let keys_path = temp.join("public-keys.json");
    let receipt_path = temp.join("receipt.json");

    let wat = fs::read_to_string(fixture.join("skill.wat")).expect("fixture wat should exist");
    let wasm = wat_parse_str(&wat).expect("fixture wat should compile");
    fs::write(&wasm_path, &wasm).expect("wasm write should succeed");
    let artifact = sha256_prefixed(&wasm);

    let mut manifest: Map<String, Value> = serde_json::from_slice(
        &fs::read(fixture.join("manifest.base.json")).expect("manifest base"),
    )
    .expect("manifest base should parse");
    manifest.insert("artifact".to_string(), Value::String(artifact.clone()));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest should encode"),
    )
    .expect("manifest write should succeed");

    let secret_key_b64 =
        fs::read_to_string(fixture.join("signer-secret-key.txt")).expect("secret key should exist");
    let secret_key_bytes = STANDARD
        .decode(secret_key_b64.trim().as_bytes())
        .expect("secret key should decode");
    let secret_key = SigningKey::from_bytes(
        &secret_key_bytes
            .as_slice()
            .try_into()
            .expect("secret key should be 32 bytes"),
    );
    fs::write(temp.join("signing.key"), secret_key_b64.as_bytes())
        .expect("signing key write should succeed");
    fs::write(
        &keys_path,
        format!(
            "{{\"alice.dev\":\"{}\"}}",
            STANDARD.encode(secret_key.verifying_key().to_bytes())
        ),
    )
    .expect("keys write should succeed");

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

    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(temp.join("signing.key"))
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let verify = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .output()
        .expect("verify should run");
    assert!(verify.status.success(), "{:?}", verify);

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
        .arg(fixture.join("policy.json"))
        .args(["--input"])
        .arg(fixture.join("input.json"))
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);

    let verify_receipt = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(verify_receipt.status.success(), "{:?}", verify_receipt);

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.artifact, artifact);
    assert!(
        receipt.caps_used.is_empty(),
        "expected no used capabilities"
    );
}

#[test]
fn pack_requires_allow_experimental_for_draft_schema_version() {
    let fixture = vectors_root().join("good/verify-run-verify-receipt");
    let temp = temp_dir("e2e_experimental_gate");
    let bundle_dir = temp.join("bundle");
    let wasm_path = temp.join("skill.wasm");
    let manifest_path = temp.join("manifest.json");

    let wat = fs::read_to_string(fixture.join("skill.wat")).expect("fixture wat should exist");
    let wasm = wat_parse_str(&wat).expect("fixture wat should compile");
    fs::write(&wasm_path, &wasm).expect("wasm write should succeed");
    let artifact = sha256_prefixed(&wasm);

    let mut manifest: Map<String, Value> = serde_json::from_slice(
        &fs::read(fixture.join("manifest.base.json")).expect("manifest base"),
    )
    .expect("manifest base should parse");
    manifest.insert(
        "schema_version".to_string(),
        Value::String("1.0.0-draft".to_string()),
    );
    manifest.insert("artifact".to_string(), Value::String(artifact));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest should encode"),
    )
    .expect("manifest write should succeed");

    let pack_without_gate = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(
        !pack_without_gate.status.success(),
        "{:?}",
        pack_without_gate
    );
    assert!(
        String::from_utf8_lossy(&pack_without_gate.stderr)
            .contains("requires --allow-experimental"),
        "{:?}",
        pack_without_gate
    );

    let pack_with_gate = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--allow-experimental")
        .output()
        .expect("pack should run");
    assert!(pack_with_gate.status.success(), "{:?}", pack_with_gate);
}
