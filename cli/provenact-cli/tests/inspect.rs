mod common;

use common::vectors_root;
use std::fs;
use std::process::Command;

use common::{temp_dir, write};
use provenact_verifier::{compute_manifest_hash, sha256_prefixed};

#[test]
fn inspect_outputs_deterministic_fields() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["inspect", "--bundle"])
        .arg(&bundle)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let expected = [
        "name=echo.minimal",
        "version=0.1.0",
        "entrypoint=run",
        "manifest_artifact=sha256:93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476",
        "signatures_artifact=sha256:93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476",
        "signatures_manifest_hash=sha256:5608b234a450b93faa080969141fb123a69abd2e5563d0e21d47fc03862856a2",
        "bundle_meta_present=false",
        "capabilities=0",
        "signers=1",
        "signer[0]=alice.dev",
        "signature_count=1",
        "signature_signer[0]=alice.dev",
    ]
    .join("\n")
        + "\n";

    assert_eq!(stdout, expected);
}

#[test]
fn inspect_succeeds_for_non_verifying_bundle() {
    let root = vectors_root();
    let bundle = root.join("bad/hash-mismatch");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["inspect", "--bundle"])
        .arg(&bundle)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn inspect_outputs_bundle_meta_when_present() {
    let root = temp_dir("inspect_bundle_meta");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");

    let wasm = b"\0asm\x01\0\0\0";
    write(&wasm_path, wasm);
    let artifact = sha256_prefixed(wasm);
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
    assert!(bundle_dir.join("bundle-meta.json").is_file());

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["inspect", "--bundle"])
        .arg(&bundle_dir)
        .output()
        .expect("inspect should run");
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");

    let manifest_raw = fs::read(bundle_dir.join("manifest.json")).expect("manifest should exist");
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest_raw).expect("manifest should be valid json");
    let manifest_hash = compute_manifest_hash(
        &provenact_verifier::parse_manifest_json(&manifest_raw).expect("manifest should parse"),
    )
    .expect("manifest hash should compute");

    assert!(
        stdout.contains("bundle_meta_present=true\n"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains("bundle_meta_schema_version=1.0.0\n"),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "bundle_meta_artifact={}\n",
            manifest_json["artifact"].as_str().unwrap_or_default()
        )),
        "stdout was: {stdout}"
    );
    assert!(
        stdout.contains(&format!("bundle_meta_manifest_hash={manifest_hash}\n")),
        "stdout was: {stdout}"
    );
}
