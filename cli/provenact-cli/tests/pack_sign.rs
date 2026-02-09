mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, vectors_root, write};
use ed25519_dalek::SigningKey;
use provenact_verifier::{parse_signatures_json, sha256_prefixed};

fn path_with_bin_dir(bin_dir: &Path) -> String {
    let mut parts = vec![bin_dir.display().to_string()];
    if let Some(existing) = std::env::var_os("PATH") {
        parts.push(existing.to_string_lossy().to_string());
    }
    parts.join(":")
}

#[test]
fn pack_creates_bundle_with_empty_signatures() {
    let root = temp_dir("pack_ok");
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

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);

    let packed_wasm = fs::read(bundle_dir.join("skill.wasm")).expect("packed wasm");
    assert_eq!(packed_wasm, wasm);
    let signatures_raw = fs::read(bundle_dir.join("signatures.json")).expect("signatures");
    let signatures = parse_signatures_json(&signatures_raw).expect("signatures should parse");
    assert_eq!(signatures.artifact, artifact);
    assert!(signatures.signatures.is_empty());
    assert!(bundle_dir.join("bundle-meta.json").is_file());
}

#[test]
fn verify_rejects_unsigned_bundle() {
    let root = temp_dir("pack_unsigned_verify");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let keys_path = root.join("public-keys.json");

    let wasm = b"\0asm\x01\0\0\0";
    write(&wasm_path, wasm);
    let artifact = sha256_prefixed(wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());
    write(
        &keys_path,
        b"{\"alice.dev\":\"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\"}",
    );

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
    assert!(!verify.status.success(), "{:?}", verify);
    let stderr = String::from_utf8(verify.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("signature set is empty"),
        "stderr was: {stderr}"
    );
}

#[test]
fn pack_rejects_manifest_artifact_mismatch() {
    let root = temp_dir("pack_bad_artifact");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");

    write(&wasm_path, b"\0asm\x01\0\0\0");
    let manifest = "{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}";
    write(&manifest_path, manifest.as_bytes());

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("manifest.artifact must match"),
        "stderr was: {stderr}"
    );
}

#[test]
fn sign_and_verify_round_trip_succeeds() {
    let root = temp_dir("sign_verify");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");

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

    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());

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
}

#[test]
fn sign_requires_all_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle", "tmp/bundle", "--signer", "alice.dev"])
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}

#[test]
fn sign_fails_for_invalid_secret_key_vector() {
    let root = vectors_root();
    let bundle = root.join("bad/sign-invalid-secret-key");
    let bad_key = bundle.join("invalid-secret-key.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&bad_key)
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("invalid base64 secret key"),
        "stderr was: {stderr}"
    );
}

#[test]
fn verify_fails_when_require_cosign_without_oci_ref() {
    let root = temp_dir("verify_require_cosign_no_oci_ref");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");

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

    let signing_key = SigningKey::from_bytes(&[77u8; 32]);
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

    let verify = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .arg("--require-cosign")
        .output()
        .expect("verify should run");
    assert!(!verify.status.success(), "{:?}", verify);
    let stderr = String::from_utf8(verify.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("--oci-ref is required when --require-cosign is set"),
        "stderr was: {stderr}"
    );
}

#[test]
fn verify_succeeds_when_cosign_verified() {
    let root = temp_dir("verify_cosign_ok");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let bin_dir = root.join("bin");
    let cosign_path = bin_dir.join("cosign");
    fs::create_dir_all(&bin_dir).expect("bin dir should exist");
    write(
        &cosign_path,
        b"#!/bin/sh\nif [ \"$1\" = \"verify\" ] && [ \"$2\" = \"ghcr.io/acme/echo:0.1.0\" ]; then\n  exit 0\nfi\necho \"unexpected cosign args: $*\" >&2\nexit 1\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&cosign_path, perms).expect("chmod should succeed");
    }

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

    let signing_key = SigningKey::from_bytes(&[78u8; 32]);
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

    let verify = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .args(["--oci-ref", "ghcr.io/acme/echo:0.1.0"])
        .arg("--require-cosign")
        .env("PATH", path_with_bin_dir(&bin_dir))
        .output()
        .expect("verify should run");
    assert!(verify.status.success(), "{:?}", verify);
}
