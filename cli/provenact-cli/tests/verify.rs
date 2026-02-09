mod common;

use std::fs;
use std::process::Command;

use common::{temp_dir, vectors_root};
use provenact_verifier::sha256_prefixed;

#[test]
fn verify_succeeds_for_good_vector() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
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
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_succeeds_for_pack_sign_roundtrip_vector() {
    let root = vectors_root();
    let bundle = root.join("good/pack-sign-roundtrip");
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
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_fails_for_hash_mismatch_vector() {
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
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_fails_for_bad_signature_vector() {
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
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_fails_for_keys_digest_mismatch() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let keys = bundle.join("public-keys.json");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args([
            "--keys-digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_succeeds_for_matching_keys_digest() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let keys = bundle.join("public-keys.json");
    let digest = sha256_prefixed(&fs::read(&keys).expect("keys should exist"));
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args(["--keys-digest", &digest])
        .output()
        .expect("command should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_fails_for_invalid_keys_digest_format() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let keys = bundle.join("public-keys.json");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args(["--keys-digest", "not-a-digest"])
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("invalid --keys-digest format"),
        "stderr was: {stderr}"
    );
}

#[test]
fn verify_fails_for_oversized_keys_file() {
    let root = temp_dir("verify_oversized_keys");
    let bundle = vectors_root().join("good/minimal-zero-cap");
    let keys = root.join("oversized-keys.json");
    fs::write(&keys, vec![b'a'; 1_100_000]).expect("keys write should succeed");

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
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("public-keys.json exceeds maximum size"),
        "stderr was: {stderr}"
    );
}

#[test]
fn verify_requires_keys_digest_flag() {
    let root = vectors_root();
    let bundle = root.join("good/minimal-zero-cap");
    let keys = bundle.join("public-keys.json");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .output()
        .expect("command should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}
