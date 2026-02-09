mod common;

use std::fs;
use std::process::Command;

use common::temp_dir;
use provenact_verifier::{md5_hex, sha256_prefixed};

#[test]
fn verify_registry_entry_succeeds_for_matching_digests() {
    let root = temp_dir("verify_registry_entry_ok");
    let artifact = root.join("artifact.bin");
    let bytes = b"registry artifact bytes";
    fs::write(&artifact, bytes).expect("artifact write should succeed");

    let sha256 = sha256_prefixed(bytes);
    let md5 = md5_hex(bytes);

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-registry-entry", "--artifact"])
        .arg(&artifact)
        .args(["--sha256", &sha256, "--md5", &md5])
        .output()
        .expect("command should run");

    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_registry_entry_fails_for_md5_mismatch() {
    let root = temp_dir("verify_registry_entry_bad_md5");
    let artifact = root.join("artifact.bin");
    let bytes = b"registry artifact bytes";
    fs::write(&artifact, bytes).expect("artifact write should succeed");

    let sha256 = sha256_prefixed(bytes);

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-registry-entry", "--artifact"])
        .arg(&artifact)
        .args([
            "--sha256",
            &sha256,
            "--md5",
            "00000000000000000000000000000000",
        ])
        .output()
        .expect("command should run");

    assert!(!output.status.success(), "{:?}", output);
}
