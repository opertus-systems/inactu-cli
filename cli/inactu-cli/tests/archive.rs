mod common;

use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, write};
use ed25519_dalek::SigningKey;
use tar::Archive;
use zstd::stream::read::Decoder as ZstdDecoder;

fn prepare_signed_bundle(root: &Path) -> std::path::PathBuf {
    let wasm_path = root.join("skill.wasm");
    let manifest_path = root.join("manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");

    write(&wasm_path, b"\0asm\x01\0\0\0");
    let wasm_digest = inactu_verifier::sha256_prefixed(&fs::read(&wasm_path).expect("wasm should exist"));
    let manifest = format!(
        "{{\"name\":\"echo.archive\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{wasm_digest}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());

    let pack = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(pack.status.success(), "{:?}", pack);

    let signing_key = SigningKey::from_bytes(&[91u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);
    bundle_dir
}

#[test]
fn archive_is_deterministic_and_canonical() {
    let root = temp_dir("archive_deterministic");
    let bundle_dir = prepare_signed_bundle(&root);
    let out_one = root.join("skill-one.tar.zst");
    let out_two = root.join("skill-two.tar.zst");

    let arch1 = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["archive", "--bundle"])
        .arg(&bundle_dir)
        .args(["--output"])
        .arg(&out_one)
        .output()
        .expect("archive should run");
    assert!(arch1.status.success(), "{:?}", arch1);

    let arch2 = Command::new(env!("CARGO_BIN_EXE_inactu-cli"))
        .args(["archive", "--bundle"])
        .arg(&bundle_dir)
        .args(["--output"])
        .arg(&out_two)
        .output()
        .expect("archive should run");
    assert!(arch2.status.success(), "{:?}", arch2);

    let one = fs::read(&out_one).expect("archive one should exist");
    let two = fs::read(&out_two).expect("archive two should exist");
    assert_eq!(one, two, "archive bytes should be deterministic");

    let decoder = ZstdDecoder::new(one.as_slice()).expect("zstd stream should decode");
    let mut tar = Archive::new(decoder);
    let mut entries = Vec::new();
    for entry in tar.entries().expect("entries should read") {
        let mut entry = entry.expect("entry should parse");
        let path = entry
            .path()
            .expect("path should parse")
            .to_string_lossy()
            .to_string();
        let header = entry.header().clone();
        let mode = header.mode().expect("mode should parse");
        let uid = header.uid().expect("uid should parse");
        let gid = header.gid().expect("gid should parse");
        let mtime = header.mtime().expect("mtime should parse");
        let mut body = Vec::new();
        entry.read_to_end(&mut body).expect("entry body should read");
        entries.push((path, mode, uid, gid, mtime, body));
    }

    let names = entries
        .iter()
        .map(|(name, _, _, _, _, _)| name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["manifest.json", "skill.wasm", "signatures.json"]);

    for (name, mode, uid, gid, mtime, _body) in entries {
        let expected_mode = if name == "skill.wasm" { 0o755 } else { 0o644 };
        assert_eq!(mode, expected_mode, "mode mismatch for {name}");
        assert_eq!(uid, 0, "uid mismatch for {name}");
        assert_eq!(gid, 0, "gid mismatch for {name}");
        assert_eq!(mtime, 0, "mtime mismatch for {name}");
    }
}
