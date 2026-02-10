mod common;

use std::fs;
use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, write};
use ed25519_dalek::SigningKey;
use provenact_verifier::sha256_prefixed;
use serde_json::Value;
use tar::Builder;
use url::Url;
use zstd::stream::write::Encoder as ZstdEncoder;

fn make_skill_archive(bundle_dir: &Path, out_path: &Path) {
    let out = fs::File::create(out_path).expect("archive should be created");
    let encoder = ZstdEncoder::new(out, 0).expect("zstd encoder should initialize");
    let mut tar = Builder::new(encoder);
    tar.append_path_with_name(bundle_dir.join("manifest.json"), "manifest.json")
        .expect("manifest should be added");
    tar.append_path_with_name(bundle_dir.join("skill.wasm"), "skill.wasm")
        .expect("wasm should be added");
    tar.append_path_with_name(bundle_dir.join("signatures.json"), "signatures.json")
        .expect("signatures should be added");
    tar.finish().expect("tar should finish");
    let mut encoder = tar.into_inner().expect("encoder should be returned");
    encoder.flush().expect("flush should succeed");
    let _out = encoder.finish().expect("zstd stream should finish");
}

fn make_skill_archive_missing_manifest(bundle_dir: &Path, out_path: &Path) {
    let out = fs::File::create(out_path).expect("archive should be created");
    let encoder = ZstdEncoder::new(out, 0).expect("zstd encoder should initialize");
    let mut tar = Builder::new(encoder);
    tar.append_path_with_name(bundle_dir.join("skill.wasm"), "skill.wasm")
        .expect("wasm should be added");
    tar.append_path_with_name(bundle_dir.join("signatures.json"), "signatures.json")
        .expect("signatures should be added");
    tar.finish().expect("tar should finish");
    let mut encoder = tar.into_inner().expect("encoder should be returned");
    encoder.flush().expect("flush should succeed");
    let _out = encoder.finish().expect("zstd stream should finish");
}

fn prepare_signed_bundle(
    root: &Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let wasm_path = root.join("skill.wasm");
    let manifest_path = root.join("manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");

    write(&wasm_path, b"\0asm\x01\0\0\0");
    let artifact = sha256_prefixed(&fs::read(&wasm_path).expect("wasm should exist"));
    let manifest = format!(
        "{{\"name\":\"echo.install\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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
    (bundle_dir, keys_path, secret_key_path)
}

fn run_install(
    provenact_home: &Path,
    artifact: &str,
    keys_path: &Path,
    require_signatures: bool,
    allow_insecure_http: bool,
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_provenact-cli"));
    cmd.args(["install", "--artifact"]).arg(artifact);
    cmd.args(["--keys"]).arg(keys_path);
    cmd.args(["--keys-digest"]).arg(sha256_prefixed(
        &fs::read(keys_path).expect("keys should exist"),
    ));
    if require_signatures {
        cmd.args(["--require-signatures"]);
    }
    if allow_insecure_http {
        cmd.args(["--allow-insecure-http"]);
    }
    cmd.env("PROVENACT_HOME", provenact_home);
    cmd.output().expect("install should run")
}

#[test]
fn install_persists_store_and_index() {
    let root = temp_dir("install_store_index");
    let provenact_home = root.join("provenact-home");
    let (bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let archive_path = root.join("skill.tar.zst");
    make_skill_archive(&bundle_dir, &archive_path);
    let digest = sha256_prefixed(&fs::read(&archive_path).expect("archive should exist"));

    let output = run_install(
        &provenact_home,
        archive_path.to_str().expect("archive path should be utf8"),
        &keys_path,
        true,
        false,
    );
    assert!(output.status.success(), "{:?}", output);

    let suffix = digest.strip_prefix("sha256:").expect("digest prefix");
    let store = provenact_home.join("store").join("sha256").join(suffix);
    assert!(store.join("manifest.json").is_file());
    assert!(store.join("skill.wasm").is_file());
    assert!(store.join("signatures.json").is_file());
    assert!(store.join("meta.json").is_file());

    let meta_raw = fs::read(store.join("meta.json")).expect("meta should exist");
    let meta: Value = serde_json::from_slice(&meta_raw).expect("meta should be valid JSON");
    assert_eq!(meta["schema_version"], "1.0.0");
    assert_eq!(meta["skill"], digest);
    assert_eq!(meta["manifest_name"], "echo.install");
    assert_eq!(meta["manifest_version"], "0.1.0");
    assert!(
        meta["installed_at"].as_u64().is_some(),
        "meta.installed_at should be numeric"
    );

    let index_raw = fs::read(provenact_home.join("index.json")).expect("index should exist");
    let index: Value = serde_json::from_slice(&index_raw).expect("index should be valid JSON");
    assert_eq!(index["schema_version"], "1.0.0");
    let entries = index["entries"]
        .as_array()
        .expect("entries should be array");
    let entry = entries
        .iter()
        .find(|entry| entry["skill"] == digest)
        .expect("installed skill should be present in index");
    assert_eq!(entry["manifest_name"], "echo.install");
    assert_eq!(entry["manifest_version"], "0.1.0");
    assert!(
        entry["installed_at"].as_u64().is_some(),
        "entry.installed_at should be numeric"
    );
}

#[test]
fn install_parallel_writes_preserve_both_index_entries() {
    let root = temp_dir("install_parallel_index");
    let provenact_home = root.join("provenact-home");

    let root_a = root.join("bundle-a");
    let root_b = root.join("bundle-b");
    fs::create_dir_all(&root_a).expect("bundle-a dir should exist");
    fs::create_dir_all(&root_b).expect("bundle-b dir should exist");

    let (bundle_dir_a, keys_path_a, _secret_key_path_a) = prepare_signed_bundle(&root_a);
    let (bundle_dir_b, keys_path_b, _secret_key_path_b) = prepare_signed_bundle(&root_b);

    let archive_path_a = root.join("skill-a.tar.zst");
    let archive_path_b = root.join("skill-b.tar.zst");
    make_skill_archive(&bundle_dir_a, &archive_path_a);
    make_skill_archive(&bundle_dir_b, &archive_path_b);

    let digest_a = sha256_prefixed(&fs::read(&archive_path_a).expect("archive a should exist"));
    let digest_b = sha256_prefixed(&fs::read(&archive_path_b).expect("archive b should exist"));

    let barrier = Arc::new(Barrier::new(3));

    let barrier_a = Arc::clone(&barrier);
    let home_a = provenact_home.clone();
    let archive_a = archive_path_a.to_string_lossy().to_string();
    let keys_a = keys_path_a.clone();
    let t1 = thread::spawn(move || {
        barrier_a.wait();
        run_install(&home_a, &archive_a, &keys_a, true, false)
    });

    let barrier_b = Arc::clone(&barrier);
    let home_b = provenact_home.clone();
    let archive_b = archive_path_b.to_string_lossy().to_string();
    let keys_b = keys_path_b.clone();
    let t2 = thread::spawn(move || {
        barrier_b.wait();
        run_install(&home_b, &archive_b, &keys_b, true, false)
    });

    barrier.wait();

    let out_a = t1.join().expect("thread a should join");
    let out_b = t2.join().expect("thread b should join");
    assert!(out_a.status.success(), "{:?}", out_a);
    assert!(out_b.status.success(), "{:?}", out_b);

    let index_raw = fs::read(provenact_home.join("index.json")).expect("index should exist");
    let index: Value = serde_json::from_slice(&index_raw).expect("index should be valid JSON");
    let entries = index["entries"]
        .as_array()
        .expect("entries should be array");

    assert!(
        entries.iter().any(|entry| entry["skill"] == digest_a),
        "index should contain digest_a"
    );
    assert!(
        entries.iter().any(|entry| entry["skill"] == digest_b),
        "index should contain digest_b"
    );
}

#[test]
fn install_recovers_from_stale_index_lock_file() {
    let root = temp_dir("install_stale_index_lock");
    let provenact_home = root.join("provenact-home");
    fs::create_dir_all(&provenact_home).expect("provenact home should exist");
    let lock_path = provenact_home.join("index.json.lock");
    write(&lock_path, b"stale lock");

    let (bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let archive_path = root.join("skill.tar.zst");
    make_skill_archive(&bundle_dir, &archive_path);

    thread::sleep(Duration::from_secs(2));
    let old_mtime = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&lock_path, old_mtime).expect("lock mtime should update");

    let output = run_install(
        &provenact_home,
        archive_path.to_str().expect("archive path should be utf8"),
        &keys_path,
        true,
        false,
    );
    assert!(output.status.success(), "{:?}", output);
    assert!(!lock_path.exists(), "stale lock should be cleaned up");
}

#[test]
fn install_accepts_file_url_source() {
    let root = temp_dir("install_file_url");
    let provenact_home = root.join("provenact-home");
    let (bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let archive_path = root.join("skill.tar.zst");
    make_skill_archive(&bundle_dir, &archive_path);
    let file_url = Url::from_file_path(
        archive_path
            .canonicalize()
            .expect("archive canonical path should resolve"),
    )
    .expect("file URL should be created");

    let output = run_install(&provenact_home, file_url.as_str(), &keys_path, true, false);
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn install_accepts_http_source() {
    let root = temp_dir("install_http_url");
    let provenact_home = root.join("provenact-home");
    let (bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let archive_path = root.join("skill.tar.zst");
    make_skill_archive(&bundle_dir, &archive_path);
    let bytes = fs::read(&archive_path).expect("archive should exist");

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener
        .local_addr()
        .expect("local addr should exist")
        .port();
    let server = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("request should connect");
        let mut req = [0u8; 1024];
        let _ = stream.read(&mut req);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        stream
            .write_all(header.as_bytes())
            .expect("header should write");
        stream.write_all(&bytes).expect("body should write");
    });
    thread::sleep(Duration::from_millis(50));

    let url = format!("http://127.0.0.1:{port}/skill.tar.zst");
    let output = run_install(&provenact_home, &url, &keys_path, true, true);
    assert!(output.status.success(), "{:?}", output);
    server.join().expect("server thread should join");
}

#[test]
fn install_rejects_http_redirect_source() {
    let root = temp_dir("install_http_redirect");
    let provenact_home = root.join("provenact-home");
    let (_bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener
        .local_addr()
        .expect("local addr should exist")
        .port();
    let server = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("request should connect");
        let mut req = [0u8; 1024];
        let _ = stream.read(&mut req);
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/skill.tar.zst\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response).expect("response should write");
    });
    thread::sleep(Duration::from_millis(50));

    let url = format!("http://127.0.0.1:{port}/skill.tar.zst");
    let output = run_install(&provenact_home, &url, &keys_path, true, true);
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("artifact fetch redirects are not allowed for security reasons"),
        "{stderr}"
    );
    server.join().expect("server thread should join");
}

#[test]
fn install_rejects_http_without_allow_insecure_http() {
    let root = temp_dir("install_http_disallowed");
    let provenact_home = root.join("provenact-home");
    let (_bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let output = run_install(
        &provenact_home,
        "http://127.0.0.1:9/skill.tar.zst",
        &keys_path,
        true,
        false,
    );
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("http:// artifacts are disabled by default"),
        "{stderr}"
    );
}

#[test]
fn install_rejects_remote_source_without_keys() {
    let root = temp_dir("install_https_requires_keys");
    let provenact_home = root.join("provenact-home");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["install", "--artifact", "https://example.com/skill.tar.zst"])
        .env("PROVENACT_HOME", &provenact_home)
        .output()
        .expect("install should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("remote artifacts require --keys and --keys-digest"),
        "{stderr}"
    );
}

#[test]
fn install_rejects_missing_manifest_in_archive() {
    let root = temp_dir("install_missing_manifest");
    let provenact_home = root.join("provenact-home");
    let (bundle_dir, keys_path, _secret_key_path) = prepare_signed_bundle(&root);
    let archive_path = root.join("skill-missing-manifest.tar.zst");
    make_skill_archive_missing_manifest(&bundle_dir, &archive_path);

    let output = run_install(
        &provenact_home,
        archive_path.to_str().expect("archive path should be utf8"),
        &keys_path,
        true,
        false,
    );
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("artifact missing required file manifest.json"),
        "{stderr}"
    );
}

#[test]
fn install_rejects_oci_refs_in_v0() {
    let root = temp_dir("install_oci_ref");
    let provenact_home = root.join("provenact-home");
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args([
            "install",
            "--artifact",
            "oci://example.com/skill@sha256:abc",
        ])
        .env("PROVENACT_HOME", &provenact_home)
        .output()
        .expect("install should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("OCI refs are not supported"), "{stderr}");
}
