mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, write};
use ed25519_dalek::SigningKey;
use provenact_verifier::{parse_receipt_json, sha256_prefixed};
use serde_json::json;
use wat::parse_str as wat_parse_str;

struct BundleCtx {
    bundle_dir: PathBuf,
    keys_path: PathBuf,
}

fn create_bundle(
    root: &Path,
    bundle_name: &str,
    wat: &str,
    capabilities: serde_json::Value,
) -> BundleCtx {
    let wasm_path = root.join(format!("{bundle_name}.wasm"));
    let manifest_path = root.join(format!("{bundle_name}.manifest.json"));
    let bundle_dir = root.join(bundle_name);
    let secret_key_path = root.join(format!("{bundle_name}.key"));
    let keys_path = root.join(format!("{bundle_name}.keys.json"));

    let wasm = wat_parse_str(wat).expect("wat should compile");
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = json!({
        "name": bundle_name,
        "version": "0.1.0",
        "entrypoint": "run",
        "artifact": artifact,
        "capabilities": capabilities,
        "signers": ["alice.dev"]
    });
    write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .expect("manifest should serialize")
            .as_slice(),
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
    assert!(pack.status.success(), "{pack:?}");

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
    assert!(sign.status.success(), "{sign:?}");

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());

    BundleCtx {
        bundle_dir,
        keys_path,
    }
}

fn run_bundle(
    bundle: &BundleCtx,
    policy_path: &Path,
    input_path: &Path,
    receipt_path: &Path,
    envs: &[(&str, &Path)],
) {
    let out = run_bundle_command(bundle, policy_path, input_path, receipt_path, envs);
    assert!(out.status.success(), "{out:?}");
}

fn run_bundle_expect_failure(
    bundle: &BundleCtx,
    policy_path: &Path,
    input_path: &Path,
    receipt_path: &Path,
    envs: &[(&str, &Path)],
) {
    let out = run_bundle_command(bundle, policy_path, input_path, receipt_path, envs);
    assert!(!out.status.success(), "{out:?}");
}

fn run_bundle_command(
    bundle: &BundleCtx,
    policy_path: &Path,
    input_path: &Path,
    receipt_path: &Path,
    envs: &[(&str, &Path)],
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_provenact-cli"));
    cmd.args(["run", "--bundle"])
        .arg(&bundle.bundle_dir)
        .args(["--keys"])
        .arg(&bundle.keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&bundle.keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(policy_path)
        .args(["--input"])
        .arg(input_path)
        .args(["--receipt"])
        .arg(receipt_path);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run should execute")
}

#[test]
fn hostcalls_fs_roundtrip_receipts() {
    let root = temp_dir("hostcalls_fs");
    let fs_write_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "fs_write_file" (func $fs_write_file (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "/tmp/provenact-fs/itest.txt")
  (func (export "run") (result i32)
    (local $n i32)
    call $input_len
    local.set $n
    i32.const 64
    i32.const 0
    local.get $n
    call $input_read
    drop
    i32.const 0
    i32.const 27
    i32.const 64
    local.get $n
    call $fs_write_file
  )
)"#;
    let fs_read_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "fs_read_file" (func $fs_read_file (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (local $path_len i32)
    (local $n i32)
    call $input_len
    local.set $path_len
    i32.const 0
    i32.const 0
    local.get $path_len
    call $input_read
    drop
    i32.const 0
    local.get $path_len
    i32.const 2048
    i32.const 16384
    call $fs_read_file
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 2048
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let write_bundle_ctx = create_bundle(
        &root,
        "fs-write",
        fs_write_wat,
        json!([{"kind":"fs.write","value":"/tmp/provenact-fs"}]),
    );
    let read_bundle_ctx = create_bundle(
        &root,
        "fs-read",
        fs_read_wat,
        json!([{"kind":"fs.read","value":"/tmp/provenact-fs"}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "fs": {"read": ["/tmp/provenact-fs"], "write": ["/tmp/provenact-fs"]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy should serialize")
            .as_slice(),
    );

    let in_write = root.join("in-write.txt");
    write(&in_write, b"hello-fs");
    let receipt_write = root.join("receipt-write.json");
    run_bundle(
        &write_bundle_ctx,
        &policy_path,
        &in_write,
        &receipt_write,
        &[],
    );

    let in_read = root.join("in-read.txt");
    write(&in_read, b"/tmp/provenact-fs/itest.txt");
    let receipt_read = root.join("receipt-read.json");
    run_bundle(&read_bundle_ctx, &policy_path, &in_read, &receipt_read, &[]);

    let receipt =
        parse_receipt_json(&fs::read(&receipt_read).expect("receipt read")).expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"hello-fs"));
    assert_eq!(receipt.caps_used, vec!["fs.read".to_string()]);
}

#[cfg(unix)]
#[test]
fn hostcalls_fs_read_blocks_symlink_escape() {
    let root = temp_dir("hostcalls_fs_read_symlink_escape");
    let allowed_root = root.join("allowed");
    let outside_root = root.join("outside");
    fs::create_dir_all(&allowed_root).expect("allowed dir");
    fs::create_dir_all(&outside_root).expect("outside dir");
    let secret_path = outside_root.join("secret.txt");
    write(&secret_path, b"top-secret");
    std::os::unix::fs::symlink(&secret_path, allowed_root.join("leak.txt")).expect("symlink");

    let wat = r#"(module
  (import "provenact" "fs_read_file" (func $fs_read_file (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "SYMLINK_PATH_PLACEHOLDER")
  (data (i32.const 256) "denied")
  (func (export "run") (result i32)
    (local $n i32)
    i32.const 0
    i32.const PATH_LEN_PLACEHOLDER
    i32.const 1024
    i32.const 4096
    call $fs_read_file
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 256
      i32.const 6
      call $output_write
      drop
      i32.const 0
      return
    end
    i32.const 1024
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;
    let symlink_path = allowed_root.join("leak.txt").display().to_string();
    let wat = wat
        .replace("SYMLINK_PATH_PLACEHOLDER", &symlink_path)
        .replace("PATH_LEN_PLACEHOLDER", &symlink_path.len().to_string());
    let bundle_ctx = create_bundle(
        &root,
        "fs-read-symlink-escape",
        &wat,
        json!([{"kind":"fs.read","value":allowed_root.display().to_string()}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "fs": {"read": [allowed_root.display().to_string()]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let input_path = root.join("in.txt");
    write(&input_path, b"");
    let receipt_path = root.join("receipt.json");
    run_bundle_expect_failure(&bundle_ctx, &policy_path, &input_path, &receipt_path, &[]);
}

#[cfg(unix)]
#[test]
fn hostcalls_fs_write_blocks_symlink_escape() {
    let root = temp_dir("hostcalls_fs_write_symlink_escape");
    let allowed_root = root.join("allowed");
    let outside_root = root.join("outside");
    fs::create_dir_all(&allowed_root).expect("allowed dir");
    fs::create_dir_all(&outside_root).expect("outside dir");
    let target_path = outside_root.join("target.txt");
    write(&target_path, b"original");
    std::os::unix::fs::symlink(&target_path, allowed_root.join("sink.txt")).expect("symlink");

    let wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "fs_write_file" (func $fs_write_file (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "SYMLINK_PATH_PLACEHOLDER")
  (data (i32.const 256) "denied")
  (data (i32.const 320) "ok")
  (func (export "run") (result i32)
    (local $n i32)
    (local $rc i32)
    call $input_len
    local.set $n
    i32.const 1024
    i32.const 0
    local.get $n
    call $input_read
    drop
    i32.const 0
    i32.const PATH_LEN_PLACEHOLDER
    i32.const 1024
    local.get $n
    call $fs_write_file
    local.set $rc
    local.get $rc
    i32.const 0
    i32.lt_s
    if
      i32.const 256
      i32.const 6
      call $output_write
      drop
      i32.const 0
      return
    end
    i32.const 320
    i32.const 2
    call $output_write
    drop
    i32.const 0
  )
)"#;
    let symlink_path = allowed_root.join("sink.txt").display().to_string();
    let wat = wat
        .replace("SYMLINK_PATH_PLACEHOLDER", &symlink_path)
        .replace("PATH_LEN_PLACEHOLDER", &symlink_path.len().to_string());
    let bundle_ctx = create_bundle(
        &root,
        "fs-write-symlink-escape",
        &wat,
        json!([{"kind":"fs.write","value":allowed_root.display().to_string()}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "fs": {"write": [allowed_root.display().to_string()]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let input_path = root.join("in.txt");
    write(&input_path, b"new-value");
    let receipt_path = root.join("receipt.json");
    run_bundle_expect_failure(&bundle_ctx, &policy_path, &input_path, &receipt_path, &[]);
    assert_eq!(
        fs::read(&target_path).expect("target read"),
        b"original",
        "symlink target must remain unchanged"
    );
}

#[test]
fn hostcalls_fs_read_tree_receipt_and_caps_used() {
    let root = temp_dir("hostcalls_fs_tree");
    let tree_root = root.join("tree");
    fs::create_dir_all(tree_root.join("sub")).expect("tree dir");
    write(&tree_root.join("a.txt"), b"hello");
    write(&tree_root.join("sub").join("b.txt"), b"world!");

    let tree_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "fs_read_tree" (func $fs_read_tree (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "run") (result i32)
    (local $root_len i32)
    (local $n i32)
    call $input_len
    local.set $root_len
    i32.const 0
    i32.const 0
    local.get $root_len
    call $input_read
    drop
    i32.const 0
    local.get $root_len
    i32.const 2048
    i32.const 32768
    call $fs_read_tree
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 2048
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let bundle_ctx = create_bundle(
        &root,
        "fs-tree",
        tree_wat,
        json!([{"kind":"fs.read","value":tree_root.display().to_string()}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "fs": {"read": [tree_root.display().to_string()]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy should serialize")
            .as_slice(),
    );

    let in_path = root.join("in-root.txt");
    write(&in_path, tree_root.display().to_string().as_bytes());
    let receipt_path = root.join("receipt-tree.json");
    run_bundle(&bundle_ctx, &policy_path, &in_path, &receipt_path, &[]);

    let expected = json!({
      "root": tree_root.display().to_string(),
      "entries": [
        {"path":"a.txt","kind":"file","bytes":5},
        {"path":"sub","kind":"dir"},
        {"path":"sub/b.txt","kind":"file","bytes":6}
      ],
      "truncated": false
    });
    let expected_bytes = serde_json::to_vec(&expected).expect("expected json bytes");

    let receipt =
        parse_receipt_json(&fs::read(&receipt_path).expect("receipt read")).expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(&expected_bytes));
    assert_eq!(receipt.caps_used, vec!["fs.read".to_string()]);
}

#[test]
fn hostcalls_kv_roundtrip_receipts() {
    let root = temp_dir("hostcalls_kv");
    let kv_dir = root.join("kv");
    fs::create_dir_all(&kv_dir).expect("kv dir");

    let kv_put_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "kv_put" (func $kv_put (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "default")
  (func (export "run") (result i32)
    (local $n i32)
    call $input_len
    local.set $n
    i32.const 64
    i32.const 0
    local.get $n
    call $input_read
    drop
    i32.const 0
    i32.const 7
    i32.const 64
    local.get $n
    call $kv_put
  )
)"#;

    let kv_get_wat = r#"(module
  (import "provenact" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "default")
  (func (export "run") (result i32)
    (local $n i32)
    i32.const 0
    i32.const 7
    i32.const 64
    i32.const 4096
    call $kv_get
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 64
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let put_bundle_ctx = create_bundle(
        &root,
        "kv-put",
        kv_put_wat,
        json!([{"kind":"kv.write","value":"*"}]),
    );
    let get_bundle_ctx = create_bundle(
        &root,
        "kv-get",
        kv_get_wat,
        json!([{"kind":"kv.read","value":"*"}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "kv": {"read": ["*"], "write": ["*"]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let in_put = root.join("in-put.txt");
    write(&in_put, b"kv-value-1");
    run_bundle(
        &put_bundle_ctx,
        &policy_path,
        &in_put,
        &root.join("receipt-put.json"),
        &[("PROVENACT_KV_DIR", kv_dir.as_path())],
    );

    let in_empty = root.join("in-empty.txt");
    write(&in_empty, b"");
    let receipt_get_path = root.join("receipt-get.json");
    run_bundle(
        &get_bundle_ctx,
        &policy_path,
        &in_empty,
        &receipt_get_path,
        &[("PROVENACT_KV_DIR", kv_dir.as_path())],
    );

    let receipt = parse_receipt_json(&fs::read(&receipt_get_path).expect("receipt read"))
        .expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"kv-value-1"));
    assert_eq!(receipt.caps_used, vec!["kv.read".to_string()]);
}

#[test]
fn hostcalls_queue_roundtrip_receipts() {
    let root = temp_dir("hostcalls_queue");
    let queue_dir = root.join("queue");
    fs::create_dir_all(&queue_dir).expect("queue dir");

    let q_put_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "queue_publish" (func $queue_publish (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "default")
  (func (export "run") (result i32)
    (local $n i32)
    call $input_len
    local.set $n
    i32.const 64
    i32.const 0
    local.get $n
    call $input_read
    drop
    i32.const 0
    i32.const 7
    i32.const 64
    local.get $n
    call $queue_publish
  )
)"#;

    let q_get_wat = r#"(module
  (import "provenact" "queue_consume" (func $queue_consume (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "default")
  (func (export "run") (result i32)
    (local $n i32)
    i32.const 0
    i32.const 7
    i32.const 64
    i32.const 4096
    call $queue_consume
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 64
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let put_bundle_ctx = create_bundle(
        &root,
        "queue-put",
        q_put_wat,
        json!([{"kind":"queue.publish","value":"*"}]),
    );
    let get_bundle_ctx = create_bundle(
        &root,
        "queue-get",
        q_get_wat,
        json!([{"kind":"queue.consume","value":"*"}]),
    );

    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "queue": {"publish": ["*"], "consume": ["*"]}
      }
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let in_put = root.join("in-put.txt");
    write(&in_put, b"queue-msg-1");
    run_bundle(
        &put_bundle_ctx,
        &policy_path,
        &in_put,
        &root.join("receipt-put.json"),
        &[("PROVENACT_QUEUE_DIR", queue_dir.as_path())],
    );

    let in_empty = root.join("in-empty.txt");
    write(&in_empty, b"");
    let receipt_get_path = root.join("receipt-get.json");
    run_bundle(
        &get_bundle_ctx,
        &policy_path,
        &in_empty,
        &receipt_get_path,
        &[("PROVENACT_QUEUE_DIR", queue_dir.as_path())],
    );

    let receipt = parse_receipt_json(&fs::read(&receipt_get_path).expect("receipt read"))
        .expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"queue-msg-1"));
    assert_eq!(receipt.caps_used, vec!["queue.consume".to_string()]);
}

#[test]
fn hostcalls_http_fetch_receipt_and_caps_used() {
    let root = temp_dir("hostcalls_http");
    let body = b"local-http-body".to_vec();
    let (url, handle) = spawn_http_server_once(body.clone());

    let http_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "http_fetch" (func $http_fetch (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (local $url_len i32)
    (local $n i32)
    call $input_len
    local.set $url_len
    i32.const 0
    i32.const 0
    local.get $url_len
    call $input_read
    drop
    i32.const 0
    local.get $url_len
    i32.const 2048
    i32.const 16384
    call $http_fetch
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 2048
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let bundle_ctx = create_bundle(
        &root,
        "http-fetch",
        http_wat,
        json!([{"kind":"net.http","value": url.clone()}]),
    );
    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {"net": [url.clone()]}
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let input_path = root.join("in-url.txt");
    write(&input_path, url.as_bytes());
    let receipt_path = root.join("receipt-http.json");
    run_bundle(&bundle_ctx, &policy_path, &input_path, &receipt_path, &[]);

    handle.join().expect("http server thread should finish");

    let receipt =
        parse_receipt_json(&fs::read(&receipt_path).expect("receipt read")).expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(&body));
    assert_eq!(receipt.caps_used, vec!["net.http".to_string()]);
}

#[test]
fn hostcalls_http_fetch_blocks_redirects() {
    let root = temp_dir("hostcalls_http_redirect");
    let (url, target_hit, redirect_handle, target_handle) =
        spawn_http_redirect_fixture_once(b"redirect-target".to_vec());

    let http_wat = r#"(module
  (import "provenact" "input_len" (func $input_len (result i32)))
  (import "provenact" "input_read" (func $input_read (param i32 i32 i32) (result i32)))
  (import "provenact" "http_fetch" (func $http_fetch (param i32 i32 i32 i32) (result i32)))
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (local $url_len i32)
    (local $n i32)
    call $input_len
    local.set $url_len
    i32.const 0
    i32.const 0
    local.get $url_len
    call $input_read
    drop
    i32.const 0
    local.get $url_len
    i32.const 2048
    i32.const 16384
    call $http_fetch
    local.set $n
    local.get $n
    i32.const 0
    i32.lt_s
    if
      i32.const 1
      return
    end
    i32.const 2048
    local.get $n
    call $output_write
    drop
    i32.const 0
  )
)"#;

    let bundle_ctx = create_bundle(
        &root,
        "http-fetch-redirect",
        http_wat,
        json!([{"kind":"net.http","value": url.clone()}]),
    );
    let policy = json!({
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {"net": [url.clone()]}
    });
    let policy_path = root.join("policy.json");
    write(
        &policy_path,
        serde_json::to_vec_pretty(&policy)
            .expect("policy serialize")
            .as_slice(),
    );

    let input_path = root.join("in-url.txt");
    write(&input_path, url.as_bytes());
    let receipt_path = root.join("receipt-http-redirect.json");
    run_bundle(&bundle_ctx, &policy_path, &input_path, &receipt_path, &[]);

    redirect_handle
        .join()
        .expect("redirect server thread should finish");
    target_handle
        .join()
        .expect("target server thread should finish");
    let receipt =
        parse_receipt_json(&fs::read(&receipt_path).expect("receipt read")).expect("receipt parse");
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"1"));
    assert_eq!(receipt.caps_used, vec!["net.http".to_string()]);
    assert!(
        !target_hit.load(Ordering::SeqCst),
        "http_fetch must not follow redirects"
    );
}

fn spawn_http_server_once(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{}/", addr);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept should succeed");
        let mut req = [0u8; 1024];
        let _ = stream.read(&mut req);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write headers should succeed");
        stream.write_all(&body).expect("write body should succeed");
        stream.flush().expect("flush should succeed");
    });
    (url, handle)
}

fn spawn_http_redirect_fixture_once(
    body: Vec<u8>,
) -> (
    String,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
    thread::JoinHandle<()>,
) {
    let target_listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let target_addr = target_listener.local_addr().expect("local addr");
    let target_url = format!("http://{target_addr}/target");

    let redirect_listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let redirect_addr = redirect_listener.local_addr().expect("local addr");
    let redirect_url = format!("http://{redirect_addr}/");

    let target_hit = Arc::new(AtomicBool::new(false));
    let target_hit_clone = Arc::clone(&target_hit);
    let target_handle = thread::spawn(move || {
        target_listener
            .set_nonblocking(true)
            .expect("set nonblocking should succeed");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match target_listener.accept() {
                Ok((mut stream, _)) => {
                    target_hit_clone.store(true, Ordering::SeqCst);
                    let mut req = [0u8; 1024];
                    let _ = stream.read(&mut req);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write headers should succeed");
                    stream.write_all(&body).expect("write body should succeed");
                    stream.flush().expect("flush should succeed");
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let redirect_handle = thread::spawn(move || {
        let (mut stream, _) = redirect_listener.accept().expect("accept should succeed");
        let mut req = [0u8; 1024];
        let _ = stream.read(&mut req);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .expect("write redirect should succeed");
        stream.flush().expect("flush should succeed");
    });

    (redirect_url, target_hit, redirect_handle, target_handle)
}
