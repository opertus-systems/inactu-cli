#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use wat::parse_str as wat_parse_str;

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn temp_dir(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let uniq = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "provenact-cli-{test_name}-{}-{nanos}-{uniq}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

pub fn write(path: &PathBuf, bytes: &[u8]) {
    fs::write(path, bytes).expect("write should succeed");
}

pub fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .canonicalize()
        .expect("test-vectors dir should exist")
}

pub fn wasm_with_i32_entrypoint(entrypoint: &str, value: i32) -> Vec<u8> {
    let wat = format!(
        r#"(module
  (func (export "{entrypoint}") (result i32)
    i32.const {value})
)"#
    );
    wat_parse_str(&wat).expect("wat should compile")
}

pub fn wasm_with_infinite_loop(entrypoint: &str) -> Vec<u8> {
    let wat = format!(
        r#"(module
  (func (export "{entrypoint}")
    (loop
      br 0))
)"#
    );
    wat_parse_str(&wat).expect("wat should compile")
}

pub fn wasm_with_memory_growth_trap(entrypoint: &str, pages: u32) -> Vec<u8> {
    let wat = format!(
        r#"(module
  (memory 1)
  (func (export "{entrypoint}") (result i32)
    i32.const {pages}
    memory.grow
    i32.const -1
    i32.eq
    if
      unreachable
    end
    i32.const 1)
)"#
    );
    wat_parse_str(&wat).expect("wat should compile")
}
