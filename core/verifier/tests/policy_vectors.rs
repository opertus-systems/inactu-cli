use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::parse_policy_document;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/policy")
        .canonicalize()
        .expect("policy vectors should exist")
}

#[test]
fn valid_policy_vectors_parse() {
    let root = vectors_root().join("valid");
    let mut files = fs::read_dir(&root)
        .expect("valid policy dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one valid policy vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("policy vector should be readable");
        parse_policy_document(&raw)
            .unwrap_or_else(|err| panic!("expected valid policy vector {}: {err}", path.display()));
    }
}

#[test]
fn invalid_policy_vectors_fail() {
    let root = vectors_root().join("invalid");
    let mut files = fs::read_dir(&root)
        .expect("invalid policy dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one invalid policy vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("policy vector should be readable");
        let result = parse_policy_document(&raw);
        assert!(
            result.is_err(),
            "expected invalid policy vector to fail: {}",
            path.display()
        );
    }
}
