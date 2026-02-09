use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{parse_receipt_json, verify_receipt_hash};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/receipt")
        .canonicalize()
        .expect("receipt vectors should exist")
}

#[test]
fn good_receipt_vectors_verify() {
    let root = vectors_root().join("good");
    let mut files = fs::read_dir(&root)
        .expect("good receipt dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one good receipt vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("receipt vector should be readable");
        let receipt = parse_receipt_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid receipt JSON {}: {err}", path.display()));
        verify_receipt_hash(&receipt).unwrap_or_else(|err| {
            panic!(
                "expected receipt hash verification success {}: {err}",
                path.display()
            )
        });
    }
}

#[test]
fn bad_receipt_vectors_fail_hash_verification() {
    let root = vectors_root().join("bad");
    let mut files = fs::read_dir(&root)
        .expect("bad receipt dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one bad receipt vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("receipt vector should be readable");
        let receipt = parse_receipt_json(&raw).unwrap_or_else(|err| {
            panic!(
                "expected parseable bad receipt JSON {}: {err}",
                path.display()
            )
        });
        let result = verify_receipt_hash(&receipt);
        assert!(
            result.is_err(),
            "expected receipt hash verification failure: {}",
            path.display()
        );
    }
}
