use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{parse_snapshot_json, verify_snapshot_hash};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/registry/snapshot")
        .canonicalize()
        .expect("registry snapshot vectors should exist")
}

#[test]
fn good_snapshot_vectors_parse_and_verify() {
    let root = vectors_root().join("good");
    let mut files = fs::read_dir(&root)
        .expect("good snapshot dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one good snapshot vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("snapshot vector should be readable");
        let snapshot = parse_snapshot_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid snapshot JSON {}: {err}", path.display()));
        verify_snapshot_hash(&snapshot).unwrap_or_else(|err| {
            panic!(
                "expected snapshot hash verification success {}: {err}",
                path.display()
            )
        });
    }
}

#[test]
fn bad_snapshot_vectors_fail() {
    let root = vectors_root().join("bad");
    let mut files = fs::read_dir(&root)
        .expect("bad snapshot dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one bad snapshot vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("snapshot vector should be readable");
        let parsed = parse_snapshot_json(&raw);
        let accepted = match parsed {
            Ok(snapshot) => verify_snapshot_hash(&snapshot).is_ok(),
            Err(_) => false,
        };
        assert!(
            !accepted,
            "expected bad snapshot vector to fail parse or hash verify: {}",
            path.display()
        );
    }
}
