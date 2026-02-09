use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{parse_manifest_json, parse_signatures_json};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/skill-format")
        .canonicalize()
        .expect("skill-format vectors should exist")
}

fn load_sorted_files(path: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(path)
        .expect("vector dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn manifest_vectors_match_expectations() {
    let root = vectors_root().join("manifest");
    let good = load_sorted_files(&root.join("good"));
    let bad = load_sorted_files(&root.join("bad"));
    assert!(
        !good.is_empty(),
        "expected at least one good manifest vector"
    );
    assert!(!bad.is_empty(), "expected at least one bad manifest vector");

    for path in good {
        let raw = fs::read(&path).expect("manifest vector should be readable");
        parse_manifest_json(&raw).unwrap_or_else(|err| {
            panic!("expected valid manifest vector {}: {err}", path.display())
        });
    }
    for path in bad {
        let raw = fs::read(&path).expect("manifest vector should be readable");
        let result = parse_manifest_json(&raw);
        assert!(
            result.is_err(),
            "expected invalid manifest vector to fail: {}",
            path.display()
        );
    }
}

#[test]
fn signatures_vectors_match_expectations() {
    let root = vectors_root().join("signatures");
    let good = load_sorted_files(&root.join("good"));
    let bad = load_sorted_files(&root.join("bad"));
    assert!(
        !good.is_empty(),
        "expected at least one good signatures vector"
    );
    assert!(
        !bad.is_empty(),
        "expected at least one bad signatures vector"
    );

    for path in good {
        let raw = fs::read(&path).expect("signatures vector should be readable");
        parse_signatures_json(&raw).unwrap_or_else(|err| {
            panic!("expected valid signatures vector {}: {err}", path.display())
        });
    }
    for path in bad {
        let raw = fs::read(&path).expect("signatures vector should be readable");
        let result = parse_signatures_json(&raw);
        assert!(
            result.is_err(),
            "expected invalid signatures vector to fail: {}",
            path.display()
        );
    }
}
