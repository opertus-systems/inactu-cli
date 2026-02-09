use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::parse_provenance_json;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/skill-format/provenance")
        .canonicalize()
        .expect("provenance vectors should exist")
}

#[test]
fn good_provenance_vectors_parse() {
    let root = vectors_root().join("good");
    let mut files = fs::read_dir(&root)
        .expect("good provenance dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one good provenance vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("provenance vector should be readable");
        parse_provenance_json(&raw).unwrap_or_else(|err| {
            panic!("expected valid provenance vector {}: {err}", path.display())
        });
    }
}

#[test]
fn bad_provenance_vectors_fail() {
    let root = vectors_root().join("bad");
    let mut files = fs::read_dir(&root)
        .expect("bad provenance dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(
        !files.is_empty(),
        "expected at least one bad provenance vector"
    );

    for path in files {
        let raw = fs::read(&path).expect("provenance vector should be readable");
        let result = parse_provenance_json(&raw);
        assert!(
            result.is_err(),
            "expected invalid provenance vector to fail: {}",
            path.display()
        );
    }
}
