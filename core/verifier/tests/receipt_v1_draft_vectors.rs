use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::parse_receipt_v1_draft_json;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/receipt-v1")
        .canonicalize()
        .expect("vectors root should exist")
}

fn load_sorted_files(path: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(path)
        .expect("vector dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn receipt_v1_draft_vectors_match_expectations() {
    let root = vectors_root();
    let good = load_sorted_files(&root.join("good"));
    let bad = load_sorted_files(&root.join("bad"));
    assert!(!good.is_empty(), "expected at least one good vector");
    assert!(!bad.is_empty(), "expected at least one bad vector");

    for path in good {
        let raw = fs::read(&path).expect("vector read should succeed");
        parse_receipt_v1_draft_json(&raw).unwrap_or_else(|err| {
            panic!(
                "expected valid v1 draft receipt vector {}: {err}",
                path.display()
            )
        });
    }

    for path in bad {
        let raw = fs::read(&path).expect("vector read should succeed");
        let result = parse_receipt_v1_draft_json(&raw);
        assert!(
            result.is_err(),
            "expected invalid v1 draft receipt vector to fail: {}",
            path.display()
        );
    }
}
