use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{enforce_capability_ceiling, Capability, Policy};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    name: String,
    policy: Policy,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    capability: Capability,
    expect: String,
}

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/capability-eval")
        .canonicalize()
        .expect("capability-eval vectors should exist")
}

#[test]
fn capability_eval_vectors_match_expected_decisions() {
    let root = vectors_root();
    let mut vector_files = fs::read_dir(&root)
        .expect("vector dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter(|path| path.file_name().is_some_and(|name| name != "schema.json"))
        .collect::<Vec<_>>();
    vector_files.sort();

    assert!(
        !vector_files.is_empty(),
        "expected at least one capability-eval vector in {}",
        root.display()
    );

    for path in vector_files {
        let raw = fs::read(&path).expect("vector file should be readable");
        let vector: VectorFile = serde_json::from_slice(&raw).expect("vector JSON should parse");
        assert!(
            !vector.cases.is_empty(),
            "vector {} has no cases",
            vector.name
        );

        for case in vector.cases {
            let result =
                enforce_capability_ceiling(std::slice::from_ref(&case.capability), &vector.policy);
            match case.expect.as_str() {
                "allow" => assert!(
                    result.is_ok(),
                    "expected allow for {} {:?} in {}",
                    case.capability.kind,
                    case.capability.value,
                    path.display()
                ),
                "deny" => assert!(
                    result.is_err(),
                    "expected deny for {} {:?} in {}",
                    case.capability.kind,
                    case.capability.value,
                    path.display()
                ),
                other => panic!("unexpected expect value '{other}' in {}", path.display()),
            }
        }
    }
}
