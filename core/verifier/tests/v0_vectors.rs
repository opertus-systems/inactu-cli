use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{
    compute_event_hash_v0, parse_pipeline_v0_json, parse_skill_manifest_v0_json,
    resolve_effective_caps_v0, verify_event_chain_v0, CapGrantV0, CapabilityRequestV0,
    EventRecordV0,
};
use serde::Deserialize;

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/v0")
        .canonicalize()
        .expect("v0 vectors should exist")
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
fn v0_manifest_vectors_match_expectations() {
    let root = vectors_root().join("skill-manifest");
    let good = load_sorted_files(&root.join("good"));
    let bad = load_sorted_files(&root.join("bad"));
    assert!(!good.is_empty(), "expected good vectors");
    assert!(!bad.is_empty(), "expected bad vectors");

    for path in good {
        let raw = fs::read(&path).expect("vector should be readable");
        parse_skill_manifest_v0_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid v0 manifest {}: {err}", path.display()));
    }
    for path in bad {
        let raw = fs::read(&path).expect("vector should be readable");
        assert!(
            parse_skill_manifest_v0_json(&raw).is_err(),
            "expected invalid v0 manifest {}",
            path.display()
        );
    }
}

#[test]
fn v0_pipeline_vectors_match_expectations() {
    let root = vectors_root().join("pipeline");
    let good = load_sorted_files(&root.join("good"));
    let bad = load_sorted_files(&root.join("bad"));
    assert!(!good.is_empty(), "expected good vectors");
    assert!(!bad.is_empty(), "expected bad vectors");

    for path in good {
        let raw = fs::read(&path).expect("vector should be readable");
        parse_pipeline_v0_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid v0 pipeline {}: {err}", path.display()));
    }
    for path in bad {
        let raw = fs::read(&path).expect("vector should be readable");
        assert!(
            parse_pipeline_v0_json(&raw).is_err(),
            "expected invalid v0 pipeline {}",
            path.display()
        );
    }
}

#[derive(Debug, Deserialize)]
struct EventHashVectorFile {
    cases: Vec<EventHashCase>,
}

#[derive(Debug, Deserialize)]
struct EventHashCase {
    prev_hash: Option<String>,
    ts: String,
    run_id: String,
    node_id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: serde_json::Value,
    expected_hash: String,
}

#[test]
fn v0_event_hash_vectors_match_expected_hashes() {
    let path = vectors_root().join("event-chain/hash-cases.json");
    let raw = fs::read(path).expect("vector should be readable");
    let vector: EventHashVectorFile =
        serde_json::from_slice(&raw).expect("vector JSON should parse");

    for case in vector.cases {
        let actual = compute_event_hash_v0(
            case.prev_hash.as_deref(),
            &case.ts,
            &case.run_id,
            &case.node_id,
            &case.event_type,
            &case.data,
        )
        .expect("event hash should compute");
        assert_eq!(actual, case.expected_hash);
    }
}

#[derive(Debug, Deserialize)]
struct EventChainVectorFile {
    events: Vec<EventRecordV0>,
}

#[test]
fn v0_event_chain_vectors_match_expectations() {
    let good_path = vectors_root().join("event-chain/good-chain.json");
    let bad_path = vectors_root().join("event-chain/bad-chain.json");

    let good_raw = fs::read(good_path).expect("good chain vector should be readable");
    let bad_raw = fs::read(bad_path).expect("bad chain vector should be readable");

    let good: EventChainVectorFile =
        serde_json::from_slice(&good_raw).expect("good vector should parse");
    let bad: EventChainVectorFile =
        serde_json::from_slice(&bad_raw).expect("bad vector should parse");

    assert!(verify_event_chain_v0(&good.events).is_ok());
    assert!(verify_event_chain_v0(&bad.events).is_err());
}

#[derive(Debug, Deserialize)]
struct CapResolutionVectorFile {
    cases: Vec<CapResolutionCase>,
}

#[derive(Debug, Deserialize)]
struct CapResolutionCase {
    requested: Vec<CapabilityRequestV0>,
    org_policy: Vec<CapGrantV0>,
    run_policy: Vec<CapGrantV0>,
    expect: String,
    #[serde(default)]
    expected_names: Vec<String>,
}

#[test]
fn v0_capability_resolution_vectors_match_expectations() {
    let path = vectors_root().join("cap-resolution/basic.json");
    let raw = fs::read(path).expect("vector should be readable");
    let vector: CapResolutionVectorFile =
        serde_json::from_slice(&raw).expect("vector should parse");

    for case in vector.cases {
        let result = resolve_effective_caps_v0(&case.requested, &case.org_policy, &case.run_policy);

        match case.expect.as_str() {
            "allow" => {
                let resolved = result.expect("expected allow");
                let names = resolved.into_iter().map(|cap| cap.name).collect::<Vec<_>>();
                assert_eq!(names, case.expected_names);
            }
            "deny" => {
                assert!(result.is_err(), "expected deny");
            }
            other => panic!("unexpected expect value: {other}"),
        }
    }
}
