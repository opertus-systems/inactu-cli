# Test Vectors (v0)

This directory contains deterministic conformance vectors for v0.

## Composable Skills v0 Vectors

- `v0/skill-manifest/{good,bad}/`:
  - v0 skill manifest vectors aligned to `spec/v0/skill-manifest.schema.json`.
- `v0/pipeline/{good,bad}/`:
  - v0 pipeline DAG vectors aligned to `spec/v0/pipeline-dag.schema.json`.
- `v0/event-chain/`:
  - deterministic event hashing and hash-chain verification vectors.
- `v0/cap-resolution/`:
  - capability intersection vectors for `manifest_caps ∩ org_policy ∩ run_policy`.

## Policy Schema Vectors

- `policy/valid/`:
  - policy documents expected to validate against
    `spec/policy/policy.schema.json`.
- `policy/invalid/`:
  - policy documents expected to fail schema validation.

## Capability Evaluation Vectors

- `capability-eval/*.json`:
  - declarative request/decision fixtures aligned to
    `spec/policy/capability-evaluation.md`.
  - each case includes `expect` (`allow` or `deny`) for a requested
    `{kind,value}` pair.

## Intended Use

- Schema validators should load all files in `policy/valid/` and
  `policy/invalid/`.
- Runtime/policy evaluators should run all capability cases and assert expected
  outcomes.
- Repository-wide conformance can be executed with:
  - `cargo conformance`

## Bundle Verification Vectors

- `good/minimal-zero-cap/`:
  - minimal WASM bundle with valid artifact hash and Ed25519 signature.
- `good/pack-sign-roundtrip/`:
  - deterministic bundle fixture used for `pack -> sign -> verify` coverage.
- `good/verify-run-verify-receipt/`:
  - canonical source fixture inputs for end-to-end
    `verify -> run -> verify-receipt` coverage.
- `bad/hash-mismatch/`:
  - manifest/signature artifact hash does not match `skill.wasm`.
- `bad/bad-signature/`:
  - artifact hash matches, signature is invalid.
- `bad/sign-invalid-secret-key/`:
  - malformed signing key input for `provenact-cli sign`.

Each bundle vector includes `public-keys.json` for `provenact-cli verify`.

## Receipt Vectors

- `receipt/good/`:
  - receipts expected to parse and pass `receipt_hash` verification.
- `receipt/bad/`:
  - receipts that parse but must fail `receipt_hash` verification.

## Skill-Format Vectors

- `skill-format/manifest/good/`:
  - manifest documents expected to satisfy
    `spec/skill-format/manifest.schema.json`.
- `skill-format/manifest/bad/`:
  - manifest documents expected to fail schema-aligned parsing.
- `skill-format/provenance/good/`:
  - provenance documents expected to satisfy
    `spec/skill-format/provenance.schema.json`.
- `skill-format/provenance/bad/`:
  - provenance documents expected to fail schema-aligned parsing.
- `skill-format/signatures/good/`:
  - signature envelope documents expected to satisfy
    `spec/skill-format/signatures.schema.json`.
- `skill-format/signatures/bad/`:
  - signature envelope documents expected to fail schema-aligned parsing.
- `skill-format/manifest-v1/good/`:
  - draft manifest documents expected to satisfy
    `spec/skill-format/manifest.v1.experimental.schema.json`.
- `skill-format/manifest-v1/bad/`:
  - draft manifest documents expected to fail draft schema validation.

## Receipt v1 Draft Vectors

- `receipt-v1/good/`:
  - draft receipt documents expected to satisfy
    `spec/execution-receipt.v1.experimental.schema.json`.
- `receipt-v1/bad/`:
  - draft receipt documents expected to fail draft schema validation.

## Registry Snapshot Vectors

- `registry/snapshot/good/`:
  - snapshots expected to parse and pass `snapshot_hash` verification.
  - each entry includes required `sha256` identity + `md5` transport checksum.
- `registry/snapshot/bad/`:
  - snapshots expected to fail parsing or hash verification.
  - includes invalid entry digest structure/format cases.
