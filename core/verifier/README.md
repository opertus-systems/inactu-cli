# provenact-verifier

Deterministic verification helpers for Provenact v0.

Current scope:
- bundled schema exports:
  - `MANIFEST_V0_SCHEMA_JSON`
  - `MANIFEST_V1_DRAFT_SCHEMA_JSON`
  - `SIGNATURES_V0_SCHEMA_JSON`
  - `PROVENANCE_V0_SCHEMA_JSON`
  - `POLICY_V0_SCHEMA_JSON`
  - `RECEIPT_V0_SCHEMA_JSON`
  - `RECEIPT_V1_DRAFT_SCHEMA_JSON`
- strict JSON parsing helpers from bytes:
  - `parse_manifest_json`
  - `parse_manifest_v1_draft_json` (non-normative draft)
  - `parse_signatures_json`
  - `parse_provenance_json`
  - `parse_snapshot_json`
  - `parse_receipt_json`
  - `parse_receipt_v1_draft_json` (non-normative draft)
- policy parsing and enforcement helpers:
  - `parse_policy_document` (JSON or YAML)
  - `verify_trusted_signers`
  - `enforce_capability_ceiling`
- v1 draft digest helpers:
  - `compute_policy_hash`
  - `compute_signatures_hash`
  - `compute_bundle_hash`
  - `compute_runtime_version_digest_v1`
  - `compute_result_digest_v1`
  - `compute_receipt_v1_draft_hash`
  - `verify_receipt_v1_draft_hash`
- artifact digest verification (`sha256:<hex>`)
- registry entry artifact verification (`md5` transport + `sha256` identity)
- canonical manifest hash computation (`sha256(JCS(manifest))`)
- registry snapshot hash verification
- execution receipt hash verification
- Ed25519 signature verification over `signatures.manifest_hash` UTF-8 bytes

Specification references:
- `spec/hashing.md`
- `spec/skill-format.md`
- `spec/execution-receipt.schema.json`
- `spec/registry/snapshot.schema.json`
