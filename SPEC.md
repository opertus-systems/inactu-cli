# Provenact Specification (v0)

This file is the normative index for Provenact contracts.

## Scope

Provenact is a secure execution substrate for immutable, verifiable skills.

In scope:
- skill packaging and identity
- signing and verification
- capability-gated WASM execution
- deterministic receipts and auditability

Out of scope:
- planners, schedulers, and orchestration loops
- autonomous agent control logic
- long-lived memory or autonomous state machines

## Normative Sources

The following files define the `v0` contract:

- `spec/v0.md`
- `spec/v0/skill-manifest.schema.json`
- `spec/v0/pipeline.schema.json`
- `spec/threat-model.md`
- `spec/compatibility.md`
- `spec/hashing.md`
- `spec/packaging.md`
- `spec/install.md`
- `spec/install/index.schema.json`
- `spec/install/meta.schema.json`
- `spec/conformance.md`
- `spec/skill-format.md`
- `spec/skill-format/manifest.schema.json`
- `spec/skill-format/provenance.schema.json`
- `spec/skill-format/signatures.schema.json`
- `spec/policy/policy.schema.json`
- `spec/policy/policy.md`
- `spec/policy/capability-evaluation.md`
- `spec/execution-receipt.schema.json`
- `spec/registry/registry.md`
- `spec/registry/snapshot.schema.json`

## Versioning

Versioning and compatibility policy is defined in
`docs/versioning-policy.md`.

## Conformance Artifacts

Deterministic vectors for the normative contract are published in
`test-vectors/` and enforced by `npm run conformance`.

## Policy Boundary

Provenact executes verified skills. Agent orchestration belongs outside this repo.
