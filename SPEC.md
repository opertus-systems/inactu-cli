# Provenact Specification (v0)

This file is the top-level specification index for Provenact v0.
Normative detail lives under `spec/`.
Repository scope boundaries are defined in `AGENTS.md`.

## Current Focus

As of 2026-02-06, project focus is to stabilize core skill execution contracts
before expanding ecosystem surface area.

Priority order:
1. Native skill contract stability (manifest, policy, receipt).
2. Conformance coverage and deterministic behavior hardening.
3. One frictionless golden CLI workflow.
4. Optional ecosystem adapters only after core contract gates pass.

## Scope

Provenact is a secure execution substrate for immutable, verifiable skills.
Provenact includes:
- skill packaging
- signing and verification
- capability-gated WASM execution
- execution receipts and auditability

Provenact does not include:
- agents
- planners
- schedulers
- workflow orchestration
- autonomous decision loops

## Normative Sources

The following files are normative for v0:
- `spec/v0.md`
- `spec/v0/skill-manifest.schema.json`
- `spec/v0/pipeline-dag.schema.json`
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

## v0 Cryptographic Profile

- Hash: SHA-256
- Signature algorithm: Ed25519
- Digest prefix format: `sha256:<hex>`
- Registry transport checksum format: `<32 lowercase hex chars>` in registry entry `md5` fields
- Skill artifact authority: `manifest.artifact`
- Exact hash/signature preimages: `spec/hashing.md`

## Canonicalization Rules

Any hashed JSON document must be serialized with RFC 8785 (JCS), UTF-8 encoded.

No implicit fields may be included in hashed payloads.
Timestamps are excluded from hash inputs unless explicitly stated.

## Capability Model

Capabilities are deny-by-default and requested in manifest metadata.
Declared capabilities are not automatically granted.
Runtime enforcement is mandatory.

## Required Runtime Verification Sequence

Before execution, runtime must:
1. verify `skill.wasm` hash against `manifest.artifact`
2. verify signature records in `signatures.json`
3. enforce local policy against requested capabilities
4. execute only if checks pass

## Execution Receipts

Each successful execution MUST produce a receipt with at least:
- artifact hash
- input hash
- output hash
- capabilities used
- timestamp
- receipt hash

Receipt hashing must follow the canonicalization rules above.
Receipt shape is defined by `spec/execution-receipt.schema.json`.
Failed executions SHOULD emit a best-effort failure transcript outside the
success receipt schema.

CLI contract: `provenact-cli run` requires `--receipt`; there is no successful run
path without writing a receipt file.

## v0 Non-Goals

- blockchain anchoring
- zero-knowledge proofs
- multi-signer quorum policy logic
- native non-WASM execution
- UI orchestration features

## Expansion Gate (Post-v0/v1 Drafts)

New integration surfaces (including adapters) MUST wait until all are true:
1. Draft schemas for manifest v1 and receipt v1 exist and are reviewable.
2. Core verification and receipt behavior are covered by conformance vectors.
3. Golden `pack -> sign -> verify -> run -> receipt-verify` workflow is stable.
