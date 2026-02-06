# RFC: Execution Receipt v1 (Draft)

Status: Draft  
Owner: TBD  
Last Updated: 2026-02-06

This RFC is non-normative until promoted into `SPEC.md`.

## 1. Summary

Define `Execution Receipt v1` as a portable, deterministic receipt contract for
cross-environment verification of Inactu skill runs.

## 2. Motivation

v0 receipts establish baseline auditability. Cross-ecosystem compatibility
requires stronger run context clarity, stable hashing semantics, and explicit
versioning behavior.

## 3. Goals

- Keep receipts deterministic and hash-stable.
- Preserve cryptographic binding to artifact, policy decision, and I/O.
- Improve portability across runtimes and external integrations.
- Keep receipt verification independent from agent/orchestrator concerns.

## 4. Non-Goals

- Workflow-level orchestration metadata
- Planner/scheduler state
- Autonomous retry/decision traces

## 5. Proposed Schema Direction

Tentative top-level fields:
- `schema_version`
- `artifact` (skill digest)
- `manifest_hash`
- `policy_hash`
- `bundle_hash`
- `inputs_hash`
- `outputs_hash`
- `runtime_version_digest`
- `result_digest`
- `caps_requested`
- `caps_granted`
- `caps_used`
- `result` (success/failure with deterministic code taxonomy)
- `runtime` (runtime id/version profile)
- `started_at` / `finished_at` (explicit timestamp semantics)
- `timestamp_strategy` (how time values were sourced)
- `receipt_hash`
- `attestations` (optional signatures/anchors)

Prototype schema path:
- `spec/execution-receipt.v1.experimental.schema.json`

## 6. Hashing and Canonicalization

- Canonical JSON remains RFC 8785 (JCS), UTF-8.
- `receipt_hash` preimage must exclude self-reference.
- Timestamp precision and normalization must be fixed by schema rules.
- Hash/signature algorithms align with cryptographic profile policy.

## 7. Verification Semantics

Receipt verification should confirm:
1. artifact and manifest linkage
2. policy linkage via `policy_hash`
3. deterministic integrity of input/output digests
4. internal consistency of capability fields and result code
5. receipt hash validity over canonicalized payload

## 8. Compatibility Strategy

- SemVer for receipt schema.
- Runtime advertises supported receipt schema versions.
- v1 verifier behavior for unknown optional fields is explicitly defined.

## 9. Security Considerations

- Prevent mutable/derived fields from altering verification outcome.
- Avoid ambiguous failure semantics that hide policy denials.
- Ensure capability use claims cannot exceed granted capabilities.

## 10. Conformance Impact

Planned additions:
- valid v1 success/failure receipt vectors
- malformed hash and linkage vectors
- timestamp normalization edge-case vectors

## 11. Open Questions

- Whether `caps_requested` should be mandatory in receipt payload.
- Required granularity of runtime profile information.
- Canonical failure-code taxonomy for portability.
- v1 timestamping strategy: local clock only vs optional TSA/transparency anchors.

## 12. Rollout Plan

1. Draft experimental v1 schema alongside v0 schema.
2. Add parser/verifier behind schema version gates.
3. Add conformance vectors and CLI validation flows.
4. Promote to normative once multi-environment checks pass.
