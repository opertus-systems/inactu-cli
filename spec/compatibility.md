# Compatibility and Stability Policy (v0)

This document defines compatibility guarantees for Provenact v0.

## Scope

Compatibility commitments in this file apply only to:
- normative schemas and rules listed in `SPEC.md`
- stable CLI commands (`pack`, `sign`, `verify`, `inspect`, `run`,
  `verify-receipt`, `verify-registry-entry`)

The following are explicitly excluded from compatibility guarantees:
- commands and schemas labeled `experimental`
- RFC draft documents under `spec/rfcs/`
- draft schema files with `.experimental.` in filename

## Versioning Contract

- Provenact follows semantic versioning for stable contracts.
- Patch releases (`0.1.x`) may tighten validation and fix bugs without changing
  accepted valid payload semantics.
- Minor releases (`0.x+1.0`) may add optional fields/behaviors that preserve
  backward verification compatibility.
- Breaking changes to stable schema semantics require a new schema version and
  migration guidance.

## Receipt Compatibility

- v0 success receipts are defined by `spec/execution-receipt.schema.json`.
- A v0-compatible runtime must emit every required v0 field exactly as defined
  by schema and hash preimage rules.
- `timestamp` is host-observed UNIX seconds and is not an external time
  attestation.
- Absence of RFC 3161/TSA or transparency-log anchoring in v0 is an explicit
  non-goal, not an implicit guarantee.

## Runtime Profile Compatibility

- v0 execution contract is WebAssembly module execution with the Provenact host ABI
  (`docs/runtime-host-abi.md`).
- WASI support is not normative in v0; skills relying on WASI imports are out of
  contract unless and until a future profile declares them.

## Reproducible Build Claim Boundary

- Deterministic packaging, hashing, and verification are normative in v0.
- End-to-end build reproducibility proofs are not yet normative and must not be
  represented as a shipped guarantee until CI evidence and toolchain pinning are
  documented.
