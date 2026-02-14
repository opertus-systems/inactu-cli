# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic
Versioning.

## [Unreleased]

### Added
- Trust-anchor pinning for `public-keys.json` via `--keys-digest` on
  `verify` and `run`.
- Key management runbook for trust-anchor rotation/revocation:
  `docs/key-management.md`.
- Runtime execution limits (fuel and Wasmtime store limits for memory/tables/
  instances).
- Defensive bounded file reads for untrusted CLI inputs.
- Signature policy hardening requiring non-empty signature sets.
- Security CI workflow (`clippy`, `cargo-deny`, `cargo-audit`).
- `deny.toml` policy for reproducible `cargo-deny` checks.
- `audit.toml` policy for explicit cargo-audit advisory handling.
- `docs/getting-started.md` secure quickstart.
- Release artifact workflow with attached checksums and SBOMs.
- `docs/observability.md` runtime telemetry and metric contract.
- `spec/compatibility.md` with stable-vs-experimental compatibility rules and
  v0 receipt/runtime profile boundaries.
- Draft v1 receipt security digests:
  - `bundle_hash`
  - `runtime_version_digest`
  - `result_digest`
  - `timestamp_strategy`
  with verifier helpers and hash-verification support.
- CLI receipt format selection: `run --receipt-format <v0|v1-draft>`.
- `verify-receipt` support for v1 draft receipt hash verification.
- Source-of-truth sync enforcement artifacts:
  - `sync-manifest.json` for mirrored `spec/` and `test-vectors/`
  - `scripts/check-sync-parity.sh` parity gate
  - `scripts/check-release-contract.sh` source-pin contract gate
  - CI jobs `sync-spec-check` and `release-contract-check`

### Changed
- `verify` and `run` now require `--keys-digest` (digest pinning is no longer
  optional).
- Security CI now enforces `--keys-digest` usage in documented/scripted
  `verify`/`run` examples.
- Signature payloads now bind to canonical `manifest_hash`.
- Net capability evaluation now uses structured URI matching.
- Trusted signer validation now requires signer intersection and declared
  signature signers.
- CLI internals refactored into cohesive modules for maintainability.
- Integration tests consolidated with shared test helpers.
- CLI success output normalized to `OK <command> ...` format.
- Threat model now specifies determinism assumptions, explicit
  side-channel/time/entropy/network boundaries, and host trust limits.
- README/SPEC/runtime docs now explicitly state v0 receipt requirement for
  successful runs, WASI non-goal status in v0 runtime profile, and that
  reproducible build proofs are not yet a shipped v0 guarantee.
- `spec/hashing.md` now specifies v1 draft receipt preimage and bundle-hash
  preimage rules.
- P0-1 remediation evidence for `RUSTSEC-2026-0009`:
  - verified no `time 0.3.36` in `Cargo.lock`
  - lockfile no longer resolves a `time` package in this workspace
  - `cargo audit` is clean for the advisory
  - mirror source pin recorded as
    `opertus-systems/provenact-spec@fe677208ab9025c44884de36fe6ebf999889048b`

## [0.1.0] - 2026-02-06

### Added
- Initial public release of Provenact v0 substrate with:
  - bundle packing/signing/verification/inspection/runtime execution
  - verifier core with policy and capability enforcement
  - deterministic execution receipts and verification
  - conformance vectors and CI conformance gate
  - threat model and security documentation
