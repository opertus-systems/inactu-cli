# Security-First Plan

This plan captures the execution order when security is the primary objective.
It is intentionally substrate-first and aligned with `AGENTS.md` boundaries.

## Scope

In scope:
- artifact signing and verification
- trust-anchor pinning
- capability policy enforcement
- tamper-evident execution receipts

Out of scope:
- planning/orchestration/memory/scheduling systems
- agent loops and autonomous control logic

## Repository Boundaries

1. Keep `provenact` as the substrate authority:
- packaging
- signing
- verification
- sandboxed execution
- receipts

2. Keep agent/orchestration logic in separate `agent-*` repositories that only
   consume substrate APIs/SDKs.

## Priority Order

1. Trust chain enforcement
- Require trust-anchor digest pinning on verify/run.
- Enforce signature checks before any execution.
- Define key rotation and revocation operating procedure.

2. Capability policy hardening
- Preserve default-deny semantics.
- Keep trusted signer and capability-ceiling checks mandatory.
- Expand negative vectors for policy edge cases.

3. Receipt and audit integrity
- Emit deterministic receipts for every successful execution.
- Verify receipt hashes in tooling and CI examples.
- Define replay contract for incident response.

4. Operator adoption path
- Maintain one golden workflow:
  `pack -> sign -> verify -> run -> verify-receipt`.
- Keep docs/scripts aligned to hardened defaults.

5. CI release gates
- Block releases on conformance + security checks.
- Keep signed artifacts, checksums, and SBOM publication in release workflows.

## Immediate Work Started

- `provenact-cli verify` now requires `--keys-digest`.
- `provenact-cli run` now requires `--keys-digest`.
- CLI integration tests now pin trust-anchor digests by default and include
  missing-digest denial coverage.
- Operator rotation/revocation runbook added:
  `docs/key-management.md`.
- CI gate added for documented/scripted verify/run command pinning:
  `scripts/check-keys-digest-usage.sh` wired in `.github/workflows/security.yml`.
