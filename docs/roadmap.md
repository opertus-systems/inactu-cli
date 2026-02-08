# Roadmap

This roadmap tracks delivery of v0 as a secure execution substrate.
Scope is intentionally limited to packaging, signing, verification, capability-gated execution, and receipts.

## v0 Milestones

### M1: Verify + Inspect Baseline (Complete)

Goal:
- Deterministically validate bundle integrity and signatures.

Work:
- `provenact-cli verify --bundle <dir> --keys <public-keys.json> --keys-digest <sha256:...>`
- `provenact-cli inspect --bundle <dir>`
- Strict parsing of manifest/signature data and digest format checks.

Acceptance criteria:
- Good vector verifies:
  - `test-vectors/good/minimal-zero-cap`
- Known-bad vectors fail verification:
  - `test-vectors/bad/hash-mismatch`
  - `test-vectors/bad/bad-signature`
- Inspect output is deterministic for the good vector.

Exit signal:
- CLI integration tests pass for verify/inspect against the vectors above.

### M2: Pack + Sign Commands (Complete)

Goal:
- Produce deterministic bundle artifacts and signature records from local inputs.

Work:
- Add `provenact-cli pack` to assemble:
  - `skill.wasm`
  - `manifest.json`
  - `signatures.json` (initially empty or unsigned scaffold)
- Add `provenact-cli sign` to append/update `signatures.json` with Ed25519 signatures over `signatures.manifest_hash` (canonical manifest hash).
- Keep hash/signature preimages aligned with `spec/hashing.md`.

Acceptance criteria:
- Packing identical inputs produces byte-stable JSON and identical artifact digest.
- Signed output verifies using `provenact-cli verify`.
- New generated vectors are added under:
  - `test-vectors/good/pack-sign-roundtrip`
  - `test-vectors/bad/` (at least one malformed signing case)

Exit signal:
- End-to-end test: `pack -> sign -> verify` succeeds in CI.

### M3: Runtime Execute + Capability Gate + Receipt (Complete)

Goal:
- Execute verified skills with deny-by-default capability enforcement and emit receipts.

Work:
- Add `provenact-cli run`.
- Enforce verification sequence before execution:
  1. artifact hash
  2. signatures
  3. policy/capability decision
  4. execute
- Emit success receipt shaped by `spec/execution-receipt.schema.json`.

Acceptance criteria:
- Execution without required granted capabilities is denied.
- Successful execution emits receipt containing:
  - artifact hash
  - input hash
  - output hash
  - capabilities used
  - timestamp
  - receipt hash
- Receipt hash verification passes canonicalization rules.

Exit signal:
- End-to-end test vector: `verify -> run -> receipt-verify`.

### M4: Conformance + Hardening (Complete)

Goal:
- Lock v0 behavior to spec and prevent drift.

Work:
- Expand negative vectors for malformed manifests/signatures/receipts.
- Add schema validation checks where required by spec.
- Document deterministic behavior guarantees and explicit nondeterminism gates.

Acceptance criteria:
- All normative docs in `SPEC.md` are covered by tests or fixtures.
- CI includes a conformance job over `test-vectors/`.
- No agent/orchestration features introduced in v0 scope.

Exit signal:
- v0 release candidate with passing conformance suite.

Exit evidence:
- `cargo conformance` passes locally.
- CI conformance job is defined in `.github/workflows/conformance.yml`.
- Normative coverage map is tracked in `docs/conformance-matrix.md`.

## v1 Candidates (Post-v0)

- Policy plugin interfaces with strict trust-boundary preservation.
- Optional transparency log integration for published bundles.

## Security-First Execution Plan (Active)

This plan prioritizes hard security gates before new feature surface.

### P0: End-to-End Trust Chain Enforcement

Goal:
- Make trust-anchor pinning and signature verification non-optional on the golden path.

Current:
- `verify` and `run` require `--keys-digest`.
- Integration tests cover missing-digest denial for both commands.
- Operator runbook published: `docs/key-management.md`.
- CI command-example gate published: `scripts/check-keys-digest-usage.sh`.

Next:
- Add key-rotation drill fixture and release checklist linkage.
- Extend command-example gate to shell scripts outside this repository root.

### P1: Capability and Policy Operations Hardening

Goal:
- Keep default-deny enforcement strict while improving policy operations.

Next:
- Add staged policy rollout modes (`audit`, `warn`, `enforce`) design doc.
- Add regression vectors for policy exception handling and signer-set drift.

### P2: Receipt and Replay Readiness

Goal:
- Improve incident/debug value of receipts without weakening determinism.

Next:
- Define deterministic replay contract and minimal replay CLI prototype.
- Add receipt correlation-id guidance to observability docs.

## Immediate Next Work (Focus Lock)

This section defines the next execution sequence to keep the product focused.

1. Freeze v1 boundary docs:
- finalize scope and non-goals in `SPEC.md`
- keep agent/orchestration features out of this repository

2. Ship one golden workflow:
- ensure `pack -> sign -> verify -> run -> receipt-verify` is documented and
  tested as the default operator path
- prioritize UX and deterministic failure modes in CLI output

3. Turn RFC drafts into concrete draft schemas:
- `spec/rfcs/skill-manifest-v1.md` -> experimental schema draft
- `spec/rfcs/execution-receipt-v1.md` -> experimental schema draft
- add positive/negative vectors for both drafts

4. Hold adapter work until gate conditions pass:
- no adapter implementation before schema + conformance gates are satisfied
- when started, implement only one thin reference adapter first

## Out of Scope Here

- Agent loops, planning, scheduling, or long-lived memory systems.
- Built-in LLM orchestration.
