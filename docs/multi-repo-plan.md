# Multi-Repo Plan (Post-v0)

This document defines how to expand beyond the core substrate while keeping
`AGENTS.md` boundaries intact.

Core rule: `provenact` executes verified skills; agent orchestration lives
elsewhere.

## Goals

- Keep execution trust boundaries clear and auditable.
- Enable ecosystem adoption through a stable SDK path.
- Avoid introducing planning, memory, or scheduling logic into core repos.

## Proposed Repositories

1. `provenact` (existing; substrate authority)
- Scope: packaging, signing, verification, sandboxed execution, receipts.
- Must not include: agent loops, planners, schedulers, memory systems.

2. `provenact-sdk` (new; Rust-first)
- Scope: library APIs for verify/execute/receipt flows.
- Initial language target: Rust.
- Follow-up language target: TypeScript/Node with behavior parity tests.
- Stability: `0.x` until substrate API freeze.

3. `provenact-skills` (new; blessed reference skills)
- Scope: stdlib-like skills, manifests, reproducible build templates, fixtures.
- Purpose: provide canonical examples and compatibility tests for SDK users.

4. `provenact-agent-kit` (new; non-core helper layer)
- Scope: integration adapters and execution helpers for external agent systems.
- Includes: retry wrappers, tracing hooks, HITL checkpoints.
- Excludes: policy authority and unsafe capability elevation.

5. `provenact-agent-reference` (new; sample app)
- Scope: one reference orchestrator showing planner/memory/scheduler patterns.
- Role: prove integration and developer ergonomics outside core.

6. `provenact-control` (dedicated repository)
- Scope: trust roots, bundle metadata distribution, provenance lookup APIs.
- Keep deterministic and governance-focused; no autonomous decisions.

## Rust-First SDK Strategy

Do not wait for full API finalization. Ship a thin alpha now and harden in
public.

Phase A (`provenact-sdk` `0.1.x`):
- Stable surface:
  - `verify_bundle(...)`
  - `execute_verified(...)`
  - `parse_receipt(...)`
- Mark unstable paths under `experimental::*`.
- Publish strict compatibility notes against `provenact` commit/tag.

Phase B (`0.2.x` to `0.9.x`):
- Add ergonomics without expanding trust boundaries.
- Add conformance fixtures shared with CLI vectors.
- Gate changes with golden roundtrip tests:
  - `pack -> sign -> verify -> run -> receipt-verify`

Phase C (`1.0.0`):
- Cut once substrate API invariants are frozen in spec/tests.
- Freeze error taxonomy and semver compatibility commitments.

## Cross-Repo Contracts

Each non-core repo must include:
- `README.md` with explicit in-scope/out-of-scope.
- `ARCHITECTURE.md` with trust boundaries and data flow.
- `SECURITY.md` with capability and key material handling rules.
- CI checks proving no ambient authority assumptions.

Shared artifacts:
- `test-vectors/` consumption for parity and regression protection.
- Conformance matrix entries for any new normative behavior.

## Ownership and Release Flow

1. Substrate first:
- `provenact` tags authoritative behavior and schemas.

2. SDK second:
- `provenact-sdk` pins to substrate tags and publishes matching releases.

3. Ecosystem third:
- `provenact-skills` and agent repos consume SDK releases, not internal APIs.

4. Control-plane lives out of tree:
- Keep `provenact-control` as its own repository and avoid reintroducing an
  in-repo control-plane implementation under `apps/`.

## Immediate Execution Checklist

1. Create `provenact-sdk` repo with Rust crate skeleton and `0.1.0-alpha.1`.
2. Implement only verify/execute/receipt parsing.
3. Import `test-vectors` fixtures as SDK conformance tests.
4. Add explicit `experimental` module for unstable entry points.
5. Draft TypeScript parity plan, but defer implementation until Rust alpha
   conformance is stable.
