# Docs

Architecture and onboarding for Inactu v0.

This repository's authority order is:
- `AGENTS.md` (project scope and boundaries)
- `SPEC.md` (top-level spec index)
- `spec/` (normative details)

Key implementation-tracking document:
- `docs/conformance-matrix.md` (normative-source-to-test coverage map)
- `docs/threat-model-controls.md` (threat-model-to-gate checklist)
- `docs/compliance-controls.md` (control-to-regulation matrix and audit evidence map)
- `docs/audit-evidence-checklist.md` (per-release audit packet template)
- `docs/getting-started.md` (secure pack/sign/verify/run quickstart)
- `docs/key-management.md` (trust-anchor rotation and revocation runbook)
- `docs/observability.md` (runtime/perf metrics and telemetry contract)
- `docs/runtime-host-abi.md` (WASM host import ABI for runtime execution)
- `docs/skill-management-roadmap.md` (cross-ecosystem skill compatibility plan)
- `docs/multi-repo-plan.md` (repo boundaries and Rust-first SDK rollout plan)
- `docs/security-first-plan.md` (active security-priority implementation order)
- `docs/v0-demo-status.md` (v0 demo coverage for agent integration and MCP-optional proof)
- `docs/cdn-distribution-draft.md` (draft CDN ownership, integrity, and cost controls)
- `audit.toml` (cargo-audit policy/ignore list with rationale)

Local developer helpers:
- `scripts/bootstrap-local.sh` (local prerequisite/version checks + CLI build smoke)
- `Makefile` (one-command local secure flows, including cosign-gated variants)
