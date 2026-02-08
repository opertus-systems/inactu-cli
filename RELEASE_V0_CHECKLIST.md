# Release v0 Checklist

This checklist defines the minimum release gate for Provenact v0.

## Hard Gates

- [x] `cargo release-v0-check` passes locally.
- [x] CI `Conformance` workflow is green on the release commit/PR.
- [x] `docs/conformance-matrix.md` shows no known conformance gaps for normative
      sources in `SPEC.md`.
- [x] v0 demo suite passes:
  - `./apps/provenact-agent-kit/scripts/demo-v0.sh`
- [x] Repository boundaries remain intact:
  - no agent/orchestration features introduced in-core
  - no ambient-authority expansion beyond declared capability model
  - scope remains consistent with `AGENTS.md`
- [x] Canonical content-addressed package contract is locked:
  - deterministic `skill.tar.zst` layout
  - archive digest (`sha256:<hex>`) is the skill ID of record
  - `manifest.json` + `skill.wasm` required
  - `sbom.spdx.json` and `sigstore.bundle.json` are optional
- [x] Install semantics are implemented and validated:
  - `provenact install` supports local path / `file://` / `http(s)://` sources
  - install sequence is enforced: `load -> hash -> verify -> validate -> store -> index`
  - signature verification is dev-optional and prod-mandatory (`--require-signatures`)
  - policy-gated install checks are supported
- [x] Local content store contract is satisfied:
  - installed artifacts live under `~/.provenact/store/sha256/<hash>/`
  - local index metadata is maintained in `~/.provenact/index.json`
- [x] Exact-hash references are first-class:
  - pipeline/contracts accept `sha256:<hash>` skill refs
  - optional source metadata may be recorded alongside hash refs
- [x] Registry backend is explicitly excluded from v0:
  - hosted registry/discovery/version-resolution features are not required for release
  - future `oci://...@sha256:...` syntax is parseable without requiring backend implementation
- [x] Roadmap status matches reality:
  - `docs/roadmap.md` marks M1-M4 complete

## Single Local Validation Command

Run from repo root:

`cargo release-v0-check`

This alias currently executes the same suite as `cargo conformance` and is kept
as the stable release gate command.
