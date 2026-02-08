# Provenact Organization Repository Map

Last updated: 2026-02-07

This document defines repository responsibilities, entry points, and remaining
build-out work after creating `provenact-spec` and `provenact-examples`.

## Start Here (External)

1. `provenact-examples`: first runnable experience.
2. `provenact-spec`: normative contract and conformance vectors.
3. `provenact-cli`: reference runtime/verifier implementation.

## Current Repositories

- `provenact-cli`
  - role: reference runtime CLI, verifier wiring, secure local execution.
  - owns: pack/sign/verify/run flows, receipt verification command surface.
  - must not own: agent orchestration or scheduler behavior.

- `provenact-spec`
  - role: implementation-neutral protocol contract.
  - owns: normative docs, schemas, vectors, compatibility policy.
  - must not own: runtime business logic.

- `provenact-examples`
  - role: adoption-focused runnable demos and integration walkthroughs.
  - owns: end-to-end scripts, CI gate examples, IDE bridge examples.
  - must not own: normative contract decisions.

- `provenact-skills`
  - role: released, signed, pinned skill bundle distribution.
  - owns: bundle publishing, lock metadata, release channel docs.

- `provenact-sdk`
  - role: SDK bindings and developer APIs.
  - owns: language-specific parsers/adapters against spec contracts.

- `provenact-control`
  - role: control-plane API and backend services.
  - owns: receipt/policy verification APIs and package/context services.

- `provenact-control-web`
  - role: control-plane UI.
  - owns: operator workflows, package/context presentation.

- `provenact-agent-kit`
  - role: adapter utilities for external orchestration ecosystems.
  - owns: bridges and wrappers that call Provenact execution surfaces.

## Remaining Repositories To Add

### 1) `provenact-skill-lib`

Purpose: source code for first-party skills, separate from released bundles.

Required initial scope:
- per-skill source directories and deterministic WASM builds
- reproducible build instructions pinned by toolchain version
- SBOM generation and signature attachment pipeline
- promotion workflow to publish immutable artifacts into `provenact-skills`

Exit criteria:
- at least `fs.read_text`, `fs.write_text`, and `git.diff` built and published
  through the promotion path
- provenance metadata links source commit to published artifact digest

### 2) `provenact-integrations`

Purpose: copy/paste integration surfaces that accelerate adoption.

Required initial scope:
- MCP server profile for Provenact invocation
- AgentSkills export templates for Codex/Claude/Cursor
- GitHub Actions examples for verify/run/receipt-verify gates
- wrapper-mode scripts for common CI systems

Exit criteria:
- each integration has a runnable sample and expected output contract
- CI validates examples do not drift from current CLI/spec

### 3) `provenact-conformance`

Purpose: implementation-agnostic conformance center (if not fully absorbed by
`provenact-sdk`).

Required initial scope:
- golden vectors promoted from `provenact-spec`
- known-bad skills and policy denial fixtures
- deterministic execution fixtures with expected receipts
- compatibility test harness with machine-readable report output

Exit criteria:
- third-party runtime can run one command and receive pass/fail per profile
- reports include spec tag, runtime version, and failing vector identifiers

### 4) `provenact-dist`

Purpose: release/distribution automation across repos.

Required initial scope:
- signed release artifact pipeline
- Homebrew tap and winget/scoop packaging automation
- Docker image publication for runtime and control-plane components
- SBOM publication and checksum manifests per release

Exit criteria:
- fresh machine install path documented and tested in CI
- every release artifact has signatures + checksums + SBOM links

## Governance Rules

- `provenact-spec` is the contract source of truth.
- Runtime repos pin spec tags; they do not silently track `main`.
- `provenact-examples` may iterate faster, but every demo must identify the spec
  tag and CLI version it targets.
- Agent behavior remains out-of-scope for `provenact-cli` and `provenact-spec`.

## Suggested Org Homepage Layout

For `.github/profile/README.md`:

- one-line mission
- Start Here section (examples -> spec -> cli)
- repository table (role + who should use it)
- security boundary statement: Provenact executes verified skills; orchestration
  lives elsewhere
