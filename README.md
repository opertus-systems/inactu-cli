# Inactu

Verifiable execution of immutable skills.

Inactu is a secure execution substrate for running immutable, attestable
executables ("skills") with explicit capabilities, reproducible builds, and
enforceable provenance.

## What Inactu Is

Inactu provides:
- a format and trust model for immutable executable bundles
- cryptographic attestation of code, inputs, and declared capabilities
- a sandboxed runtime for deterministic, policy-constrained execution
- tooling to package, sign, verify, inspect, and run skills
- conformance vectors and receipt verification for auditability

Inactu is not an agent framework, workflow engine, or orchestration layer.

## Core Principles

1. Immutability by default.
2. Explicit capabilities.
3. Verifiable provenance.
4. Deterministic execution.
5. Composability without trust collapse.

## What Inactu Is Not

- Not an LLM/agent framework
- Not a scheduler or workflow orchestrator
- Not a general container runtime
- Not a blockchain

## Repository Layout

```text
inactu/
├─ spec/            # Normative specs (formats, policies, threat model)
├─ core/            # Verification, signing, policy libraries (Rust)
├─ runtime/         # Runtime execution/transcript docs
├─ cli/             # Developer tooling (pack, sign, verify, run)
├─ skills/          # Blessed stdlib skills (v0 placeholder)
├─ test-vectors/    # Conformance vectors
├─ docs/            # Architecture and release/readiness docs
├─ apps/            # Temporary app/control-plane scaffolds
└─ README.md
```

## Runtime Architecture

Execution is intentionally split into narrow layers:

1. `core/verifier`
- strict parsing and deterministic verification primitives
- policy and capability evaluation
- canonical hashing and signature checks

2. `cli/inactu-cli`
- user-facing command orchestration (`pack`, `sign`, `verify`, `run`)
- preflight bundle validation and trust-anchor handling
- runtime invocation with resource limits

3. `runtime/` docs + specs
- execution rules, transcript model, and threat boundaries

This separation keeps cryptographic checks reusable and keeps command UX logic
out of the verifier core.

## Status

Early development / v0 with conformance-first hardening.

## Security Model

Assumptions and non-goals are defined in `spec/threat-model.md`.

## Conformance And Release

- Run full conformance: `cargo conformance`
- Run release gate locally: `cargo release-v0-check`
- Release checklist: `RELEASE_V0_CHECKLIST.md`
- Coverage matrix: `docs/conformance-matrix.md`
- Secure quickstart: `docs/getting-started.md`
- Observability contract: `docs/observability.md`

## Secure CLI Flow (Quickstart)

1. Pack:
`inactu-cli pack --bundle ./bundle --wasm ./skill.wasm --manifest ./manifest.json`

2. Sign:
`inactu-cli sign --bundle ./bundle --signer alice.dev --secret-key ./alice.key`

3. Pin trust anchor digest:
`KEYS_DIGEST="$(shasum -a 256 ./public-keys.json | awk '{print "sha256:"$1}')"`.

4. Verify:
`inactu-cli verify --bundle ./bundle --keys ./public-keys.json --keys-digest "$KEYS_DIGEST"`

5. Run:
`inactu-cli run --bundle ./bundle --keys ./public-keys.json --keys-digest "$KEYS_DIGEST" --policy ./policy.json --input ./input.json --receipt ./receipt.json`

## Specification Notes

- `AGENTS.md` defines repository scope boundaries.
- `SPEC.md` is the top-level spec index.
- `spec/` contains normative v0 format and policy documents.
