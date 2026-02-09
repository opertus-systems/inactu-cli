# Skill Management Roadmap (Cross-Agent Compatibility)

This document defines how Provenact can support broad skill portability without
violating repository scope boundaries in `AGENTS.md`.

Provenact remains the execution substrate. Agent orchestration remains out of repo.

## Objectives

- Use one portable skill artifact contract across ecosystems.
- Keep execution verification and policy enforcement in Provenact.
- Make skill-native integration the primary compatibility path.
- Support major agent/tool ecosystems through optional external adapters.
- Align with open standards for packaging, signing, and typed interfaces.

## Boundary Contract

Provenact owns:
- skill packaging and distribution format
- signing and verification
- capability policy enforcement
- deterministic execution and receipts

Out of scope for this repository:
- planning loops
- memory/state orchestration
- scheduler/workflow logic
- tool selection and autonomous decision logic

## Compatibility Principles

- Provenact is fully usable through its native skill contract and CLI/API.
- No adapter is required to package, verify, authorize, execute, or receipt a skill.
- Adapters are optional convenience layers for external ecosystems.
- Adapters must not redefine security, capability, or verification semantics.
- Native contract behavior is authoritative when adapter behavior diverges.

## Interoperability Strategy

1. Canonical artifact: immutable bundle with strict manifest and provenance.
2. Registry distribution: OCI-compatible push/pull model.
3. Invocation contract: typed input/output schemas and deterministic receipt.
4. Policy model: deny-by-default capabilities with explicit grants.
5. Integration strategy: native skill lifecycle first, adapters second.

## Open Standards Alignment

- OCI image/artifact distribution for skill transport.
- WASM/WASI execution targets for portability.
- JSON Schema (and optionally OpenAPI) for invocation contracts.
- Sigstore/cosign and in-toto/SLSA-style attestations for provenance.
- SPDX/CycloneDX as optional metadata extensions.

## Ecosystem Compatibility (Optional, Out-of-Repo Adapters)

- Native integration via Provenact skill APIs/CLI should be sufficient on its own.
- Adapters are translation layers for ecosystems that cannot call native flows.
- MCP tool adapters
- OpenAI-style tool calling adapters
- LangChain/LangGraph wrappers
- AutoGen/CrewAI wrappers

Each adapter should map ecosystem input into the same Provenact invoke lifecycle:
`resolve -> verify -> authorize -> execute -> receipt`.

## Work Plan (90 Days)

### Phase 1 (Weeks 1-2): RFCs and Contracts

- Draft `Skill Manifest v1` RFC (non-normative draft).
- Draft `Execution Receipt v1` RFC (non-normative draft).
- Define compatibility profile and version negotiation rules.

### Phase 2 (Weeks 3-6): Packaging + Verification

- Add OCI packaging/distribution profile for skill bundles.
- Define signing/attestation profile and verification gates.
- Add compatibility fixtures and golden test vectors.

Adapter start gate (must pass before any adapter implementation):
- Draft manifest v1 and receipt v1 contracts are stable enough for integration.
- Conformance vectors cover verification and receipt invariants.
- Native invoke lifecycle is validated end-to-end without adapters.

### Phase 3 (Weeks 7-10): Native SDK/CLI Contract + Optional Adapters

- Publish a reference native invoke contract (SDK/CLI examples).
- Validate native cross-runtime compatibility with shared vectors.
- Implement one optional adapter for ecosystem convenience.
- Publish mapping docs from adapter contracts to Provenact contracts.

### Phase 4 (Weeks 11-12): Conformance and Publication

- Run cross-adapter conformance matrix over shared vectors.
- Publish compatibility report and migration guidance.
- Identify v1 normative cut candidates for `SPEC.md`.

## Deliverables

- Roadmap and design docs in this repository.
- Two draft RFC skeletons under `spec/rfcs/`.
- Conformance vectors and schema test fixtures.
- External adapter repos with explicit compatibility statements.

## Success Criteria

- Same signed skill artifact executes consistently across at least two native
  runtime environments.
- Receipts are schema-valid and hash-stable across environments.
- Capability enforcement remains identical regardless of adapter.
- No agent-loop logic is added to Provenact core.

## Risks and Mitigations

- Risk: adapter divergence in semantics.
  Mitigation: normative lifecycle mapping and shared vectors.
- Risk: hidden privilege expansion in wrappers.
  Mitigation: enforce deny-by-default policy in runtime, not adapter.
- Risk: schema churn slows ecosystem adoption.
  Mitigation: strict semver + compatibility profiles + deprecation windows.
