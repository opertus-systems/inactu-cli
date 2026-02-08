# RFC: Skill Manifest v1 (Draft)

Status: Draft  
Owner: Provenact Maintainers  
Last Updated: 2026-02-06

This RFC is non-normative until promoted into `SPEC.md`.

## 1. Summary

Define a versioned, portable `manifest.json` contract that enables cross-agent
skill interoperability while preserving Provenact verification and policy controls.

## 2. Motivation

Current v0 manifest fields focus on secure execution. Cross-ecosystem reuse
needs clearer invocation contracts, version negotiation, and metadata for
distribution compatibility.

## 3. Goals

- Preserve immutable artifact identity.
- Define stable invocation metadata and schema references.
- Keep capability requests explicit and machine-verifiable.
- Support transport via OCI-compatible registries.

## 4. Non-Goals

- Agent orchestration behavior
- Planner or scheduler metadata
- Long-lived memory/state model

## 5. Proposed Schema Direction

Tentative top-level fields:
- `schema_version` (semantic version string)
- `id` (stable skill identifier)
- `version` (artifact version)
- `artifact` (digest, required)
- `entrypoint` (runtime entry descriptor)
- `inputs_schema` (JSON Schema reference or embedded object)
- `outputs_schema` (JSON Schema reference or embedded object)
- `capabilities` (requested capability declarations)
- `provenance` (attestation references)
- `compatibility` (supported runtime/adapter profile tags)

Prototype schema path:
- `spec/skill-format/manifest.v1.experimental.schema.json`

## 6. Canonicalization and Integrity

- Hashing and signing remain aligned with `spec/hashing.md`.
- JSON canonicalization remains RFC 8785 (JCS).
- No implicit fields may affect signed preimages.

## 7. Compatibility Strategy

- SemVer for manifest schema.
- Runtime capability to advertise supported manifest schema versions.
- Defined downgrade behavior when optional v1 fields are unsupported.

## 8. Security Considerations

- Prevent privilege escalation through defaulted capability fields.
- Ensure schema references cannot bypass local policy evaluation.
- Require deterministic interpretation of entrypoint descriptors.

## 9. Conformance Impact

Planned additions:
- valid v1 manifest vectors
- malformed schema/reference vectors
- downgrade/compatibility behavior vectors

## 10. Open Questions

- Embedded schemas vs referenced schemas as default.
- Required compatibility profile granularity.
- Optional metadata bounds to avoid unbounded manifest growth.

## 11. Rollout Plan

1. Draft schema in `spec/skill-format/` as experimental.
2. Add parser/validator behind explicit version gate.
3. Add conformance vectors and CLI compatibility checks.
4. Promote to normative after interoperability validation.
