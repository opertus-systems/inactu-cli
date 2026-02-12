# Policy Semantics (v0)

This document defines how `spec/policy/policy.schema.json` is interpreted at
runtime in v0.

## Model

- Policies are deny-by-default.
- A requested capability is granted only if it is explicitly allowed by
  `capability_ceiling`.
- Unknown capability kinds are denied.

## Fields

- `version`:
  - MUST be `1`.
- `trusted_signers`:
  - Non-empty signer identifiers trusted by local policy.
  - Runtime MUST require at least one matching signer identity between
    `manifest.signers` and `trusted_signers`.
- `capability_ceiling`:
  - Ceiling, not grant. It defines upper bounds that requested capabilities must
    fit within.

## Capability Kinds (v0)

- `fs`:
  - `read` and `write` are absolute-path prefixes.
  - A requested fs path is allowed only when it has an allowed prefix for the
    requested access mode.
- `net`:
  - List of allowed absolute URI prefixes.
  - Requested `net.http` destinations MUST match one allowed prefix.
- `env`:
  - Exact allowlist of environment variable names.
- `exec`:
  - Boolean gate for `exec` and `exec.safe` capabilities.
- `time`:
  - Boolean gate for `time.now` capability.
- `random`:
  - Boolean gate for `random.bytes` capability.
- `kv`:
  - `read` and `write` are exact-key allowlists.
  - `*` in an allowlist grants all keys for that operation.
- `queue`:
  - `publish` and `consume` are exact-topic allowlists.
  - `*` in an allowlist grants all topics for that operation.

## Validation and Enforcement

- Policy documents MUST validate against `policy.schema.json`.
- Runtime MUST enforce both signer trust and capability ceilings before
  execution.
- If policy evaluation fails, execution MUST be denied.
