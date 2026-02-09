# SECURITY.md

## Security Policy — Provenact

This document describes the security posture, threat assumptions, and vulnerability handling process for **Provenact**.

Provenact is a **security-sensitive execution substrate**. Security considerations are first-class and prioritized over convenience or feature velocity.

---

## Scope

This security policy applies to:

- Skill packaging, hashing, signing, and verification
- Capability enforcement and sandboxing
- The execution runtime
- Any code in:
  - `core/`
  - `runtime/`
  - `spec/`

It does **not** apply to:
- External agent frameworks
- Orchestration layers
- User interfaces
- Third-party skills not distributed with this repository

---

## Threat Model (Summary)

Provenact assumes the following adversarial conditions:

- Skills may be malicious or intentionally crafted to escape confinement
- Inputs may be adversarial
- Callers may be untrusted
- Skill authors may be compromised
- Supply-chain attacks are possible

The host operating system is assumed to be trusted but not omnipotent.

A full threat model is maintained in:
- `spec/threat-model.md`

Key lifecycle operations are documented in:
- `docs/key-management.md`

---

## Security Goals

Provenact is designed to ensure:

1. **Integrity**
   - Executed code matches the signed artifact
   - No tampering between verification and execution

2. **Capability Safety**
   - Skills cannot access resources beyond declared capabilities
   - No ambient authority is available

3. **Provenance**
   - All executions are attributable to a signed artifact
   - Inputs and outputs are inspectable

4. **Determinism**
   - Execution is reproducible given identical inputs and environment
   - Sources of nondeterminism must be explicit

5. **Auditability**
   - Execution decisions are explainable after the fact

---

## Explicit Non-Goals

Provenact does NOT currently aim to:

- Defend against a fully compromised host kernel or hypervisor
- Mitigate hardware-level side-channel attacks (e.g. speculative execution)
- Provide anonymity or deniability
- Secure long-lived secrets inside skills
- Act as a general-purpose container runtime

---

## Supported Cryptography

Provenact uses only:

- Well-established cryptographic primitives
- Widely reviewed libraries
- Conservative defaults

Custom cryptography is **explicitly forbidden**.

Cryptographic agility may be introduced later but is not a v0 priority.

---

## Capability Model

Capabilities are:

- Declared statically in the skill manifest
- Verified prior to execution
- Enforced by the runtime

Undeclared access to:
- filesystem
- network
- environment
- time
- randomness
- downstream execution

must result in **hard failure**.

---

## Vulnerability Reporting

Please report security issues **privately**.

Do NOT open a public issue for vulnerabilities.

GitHub Security Advisories:
- https://github.com/opertus-systems/provenact/security/advisories

### How to Report
- Email: security@opertus.systems (preferred)
- Include:
  - affected component
  - reproduction steps
  - expected vs actual behavior
  - any proof-of-concept code

Encrypted email is appreciated but not required.

---

## Disclosure Process

1. Report received and acknowledged
2. Issue triaged and reproduced
3. Fix developed privately
4. Release coordinated with reporter
5. Public disclosure after fix is available

Timelines will vary based on severity.

---

## Secure Development Practices

Contributors are expected to:

- Minimize unsafe code
- Justify any `unsafe` blocks explicitly
- Add tests for security-sensitive behavior
- Keep specs and implementation aligned
- Avoid expanding trust boundaries without review

All changes to `core/` and `runtime/` require careful review.

---

## Automated Tools

Where possible, the project may use:

- Static analysis
- Fuzzing (especially for parsers and runtime boundaries)
- Dependency auditing

Tooling choices will favor signal over noise.

---

## Final Note

If a change makes Provenact:
- harder to audit
- harder to reason about
- less explicit about authority

it is probably a security regression.

Security bugs are correctness bugs.

---

Last updated: 2026
