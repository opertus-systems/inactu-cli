# Threat Model (v0)

Inactu assumes hostile inputs, potentially malicious skills, and imperfect
hosts. This model defines what v0 does and does not defend.

## Assets to Protect

- Integrity of immutable skill artifacts and metadata.
- Correctness of capability enforcement decisions.
- Integrity and auditability of execution receipts.
- Reproducibility of verification and execution outcomes.

## Trust Boundaries and Authorities

- Skill bundle contents are untrusted until verification succeeds.
- Callers are untrusted and may provide adversarial inputs.
- Local policy files and trust anchors are local authority.
- Runtime host process and host kernel are trusted for v0 isolation primitives.
- Clock and entropy sources are trusted only when explicitly permitted by
  capability policy.

## Determinism Model (v0)

- Verification determinism: hash/signature/policy decisions for a fixed input set
  must be stable and reproducible.
- Execution determinism baseline: with no time/random/network capabilities and
  equivalent runtime profile, output bytes and receipt hash preimage fields are
  expected to be stable.
- Determinism exceptions are explicit and capability-gated:
  - `time.now` introduces clock variance.
  - `random.bytes` introduces entropy variance.
  - any future network capability introduces remote state variance.

## Threats In Scope

- Tampered artifact, manifest, signatures, or receipt payload.
- Signature forgery, signer confusion, or trust-anchor substitution.
- Capability escalation via undeclared or over-broad requests.
- Policy bypass attempts via malformed inputs or parser differentials.
- Receipt forgery via digest mismatch or canonicalization ambiguity.
- Runtime abuse attempts (fuel/memory/table/instance exhaustion within process
  limits).

## Threats Explicitly Out Of Scope (v0)

- Fully compromised host kernel/hypervisor or privileged host process.
- Hardware-level side channels (cache timing, speculative execution, power/EM).
- Availability guarantees under denial-of-service conditions.
- External timestamp authority, secure time attestation, or global ordering of
  receipts.
- Cross-host network nondeterminism controls for remote services.

## Environment Assumptions

- Filesystem integrity outside verified bundle paths is a host concern.
- Network isolation is policy/runtime dependent and not globally guaranteed by
  v0.
- Host clock may drift; timestamp fields are informational for local audit
  timelines, not trusted notarization.
- Host entropy quality is delegated to OS RNG when `random.bytes` is allowed.

## Security Goals

- Prevent unauthorized capability escalation.
- Ensure provenance and integrity before execution.
- Keep nondeterminism explicit, capability-gated, and auditable.
- Produce auditable receipts for every successful execution.
