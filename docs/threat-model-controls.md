# Threat Model Controls (v0)

This checklist maps `spec/threat-model.md` risks and goals to concrete
automated gates in the repository.

## Gate Checklist

- [x] Tampered artifact is rejected before execution.
  Evidence: `cli/provenact-cli/tests/threat_model_gates.rs` (`gate_tampered_artifact_is_rejected`), `test-vectors/bad/hash-mismatch`.
- [x] Signature forgery / signer confusion is rejected.
  Evidence: `cli/provenact-cli/tests/threat_model_gates.rs` (`gate_bad_signature_is_rejected`), `test-vectors/bad/bad-signature`.
- [x] Trust-anchor substitution can be pinned and mismatches are rejected.
  Evidence: `cli/provenact-cli/tests/verify.rs` (`verify_fails_for_keys_digest_mismatch`), `cli/provenact-cli/tests/run.rs` (`run_rejects_keys_digest_mismatch`).
- [x] Unauthorized capability escalation is denied.
  Evidence: `cli/provenact-cli/tests/threat_model_gates.rs` (`gate_unauthorized_capability_is_denied`), `core/verifier/tests/capability_eval_vectors.rs`.
- [x] Policy bypass via malformed/invalid policy input is denied.
  Evidence: `core/verifier/tests/policy_vectors.rs` with `test-vectors/policy/invalid/*`.
- [x] Oversized untrusted CLI inputs are rejected with bounded file reads.
  Evidence: `cli/provenact-cli/tests/verify.rs` (`verify_fails_for_oversized_keys_file`).
- [x] Successful execution produces auditable receipt material.
  Evidence: `cli/provenact-cli/tests/threat_model_gates.rs` (`gate_successful_run_produces_auditable_receipt`), `cli/provenact-cli/tests/receipt.rs`.
- [x] Unbounded runtime behaviors are curtailed by execution limits.
  Evidence: `cli/provenact-cli/tests/run.rs` (`run_stops_infinite_loop_on_fuel_exhaustion`, `run_stops_memory_growth_abuse`).

## Known Non-Goals (Explicitly Not Gated)

- Fully compromised host-kernel defense.
- Hardware side-channel resistance.
- DoS/availability guarantees.
