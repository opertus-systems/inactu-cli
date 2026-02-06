# Audit Evidence Checklist (Per Release)

Use this checklist for each release window to assemble a regulator/auditor-ready
packet. This template maps to `docs/compliance-controls.md`.

- Release identifier: `<tag/version>`
- Release date (UTC): `<YYYY-MM-DD>`
- Evidence owner: `<name/team>`
- Scope (services/environments): `<prod/staging/etc>`

## 1) Build And Test Evidence

- [ ] Conformance run attached (`cargo conformance`) with timestamp and run ID.
- [ ] CLI test run attached (`cargo test -p inactu-cli`) with timestamp and run ID.
- [ ] Security workflow results attached (`security.yml`: clippy, deny, audit).
- [ ] Commit SHA and branch/tag provenance recorded.

Artifacts to include:
- CI logs or exported summaries
- Workflow URLs and immutable run IDs
- Commit SHA list in scope

## 2) Artifact Integrity And Provenance Evidence

- [ ] OCI artifact reference recorded (`ghcr.io/...:<tag>`).
- [ ] OCI digest recorded (`sha256:...`).
- [ ] Signature verification output attached (`cosign verify`).
- [ ] Rekor/transparency details retained (if available in environment).
- [ ] Attestation/provenance references attached (if enabled).

Artifacts to include:
- `oras` push output (or registry metadata)
- `cosign verify` output
- Attestation URIs/digests

## 3) SBOM And Vulnerability Evidence

- [ ] SBOM attached (`syft`, SPDX/CycloneDX).
- [ ] Vulnerability scan output attached (`trivy` or equivalent).
- [ ] High/Critical findings triaged and dispositioned.
- [ ] Exception approvals documented with expiry.

Artifacts to include:
- `sbom.spdx.json` (or equivalent)
- scan reports + remediation tickets

## 4) Policy And Access Control Evidence

- [ ] Trusted signer set version recorded.
- [ ] Capability ceiling policy version recorded.
- [ ] Policy change approvals attached (PR links/reviews).
- [ ] Any temporary policy exceptions documented and time-bounded.

Artifacts to include:
- policy file hashes
- signer key set hash (`--keys-digest` value)
- approval records

## 5) Runtime And Receipt Evidence

- [ ] Sample production/staging receipts attached.
- [ ] Receipt verification outputs attached (`verify-receipt`).
- [ ] Telemetry extracts attached for `inactu.verify`, `inactu.run`, `inactu.verify_receipt`.
- [ ] Failed verification/policy-deny events reviewed and dispositioned.

Artifacts to include:
- receipt JSON samples (redacted as needed)
- validation logs
- observability query exports

## 6) Incident And Exception Evidence

- [ ] Security incidents during window listed (or explicit “none”).
- [ ] Incident tickets and postmortems linked where applicable.
- [ ] Control exceptions documented with owner + closure date.
- [ ] Breach/notification legal review notes linked where applicable.

Artifacts to include:
- incident register excerpt
- PIR/postmortem docs
- exception register

## 7) Privacy Program Attachments (Operator Controls)

Required for HIPAA/GDPR/CCPA/CPRA audit readiness outside this repo:

- [ ] Data inventory / record of processing activities updated.
- [ ] Data retention/deletion schedule and evidence of execution.
- [ ] Data subject/consumer request handling metrics and samples.
- [ ] Vendor/processor agreements and transfer mechanisms updated.
- [ ] Training, access review, and risk-assessment/audit evidence attached.

## 8) Sign-Off

- Security sign-off: `<name/date>`
- Privacy/legal sign-off: `<name/date>`
- Engineering owner sign-off: `<name/date>`
- Residual risk accepted by: `<name/date>`

## 9) Evidence Index (Fill In)

| Item | Location | Immutable ID |
|---|---|---|
| CI conformance run | `<url/path>` | `<run-id>` |
| CLI test run | `<url/path>` | `<run-id>` |
| Security workflow | `<url/path>` | `<run-id>` |
| OCI artifact | `<registry ref>` | `<digest>` |
| Signature verification | `<url/path>` | `<log hash/id>` |
| SBOM | `<url/path>` | `<artifact digest>` |
| Vulnerability report | `<url/path>` | `<artifact digest>` |
| Policy version | `<repo path>` | `<commit/hash>` |
| Receipt sample set | `<url/path>` | `<artifact digest>` |
| Observability export | `<url/path>` | `<query/run id>` |
