# Compliance Controls Matrix

This document maps Inactu controls to common regulatory obligations and defines
which evidence artifacts to collect for audits.

It is written for implementation teams and auditors. It is **not legal advice**.
Use counsel to confirm applicability and final interpretations.

## Scope Boundary

Inactu is an execution substrate (artifact verification, capability enforcement,
receipt generation). It is not a full privacy program by itself.

This matrix therefore distinguishes:
- `Platform controls`: implemented in this repository.
- `Operator controls`: required in the environment running Inactu.

## Evidence-First Rule

For each control below, maintain auditable evidence in immutable storage:
- CI logs and workflow run IDs
- signed artifacts and attestation records
- policy files and change history
- execution receipts and telemetry events
- test evidence (`cargo conformance`, CLI gate tests)

## Control Catalog

| Control ID | Control | Inactu implementation | Evidence in repo/runtime |
|---|---|---|---|
| `IC-01` | Artifact integrity and signature verification before execution | `pack/sign/verify/run` flow validates digests and signatures; optional `--require-cosign --oci-ref` gate | `/Users/jove/code/inactu/cli/inactu-cli/src/main.rs`, `/Users/jove/code/inactu/cli/inactu-cli/tests/pack_sign.rs`, `/Users/jove/code/inactu/.github/workflows/release-skill.yml` |
| `IC-02` | Least-privilege execution (capability ceilings + trusted signers) | Policy parsing and enforcement before execution | `/Users/jove/code/inactu/spec/policy/policy.md`, `/Users/jove/code/inactu/cli/inactu-cli/src/main.rs`, `/Users/jove/code/inactu/cli/inactu-cli/tests/threat_model_gates.rs` |
| `IC-03` | Tamper-evident execution receipts and verification | Deterministic receipt hash + `verify-receipt`; structured observability events | `/Users/jove/code/inactu/spec/execution-receipt.schema.json`, `/Users/jove/code/inactu/cli/inactu-cli/tests/receipt.rs`, `/Users/jove/code/inactu/docs/observability.md` |
| `IC-04` | Secure software supply chain checks | Conformance + security checks, SBOM generation, vuln scan, signed publish workflow | `/Users/jove/code/inactu/.github/workflows/conformance.yml`, `/Users/jove/code/inactu/.github/workflows/security.yml`, `/Users/jove/code/inactu/.github/workflows/release-skill.yml` |
| `IC-05` | Security configuration documentation and change control | Versioned specs + threat model + control checklist | `/Users/jove/code/inactu/SPEC.md`, `/Users/jove/code/inactu/spec/threat-model.md`, `/Users/jove/code/inactu/docs/threat-model-controls.md` |
| `IC-06` | Incident evidence support and forensic traceability | Verifiable receipts, deterministic command outputs, policy and artifact identifiers | `/Users/jove/code/inactu/cli/inactu-cli/README.md`, runtime receipt files, CI logs |

## Mapping to HIPAA Security Rule (45 CFR Part 164 Subpart C)

| Inactu Control | HIPAA citation(s) | Why it helps |
|---|---|---|
| `IC-01` | `45 CFR 164.306(a)(1)-(2)`, `164.312(c)`, `164.312(e)` | Supports integrity and transmission/security controls by ensuring only verified artifacts run. |
| `IC-02` | `45 CFR 164.308(a)(4)`, `164.312(a)` | Supports information access management and access control through explicit capability policy. |
| `IC-03` | `45 CFR 164.312(b)`, `164.316(b)` | Supports audit controls and documentation retention with receipts and verifiable logs. |
| `IC-04` | `45 CFR 164.308(a)(1)(ii)(A-D)`, `164.308(a)(8)` | Supports risk analysis/management and evaluation through recurring CI and scanning evidence. |
| `IC-06` | `45 CFR 164.308(a)(6)` | Supports incident response evidence capture and post-incident reconstruction. |

HIPAA operator requirements outside this repo:
- Administrative safeguards program, workforce sanctions/training, contingency plans.
- Physical safeguards for facilities/workstations/media.
- BA agreements, breach notification workflow, and six-year documentation retention.

## Mapping to GDPR

| Inactu Control | GDPR article(s) | Why it helps |
|---|---|---|
| `IC-01` | Art. 5(1)(f), Art. 25, Art. 32 | Supports integrity/confidentiality and security-by-design for execution paths. |
| `IC-02` | Art. 25, Art. 32 | Supports data minimization/least privilege through explicit capability ceilings. |
| `IC-03` | Art. 5(2), Art. 30, Art. 33(5) | Supports accountability, records of processing context, and breach documentation evidence. |
| `IC-04` | Art. 24, Art. 25, Art. 32 | Supports controller governance and regular testing/evaluation of safeguards. |
| `IC-06` | Art. 33, Art. 34 | Supports rapid evidence collection needed for breach notification assessments. |

GDPR operator requirements outside this repo:
- Lawful basis, RoPA completeness, DPA/processor terms, transfer controls.
- Data subject rights workflow (access/erasure/correction/portability/objection).
- DPIA process where required; DPO governance where required.

## Mapping to California CCPA/CPRA

| Inactu Control | CCPA/CPRA citation(s) | Why it helps |
|---|---|---|
| `IC-01` | Civ. Code `1798.100(e)` | Supports “reasonable security procedures and practices.” |
| `IC-02` | Civ. Code `1798.100(c)` | Supports purpose limitation/proportional processing with explicit policy ceilings. |
| `IC-03` | Civ. Code `1798.100(d)(5)`, `1798.130` (operational evidence), `1798.150` (breach risk context) | Improves ability to detect, remediate, and evidence secure processing behavior. |
| `IC-04` | Civ. Code `1798.185` + CPPA regulations (effective Jan 1, 2026) | Supports demonstrable governance via auditable technical controls and testing evidence. |
| `IC-06` | Civ. Code `1798.105`, `1798.106`, `1798.130` (operator process) | Receipts/logs help validate request handling outcomes when integrated into DSR workflows. |

CCPA/CPRA operator requirements outside this repo:
- Consumer request handling (know/delete/correct/opt-out/limit sensitive PI).
- Notice at collection, retention disclosures, and contract terms with service providers/contractors.
- Annual cybersecurity audit/risk-assessment obligations where applicable under CPPA rules.

## Minimum Audit Evidence Package

For each release window, collect:
1. `cargo conformance` and `cargo test -p inactu-cli` run outputs.
2. OCI artifact digest, signature verification result, and attestation references.
3. SBOM (`syft`) and vulnerability scan outputs (`trivy`/equivalent).
4. Approved policy versions and signer trust set used in production.
5. Sample execution receipts and `verify-receipt` validation outputs.
6. Telemetry extracts for `inactu.verify`, `inactu.run`, and `inactu.verify_receipt`.

## Suggested Operating Cadence

- Per PR: conformance + security CI checks.
- Per release: signed OCI publish + SBOM + vulnerability gate + evidence bundle.
- Weekly: review failed verification/policy events.
- Quarterly: access/policy review and control effectiveness review.

## Sources

- HIPAA Security Rule overview (HHS):
  - https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html
- 45 CFR Part 164 Subpart C (eCFR):
  - https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C
- GDPR official text (EUR-Lex, Regulation (EU) 2016/679):
  - https://eur-lex.europa.eu/eli/reg/2016/679/oj
- California Privacy Protection Agency laws/regulations portal:
  - https://cppa.ca.gov/regulations/
- CCPA statute text (effective January 1, 2026 PDF, CPPA):
  - https://cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf
