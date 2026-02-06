# Spec

This directory contains normative v0 definitions for Inactu.

- `threat-model.md` - trust assumptions, goals, and non-goals
- `compatibility.md` - stable-vs-experimental compatibility contract
- `hashing.md` - canonical hashing and signature preimage rules
- `packaging.md` - deterministic skill bundle packaging rules
- `conformance.md` - mandatory v0 conformance checks and vectors
- `policy/` — policy schema and example
- `policy/policy.md` - normative policy evaluation semantics
- `policy/capability-evaluation.md` - capability request matching semantics
- `execution-receipt.schema.json` - execution receipt schema
- `registry/` — snapshot schema and rules
- `registry/snapshot.schema.json` - registry snapshot schema
- `skill-format/` — immutable skill artifact contract
- `skill-format.md` - normative rules that bind format, hashing, and signing behavior
- `skill-format/manifest.v1.experimental.schema.json` - draft v1 manifest schema (non-normative)
- `execution-receipt.v1.experimental.schema.json` - draft v1 receipt schema (non-normative)

Related tracking:
- `docs/conformance-matrix.md` - current enforcement coverage per normative source

Draft RFCs (non-normative):
- `rfcs/skill-manifest-v1.md` - draft manifest v1 direction
- `rfcs/execution-receipt-v1.md` - draft execution receipt v1 direction
