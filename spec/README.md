# Spec

This directory contains normative v0 definitions for Provenact plus legacy
reference material.

- `v0.md` - legacy composable-skills draft (non-normative reference)
- `v0/` - legacy composable skill/pipeline schemas (non-normative reference)
- `threat-model.md` - trust assumptions, goals, and non-goals
- `compatibility.md` - stable-vs-experimental compatibility contract
- `hashing.md` - canonical hashing and signature preimage rules
- `packaging.md` - deterministic skill bundle packaging rules
- `install.md` - content-addressed install flow and local store/index contract
- `install/` - install metadata schemas
- `install/README.md` - schema-to-runtime writer mapping for install metadata
- `install/index.schema.json` - local install index schema
- `install/meta.schema.json` - installed skill metadata schema
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
