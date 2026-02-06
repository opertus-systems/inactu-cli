# Install Schema Mapping (v0)

This document maps `spec/install/*.schema.json` fields to current CLI write
behavior and test coverage.

## Writer Authority

Install metadata is written by `inactu-cli` install flow in:

- `cli/inactu-cli/src/install.rs`

Canonical archive bytes are written by:

- `cli/inactu-cli/src/archive.rs`

Primary write points:

- `persist_to_store(...)` writes `meta.json` in content store
- `update_index(...)` writes/updates `index.json` in local install home

## `meta.schema.json` Field Mapping

Schema source:
- `spec/install/meta.schema.json`

Field mapping:

- `schema_version`
  - writer: fixed to `"1.0.0"` in `persist_to_store(...)`
- `skill`
  - writer: archive digest (`sha256:<hash>`) computed from raw `skill.tar.zst`
- `source`
  - writer: exact install source string passed to `inactu-cli install --artifact`
- `manifest_name`
  - writer: parsed from `manifest.json` (`manifest.name`)
- `manifest_version`
  - writer: parsed from `manifest.json` (`manifest.version`)
- `installed_at`
  - writer: unix epoch seconds from local system clock at install time

## `index.schema.json` Field Mapping

Schema source:
- `spec/install/index.schema.json`

Top-level mapping:

- `schema_version`
  - writer: fixed to `"1.0.0"`
- `entries`
  - writer: append/update by skill digest; sorted lexicographically by `skill`

Per-entry mapping:

- `skill`
  - writer: archive digest (`sha256:<hash>`) of installed artifact
- `source`
  - writer: install source string
- `store`
  - writer: resolved local store path (`.../store/sha256/<hash>`)
- `installed_at`
  - writer: unix epoch seconds for install/update time
- `manifest_name`
  - writer: `manifest.name`
- `manifest_version`
  - writer: `manifest.version`

## Behavioral Notes

- Installing the same digest updates existing `index.entries[*]` for that digest
  (source/store/timestamp/name/version) rather than duplicating entries.
- `meta.json` is always rewritten for the installed digest path.
- Optional artifact files (`signatures.json`, `sbom.spdx.json`,
  `sigstore.bundle.json`) are copied into store only when present.

## Coverage Linkage

Install behavior and schema-shape assertions are covered by:

- `cli/inactu-cli/tests/install.rs`

Key tests:

- `archive_is_deterministic_and_canonical`
  - asserts byte-stable archive output and canonical tar ordering/metadata
- `install_persists_store_and_index`
  - asserts `meta.json` and `index.json` required fields and value wiring
- `install_accepts_file_url_source`
  - source handling for `file://...`
- `install_accepts_http_source`
  - source handling for `http://...`
- `install_rejects_missing_manifest_in_archive`
  - required package entry enforcement
- `install_rejects_oci_refs_in_v0`
  - reserved registry hook syntax fails closed in v0
