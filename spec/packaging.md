# Skill Packaging Specification (v0)

This document defines deterministic skill bundle packaging for Provenact v0.

## Logical Bundle

The canonical v0 bundle is a directory with this exact top-level layout:

```
<skill>.pkg/
  skill.wasm
  manifest.json
  provenance.json
  signatures.json
  log-proof.json   # optional in v0
```

Required files:
- `skill.wasm`
- `manifest.json`
- `provenance.json`
- `signatures.json`

Optional files:
- `log-proof.json`

No additional top-level files are allowed in v0.

## File Encoding Rules

- `skill.wasm` MUST be raw WASM bytes.
- `*.json` files MUST be UTF-8 encoded.
- JSON files MUST validate against their corresponding schemas when a schema
  exists.

## Consistency Rules

- `manifest.artifact` MUST equal `sha256(skill.wasm bytes)`.
- `signatures.artifact` MUST equal `manifest.artifact`.
- `signatures.manifest_hash` MUST equal `sha256(JCS(manifest.json))`.
- Signature verification rules are defined in `spec/hashing.md` and
  `spec/skill-format.md`.

## Transport Packaging (Optional)

For transport, a bundle MAY be wrapped as a tar archive. When used, the tar
stream MUST be deterministic:

- USTAR format.
- Lexicographic file order by path.
- Fixed metadata for all entries:
  - uid = 0
  - gid = 0
  - uname = ""
  - gname = ""
  - mtime = 0
- File mode:
  - `0644` for JSON files
  - `0755` for `skill.wasm`

Runtimes MUST verify logical bundle contents after extraction and MUST NOT rely
on archive metadata for trust decisions.
