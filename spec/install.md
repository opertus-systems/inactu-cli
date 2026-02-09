# Install and Local Store Specification (v0)

This document defines normative install semantics for content-addressed skill
packages in Provenact v0.

## 1. Canonical Install Artifact

The canonical install artifact is a zstd-compressed tar archive:

`skill.tar.zst`

Archive path rules:
- top-level files only (no nested directories)
- normalized relative paths only (no absolute paths, no `..`)
- no unknown top-level entries

Required entries:
- `manifest.json`
- `skill.wasm`

Optional entries:
- `signatures.json`
- `sbom.spdx.json`
- `sigstore.bundle.json`

Deterministic archive layout (canonical writer profile):
- entry order: `manifest.json`, `skill.wasm`, `sbom.spdx.json`,
  `sigstore.bundle.json`, `signatures.json`
- optional entries are included only when present
- tar header profile: USTAR with `uid=0`, `gid=0`, `uname=""`, `gname=""`,
  `mtime=0`
- file mode profile: `0644` for JSON entries, `0755` for `skill.wasm`

## 2. Skill Identity

Skill identity of record is the SHA-256 digest of raw archive bytes:

- digest format: `sha256:<64 lowercase hex>`
- this digest is the installed skill reference used by local index and pipeline
  references

## 3. v0 Install Flow

Implementations MUST enforce the following sequence:

1. Load artifact bytes from source (`path`, `file://`, or `http(s)://`).
2. Hash archive bytes to compute skill identity.
3. Verify signatures according to install mode:
   - dev mode: signature verification MAY be omitted.
   - prod mode: signature verification MUST be required.
4. Validate manifest and install limits:
   - parse `manifest.json`
   - verify `manifest.artifact == sha256(skill.wasm bytes)`
   - enforce size bounds for untrusted artifact/metadata files
   - apply policy-gated capability ceiling checks when policy is provided
5. Persist to local content store.
6. Register metadata in local index.

## 4. Local Content Store Contract

Implementations MUST persist installed content at:

`~/.provenact/store/sha256/<hash>/`

Equivalent custom home paths (for tests or operators) MUST preserve
`store/sha256/<hash>` structure beneath configured home.

Store content MUST include:
- `manifest.json`
- `skill.wasm`
- `meta.json` (schema: `spec/install/meta.schema.json`)

If present in the artifact, implementations MUST persist:
- `signatures.json`
- `sbom.spdx.json`
- `sigstore.bundle.json`

## 5. Local Index Contract

Implementations MUST maintain local install index metadata at:

`~/.provenact/index.json`

Index format MUST validate against `spec/install/index.schema.json`.

At minimum each entry MUST bind:
- installed skill digest (`sha256:<hash>`)
- source reference used for installation
- local store path
- install timestamp
- manifest name/version

## 6. Reference Forms

Exact-hash references are first-class in v0:
- `sha256:<hash>`

Optional source metadata MAY be carried alongside hash references, for example:

```json
{
  "skill": {
    "hash": "sha256:<hash>",
    "source": "file:///path/to/skill.tar.zst"
  }
}
```

## 7. Registry Hooks and Non-Goals

v0 parsers MAY accept future registry-style references such as:

`oci://registry.example.com/org/skill@sha256:<hash>`

But v0 MUST NOT require hosted registry behavior for conformance:
- no centralized publishing flow
- no namespace or version resolution
- no discovery/marketplace behavior
