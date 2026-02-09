# Registry Snapshots (v0)

Resolution is snapshot-based.

Rules:
- No live lookups during resolution.
- Snapshot refresh is an external concern and out of scope for Provenact v0.
- `snapshot_hash` must be computed from a payload that excludes `snapshot_hash`
  itself; see `spec/hashing.md`.
- Each `entries.<name>` record MUST include:
  - `sha256`: artifact identity digest (`sha256:<64 lowercase hex chars>`)
  - `md5`: transport checksum (`<32 lowercase hex chars>`)
- Implementations resolving artifacts from registry metadata MUST fail closed if:
  - `md5` is missing or invalid
  - downloaded artifact bytes do not match `md5`
  - downloaded artifact bytes do not match `sha256`
- `md5` is transport integrity only; artifact authority remains `sha256`.

Snapshot schema: `snapshot.schema.json`.
Example snapshot: `snapshot.example.json`.
