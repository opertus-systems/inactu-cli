# Execution Transcript (v0)

Each successful skill execution MUST emit:

{
  "artifact": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "inputs_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "outputs_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "caps_used": ["net:https://api.open-meteo.com"],
  "timestamp": 1738600999,
  "receipt_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}

Rules:
- All hashes are SHA-256.
- Canonical JSON serialization follows RFC 8785 (JCS).
- `receipt_hash` preimage MUST include `timestamp` as specified in `spec/hashing.md`.
- Receipt schema: `spec/execution-receipt.schema.json`.
- Exact `receipt_hash` preimage is defined in `spec/hashing.md`.
- `receipt_hash` MUST be computed over the payload that excludes `receipt_hash`.
- `timestamp` is host-observed UNIX seconds; it is not external time attestation.
- Successful runs must emit a receipt artifact; failed runs must not emit a
  success receipt.
- `outputs_hash` is computed from execution output bytes:
  - for `() -> i32` entrypoints, output bytes are decimal UTF-8 of the return value
  - for `() -> ()` entrypoints, output bytes are empty
- On verification/policy/execution failure, no success transcript is emitted.
