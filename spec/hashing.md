# Hashing and Signature Rules (v0)

This document defines deterministic hash and signature preimages for Inactu v0.

## Common Rules

- Hash function: SHA-256
- Digest text format: `sha256:<64 lowercase hex chars>`
- Canonical JSON: RFC 8785 (JCS), UTF-8 encoded bytes
- Registry transport checksum format: `md5` field uses `<32 lowercase hex chars>`

## Artifact Hash

`artifact_hash = sha256(skill.wasm raw bytes)`

The resulting digest string must match:
- `manifest.artifact`
- `signatures.artifact`

## Manifest Hash

`manifest_hash = sha256(JCS(manifest_object))`

Where `manifest_object` is the parsed manifest document as represented by the
manifest schema.

The resulting digest string must match:
- `signatures.manifest_hash`

## Policy Hash

`policy_hash = sha256(JCS(policy_object))`

Where `policy_object` is the parsed policy document as represented by the
policy schema. Policy examples are not authoritative for field ordering.

## Registry Snapshot Hash

`snapshot_hash = sha256(JCS(snapshot_payload))`

`snapshot_payload` is:
```json
{
  "timestamp": <u64>,
  "entries": {
    "<name>": {
      "sha256": "sha256:...",
      "md5": "<32 lowercase hex chars>"
    }
  }
}
```

`snapshot_hash` must not be included in its own preimage.

`entries.<name>.md5` is for transport integrity checks and does not replace
artifact identity authority (`sha256`).

## Execution Receipt Hash

`receipt_hash = sha256(JCS(receipt_payload))`

`receipt_payload` is:
```json
{
  "artifact": "sha256:...",
  "inputs_hash": "sha256:...",
  "outputs_hash": "sha256:...",
  "caps_used": ["..."],
  "timestamp": <u64>
}
```

`receipt_hash` must not be included in its own preimage.

## Execution Receipt v1 Draft Hash

For `spec/execution-receipt.v1.experimental.schema.json`, `receipt_hash` is:

`receipt_hash = sha256(JCS(v1_receipt_payload_without_receipt_hash))`

The preimage includes all v1 receipt fields except `receipt_hash`, including:
- `bundle_hash`
- `runtime_version_digest`
- `result_digest`
- `timestamp_strategy`

## Bundle Hash (v1 Draft Component)

`bundle_hash = sha256(JCS(bundle_payload))`

`bundle_payload` is:
```json
{
  "artifact": "sha256:...",
  "manifest_hash": "sha256:...",
  "signatures_hash": "sha256:..."
}
```

Where:
- `artifact` is `manifest.artifact`
- `manifest_hash` is canonical manifest hash
- `signatures_hash` is `sha256(JCS(signatures_object))`

## Signature Payload

For v0, each Ed25519 signature is computed over the UTF-8 bytes of the
`signatures.manifest_hash` string value exactly (for example `sha256:...`).

Signature encoding in JSON uses RFC 4648 base64 text.
