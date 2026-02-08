# Getting Started (Secure v0.1 Flow)

This guide shows the recommended signed execution flow for Provenact v0.

Prereqs:
- Rust toolchain installed
- Build the CLI once: `cargo build -p provenact-cli`
- Optional (for cosign-gated verify/run): `cosign` installed locally

Recommended local bootstrap:

```bash
./scripts/bootstrap-local.sh
```

## 1) Prepare Files

You need:
- `skill.wasm`
- `manifest.json`
- `public-keys.json`
- signer secret key file (`base64` Ed25519 32-byte seed)
- `policy.json` (or YAML)
- `input.json`

## 2) Pack Bundle

```bash
cargo run -p provenact-cli -- pack \
  --bundle ./bundle \
  --wasm ./skill.wasm \
  --manifest ./manifest.json
```

## 3) Sign Bundle

```bash
cargo run -p provenact-cli -- sign \
  --bundle ./bundle \
  --signer alice.dev \
  --secret-key ./alice.key
```

## 4) Pin Trust Anchor Digest

```bash
KEYS_DIGEST="$(shasum -a 256 ./public-keys.json | awk '{print "sha256:"$1}')"
```

## 5) Verify Bundle

```bash
cargo run -p provenact-cli -- verify \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST"
```

Optional cosign-gated verify:

```bash
cargo run -p provenact-cli -- verify \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --require-cosign \
  --oci-ref ghcr.io/<org>/<skill>:<tag>
```

## 6) Run with Policy

```bash
cargo run -p provenact-cli -- run \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --policy ./policy.json \
  --input ./input.json \
  --receipt ./receipt.json
```

Optional cosign-gated run:

```bash
cargo run -p provenact-cli -- run \
  --bundle ./bundle \
  --keys ./public-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --policy ./policy.json \
  --input ./input.json \
  --receipt ./receipt.json \
  --require-cosign \
  --oci-ref ghcr.io/<org>/<skill>:<tag>
```

## 7) Verify Receipt

```bash
cargo run -p provenact-cli -- verify-receipt --receipt ./receipt.json
```

## Notes

- `verify` and `run` reject unsigned bundles.
- Runtime execution is fuel-metered and resource-limited.
- File sizes are bounded for untrusted inputs.
- `--keys-digest` is required for `verify` and `run`; mismatches deny execution.
- `pack` writes `bundle-meta.json` for deterministic bundle metadata linkage.
- Key rotation/revocation operations are in `docs/key-management.md`.

## Useful Local Shortcuts

From repo root:

```bash
make bootstrap
make flow
make flow-cosign OCI_REF=ghcr.io/<org>/<skill>:<tag>
```
