#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/apps/provenact-agent-kit/fixtures/echo-v0"
CLI=(cargo run -q -p provenact-cli --bin provenact --)

OUT_DIR="${1:-}"
RECEIPT_PATH="${2:-}"
if [[ -z "$OUT_DIR" || -z "$RECEIPT_PATH" ]]; then
  echo "usage: $0 <out-dir> <receipt-path>" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
BUNDLE_DIR="$OUT_DIR/bundle"

"${CLI[@]}" pack \
  --bundle "$BUNDLE_DIR" \
  --wasm "$FIXTURE_DIR/skill.wasm" \
  --manifest "$FIXTURE_DIR/manifest.json"

"${CLI[@]}" sign \
  --bundle "$BUNDLE_DIR" \
  --signer alice.dev \
  --secret-key "$FIXTURE_DIR/signer-secret-key.txt"

KEYS_DIGEST="$(shasum -a 256 "$FIXTURE_DIR/public-keys.json" | awk '{print "sha256:"$1}')"

"${CLI[@]}" verify \
  --bundle "$BUNDLE_DIR" \
  --keys "$FIXTURE_DIR/public-keys.json" \
  --keys-digest "$KEYS_DIGEST"

"${CLI[@]}" run \
  --bundle "$BUNDLE_DIR" \
  --keys "$FIXTURE_DIR/public-keys.json" \
  --keys-digest "$KEYS_DIGEST" \
  --policy "$FIXTURE_DIR/policy.json" \
  --input "$FIXTURE_DIR/input.json" \
  --receipt "$RECEIPT_PATH"

"${CLI[@]}" verify-receipt --receipt "$RECEIPT_PATH"

echo "OK direct-demo receipt=$RECEIPT_PATH"
