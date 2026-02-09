#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/apps/provenact-agent-kit/fixtures/echo-v0"
CLI=(cargo run -q -p provenact-cli --)

WORK_DIR="${1:-$(mktemp -d)}"
mkdir -p "$WORK_DIR"

MANUAL_DIR="$WORK_DIR/manual-agent"
DIRECT_DIR="$WORK_DIR/direct"
MCP_DIR="$WORK_DIR/mcp"
DENY_DIR="$WORK_DIR/capability-deny"

MANUAL_RECEIPT="$MANUAL_DIR/receipt.json"
DIRECT_RECEIPT="$DIRECT_DIR/receipt.json"
MCP_RECEIPT="$MCP_DIR/receipt.json"

"$ROOT_DIR/apps/provenact-agent-kit/scripts/manual-agent.sh" \
  "$ROOT_DIR/apps/provenact-agent-kit/examples/manual-agent-request.json" \
  "$MANUAL_DIR" \
  "$MANUAL_RECEIPT"

"$ROOT_DIR/apps/provenact-agent-kit/scripts/run-direct.sh" \
  "$DIRECT_DIR" \
  "$DIRECT_RECEIPT"

"$ROOT_DIR/apps/provenact-agent-kit/scripts/mcp-tool-adapter.sh" \
  "$ROOT_DIR/apps/provenact-agent-kit/examples/mcp-tools-call.json" \
  "$MCP_DIR" \
  "$MCP_RECEIPT"

python3 - "$DIRECT_RECEIPT" "$MCP_RECEIPT" <<'PY'
import json
import sys

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

a = load(sys.argv[1])
b = load(sys.argv[2])
keys = ["artifact", "inputs_hash", "outputs_hash", "caps_used"]
for k in keys:
    if a.get(k) != b.get(k):
        raise SystemExit(f"receipt mismatch for {k}: {a.get(k)!r} != {b.get(k)!r}")
print("OK mcp-optional-proof receipt semantics match for artifact/inputs_hash/outputs_hash/caps_used")
PY

mkdir -p "$DENY_DIR"
cat > "$DENY_DIR/manifest-deny.json" <<'JSON'
{
  "name": "echo.e2e",
  "version": "0.1.0",
  "entrypoint": "run",
  "artifact": "sha256:c9e2d2c87ed55e68710f8ba626e6787518a9d544e6502c24d6a319631e15590a",
  "capabilities": [
    {
      "kind": "net",
      "value": "https://example.com/api"
    }
  ],
  "signers": ["alice.dev"]
}
JSON

cat > "$DENY_DIR/policy-deny.yaml" <<'YAML'
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  net: ["https://api.open-meteo.com"]
  exec: false
  time: false
YAML

"${CLI[@]}" pack \
  --bundle "$DENY_DIR/bundle" \
  --wasm "$FIXTURE_DIR/skill.wasm" \
  --manifest "$DENY_DIR/manifest-deny.json"

"${CLI[@]}" sign \
  --bundle "$DENY_DIR/bundle" \
  --signer alice.dev \
  --secret-key "$FIXTURE_DIR/signer-secret-key.txt"

KEYS_DIGEST="$(shasum -a 256 "$FIXTURE_DIR/public-keys.json" | awk '{print "sha256:"$1}')"

set +e
"${CLI[@]}" run \
  --bundle "$DENY_DIR/bundle" \
  --keys "$FIXTURE_DIR/public-keys.json" \
  --keys-digest "$KEYS_DIGEST" \
  --policy "$DENY_DIR/policy-deny.yaml" \
  --input "$FIXTURE_DIR/input.json" \
  --receipt "$DENY_DIR/receipt-deny.json"
STATUS=$?
set -e

if [[ "$STATUS" -eq 0 ]]; then
  echo "expected capability deny but run succeeded" >&2
  exit 1
fi
if [[ -f "$DENY_DIR/receipt-deny.json" ]]; then
  echo "receipt should not exist for denied execution" >&2
  exit 1
fi

echo "OK capability-enforcement-proof denied out-of-policy run"
echo "OK demo-v0-complete work_dir=$WORK_DIR"
