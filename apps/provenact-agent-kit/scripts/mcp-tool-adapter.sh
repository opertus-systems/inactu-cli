#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_REQUEST="$ROOT_DIR/apps/provenact-agent-kit/examples/mcp-tools-call.json"

REQUEST_PATH="${1:-$DEFAULT_REQUEST}"
OUT_DIR="${2:-}"
RECEIPT_PATH="${3:-}"
if [[ -z "$OUT_DIR" || -z "$RECEIPT_PATH" ]]; then
  echo "usage: $0 [request.json] <out-dir> <receipt-path>" >&2
  exit 2
fi

METHOD="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("method", ""))' "$REQUEST_PATH")"
TOOL_NAME="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("params", {}).get("name", ""))' "$REQUEST_PATH")"
FIXTURE="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("params", {}).get("arguments", {}).get("fixture", ""))' "$REQUEST_PATH")"

if [[ "$METHOD" != "tools/call" ]]; then
  echo "unsupported method: $METHOD" >&2
  exit 1
fi
if [[ "$TOOL_NAME" != "provenact.execute_skill" ]]; then
  echo "unsupported tool: $TOOL_NAME" >&2
  exit 1
fi
if [[ "$FIXTURE" != "echo-v0" ]]; then
  echo "unsupported fixture: $FIXTURE" >&2
  exit 1
fi

"$ROOT_DIR/apps/provenact-agent-kit/scripts/run-direct.sh" "$OUT_DIR" "$RECEIPT_PATH"

echo "OK mcp-adapter-demo method=$METHOD tool=$TOOL_NAME receipt=$RECEIPT_PATH"
