#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_REQUEST="$ROOT_DIR/apps/provenact-agent-kit/examples/manual-agent-request.json"

REQUEST_PATH="${1:-$DEFAULT_REQUEST}"
OUT_DIR="${2:-}"
RECEIPT_PATH="${3:-}"
if [[ -z "$OUT_DIR" || -z "$RECEIPT_PATH" ]]; then
  echo "usage: $0 [request.json] <out-dir> <receipt-path>" >&2
  exit 2
fi

FRAMEWORK="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("framework", ""))' "$REQUEST_PATH")"
TOOL_NAME="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("tool", ""))' "$REQUEST_PATH")"
FIXTURE="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("arguments", {}).get("fixture", ""))' "$REQUEST_PATH")"

if [[ "$FRAMEWORK" != "manual-tool-caller" ]]; then
  echo "unsupported framework: $FRAMEWORK" >&2
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

echo "OK manual-agent-demo framework=$FRAMEWORK tool=$TOOL_NAME receipt=$RECEIPT_PATH"
