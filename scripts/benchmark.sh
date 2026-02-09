#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_BIN="${PROVENACT_CLI_BIN:-$ROOT_DIR/target/debug/provenact-cli}"
ITERATIONS="${ITERATIONS:-15}"
OUT_FILE="${OUT_FILE:-$ROOT_DIR/bench/latest.json}"

if [[ "$ITERATIONS" -lt 1 ]]; then
  echo "error: ITERATIONS must be >= 1" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ ! -x "$CLI_BIN" ]]; then
  cargo build -p provenact-cli --manifest-path "$ROOT_DIR/Cargo.toml" >/dev/null
fi

BUNDLE="$TMP_DIR/bench.bundle"
KEYS="$BUNDLE/public-keys.json"
INPUT="$TMP_DIR/input.json"
POLICY="$TMP_DIR/policy.json"
RECEIPT="$TMP_DIR/receipt.json"
SECRET_KEY="$ROOT_DIR/test-vectors/good/verify-run-verify-receipt/signer-secret-key.txt"
mkdir -p "$BUNDLE"

printf '%s' '0061736d010000000105016000017f030201000707010372756e00000a0601040041000b' | xxd -r -p > "$BUNDLE/skill.wasm"
ARTIFACT="sha256:$(shasum -a 256 "$BUNDLE/skill.wasm" | awk '{print $1}')"
cat > "$BUNDLE/manifest.json" <<JSON
{
  "name": "bench.echo",
  "version": "0.1.0",
  "entrypoint": "run",
  "artifact": "$ARTIFACT",
  "capabilities": [],
  "signers": ["alice.dev"]
}
JSON
cp "$ROOT_DIR/test-vectors/good/minimal-zero-cap/public-keys.json" "$KEYS"
"$CLI_BIN" pack --bundle "$BUNDLE" --wasm "$BUNDLE/skill.wasm" --manifest "$BUNDLE/manifest.json" >/dev/null
"$CLI_BIN" sign --bundle "$BUNDLE" --signer alice.dev --secret-key "$SECRET_KEY" >/dev/null
KEYS_DIGEST="sha256:$(shasum -a 256 "$KEYS" | awk '{print $1}')"

echo '{}' > "$INPUT"
cp "$ROOT_DIR/test-vectors/good/verify-run-verify-receipt/policy.json" "$POLICY"

VERIFY_TIMES="$TMP_DIR/verify_ms.txt"
RUN_TIMES="$TMP_DIR/run_ms.txt"

for _ in $(seq 1 "$ITERATIONS"); do
  start="$(python3 -c 'import time; print(int(time.time()*1000))')"
  "$CLI_BIN" verify --bundle "$BUNDLE" --keys "$KEYS" --keys-digest "$KEYS_DIGEST" >/dev/null
  end="$(python3 -c 'import time; print(int(time.time()*1000))')"
  echo $((end-start)) >> "$VERIFY_TIMES"

done

for _ in $(seq 1 "$ITERATIONS"); do
  start="$(python3 -c 'import time; print(int(time.time()*1000))')"
  "$CLI_BIN" run --bundle "$BUNDLE" --keys "$KEYS" --keys-digest "$KEYS_DIGEST" --policy "$POLICY" --input "$INPUT" --receipt "$RECEIPT" >/dev/null
  end="$(python3 -c 'import time; print(int(time.time()*1000))')"
  echo $((end-start)) >> "$RUN_TIMES"
done

python3 - "$ITERATIONS" "$VERIFY_TIMES" "$RUN_TIMES" "$OUT_FILE" <<'PY'
import json, statistics, sys
iters = int(sys.argv[1])
verify_path, run_path, out = sys.argv[2], sys.argv[3], sys.argv[4]

def load(path):
    vals = [int(l.strip()) for l in open(path) if l.strip()]
    vals.sort()
    return vals

def p95(vals):
    if not vals:
        return 0
    idx = max(0, min(len(vals)-1, int((len(vals)-1)*0.95)))
    return vals[idx]

verify = load(verify_path)
run = load(run_path)
report = {
    "schema_version": "1.0.0",
    "iterations": iters,
    "verify_ms": {
        "p50": int(statistics.median(verify)) if verify else 0,
        "p95": int(p95(verify)),
        "min": min(verify) if verify else 0,
        "max": max(verify) if verify else 0,
    },
    "run_ms": {
        "p50": int(statistics.median(run)) if run else 0,
        "p95": int(p95(run)),
        "min": min(run) if run else 0,
        "max": max(run) if run else 0,
    },
}
with open(out, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")
print(json.dumps(report))
PY

echo "OK benchmark report=$OUT_FILE iterations=$ITERATIONS"
