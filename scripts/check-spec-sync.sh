#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_REPO="${1:-}"
SYNC_SOURCE_FILE="$ROOT_DIR/spec/.sync-source.json"

die() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_cmd diff
require_cmd find
require_cmd git
require_cmd sed

[[ -f "$SYNC_SOURCE_FILE" ]] || die "missing sync source file: $SYNC_SOURCE_FILE"

EXPECTED_COMMIT="$(sed -n 's/^[[:space:]]*"commit"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SYNC_SOURCE_FILE")"
[[ -n "$EXPECTED_COMMIT" ]] || die "unable to parse commit from $SYNC_SOURCE_FILE"

if [[ -z "$SOURCE_REPO" ]]; then
  SOURCE_REPO="$ROOT_DIR/../provenact-spec"
fi

[[ -d "$SOURCE_REPO/.git" ]] || die "source repo must be a git checkout: $SOURCE_REPO"

SOURCE_HEAD="$(git -C "$SOURCE_REPO" rev-parse HEAD)"
if [[ "$SOURCE_HEAD" != "$EXPECTED_COMMIT" ]]; then
  die "source repo HEAD ($SOURCE_HEAD) does not match pinned commit ($EXPECTED_COMMIT)"
fi

SRC_SPEC="$SOURCE_REPO/spec"
SRC_VECTORS="$SOURCE_REPO/test-vectors"
DST_SPEC="$ROOT_DIR/spec"
DST_VECTORS="$ROOT_DIR/test-vectors"

[[ -d "$SRC_SPEC" ]] || die "missing source spec dir: $SRC_SPEC"
[[ -d "$SRC_VECTORS" ]] || die "missing source test-vectors dir: $SRC_VECTORS"
[[ -d "$DST_SPEC" ]] || die "missing target spec dir: $DST_SPEC"
[[ -d "$DST_VECTORS" ]] || die "missing target test-vectors dir: $DST_VECTORS"

echo "checking spec parity..."
diff -qr -x ".sync-source.json" "$SRC_SPEC" "$DST_SPEC"

echo "checking test-vectors parity..."
diff -qr "$SRC_VECTORS" "$DST_VECTORS"

SRC_SPEC_FILES="$(find "$SRC_SPEC" -type f | wc -l | tr -d ' ')"
DST_SPEC_FILES="$(find "$DST_SPEC" -type f | wc -l | tr -d ' ')"
SRC_VECTOR_FILES="$(find "$SRC_VECTORS" -type f | wc -l | tr -d ' ')"
DST_VECTOR_FILES="$(find "$DST_VECTORS" -type f | wc -l | tr -d ' ')"

echo "ok: spec parity (commit=$EXPECTED_COMMIT)"
echo "spec files: source=$SRC_SPEC_FILES mirror=$DST_SPEC_FILES"
echo "test-vectors files: source=$SRC_VECTOR_FILES mirror=$DST_VECTOR_FILES"
