#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec python3 - "$ROOT_DIR" "$@" <<'PY'
import json
import sys
from pathlib import Path


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


root = Path(sys.argv[1]).resolve()
argv = sys.argv[2:]
manifest_path = Path(argv[0]).resolve() if len(argv) > 0 else root / "sync-manifest.json"
compat_doc = Path(argv[1]).resolve() if len(argv) > 1 else root / "docs/conformance-matrix.md"
changelog_path = Path(argv[2]).resolve() if len(argv) > 2 else root / "CHANGELOG.md"

if not manifest_path.is_file():
    die(f"missing manifest: {manifest_path}")
if not compat_doc.is_file():
    die(f"missing compatibility doc: {compat_doc}")
if not changelog_path.is_file():
    die(f"missing changelog: {changelog_path}")

data = json.loads(manifest_path.read_text(encoding="utf-8"))
source_repo = data["source_repo"]["name"]
source_commit = data["source_repo"]["commit"]

compat_text = compat_doc.read_text(encoding="utf-8")
if source_commit not in compat_text:
    die(f"compatibility doc missing source commit {source_commit}")

changelog_text = changelog_path.read_text(encoding="utf-8")
if source_commit not in changelog_text:
    die(f"changelog missing source commit {source_commit}")

print(f"ok: release contract pin present ({source_repo}@{source_commit})")
PY
