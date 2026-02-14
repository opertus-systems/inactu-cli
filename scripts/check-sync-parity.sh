#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec python3 - "$ROOT_DIR" "$@" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dir_manifest_sha256(path: Path) -> str:
    lines = []
    rel_paths = sorted(
        p.relative_to(path).as_posix() for p in path.rglob("*") if p.is_file()
    )
    for rel in rel_paths:
        lines.append(f"{file_sha256(path / rel)}  {rel}")
    blob = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def git_head(path: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


root = Path(sys.argv[1]).resolve()
argv = sys.argv[2:]
manifest_path = Path(argv[0]).resolve() if len(argv) > 0 else root / "sync-manifest.json"
source_repo = Path(argv[1]).resolve() if len(argv) > 1 else None

if not manifest_path.is_file():
    die(f"missing manifest: {manifest_path}")

data = json.loads(manifest_path.read_text(encoding="utf-8"))
if data.get("mode") != "spec-cli":
    die("manifest mode must be spec-cli")

source_commit = data["source_repo"]["commit"]
if source_repo is not None:
    if not (source_repo / ".git").exists():
        die(f"source repo must be a git checkout: {source_repo}")
    head = git_head(source_repo)
    if head != source_commit:
        die(f"source repo commit mismatch: expected {source_commit}, got {head}")

artifacts = data.get("artifacts", [])
if not artifacts:
    die("manifest has no artifacts")

for artifact in artifacts:
    name = artifact["name"]
    source_path = artifact["source_path"]
    target_path = artifact["target_path"]
    expected_count = int(artifact["target_file_count"])
    expected_digest = artifact["target_manifest_sha256"]

    target_dir = root / target_path
    if not target_dir.is_dir():
        die(f"missing target path for {name}: {target_dir}")

    actual_count = sum(1 for p in target_dir.rglob("*") if p.is_file())
    if actual_count != expected_count:
        die(f"{name} file count mismatch: expected {expected_count}, got {actual_count}")

    actual_digest = dir_manifest_sha256(target_dir)
    if actual_digest != expected_digest:
        die(f"{name} digest mismatch: expected {expected_digest}, got {actual_digest}")

    if source_repo is not None:
        source_dir = source_repo / source_path
        if not source_dir.is_dir():
            die(f"missing source path for {name}: {source_dir}")
        source_digest = dir_manifest_sha256(source_dir)
        if source_digest != actual_digest:
            die(f"{name} source/target mismatch: source={source_digest} target={actual_digest}")

    print(f"ok: {name} parity")

print("ok: sync parity")
PY
