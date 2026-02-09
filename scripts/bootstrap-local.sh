#!/usr/bin/env bash
set -euo pipefail

need_cmd() {
  local name="$1"
  local install_hint="$2"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing: $name"
    echo "install: $install_hint"
    return 1
  fi
  return 0
}

echo "== provenact local bootstrap check =="

missing=0

if ! need_cmd rustup "https://rustup.rs"; then
  missing=1
fi
if ! need_cmd cargo "installed with rustup"; then
  missing=1
fi
if ! need_cmd shasum "macOS built-in (or use sha256sum on Linux)"; then
  missing=1
fi

if ! need_cmd cosign "https://docs.sigstore.dev/cosign/system_config/installation/"; then
  echo "note: required only for --require-cosign flows"
fi
if ! need_cmd oras "https://oras.land/docs/installation"; then
  echo "note: required for OCI push/attach flows"
fi
if ! need_cmd syft "https://github.com/anchore/syft#installation"; then
  echo "note: required for SBOM generation"
fi
if ! need_cmd trivy "https://trivy.dev/latest/getting-started/installation/"; then
  echo "note: required for vulnerability scanning"
fi

echo
echo "== versions =="
command -v rustup >/dev/null 2>&1 && rustup --version || true
command -v cargo >/dev/null 2>&1 && cargo --version || true
command -v cosign >/dev/null 2>&1 && cosign version || true
command -v oras >/dev/null 2>&1 && oras version || true
command -v syft >/dev/null 2>&1 && syft version || true
command -v trivy >/dev/null 2>&1 && trivy version || true

echo
echo "== local build smoke =="
cargo build -p provenact-cli

echo
if [[ "$missing" -ne 0 ]]; then
  echo "bootstrap incomplete: install required tools above"
  exit 1
fi

echo "bootstrap complete"
