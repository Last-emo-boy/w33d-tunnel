#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mode="${1:-write}"

mapfile -t go_files < <(git ls-files '*.go')

if [[ "${#go_files[@]}" -eq 0 ]]; then
  echo "[fmt] no go files found"
  exit 0
fi

if [[ "$mode" == "--check" ]]; then
  echo "[fmt] checking gofmt"
  out="$(gofmt -l "${go_files[@]}")"
  if [[ -n "$out" ]]; then
    echo "[fmt] files need formatting:"
    echo "$out"
    exit 1
  fi
  echo "[fmt] ok"
  exit 0
fi

echo "[fmt] formatting go files"
gofmt -w "${go_files[@]}"
echo "[fmt] done"
