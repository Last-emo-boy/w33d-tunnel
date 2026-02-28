#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[core-test] running stable core package tests"
go test -count=1 ./pkg/kernel ./pkg/transport ./pkg/protocol ./pkg/client ./cmd/server ./cmd/manager
