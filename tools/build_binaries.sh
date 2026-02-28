#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${1:-dist}"
GOOS_VALUE="${GOOS:-$(go env GOOS)}"
GOARCH_VALUE="${GOARCH:-$(go env GOARCH)}"

BINARIES=(
  "client:./cmd/client"
  "server:./cmd/server"
  "manager:./cmd/manager"
  "bench:./cmd/bench"
  "http_bench:./cmd/http_bench"
  "fetch_page:./cmd/fetch_page"
)

mkdir -p "$OUT_DIR"

ext=""
if [[ "$GOOS_VALUE" == "windows" ]]; then
  ext=".exe"
fi

echo "[build] target ${GOOS_VALUE}/${GOARCH_VALUE}"
for entry in "${BINARIES[@]}"; do
  name="${entry%%:*}"
  pkg="${entry#*:}"
  out="${OUT_DIR}/${name}-${GOOS_VALUE}-${GOARCH_VALUE}${ext}"
  echo "[build] ${pkg} -> ${out}"
  GOOS="$GOOS_VALUE" GOARCH="$GOARCH_VALUE" go build -trimpath -o "$out" "$pkg"
done

echo "[build] done"
