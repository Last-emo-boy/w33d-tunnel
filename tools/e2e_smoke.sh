#!/usr/bin/env bash
set -euo pipefail

TOKEN="${TOKEN:-admin-token-123}"
MANAGER="${MANAGER:-http://127.0.0.1:2933}"
SOCKS="${SOCKS:-127.0.0.1:1080}"
SUBSCRIBE_URL="${MANAGER}/api/subscribe?token=${TOKEN}"

echo "[1/4] Checking manager subscription endpoint..."
nodes_count="$(curl -fsS --max-time 10 "$SUBSCRIBE_URL" | grep -o '"addr"' | wc -l | tr -d ' ')"
if [[ "$nodes_count" -lt 1 ]]; then
  echo "No nodes found in subscription response"
  exit 1
fi
echo "      OK: nodes=${nodes_count}"

echo "[2/4] Checking server admin ping endpoint..."
curl -fsS --max-time 10 "http://127.0.0.1:8090/ping" >/dev/null
echo "      OK: /ping=200"

echo "[3/4] Starting local client..."
client_pid=""
cleanup() {
  if [[ -n "${client_pid}" ]]; then
    kill "${client_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -x "./client" ]]; then
  ./client -subscribe "$SUBSCRIBE_URL" -socks "$SOCKS" >/tmp/w33d-client-smoke.log 2>&1 &
else
  go run ./cmd/client -- -subscribe "$SUBSCRIBE_URL" -socks "$SOCKS" >/tmp/w33d-client-smoke.log 2>&1 &
fi
client_pid="$!"

sleep 5

echo "[4/4] Validating SOCKS reachability..."
curl --socks5-hostname "$SOCKS" --max-time 15 --silent --show-error --fail "http://example.com" >/dev/null
echo "      OK: SOCKS tunnel fetch succeeded"

echo "Smoke test passed."
