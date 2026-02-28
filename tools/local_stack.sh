#!/usr/bin/env bash
set -euo pipefail

action="${1:-up}"

case "$action" in
  up)
    docker compose up -d --build
    echo ""
    echo "Local stack started:"
    echo "  Manager: http://127.0.0.1:2933"
    echo "  Web:     http://127.0.0.1:7729"
    echo "  Server:  udp://127.0.0.1:8080"
    echo "  Admin:   http://127.0.0.1:8090 (ping/metrics)"
    echo ""
    echo "Quick checks:"
    if curl -fsS --max-time 5 http://127.0.0.1:8090/ping >/dev/null; then
      echo "  /ping:      ok"
    else
      echo "  /ping:      failed"
    fi
    if curl -fsS --max-time 5 http://127.0.0.1:2933/api/nodes >/dev/null; then
      echo "  /api/nodes: ok"
    else
      echo "  /api/nodes: failed"
    fi
    ;;
  down)
    docker compose down
    ;;
  logs)
    docker compose logs -f --tail 100
    ;;
  status)
    docker compose ps
    ;;
  *)
    echo "Usage: $0 {up|down|logs|status}"
    exit 1
    ;;
esac
