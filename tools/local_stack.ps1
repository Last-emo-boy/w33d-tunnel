param(
    [ValidateSet("up", "down", "logs", "status")]
    [string]$Action = "up"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

switch ($Action) {
    "up" {
        docker compose up -d --build
        Write-Host ""
        Write-Host "Local stack started:"
        Write-Host "  Manager: http://127.0.0.1:2933"
        Write-Host "  Web:     http://127.0.0.1:7729"
        Write-Host "  Server:  udp://127.0.0.1:8080"
        Write-Host "  Admin:   http://127.0.0.1:8090 (ping/metrics)"
        Write-Host ""
        Write-Host "Quick checks:"
        try {
            $ping = Invoke-WebRequest -Uri "http://127.0.0.1:8090/ping" -TimeoutSec 5
            Write-Host "  /ping:    $($ping.StatusCode)"
        } catch {
            Write-Host "  /ping:    failed"
        }
        try {
            $nodes = Invoke-WebRequest -Uri "http://127.0.0.1:2933/api/nodes" -TimeoutSec 5
            Write-Host "  /api/nodes: $($nodes.StatusCode)"
        } catch {
            Write-Host "  /api/nodes: failed"
        }
    }
    "down" {
        docker compose down
    }
    "logs" {
        docker compose logs -f --tail 100
    }
    "status" {
        docker compose ps
    }
}
