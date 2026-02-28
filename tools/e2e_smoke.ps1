param(
    [string]$Token = "admin-token-123",
    [string]$Manager = "http://127.0.0.1:2933",
    [string]$Socks = "127.0.0.1:1080"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$subscribeUrl = "$Manager/api/subscribe?token=$Token"

Write-Host "[1/4] Checking manager subscription endpoint..."
$sub = Invoke-RestMethod -Uri $subscribeUrl -TimeoutSec 10
if (-not $sub.nodes -or $sub.nodes.Count -lt 1) {
    throw "No nodes found in subscription response"
}
Write-Host "      OK: nodes=$($sub.nodes.Count)"

Write-Host "[2/4] Checking server admin ping endpoint..."
$ping = Invoke-WebRequest -Uri "http://127.0.0.1:8090/ping" -TimeoutSec 10
if ($ping.StatusCode -ne 200) {
    throw "Ping endpoint returned $($ping.StatusCode)"
}
Write-Host "      OK: /ping=$($ping.StatusCode)"

Write-Host "[3/4] Starting local client..."
$clientPath = Join-Path (Get-Location) "client.exe"
$args = @("-subscribe", $subscribeUrl, "-socks", $Socks)

if (Test-Path $clientPath) {
    $proc = Start-Process -FilePath $clientPath -ArgumentList $args -PassThru -WindowStyle Hidden
} else {
    $runArgs = @("run", "./cmd/client", "--") + $args
    $proc = Start-Process -FilePath "go" -ArgumentList $runArgs -PassThru -WindowStyle Hidden
}

Start-Sleep -Seconds 5

try {
    Write-Host "[4/4] Validating SOCKS reachability..."
    & curl.exe --socks5-hostname $Socks --max-time 15 --silent --show-error --fail "http://example.com" | Out-Null
    Write-Host "      OK: SOCKS tunnel fetch succeeded"
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
    }
}

Write-Host "Smoke test passed."
