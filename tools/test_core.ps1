$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

Write-Host "[core-test] running stable core package tests"
go test -count=1 ./pkg/kernel ./pkg/transport ./pkg/protocol ./pkg/client ./cmd/server ./cmd/manager
