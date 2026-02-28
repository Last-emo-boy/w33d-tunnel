$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$mode = if ($args.Count -gt 0) { $args[0] } else { "write" }
$files = git ls-files "*.go"

if (!$files -or $files.Count -eq 0) {
    Write-Host "[fmt] no go files found"
    exit 0
}

if ($mode -eq "--check") {
    Write-Host "[fmt] checking gofmt"
    $output = & gofmt -l $files
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt check failed"
    }
    if ($output) {
        Write-Host "[fmt] files need formatting:"
        $output | ForEach-Object { Write-Host $_ }
        exit 1
    }
    Write-Host "[fmt] ok"
    exit 0
}

Write-Host "[fmt] formatting go files"
& gofmt -w $files
if ($LASTEXITCODE -ne 0) {
    throw "gofmt write failed"
}
Write-Host "[fmt] done"
