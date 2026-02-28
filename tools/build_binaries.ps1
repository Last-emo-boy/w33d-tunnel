$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

$outDir = if ($args.Count -gt 0) { $args[0] } else { "dist" }
$targetOS = if ($env:GOOS -and $env:GOOS.Trim() -ne "") { $env:GOOS } else { go env GOOS }
$targetArch = if ($env:GOARCH -and $env:GOARCH.Trim() -ne "") { $env:GOARCH } else { go env GOARCH }

$binaries = @(
    @{ Name = "client"; Path = "./cmd/client" },
    @{ Name = "server"; Path = "./cmd/server" },
    @{ Name = "manager"; Path = "./cmd/manager" },
    @{ Name = "bench"; Path = "./cmd/bench" },
    @{ Name = "http_bench"; Path = "./cmd/http_bench" },
    @{ Name = "fetch_page"; Path = "./cmd/fetch_page" }
)

if (!(Test-Path -Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$ext = ""
if ($targetOS -eq "windows") {
    $ext = ".exe"
}

Write-Host "[build] target $targetOS/$targetArch"
foreach ($bin in $binaries) {
    $output = Join-Path $outDir "$($bin.Name)-$targetOS-$targetArch$ext"
    Write-Host "[build] $($bin.Path) -> $output"
    $env:GOOS = $targetOS
    $env:GOARCH = $targetArch
    go build -trimpath -o $output $bin.Path
}

Write-Host "[build] done"
