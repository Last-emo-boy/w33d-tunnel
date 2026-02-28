# Build all CLI binaries for common target platforms.

$ErrorActionPreference = "Stop"

$platforms = @(
    @{ OS = "windows"; Arch = "amd64" },
    @{ OS = "windows"; Arch = "arm64" },
    @{ OS = "linux";   Arch = "amd64" },
    @{ OS = "linux";   Arch = "arm64" },
    @{ OS = "darwin";  Arch = "amd64" },
    @{ OS = "darwin";  Arch = "arm64" }
)

foreach ($p in $platforms) {
    $env:GOOS = $p.OS
    $env:GOARCH = $p.Arch
    Write-Host "Building for $($p.OS)/$($p.Arch)..."
    & .\tools\build_binaries.ps1 "dist"
}

$env:GOOS = ""
$env:GOARCH = ""

Write-Host "Build complete. Artifacts in dist"
