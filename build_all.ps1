# Build Script for Multi-Platform Binaries

$platforms = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" },
    @{ OS = "linux";   Arch = "amd64"; Ext = "" },
    @{ OS = "linux";   Arch = "arm64"; Ext = "" },
    @{ OS = "darwin";  Arch = "amd64"; Ext = "" },
    @{ OS = "darwin";  Arch = "arm64"; Ext = "" }
)

$outputDir = "dist"
if (!(Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

foreach ($p in $platforms) {
    $env:GOOS = $p.OS
    $env:GOARCH = $p.Arch
    $ext = $p.Ext
    
    $clientName = "$outputDir/client-$($p.OS)-$($p.Arch)$ext"
    $serverName = "$outputDir/server-$($p.OS)-$($p.Arch)$ext"

    Write-Host "Building for $($p.OS)/$($p.Arch)..."
    
    go build -o $clientName ./cmd/client
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed for client $($p.OS)"; continue }
    
    go build -o $serverName ./cmd/server
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed for server $($p.OS)"; continue }
}

Write-Host "Build complete. Artifacts in $outputDir"

# Reset env vars
$env:GOOS = ""
$env:GOARCH = ""
