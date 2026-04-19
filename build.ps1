# Sero C2 - Package server for distribution
# Usage: powershell -ExecutionPolicy Bypass -File publish-server.ps1

$ErrorActionPreference = "Stop"
$Root    = $PSScriptRoot
$Server  = Join-Path $Root "server"
$Out     = Join-Path $Root "dist"
$Stubs   = Join-Path $Root "stub"

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }

Write-Host "=== Sero C2 - Publish ===" -ForegroundColor Yellow

# Clean output
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
New-Item -ItemType Directory -Path $Out | Out-Null

# Publish server (self-contained single file)
Write-Step "Building server..."
$csproj = Get-ChildItem $Server -Filter "*.csproj" | Select-Object -First 1
if (-not $csproj) { Write-Err "No .csproj found in server/" }

$tmpOut = Join-Path $env:TEMP "sero_publish_$(Get-Random)"
& dotnet publish $csproj.FullName `
    -c Release -r win-x64 --self-contained `
    -p:PublishSingleFile=true `
    -p:PublishTrimmed=false `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=None `
    -o $tmpOut

if ($LASTEXITCODE -ne 0) { Write-Err "dotnet publish failed" }

# Copy server exe
$serverExe = Get-ChildItem $tmpOut -Filter "*.exe" | Select-Object -First 1
if (-not $serverExe) { Write-Err "Server exe not found in publish output" }
Copy-Item $serverExe.FullName (Join-Path $Out "SeroServer.exe")

# Copy stub source (needed by builder at runtime)
$stubOut = Join-Path $Out "stub"
New-Item -ItemType Directory -Path $stubOut | Out-Null
Copy-Item (Join-Path $Stubs "*.cs")     $stubOut -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Stubs "*.csproj") $stubOut -ErrorAction SilentlyContinue

# Copy Stubs folder (loader.cpp)
$stubsOut = Join-Path $Out "Stubs"
New-Item -ItemType Directory -Path $stubsOut | Out-Null
Copy-Item (Join-Path $Server "Stubs\loader.cpp") $stubsOut -ErrorAction SilentlyContinue

# Copy icon if present
Get-ChildItem $Root -Filter "*.ico" | ForEach-Object { Copy-Item $_.FullName $Out }

# Cleanup temp
Remove-Item $tmpOut -Recurse -Force -ErrorAction SilentlyContinue

Write-OK "Published to: $Out"
Write-Host ""
Write-Host "Contents:" -ForegroundColor White
Get-ChildItem $Out -Recurse | ForEach-Object {
    $rel = $_.FullName.Replace($Out, "").TrimStart("\")
    Write-Host "  $rel"
}
Write-Host ""
Write-OK "Done. Copy the 'dist' folder to deploy SeroServer on another machine."
Write-Host "Prerequisites on target machine: none (self-contained)" -ForegroundColor Gray
