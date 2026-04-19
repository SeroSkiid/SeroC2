#Requires -RunAsAdministrator
# Sero C2 - Install build prerequisites
# Run as Administrator: powershell -ExecutionPolicy Bypass -File setup-prerequisites.ps1

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[!] $msg" -ForegroundColor Red }

Write-Host "=== Sero C2 Prerequisites Setup ===" -ForegroundColor Yellow

# 1. Check winget
Write-Step "Checking winget..."
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Err "winget not found. Install App Installer from the Microsoft Store first."
    exit 1
}
Write-OK "winget found"

Write-Step "Fixing winget sources (msstore SSL issue workaround)..."
try {
    winget source reset --force | Out-Null
    winget source update | Out-Null
    winget source disable msstore | Out-Null
} catch {
    Write-Err "Winget source fix skipped (non-critical)"
}

Write-OK "winget sources ready"

# 2. .NET 10 SDK
Write-Step "Checking .NET 10 SDK..."
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetOk = $false

if ($dotnet) {
    $ver = & dotnet --version 2>$null
    if ($ver -match "^10\.") {
        $dotnetOk = $true
        Write-OK ".NET SDK $ver already installed"
    }
}

if (-not $dotnetOk) {
    Write-Step "Installing .NET 10 SDK..."

    winget install --id Microsoft.DotNet.SDK.10 -e `
        --source winget `
        --silent `
        --accept-package-agreements `
        --accept-source-agreements

    Write-OK ".NET 10 SDK installed"
}

# 3. Visual Studio Build Tools 2022 with C++ workload
Write-Step "Checking MSVC (cl.exe)..."

$clFound = Get-ChildItem "C:\Program Files\Microsoft Visual Studio" -Recurse -Filter "cl.exe" -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -match "HostX64\\x64" } |
           Select-Object -First 1

if ($clFound) {
    Write-OK "cl.exe found: $($clFound.FullName)"
} else {
    Write-Step "Installing VS Build Tools 2022 with C++ workload (this may take 5-10 minutes)..."

    winget install Microsoft.VisualStudio.2022.BuildTools `
        --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --wait" `
        --accept-package-agreements `
        --accept-source-agreements

    Write-OK "VS Build Tools installed"
}

# 4. Windows SDK (for rc.exe)
Write-Step "Checking Windows SDK (rc.exe)..."

$rcFound = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "rc.exe" -ErrorAction SilentlyContinue |
           Select-Object -First 1

if ($rcFound) {
    Write-OK "rc.exe found"
} else {
    Write-Step "Installing Windows 10 SDK..."

    winget install Microsoft.WindowsSDK.10.0.22621 `
        --silent `
        --accept-package-agreements `
        --accept-source-agreements

    Write-OK "Windows SDK installed"
}

Write-Host ""
Write-Host "=== All prerequisites installed ===" -ForegroundColor Green
Write-Host "You can now build Sero C2 from Visual Studio or via 'dotnet build'." -ForegroundColor White