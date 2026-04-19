@echo off
cd /d "%~dp0"

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ====================================
echo   Sero C2 Prerequisites Installer
echo ====================================
echo.

set "SCRIPT=%~dp0setup-prerequisites.ps1"

if not exist "%SCRIPT%" (
    echo [!] setup-prerequisites.ps1 not found!
    pause
    exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo Done.
pause