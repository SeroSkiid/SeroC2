@echo off
set PORT=8080
set TOKEN=YOUR_STATS_TOKEN_HERE

:: Allow binding on all interfaces without needing admin each time
netsh http add urlacl url=http://+:%PORT%/ user=Everyone >nul 2>&1

:: Open firewall port (inbound)
netsh advfirewall firewall add rule name="SeroStats_%PORT%" dir=in action=allow protocol=TCP localport=%PORT% >nul 2>&1

"%~dp0stats-server\publish\StatsServer.exe" %PORT% %TOKEN%
pause
