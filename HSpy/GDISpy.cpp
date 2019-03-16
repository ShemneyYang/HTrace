#include "stdafx.h"
#include "GDISpy.h"
#include <algorithm>
#include <tlhelp32.h>
#include <map>
#include "StackWalker.h"
#include "pehack.h"

//All the dll has been sorted by alphabeta and capitalized.
const WCHAR* g_SystemDlls[] =
{
	L"ACTIVEDS.DLL",
	L"ADSLDPC.DLL",
	L"ADVAPI32.DLL",
	L"ADVPACK.DLL",
	L"APPHELP.DLL",
	L"ATL.DLL",
	L"AUTHZ.DLL",
	L"BROWSEUI.DLL",
	L"CABINET.DLL",
	L"CDFVIEW.DLL",
	L"CERTCLI.DLL",
	L"CFGMGR32.DLL",
	L"CLUSAPI.DLL",
	L"COMDLG32.DLL",
	L"CREDUI.DLL",
	L"CRYPT32.DLL",
	L"CRYPTUI.DLL",
	L"CSCDLL.DLL",
	L"DBGHELP.DLL",
	L"DEVMGR.DLL",
	L"DHCPCSVC.DLL",
	L"DNSAPI.DLL",
	L"DUSER.DLL",
	L"DWMAPI.DLL",
	L"EFSADU.DLL",
	L"ESENT.DLL",
	L"GDI32.DLL",
	L"HLINK.DLL",
	L"HNETCFG.DLL",
	L"IEFRAME.DLL",
	L"IERTUTIL.DLL",
	L"IEUI.DLL",
	L"IMAGEHLP.DLL",
	L"IMGUTIL.DLL",
	L"IMM32.DLL",
	L"INETCOMM.DLL",
	L"IPHLPAPI.DLL",
	L"KERNEL32.DLL",
	L"LINKINFO.DLL",
	L"LZ32.DLL",
	L"MLANG.DLL",
	L"MOBSYNC.DLL",
	L"MPR.DLL",
	L"MPRAPI.DLL",
	L"MPRUI.DLL",
	L"MSASN1.DLL",
	//Microsoft Input Method
	L"MSCTFIME.IME",
	L"MSGINA.DLL",
	L"MSHTML.DLL",
	L"MSI.DLL",
	L"MSIMG32.DLL",
	L"MSLS31.DLL",
	L"MSOERT2.DLL",
	L"MSRATING.DLL",
	L"MSSIGN32.DLL",
	L"MSVCP60.DLL",
	L"MSVCRT.DLL",
	L"MSWSOCK.DLL",
	L"NETAPI32.DLL",
	L"NETCFGX.DLL",
	L"NETMAN.DLL",
	L"NETPLWIZ.DLL",
	L"NETRAP.DLL",
	L"NETSHELL.DLL",
	L"NETUI0.DLL",
	L"NETUI1.DLL",
	L"NETUI2.DLL",
	L"NORMALIZ.DLL",
	L"NTDLL.DLL",
	L"NTDSAPI.DLL",
	L"NTLANMAN.DLL",
	L"ODBC32.DLL",
	L"OLE32.DLL",
	L"OLEACC.DLL",
	L"OLEAUT32.DLL",
	L"OLEDLG.DLL",
	L"OLEPRO32.DLL",
	L"POWRPROF.DLL",
	L"PRINTUI.DLL",
	L"PSAPI.DLL",
	L"QUERY.DLL",
	L"RASAPI32.DLL",
	L"RASDLG.DLL",
	L"RASMAN.DLL",
	L"REGAPI.DLL",
	L"RPCRT4.DLL",
	L"RTUTILS.DLL",
	L"SAMLIB.DLL",
	L"SCECLI.DLL",
	L"SECUR32.DLL",
	L"SETUPAPI.DLL",
	L"SHDOCVW.DLL",
	L"SHELL32.DLL",
	L"SHLWAPI.DLL",
	L"SHSVCS.DLL",
	L"TAPI32.DLL",
	L"URLMON.DLL",
	L"USER32.DLL",
	L"USERENV.DLL",
	L"USP10.DLL",
	L"UTILDLL.DLL",
	L"UXTHEME.DLL",
	L"VERSION.DLL",
	L"W32TOPL.DLL",
	L"WINHTTP.DLL",
	L"WININET.DLL",
	L"WINMM.DLL",
	L"WINSCARD.DLL",
	L"WINSPOOL.DRV",
	L"WINSTA.DLL",
	L"WINTRUST.DLL",
	L"WLDAP32.DLL",
	L"WMI.DLL",
	L"WS2_32.DLL",
	L"WS2HELP.DLL",
	L"WSOCK32.DLL",
	L"WTSAPI32.DLL",
	L"WZCDLG.DLL",
	L"WZCSAPI.DLL",
	L"WZCSVC.DLL"
};

static std::map<DWORD, std::vector<std::string> > g_HandleInfo;
static CStackWalker g_StackWalker;

bool Str1LessStr2(const TCHAR* str1, const TCHAR* str2)
{
	return wcscmp(str1, str2) < 0;
}

BOOL IsSystemDll(TCHAR* dllName, int nLen)
{
	_wcsupr_s(dllName, nLen);
	const TCHAR** pIndex = std::lower_bound(&g_SystemDlls[0], &g_SystemDlls[0] + _countof(g_SystemDlls),
		dllName, Str1LessStr2);
	if (pIndex != &g_SystemDlls[0] + _countof(g_SystemDlls))
		return wcscmp(*pIndex, dllName) == 0;
	return FALSE;
}

CGDISpy::CGDISpy()
{
	HMODULE hGDI32 = GetModuleHandle(TEXT("GDI32.DLL"));
	HMODULE hUSER32 = GetModuleHandle(TEXT("USER32.DLL"));
	// device context
	__CreateCompatibleDC = (pfn_CreateCompatibleDC)GetProcAddress(hGDI32, "CreateCompatibleDC");

	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	DWORD ProcessID = GetCurrentProcessId();
	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
	if (INVALID_HANDLE_VALUE == hModuleSnap)
	{
		return;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object!
		return;
	}

	// Now walk the module list of the process,
	do
	{
		if (IsSystemDll(me32.szModule, 256))
			continue;

		//KPEFile can be found in the book "Windows Graphics Programming" (author: Feng Yuan). The
		//class can modify the addresses of imported functions and exported functions.
		//The parameter of constructor is the base address of a module.
		KPEFile module((HMODULE)me32.modBaseAddr);
		if (!module.IsPeFile())
			continue;
		__try
		{
			PIMAGE_IMPORT_DESCRIPTOR pImport1 = module.GetImportDescriptor("GDI32.dll");
			if (pImport1)
			{
				// device context
				module.SetImportAddress(pImport1, "CreateCompatibleDC", (FARPROC)CGDISpy::_myCreateCompatibleDC);
			}

// 			PIMAGE_IMPORT_DESCRIPTOR pImport2 = module.GetImportDescriptor("USER32.dll");
// 			if (pImport2)
// 			{
// 				module.SetImportAddress(pImport2, "GetDC", (FARPROC)_GetDC);
// 				module.SetImportAddress(pImport2, "GetDCEx", (FARPROC)_GetDCEx);
// 				module.SetImportAddress(pImport2, "GetWindowDC", (FARPROC)_GetWindowDC);
// 				module.SetImportAddress(pImport2, "LoadBitmapA", (FARPROC)_LoadBitmapA);
// 				module.SetImportAddress(pImport2, "LoadBitmapW", (FARPROC)_LoadBitmapW);
// 				module.SetImportAddress(pImport2, "ReleaseDC", (FARPROC)_ReleaseDC);
// 			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	} while ( /*FALSE*/Module32Next(hModuleSnap, &me32));

	// Don't forget to clean up the snapshot object.
	CloseHandle(hModuleSnap);

	//for those DLLs which are loaded after GdiSpy.dll was loaded, we must modify addresses of 
	//the exported functions of GDI32.dll to hook the functions in the DLLs.
	KPEFile module(hGDI32);
	// device context
	module.SetExportAddress("CreateCompatibleDC", (FARPROC)_myCreateCompatibleDC);
}


CGDISpy::~CGDISpy()
{
}

HDC CGDISpy::_myCreateCompatibleDC(HDC x)
{
	if (NULL == __CreateCompatibleDC)
	{
		return NULL;
	}
	HDC hVarHDC = __CreateCompatibleDC(x);

	if (hVarHDC != NULL)
	{
		g_StackWalker.GetCallstack(g_HandleInfo[(DWORD)hVarHDC], 2);
	}
	return hVarHDC;
}

BOOL CGDISpy::_myDeleteDC(HDC x)
{
	if (NULL == __DeleteDC)
	{
		return NULL;
	}
	BOOL ret = __DeleteDC(x);

	if (ret)
	{
		g_HandleInfo.erase((DWORD)x);
	}
	return ret;
}