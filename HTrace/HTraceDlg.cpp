
// HTraceDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "HTrace.h"
#include "HTraceDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BOOL GetProcessDllName(HANDLE hProcess, HMODULE hDll, LPSTR dllName, SIZE_T dllNameSize)
{
	_ASSERTE(dllName != NULL);
	_ASSERTE(dllNameSize >= 24);
	dllName[0] = 0;

	SIZE_T bytesRead;

	IMAGE_DOS_HEADER dosHdr;
	if (!ReadProcessMemory(hProcess, hDll, &dosHdr, sizeof(dosHdr), &bytesRead))
		return FALSE;

	IMAGE_NT_HEADERS        ntHdr;
	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll + dosHdr.e_lfanew), &ntHdr, sizeof(ntHdr), &bytesRead))
		return FALSE;

	DWORD exportsRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (!exportsRVA)
		return FALSE;

	IMAGE_EXPORT_DIRECTORY  exportDir;
	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll + exportsRVA), &exportDir, sizeof(exportDir), &bytesRead))
		return(FALSE);

	if (!ReadProcessMemory(hProcess, (PVOID)((char*)hDll + exportDir.Name), dllName, dllNameSize, &bytesRead))
		return(FALSE);

	return(TRUE);
}

BOOL CreateRemoteThread(HANDLE hProcess)
{
	BOOL bSuccess = FALSE;
	TCHAR szFilename[_MAX_PATH];
	::GetModuleFileName(NULL, szFilename, _countof(szFilename));
	TCHAR* pPos = _tcsrchr(szFilename, _T('\\'));
	_tcscpy(pPos, _T("\\HSpy.dll"));
	PTSTR pRemoteDllPath = (PTSTR)VirtualAllocEx(hProcess, NULL, sizeof(szFilename), MEM_COMMIT,
		PAGE_READWRITE);
	if (pRemoteDllPath != NULL)
	{
		WriteProcessMemory(hProcess, pRemoteDllPath, szFilename, sizeof(szFilename), NULL);
		//The call to CreateRemoteThread assumes that Kernel32.dll is mapped to the same memory 
		//location in both the local and the remote processes' address spaces. Every application 
		//requires Kernel32.dll, and in my experience the system maps Kernel32.dll to the same 
		//address in every process.--Chapter: Injecting a DLL Using Remote Threads 
		//"Programming Applications for Microsoft Windows"(author: Jeffrey Richter)
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(
			GetModuleHandle(TEXT("Kernel32")),
			"LoadLibraryW"
		);
		//The result proves: the Injected DLL by this way won't send notification to the debugger.
		HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, pRemoteDllPath, 0, NULL);
		if (hThread != NULL)
		{
			bSuccess = TRUE;
			SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);
			//WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
		//Mustn't free the memory, otherwise the remote thread maybe haven't done its work. 
		//Let it be, we are just debugging.
		//VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
	}
	return bSuccess;
}

BOOL AtoW(LPCSTR lpszSrc, int cch/*=-1*/, std::wstring &wstrDst)
{
	if (cch == -1)
		cch = (int)strlen(lpszSrc);

	wstrDst.resize(cch, NULL);
	int n = MultiByteToWideChar(CP_ACP, 0, lpszSrc, cch, &wstrDst[0], cch);
	wstrDst.resize(n);
	return n > 0;
}


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CHTraceDlg 对话框



CHTraceDlg::CHTraceDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_HTRACE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CHTraceDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TXT_LOG, m_logTextCtrl);
}

BEGIN_MESSAGE_MAP(CHTraceDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_OPEN_EXE, &CHTraceDlg::OnBnClickedOpenExe)
	ON_BN_CLICKED(IDC_BTN_START, &CHTraceDlg::OnBnClickedBtnStart)
	ON_BN_CLICKED(IDC_BTN_DIFF, &CHTraceDlg::OnBnClickedBtnDiff)
END_MESSAGE_MAP()


// CHTraceDlg 消息处理程序

BOOL CHTraceDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CHTraceDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CHTraceDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CHTraceDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CHTraceDlg::OnBnClickedOpenExe()
{
	TCHAR szBuffer[MAX_PATH] = { 0 };
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFilter = _T("exe文件(*.exe)\0*.exe\0所有文件(*.*)\0*.*\0");
	ofn.lpstrInitialDir = NULL;
	ofn.lpstrFile = szBuffer;
	ofn.nMaxFile = sizeof(szBuffer) / sizeof(*szBuffer);
	ofn.nFilterIndex = 0;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;
	BOOL bSel = GetOpenFileName(&ofn);
	if (!bSel)
	{
		return;
	}

	m_strSpyExeFile = szBuffer;
	DWORD dwThreadId = 0;
	HANDLE hThread = CreateThread(NULL,                   // default security attributes
		0,                      // use default stack size  
		spyThreadPro,       // thread function name
		(LPVOID)this,          // argument to thread function 
		0,                      // use default creation flags 
		&dwThreadId);   // returns the thread identifier 
}


void CHTraceDlg::OnBnClickedBtnStart()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CHTraceDlg::OnBnClickedBtnDiff()
{
	// TODO: 在此添加控件通知处理程序代码
}

DWORD CHTraceDlg::spyThreadPro(LPVOID lpParam)
{
	CHTraceDlg* _this = (CHTraceDlg*)lpParam;
	_this->doSpy();
	return 0;
}

void CHTraceDlg::doSpy(void)
{
	//打开进程.
	STARTUPINFO startupInfo;
	memset(&startupInfo, 0, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION  processInformation;
	static BOOL bThreadStart = FALSE;

	BOOL bReturn = ::CreateProcess(
		(LPCTSTR)m_strSpyExeFile,				// lpszImageName
		NULL,						// lpszCommandLine
		NULL, NULL,					// lpsaProcess and lpsaThread
		FALSE,						// fInheritHandles
		DEBUG_ONLY_THIS_PROCESS,
		NULL, NULL,					// lpvEnvironment and lpszCurDir
		&startupInfo,
		&processInformation
	);
	if (bReturn == FALSE)
	{
		CString str;
		str.Format(L"Failed to run exe, file=%s", m_strSpyExeFile);
		log(str);
		return;
	}
	else
	{
		CString str;
		str.Format(L"Successful to run exe, file=%s", m_strSpyExeFile);
		log(str);
	}

	TCHAR message[256];
	char dllName[64];
	DEBUG_EVENT DebugEv;
	BOOL bGdi32Loaded = FALSE;
	BOOL bKernel32Loaded = FALSE;
	BOOL bUser32Loaded = FALSE;
	while (TRUE)
	{
		DWORD dwContinueStatus = DBG_CONTINUE;
		::WaitForDebugEvent(&DebugEv, INFINITE);

		switch (DebugEv.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			//For breakpoint exceptions，dwContinueStatus must be DBG_CONTINUE，otherwise the 
			//debuggee will terminate immediately.
			if (EXCEPTION_BREAKPOINT != DebugEv.u.Exception.ExceptionRecord.ExceptionCode)
			{
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				//ShowDebugString(_T("Exception occurred"));
			}
			break;

		case LOAD_DLL_DEBUG_EVENT:
			GetProcessDllName(processInformation.hProcess, (HMODULE)DebugEv.u.LoadDll.lpBaseOfDll, dllName, sizeof(dllName));
			strlwr(dllName);
			if (bKernel32Loaded && bGdi32Loaded && bUser32Loaded)
			{
				if (!bThreadStart)
				{
					bThreadStart = TRUE;
					//Create a remote thread to inject GdiSpy.dll to the debugged to intercept the
					//calls of creation and deletion of GDI objects.
					BOOL bRet = CreateRemoteThread(processInformation.hProcess);
					CString str;
					str.Format(L"CreateRemoteThread return %s", bRet ? L"True" : L"False");
					log(str);
				}
			}
			else
			{
				if (strcmp(dllName, "kernel32.dll") == 0)
					bKernel32Loaded = TRUE;
				else if (strcmp(dllName, "user32.dll") == 0)
					bUser32Loaded = TRUE;
				else if (strcmp(dllName, "gdi32.dll") == 0)
					bGdi32Loaded = TRUE;
			}
			if (dllName[0])
				dllName[0] += 'A' - 'a';//Capitalize the first letter.
			strcat(dllName, " loaded");
			log(dllName);
			if (DebugEv.u.LoadDll.hFile)
				::CloseHandle(DebugEv.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
		{
			DWORD bufferSize = DebugEv.u.DebugString.nDebugStringLength;
			if (DebugEv.u.DebugString.fUnicode)
				bufferSize *= sizeof(wchar_t);
			bufferSize = min(bufferSize, sizeof(message));
			if (ReadProcessMemory(processInformation.hProcess, DebugEv.u.DebugString.lpDebugStringData,
				message, bufferSize, NULL) == FALSE)
			{
				wsprintf(message, _T("Read debuggee output failed (error = %d)."),
					GetLastError());

			}
			else
			{
				if (DebugEv.u.DebugString.fUnicode)
				{
					//strcpy(message, CW2A(message));
				}
				else
				{
					wcscpy(message, CA2W((char*)message));
				}
			}
			log(message);
		}
		break;

		case CREATE_THREAD_DEBUG_EVENT:
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			log(_T("Process created"));

			if (DebugEv.u.CreateProcessInfo.hFile)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hFile);
			if (DebugEv.u.CreateProcessInfo.hProcess)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hProcess);
			if (DebugEv.u.CreateProcessInfo.hThread)
				::CloseHandle(DebugEv.u.CreateProcessInfo.hThread);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			bThreadStart = FALSE;
			log(_T("Process exited"));
			break;

		default:
			break;
		}

		::ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
		//The sentence must be placed after the previous sentence, otherwis the debuggee won't be 
		//terminated.
		if (EXIT_PROCESS_DEBUG_EVENT == DebugEv.dwDebugEventCode)
			break;
	}

	::CloseHandle(processInformation.hProcess);
	::CloseHandle(processInformation.hThread);
}

void CHTraceDlg::log(const std::string& str)
{
	std::wstring strTemp;
	AtoW(str.c_str(), str.size(), strTemp);
	log(strTemp.c_str());
}

void CHTraceDlg::log(const CString& str)
{
	static int g_nCount = 0;
	CString strTxt;
	strTxt.Format(L"%.4d %s\n", ++g_nCount, str);
	m_logTextCtrl.SetSel(-1, -1);
	m_logTextCtrl.ReplaceSel(strTxt);
	m_logTextCtrl.PostMessage(WM_VSCROLL, SB_BOTTOM, 0);
}
