
// HTraceDlg.h: 头文件
//

#pragma once


// CHTraceDlg 对话框
class CHTraceDlg : public CDialogEx
{
// 构造
public:
	CHTraceDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_HTRACE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOpenExe();
	afx_msg void OnBnClickedBtnStart();
	afx_msg void OnBnClickedBtnDiff();

protected:
	static DWORD WINAPI spyThreadPro(LPVOID lpParam);

	void doSpy(void);
	void log(const std::string& str);
	void log(const CString& str);

private:
	CString m_strSpyExeFile;
	CString m_strLogTxt;

	CRichEditCtrl m_logTextCtrl;
};
