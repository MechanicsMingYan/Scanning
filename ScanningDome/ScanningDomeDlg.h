
// ScanningDomeDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CScanningDomeDlg 对话框
class CScanningDomeDlg : public CDialogEx
{
// 构造
public:
	CScanningDomeDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SCANNINGDOME_DIALOG };
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
	CEdit edit_feature_shift_;
	CEdit edit_feature_len_;
	CEdit edit_file_path_;
	CEdit edit_feature_;
	bool GetFile(wchar_t* file_path);
	bool OnCopyText(CString source);
	afx_msg void OnBnClickedButtonOpenFile();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButtonCopyFilePath();
	afx_msg void OnBnClickedButtonCopyFeature();
	afx_msg void OnBnClickedButtonCopyFileImage();
	CEdit m_edit_iamge_md5_;
	CEdit edit_file_size_start_;
	afx_msg void OnBnClickedButtonCopyFileSize();
};
