#pragma once


// cdll_dlg �Ի���

class cdll_dlg : public CDialogEx
{
	DECLARE_DYNAMIC(cdll_dlg)

public:
	cdll_dlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~cdll_dlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
};
