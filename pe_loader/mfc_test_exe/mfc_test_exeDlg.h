
// mfc_test_exeDlg.h : ͷ�ļ�
//

#pragma once


// Cmfc_test_exeDlg �Ի���
class Cmfc_test_exeDlg : public CDialogEx
{
// ����
public:
	Cmfc_test_exeDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFC_TEST_EXE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
};
