// cdll_dlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "test_mfc_dll.h"
#include "cdll_dlg.h"
#include "afxdialogex.h"


// cdll_dlg �Ի���

IMPLEMENT_DYNAMIC(cdll_dlg, CDialogEx)

cdll_dlg::cdll_dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

cdll_dlg::~cdll_dlg()
{
}

void cdll_dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(cdll_dlg, CDialogEx)
END_MESSAGE_MAP()


// cdll_dlg ��Ϣ�������
