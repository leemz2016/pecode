// test_mfc_dll.cpp : ���� DLL �ĳ�ʼ�����̡�
//

#include "stdafx.h"
#include "test_mfc_dll.h"
#include "cdll_dlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO:  ����� DLL ����� MFC DLL �Ƕ�̬���ӵģ�
//		��Ӵ� DLL �������κε���
//		MFC �ĺ������뽫 AFX_MANAGE_STATE ����ӵ�
//		�ú�������ǰ�档
//
//		����: 
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// �˴�Ϊ��ͨ������
//		}
//
//		�˺������κ� MFC ����
//		������ÿ��������ʮ����Ҫ��  ����ζ��
//		��������Ϊ�����еĵ�һ�����
//		���֣������������ж������������
//		������Ϊ���ǵĹ��캯���������� MFC
//		DLL ���á�
//
//		�й�������ϸ��Ϣ��
//		����� MFC ����˵�� 33 �� 58��
//

// Ctest_mfc_dllApp

BEGIN_MESSAGE_MAP(Ctest_mfc_dllApp, CWinApp)
END_MESSAGE_MAP()


// Ctest_mfc_dllApp ����

Ctest_mfc_dllApp::Ctest_mfc_dllApp()
{
	// TODO:  �ڴ˴���ӹ�����룬
	// ��������Ҫ�ĳ�ʼ�������� InitInstance ��
}


// Ψһ��һ�� Ctest_mfc_dllApp ����

Ctest_mfc_dllApp theApp;


// Ctest_mfc_dllApp ��ʼ��

BOOL Ctest_mfc_dllApp::InitInstance()
{
	CWinApp::InitInstance();
	MessageBox(NULL, L"hello mfc", L"hello", MB_OK);
	USES_CONVERSION;
	CString m = CString(A2W("helll"));
	AfxMessageBox(m);
	cdll_dlg md;
	md.DoModal();
	return TRUE;
}
