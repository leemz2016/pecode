// test_mfc_dll.cpp : 定义 DLL 的初始化例程。
//

#include "stdafx.h"
#include "test_mfc_dll.h"
#include "cdll_dlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//
//TODO:  如果此 DLL 相对于 MFC DLL 是动态链接的，
//		则从此 DLL 导出的任何调入
//		MFC 的函数必须将 AFX_MANAGE_STATE 宏添加到
//		该函数的最前面。
//
//		例如: 
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// 此处为普通函数体
//		}
//
//		此宏先于任何 MFC 调用
//		出现在每个函数中十分重要。  这意味着
//		它必须作为函数中的第一个语句
//		出现，甚至先于所有对象变量声明，
//		这是因为它们的构造函数可能生成 MFC
//		DLL 调用。
//
//		有关其他详细信息，
//		请参阅 MFC 技术说明 33 和 58。
//

// Ctest_mfc_dllApp

BEGIN_MESSAGE_MAP(Ctest_mfc_dllApp, CWinApp)
END_MESSAGE_MAP()


// Ctest_mfc_dllApp 构造

Ctest_mfc_dllApp::Ctest_mfc_dllApp()
{
	// TODO:  在此处添加构造代码，
	// 将所有重要的初始化放置在 InitInstance 中
}


// 唯一的一个 Ctest_mfc_dllApp 对象

Ctest_mfc_dllApp theApp;


// Ctest_mfc_dllApp 初始化

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
