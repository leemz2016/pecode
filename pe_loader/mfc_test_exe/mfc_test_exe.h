
// mfc_test_exe.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cmfc_test_exeApp: 
// �йش����ʵ�֣������ mfc_test_exe.cpp
//

class Cmfc_test_exeApp : public CWinApp
{
public:
	Cmfc_test_exeApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Cmfc_test_exeApp theApp;