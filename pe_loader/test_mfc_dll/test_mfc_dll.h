// test_mfc_dll.h : test_mfc_dll DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Ctest_mfc_dllApp
// �йش���ʵ�ֵ���Ϣ������� test_mfc_dll.cpp
//

class Ctest_mfc_dllApp : public CWinApp
{
public:
	Ctest_mfc_dllApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};
