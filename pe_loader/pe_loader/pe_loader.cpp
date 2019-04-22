// pe_loader.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "PeLibEx.h"

int main(int argc,char *argv[])
{
	magic::CPeLibEx pe_loader;
	//pe_loader.load_pe_file(std::string("f:\\test.dll"));
	//pe_loader.load_pe_file(std::string("f:\\mfc.dll"));
	pe_loader.load_pe_file(std::string(argv[1]));
	pe_loader.run_image();
	while (1)
	{
		//mfc 
		Sleep(1);
	}
	//LoadLibraryA("f:\\mfc.dll");
    return 0;
}

