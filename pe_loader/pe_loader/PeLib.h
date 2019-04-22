#pragma once
#include <windows.h>
#include <winnt.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

// CodeView header 
struct CV_HEADER
{
	DWORD CvSignature; // NBxx
	LONG  Offset;      // Always 0 for NB10
};

// CodeView NB10 debug information 
// (used when debug information is stored in a PDB 2.00 file) 
struct CV_INFO_PDB20
{
	CV_HEADER  Header;
	DWORD      Signature;       // seconds since 01.01.1970
	DWORD      Age;             // an always-incrementing value 
	BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
};

// CodeView RSDS debug information 
// (used when debug information is stored in a PDB 7.00 file) 
struct CV_INFO_PDB70
{
	DWORD      CvSignature;
	GUID       Signature;       // unique identifier 
	DWORD      Age;             // an always-incrementing value 
	BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
};
class CPeLib
{
private:
	bool load_pe_image64(PVOID buffer, SIZE_T buffer_size);
public:
	CPeLib();
	~CPeLib();
	bool load_pe_file(std::string file_name);
	bool load_pe_image(PVOID buffer, SIZE_T buffer_size);
private:
	bool b_loaded;
	bool b_image64;
	std::vector<BYTE> m_image;
	std::vector<BYTE> file_buffer;
public:
	void dump_info();
private:
	void dump_dos_header();
	void dump_nt_header();
	void dump_file_header(PIMAGE_FILE_HEADER file_header);
	void dump_option_header32();
	void dump_option_header64();
	void dump_section_headers();
	void dump_iat();
public:
	void dump_iat32();
	void dump_iat64();
private:
	void dump_eat();
	void dump_dbg();
	void dump_res();
public:
	void get_image(std::vector<BYTE> & image);
	bool is_image64();
};

