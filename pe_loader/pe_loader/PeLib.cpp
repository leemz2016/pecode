#include "stdafx.h"
#include "PeLib.h"

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]
#define ALIGN_DOWN(address, alignment)      (LPVOID)((uintptr_t)(address) & ~((alignment) - 1))
#define ALIGN_VALUE_UP(value, alignment)    (((value) + (alignment) - 1) & ~((alignment) - 1))

CPeLib::CPeLib()
{
	b_loaded = false;
	b_image64 = false;
}


CPeLib::~CPeLib()
{
	file_buffer.clear();
	file_buffer.resize(1);
	if (b_loaded)
	{
		m_image.clear();
		m_image.resize(1);
	}
}


bool CPeLib::load_pe_file(std::string file_name)
{

	try
	{
		std::ifstream file_stream(file_name, std::ios::binary);
		file_stream.seekg(0, std::ios::end);
		auto length = std::size_t(file_stream.tellg());
		file_stream.seekg(0, std::ios::beg);
		auto buff = new BYTE[length];
		file_buffer.resize(length);
		file_stream.read(reinterpret_cast<char *>(buff), length);
		RtlCopyMemory(&file_buffer[0], buff, length);
		delete[] buff;
		//file_buffer = std::vector<BYTE>((std::istream_iterator<BYTE>(file_stream)), (std::istream_iterator<BYTE>()));
		file_stream.close();
		return load_pe_image(file_buffer.data(), file_buffer.size());
	}
	catch (const std::exception&)
	{
		std::cout << "failed" << std::endl;
	}
	return false;
}


bool CPeLib::load_pe_image(PVOID buffer, SIZE_T buffer_size)
{
	/*auto p_header = reinterpret_cast<ULONG_PTR>(buffer);*/
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	do
	{
		if (b_loaded)
		{
			return false;
		}
		if (buffer_size < sizeof(IMAGE_DOS_HEADER))
		{
			std::cout << "failed size dos_header" << std::endl;
			break;
		}
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			std::cout << "failed dos sig" << std::endl;
			break;
		}
		if (buffer_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32))
		{
			std::cout << "failed size dos size" << std::endl;
			break;
		}
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			std::cout << "failed nt sig " << nt_header->Signature << std::endl;
			break;
		}
		if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
		{
			b_image64 = true;
			return load_pe_image64(buffer, buffer_size);
		}
		if (nt_header->OptionalHeader.SectionAlignment & 1)
		{
			std::cout << "alignment size is 1" << std::endl;
			break;
		}

		SYSTEM_INFO sysInfo;
		GetNativeSystemInfo(&sysInfo);
		auto image_size = ALIGN_VALUE_UP(nt_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
		image_size = ALIGN_VALUE_UP(image_size, nt_header->OptionalHeader.SectionAlignment);
		auto section_header = IMAGE_FIRST_SECTION(nt_header);
		for (int i = 0; i< nt_header->FileHeader.NumberOfSections; i++)
		{
			if ((section_header[i].PointerToRawData + section_header[i].SizeOfRawData) >(DWORD)buffer_size)
			{
				std::cout << "failed size" << std::endl;
				return false;
			}
		}
		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
		{
			//得到该节的大小
			auto nCodeSize = section_header[i].Misc.VirtualSize;
			auto nLoadSize = section_header[i].SizeOfRawData;
			auto nMaxSize = (nLoadSize > nCodeSize) ? (nLoadSize) : (nCodeSize);
			auto nSectionSize = ALIGN_VALUE_UP(section_header[i].VirtualAddress + nMaxSize, sysInfo.dwPageSize);

			if (image_size < nSectionSize)
			{
				image_size = nSectionSize;  //Use the Max;
			}
		}

		m_image.resize(image_size);
		auto buff_byte = reinterpret_cast<BYTE*>(buffer);
		{
			int  nHeaderSize = nt_header->OptionalHeader.SizeOfHeaders;
			int  nSectionSize = nt_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			int  nMoveSize = nHeaderSize + nSectionSize;
			RtlCopyMemory(m_image.data(), buff_byte, nMoveSize);
		}
		{
			for (auto i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
			{
				if (section_header[i].VirtualAddress == 0 || section_header[i].SizeOfRawData == 0)
				{
					continue;
				}
				// 定位该节在内存中的位置
				void *pSectionAddress = (void *)((PBYTE)m_image.data() + section_header[i].VirtualAddress);
				// 复制段数据到虚拟内存
				RtlCopyMemory(pSectionAddress, &(buff_byte[section_header[i].PointerToRawData]), section_header[i].SizeOfRawData);
			}
		}
		b_loaded = true;
	} while (0);
	return b_loaded;
}

bool CPeLib::load_pe_image64(PVOID buffer, SIZE_T buffer_size)
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	do
	{
		if (b_loaded)
		{
			return false;
		}
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			break;
		}
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			break;
		}
		if (buffer_size < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64))
		{
			break;
		}
		if (nt_header->OptionalHeader.SectionAlignment & 1)
		{
			break;
		}
		//加载!!
		SYSTEM_INFO sysInfo;
		GetNativeSystemInfo(&sysInfo);
		auto image_size = ALIGN_VALUE_UP(nt_header->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
		image_size = ALIGN_VALUE_UP(image_size, nt_header->OptionalHeader.SectionAlignment);
		auto section_header = IMAGE_FIRST_SECTION(nt_header);
		for (int i = 0; i< nt_header->FileHeader.NumberOfSections; i++)
		{
			if ((section_header[i].PointerToRawData + section_header[i].SizeOfRawData) >(DWORD)buffer_size)
			{
				return false;
			}
		}
		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
		{
			//得到该节的大小
			auto nCodeSize = section_header[i].Misc.VirtualSize;
			auto nLoadSize = section_header[i].SizeOfRawData;
			auto nMaxSize = (nLoadSize > nCodeSize) ? (nLoadSize) : (nCodeSize);
			auto nSectionSize = ALIGN_VALUE_UP(section_header[i].VirtualAddress + nMaxSize, sysInfo.dwPageSize);

			if (image_size < nSectionSize)
			{
				image_size = nSectionSize;  //Use the Max;
			}
		}

		m_image.resize(image_size);
		auto buff_byte = reinterpret_cast<BYTE*>(buffer);
		{
			int  nHeaderSize = nt_header->OptionalHeader.SizeOfHeaders;
			int  nSectionSize = nt_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			int  nMoveSize = nHeaderSize + nSectionSize;
			RtlCopyMemory(m_image.data(), buff_byte, nMoveSize);
		}
		{
			for (auto i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
			{
				if (section_header[i].VirtualAddress == 0 || section_header[i].SizeOfRawData == 0)
				{
					continue;
				}
				// 定位该节在内存中的位置
				void *pSectionAddress = (void *)((PBYTE)m_image.data() + section_header[i].VirtualAddress);
				// 复制段数据到虚拟内存
				RtlCopyMemory(pSectionAddress, &(buff_byte[section_header[i].PointerToRawData]), section_header[i].SizeOfRawData);
			}
		}
		b_loaded = true;
	} while (0);
	return b_loaded;
}
void CPeLib::dump_info()
{
	if (b_loaded)
	{
		dump_dos_header();
		dump_nt_header();
		dump_section_headers();
		dump_iat();
		dump_eat();
		dump_dbg();
		dump_res();
	}
}


void CPeLib::dump_dos_header()
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	std::cout << "[IMAGE_DOS_HEADER]" << std::endl;
	std::cout << "offset\tvalue\t description\r\n";
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << int(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};
	new_print(&dos_header->e_magic, dos_header->e_magic, "dos header sig");
	new_print(&dos_header->e_lfanew, dos_header->e_lfanew, "offset to nt header");
	//new_print(sizeof(IMAGE_DOS_HEADER) + int(&dos_header), dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER), "dos stub");
	//std::cout << "dos_header offset =" << std::hex << FIELD_OFFSET(IMAGE_DOS_HEADER, e_lfanew) << " e_lfanew = " << dos_header->e_lfanew << std::endl;
	std::cout << "dos stub offset = " << std::hex << sizeof(IMAGE_DOS_HEADER) << " size = " << dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER) << std::endl;
}


void CPeLib::dump_nt_header()
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	auto st_offset = dos_header->e_lfanew;
	std::cout << "[IMAGE_NT_HEADERS]" << std::endl;
	std::cout << "offset\tvalue\t description\r\n";
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << int(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};
	new_print(&nt_header->Signature, nt_header->Signature, "nt header sig");
	//std::cout << "nt signature offset = " << std::hex<<st_offset << " value = " << nt_header->Signature << std::endl;
	//std::cout << "nt file header offset = " << std::hex<<st_offset + FIELD_OFFSET(IMAGE_NT_HEADERS32, FileHeader) << " value = " << &nt_header->FileHeader << std::endl;
	dump_file_header(&nt_header->FileHeader);
	if (nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		dump_option_header64();
	}
	else
	{
		dump_option_header32();
	}
}


void CPeLib::dump_file_header(PIMAGE_FILE_HEADER file_header)
{
	std::cout << "[IMAGE_FILE_HEADER]" << std::endl;
	std::cout << "offset\tvalue\t description\r\n";
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << int(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};
	new_print(&file_header->Machine, file_header->Machine, "machine");
	new_print(&file_header->NumberOfSections, file_header->NumberOfSections, "section number");
	new_print(&file_header->TimeDateStamp, file_header->TimeDateStamp, "TimeDateStamp");
	new_print(&file_header->PointerToSymbolTable, file_header->PointerToSymbolTable, "offset to symbol table");
	new_print(&file_header->NumberOfSymbols, file_header->NumberOfSymbols, "number of symbols");
	new_print(&file_header->SizeOfOptionalHeader, file_header->SizeOfOptionalHeader, "size of optional header");
	new_print(&file_header->Characteristics, file_header->Characteristics, "Characteristics");
}


void CPeLib::dump_option_header32()
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	std::cout << "[IMAGE_OPTIONAL_HEADER32]" << std::endl;
	std::cout << "offset\tvalue\t description\r\n";
	auto opt_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(&nt_header->OptionalHeader);
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << int(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};
	new_print(&opt_header->Magic, opt_header->Magic, "Magic");
	new_print(&opt_header->MajorLinkerVersion, (opt_header->MajorLinkerVersion), "MajorLinkerVersion");
	new_print(&opt_header->MinorLinkerVersion, (opt_header->MinorLinkerVersion), "MinorLinkerVersion");

	new_print(&opt_header->SizeOfCode, opt_header->SizeOfCode, "SizeOfCode");

	new_print(&opt_header->SizeOfInitializedData, opt_header->SizeOfInitializedData, "SizeOfInitializedData");
	new_print(&opt_header->SizeOfUninitializedData, opt_header->SizeOfUninitializedData, "SizeOfUninitializedData");

	new_print(&opt_header->AddressOfEntryPoint, opt_header->AddressOfEntryPoint, "AddressOfEntryPoint EP!!!!!!");

	new_print(&opt_header->BaseOfCode, opt_header->BaseOfCode, "BaseOfCode");
	new_print(&opt_header->BaseOfData, opt_header->BaseOfData, "BaseOfData");

	new_print(&opt_header->ImageBase, opt_header->ImageBase, "ImageBase");

	new_print(&opt_header->SectionAlignment, opt_header->SectionAlignment, "SectionAlignment");
	new_print(&opt_header->FileAlignment, opt_header->FileAlignment, "FileAlignment");

	new_print(&opt_header->MajorOperatingSystemVersion, opt_header->MajorOperatingSystemVersion, "MajorOperatingSystemVersion");
	new_print(&opt_header->MinorOperatingSystemVersion, opt_header->MinorOperatingSystemVersion, "MinorOperatingSystemVersion");

	new_print(&opt_header->MajorImageVersion, opt_header->MajorImageVersion, "MajorImageVersion");
	new_print(&opt_header->MinorImageVersion, opt_header->MinorImageVersion, "MinorImageVersion");

	new_print(&opt_header->MajorSubsystemVersion, opt_header->MajorSubsystemVersion, "MajorSubsystemVersion");
	new_print(&opt_header->MinorSubsystemVersion, opt_header->MinorSubsystemVersion, "MinorSubsystemVersion");

	new_print(&opt_header->Win32VersionValue, opt_header->Win32VersionValue, "Win32VersionValue");

	new_print(&opt_header->SizeOfImage, opt_header->SizeOfImage, "SizeOfImage");

	new_print(&opt_header->SizeOfHeaders, opt_header->SizeOfHeaders, "SizeOfHeaders");

	new_print(&opt_header->CheckSum, opt_header->CheckSum, "CheckSum");

	new_print(&opt_header->Subsystem, opt_header->Subsystem, "Subsystem");

	new_print(&opt_header->DllCharacteristics, opt_header->DllCharacteristics, "DllCharacteristics");


	new_print(&opt_header->SizeOfStackReserve, opt_header->SizeOfStackReserve, "SizeOfStackReserve");
	new_print(&opt_header->SizeOfStackCommit, opt_header->SizeOfStackCommit, "SizeOfStackCommit");
	new_print(&opt_header->SizeOfHeapReserve, opt_header->SizeOfHeapReserve, "SizeOfHeapReserve");
	new_print(&opt_header->SizeOfHeapCommit, opt_header->SizeOfHeapCommit, "SizeOfHeapCommit");


	new_print(&opt_header->LoaderFlags, opt_header->LoaderFlags, "LoaderFlags");

	new_print(&opt_header->NumberOfRvaAndSizes, opt_header->NumberOfRvaAndSizes, "NumberOfRvaAndSizes");

	std::string descp[] =
	{
		"export directory",
		"import directory",
		"resources directory",
		"exception directory",
		"security directory",
		"basereloc directory",
		"debug directory",
		"copyright directory",
		"globalptr directory",
		"tls directory",
		"load config directory",
		"bound import directory",
		"IAT directory",
		"daley import directory",
		"com descriptor directory",
		"reserved directory",
	};
	for (DWORD i = 0; i < opt_header->NumberOfRvaAndSizes; i++)
	{
		auto directory_header = &opt_header->DataDirectory[i];
		std::cout << "[IMAGE_DIRECTORY_HEADER] [" << std::hex << i << "]" << std::endl;
		if (i < 16)
		{
			std::cout << descp[i] << std::endl;
		}
		std::cout << "offset\tvalue\t description\r\n";
		new_print(&directory_header->VirtualAddress, directory_header->VirtualAddress, "VirtualAddress");
		new_print(&directory_header->Size, directory_header->Size, "Size");
	}
}


void CPeLib::dump_option_header64()
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	std::cout << "[IMAGE_OPTIONAL_HEADER64]" << std::endl;
	std::cout << "offset\tvalue\t description\r\n";
	auto opt_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(&nt_header->OptionalHeader);
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << __int64(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};

	new_print(&opt_header->Magic, opt_header->Magic, "Magic");
	new_print(&opt_header->MajorLinkerVersion, (opt_header->MajorLinkerVersion), "MajorLinkerVersion");
	new_print(&opt_header->MinorLinkerVersion, (opt_header->MinorLinkerVersion), "MinorLinkerVersion");

	new_print(&opt_header->SizeOfCode, opt_header->SizeOfCode, "SizeOfCode");

	new_print(&opt_header->SizeOfInitializedData, opt_header->SizeOfInitializedData, "SizeOfInitializedData");
	new_print(&opt_header->SizeOfUninitializedData, opt_header->SizeOfUninitializedData, "SizeOfUninitializedData");

	new_print(&opt_header->AddressOfEntryPoint, opt_header->AddressOfEntryPoint, "AddressOfEntryPoint EP!!!!!!");

	new_print(&opt_header->BaseOfCode, opt_header->BaseOfCode, "BaseOfCode");
	//new_print(&opt_header->BaseOfData, opt_header->BaseOfData, "BaseOfData");

	new_print(&opt_header->ImageBase, opt_header->ImageBase, "ImageBase");

	new_print(&opt_header->SectionAlignment, opt_header->SectionAlignment, "SectionAlignment");
	new_print(&opt_header->FileAlignment, opt_header->FileAlignment, "FileAlignment");

	new_print(&opt_header->MajorOperatingSystemVersion, opt_header->MajorOperatingSystemVersion, "MajorOperatingSystemVersion");
	new_print(&opt_header->MinorOperatingSystemVersion, opt_header->MinorOperatingSystemVersion, "MinorOperatingSystemVersion");

	new_print(&opt_header->MajorImageVersion, opt_header->MajorImageVersion, "MajorImageVersion");
	new_print(&opt_header->MinorImageVersion, opt_header->MinorImageVersion, "MinorImageVersion");

	new_print(&opt_header->MajorSubsystemVersion, opt_header->MajorSubsystemVersion, "MajorSubsystemVersion");
	new_print(&opt_header->MinorSubsystemVersion, opt_header->MinorSubsystemVersion, "MinorSubsystemVersion");

	new_print(&opt_header->Win32VersionValue, opt_header->Win32VersionValue, "Win32VersionValue");

	new_print(&opt_header->SizeOfImage, opt_header->SizeOfImage, "SizeOfImage");

	new_print(&opt_header->SizeOfHeaders, opt_header->SizeOfHeaders, "SizeOfHeaders");

	new_print(&opt_header->CheckSum, opt_header->CheckSum, "CheckSum");

	new_print(&opt_header->Subsystem, opt_header->Subsystem, "Subsystem");

	new_print(&opt_header->DllCharacteristics, opt_header->DllCharacteristics, "DllCharacteristics");


	new_print(&opt_header->SizeOfStackReserve, opt_header->SizeOfStackReserve, "SizeOfStackReserve");
	new_print(&opt_header->SizeOfStackCommit, opt_header->SizeOfStackCommit, "SizeOfStackCommit");
	new_print(&opt_header->SizeOfHeapReserve, opt_header->SizeOfHeapReserve, "SizeOfHeapReserve");
	new_print(&opt_header->SizeOfHeapCommit, opt_header->SizeOfHeapCommit, "SizeOfHeapCommit");


	new_print(&opt_header->LoaderFlags, opt_header->LoaderFlags, "LoaderFlags");

	new_print(&opt_header->NumberOfRvaAndSizes, opt_header->NumberOfRvaAndSizes, "NumberOfRvaAndSizes");

	std::string descp[] =
	{
		"export directory",
		"import directory",
		"resources directory",
		"exception directory",
		"security directory",
		"basereloc directory",
		"debug directory",
		"copyright directory",
		"globalptr directory",
		"tls directory",
		"load config directory",
		"bound import directory",
		"IAT directory",
		"daley import directory",
		"com descriptor directory",
		"reserved directory",
	};
	for (DWORD i = 0; i < opt_header->NumberOfRvaAndSizes; i++)
	{
		auto directory_header = &opt_header->DataDirectory[i];
		std::cout << "[IMAGE_DIRECTORY_HEADER] [" << std::hex << i << "]" << std::endl;
		if (i < 16)
		{
			std::cout << descp[i] << std::endl;
		}
		std::cout << "offset\tvalue\t description\r\n";
		new_print(&directory_header->VirtualAddress, directory_header->VirtualAddress, "VirtualAddress");
		new_print(&directory_header->Size, directory_header->Size, "Size");
	}
}


void CPeLib::dump_section_headers()
{
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	auto section_header = IMAGE_FIRST_SECTION(nt_header);
	auto new_print = [=](auto offset, auto value, auto descript) {
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << reinterpret_cast<int>(offset) - reinterpret_cast<int>(&m_image[0])
			<< std::setw(8) << std::hex << int(value) << std::setw(8) << std::string(" ") + descript << std::endl;
	};
	for (auto i = 0; i < nt_header->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &section_header[i];
		CHAR name[IMAGE_SIZEOF_SHORT_NAME+1] = { 0 };
		RtlCopyMemory(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
		std::cout << "[IMAGE_SECNTION_HEADERS]" << "["<<i<<"]"<<std::endl;
		std::cout << "offset\tvalue\t description\r\n";
		new_print(&section->Name, section->Name, std::string("name = ") + std::string(name));
		new_print(&section->VirtualAddress, section->VirtualAddress, "VirtualAddress");
		new_print(&section->SizeOfRawData, section->SizeOfRawData, "SizeOfRawData");
		new_print(&section->PointerToRawData, section->PointerToRawData, "PointerToRawData");
		new_print(&section->PointerToRelocations, section->PointerToRelocations, "PointerToRelocations");
		new_print(&section->PointerToLinenumbers, section->PointerToLinenumbers, "PointerToLinenumbers");
		new_print(&section->NumberOfRelocations, section->NumberOfRelocations, "NumberOfRelocations");
		new_print(&section->NumberOfLinenumbers, section->NumberOfLinenumbers, "NumberOfLinenumbers");
		new_print(&section->Characteristics, section->Characteristics, "Characteristics");
	}
}


void CPeLib::dump_iat()
{
	
	if (b_image64)
	{
		dump_iat64();
	}
	else
	{
		dump_iat32();
	}
}


void CPeLib::dump_iat32()
{
	std::cout << "[IAT]" << std::endl;
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	auto nOffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (nOffset == 0)
	{
		return;
	}
	auto image_base = reinterpret_cast<char *>(dos_header);
	auto iat_header = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base + nOffset);
	while (iat_header->Characteristics != 0)
	{
		auto real_iat = reinterpret_cast<PIMAGE_THUNK_DATA32>(image_base + iat_header->FirstThunk);
		auto orig_iat = reinterpret_cast<PIMAGE_THUNK_DATA32>(image_base + iat_header->OriginalFirstThunk);
		//获取dll的名字
#define NAME_BUF_SIZE 256

		char dll_name[NAME_BUF_SIZE] = { 0 }; //dll name;
		auto p_name = reinterpret_cast<BYTE*>(image_base + iat_header->Name);
		int i = 0;

		for (i = 0; i < NAME_BUF_SIZE; i++)
		{
			if (p_name[i] == 0)
			{
				break;
			}
			dll_name[i] = p_name[i];
		}
		if (i >= NAME_BUF_SIZE)
		{
			break;
		}
		else
		{
			dll_name[i] = 0;
		}
		std::cout << "import dll name = " << dll_name << std::endl;
		for (i = 0; ; i++)
		{
			if (orig_iat[i].u1.Function == 0)
			{
				break;
			}
			if (orig_iat[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
			{
				std::cout << "import by ordinal " << int(orig_iat[i].u1.Ordinal) << std::endl;
			}
			else //按照名字导入
			{
				//获取此IAT项所描述的函数名称
				auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + orig_iat[i].u1.AddressOfData);
				std::cout << "import by name " << std::string(by_name->Name) << std::endl;
			}
		}
		iat_header = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char *>(iat_header) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

}


void CPeLib::dump_iat64()
{
	std::cout << "[IAT]" << std::endl;
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
	auto nOffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (nOffset==0)
	{
		return;
	}
	auto image_base = reinterpret_cast<char *>(dos_header);
	auto iat_header = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image_base+ nOffset);
	while (iat_header->Characteristics != 0)
	{
		auto real_iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + iat_header->FirstThunk);
		auto orig_iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + iat_header->OriginalFirstThunk);
		//获取dll的名字
#define NAME_BUF_SIZE 256

		char dll_name[NAME_BUF_SIZE] = { 0 }; //dll name;
		auto p_name = reinterpret_cast<BYTE*>(image_base + iat_header->Name);
		int i = 0;

		for (i = 0; i < NAME_BUF_SIZE; i++)
		{
			if (p_name[i] == 0)
			{
				break;
			}
			dll_name[i] = p_name[i];
		}
		if (i >= NAME_BUF_SIZE)
		{
			break;
		}
		else
		{
			dll_name[i] = 0;
		}
		std::cout << "import dll name = " << dll_name << std::endl;
		for (i = 0; ; i++)
		{
			if (orig_iat[i].u1.Function == 0)
			{
				break;
			}
			if (orig_iat[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
			{
				std::cout << "import by ordinal " << int(orig_iat[i].u1.Ordinal) << std::endl;
			}
			else //按照名字导入
			{
				//获取此IAT项所描述的函数名称
				auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + orig_iat[i].u1.AddressOfData);
				std::cout << "import by name " << std::string(by_name->Name) << std::endl;
			}
		}
		iat_header = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char *>(iat_header) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

}


void CPeLib::dump_eat()
{
	std::cout << "[EAT]" << std::endl;
	auto noffset = 0;
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	if (b_image64)
	{
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		noffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else
	{
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		noffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	
	if (noffset==0)
	{
		return;
	}
	auto image_base = reinterpret_cast<char *>(dos_header);
	
	auto export_table = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(image_base + noffset);
	auto AddressOfFunctions = reinterpret_cast<PULONG>(image_base+export_table->AddressOfFunctions);
	auto AddrOfOrdinals = reinterpret_cast<PSHORT>(image_base+export_table->AddressOfNameOrdinals);
	auto AddressOfNames = reinterpret_cast<PULONG>(image_base+ export_table->AddressOfNames);
	std::cout << "RVA\tname" << std::endl;
	for (ULONG i = 0; i < export_table->NumberOfFunctions; i++)
	{
		auto name = reinterpret_cast<char *>(image_base + AddressOfNames[i]);
		std::cout << std::setiosflags(std::ios::left) << std::setw(8) << std::hex << int(AddressOfFunctions[AddrOfOrdinals[i]])
			<< std::string(" ") + name << std::endl;
	}

}


void CPeLib::dump_dbg()
{
	std::cout << "[DBG]" << std::endl;
	auto noffset = 0;
	auto nsize = 0;
	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
	if (b_image64)
	{
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		noffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		nsize = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}
	else
	{
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS32>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		noffset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		nsize = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}

	if (noffset == 0)
	{
		return;
	}
	auto image_base = reinterpret_cast<char *>(dos_header);

	auto dbg_header = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(image_base + noffset);
	for (unsigned int i = 0; i < nsize / sizeof(IMAGE_DEBUG_DIRECTORY);i++)
	{
		if (dbg_header[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			auto cvinfo = reinterpret_cast<CV_HEADER *>(image_base + dbg_header[i].AddressOfRawData);
			if (cvinfo->CvSignature == CV_SIGNATURE_NB10)
			{
				auto p_cv_info = reinterpret_cast<CV_INFO_PDB20 *>(image_base + dbg_header[i].AddressOfRawData);
				std::cout << "pdb filename = " << reinterpret_cast<char *>(p_cv_info->PdbFileName) << std::endl;
			}
			if (cvinfo->CvSignature == CV_SIGNATURE_RSDS)
			{
				CHAR szSymSignature[65] = { 0 };
				auto pCvData = reinterpret_cast<CV_INFO_PDB70 *>(image_base + dbg_header[i].AddressOfRawData);
				_snprintf_s(szSymSignature, 64,
					"%08X%04X%04X%02hX%02hX%02hX%02hX%02hX%02hX%02hX%02hX%d",
					pCvData->Signature.Data1, pCvData->Signature.Data2,
					pCvData->Signature.Data3, pCvData->Signature.Data4[0],
					pCvData->Signature.Data4[1], pCvData->Signature.Data4[2],
					pCvData->Signature.Data4[3], pCvData->Signature.Data4[4],
					pCvData->Signature.Data4[5], pCvData->Signature.Data4[6],
					pCvData->Signature.Data4[7], pCvData->Age);
				std::cout << "pdb filename = " << reinterpret_cast<char *>(pCvData->PdbFileName) << std::endl;
				std::cout << "pdb sig = " << szSymSignature << std::endl;
			}
		}
		if (dbg_header[i].Type == IMAGE_DEBUG_TYPE_MISC)
		{
			auto dbg_misc = reinterpret_cast<IMAGE_DEBUG_MISC *>(image_base + dbg_header[i].AddressOfRawData);
			std::cout << "pdb filename = " << reinterpret_cast<char*>(dbg_misc->Data) << std::endl;
		}
	}

}


void CPeLib::dump_res()
{
	std::cout << "[RESOURCE]" << std::endl;
	std::cout << "not support now" << std::endl;
}


void CPeLib::get_image(std::vector<BYTE> & image)
{
	if(b_loaded)
		image = std::vector<BYTE>(m_image);
}


bool CPeLib::is_image64()
{
	return b_image64;
}
