#include "stdafx.h"
#include "PeLibEx.h"
#include "VersionHelpers.h"
#include "NtLdr.h"
#include "DynImport.h"
#include "Types.h"
#include "PEImage.h"
#include "PatternSearch.h"
#include "Macro.h"

namespace magic
{
	CPeLibEx::CPeLibEx()
	{
		_hctx = INVALID_HANDLE_VALUE;
		init();
	}


	CPeLibEx::~CPeLibEx()
	{
		m_image.clear();
		m_image.resize(1);
		if (_hctx != INVALID_HANDLE_VALUE)
		{
			ReleaseActCtx(_hctx);
			DeleteFileW(_manifestPath.c_str());
			_hctx = INVALID_HANDLE_VALUE;
		}
	}


	bool CPeLibEx::load_pe_file(std::string file_name)
	{
		auto load = m_pelib.load_pe_file(file_name);
		do
		{
			if (!load)
			{
				break;
			}
			m_pelib.get_image(m_image);
			DWORD dwOld = 0;
			VirtualProtect(m_image.data(), m_image.size(), PAGE_EXECUTE_READWRITE, &dwOld);
			//先解析拆分一些结构
			parse_image();
			//处理reloc
			reloc_image();
			//处理iat
			rebuild_import();
			//处理mainfest
			load_manifest();
			//处理exception
			load_exception();
			//处理security cookie
			init_security_cookie();
			//处理tls 结构
			init_tls();
			//修复ldr ref
			if (!_isExe)
			{
				//DLL需要建立THREAD ATATCH的LdrRef
				init_ldr_ref();
			}
			//修复资源访问问题
			//STATUS_TIMEOUT

		} while (0);
		return false;
	}


	void CPeLibEx::run_image()
	{
		//创建AtxContext!!
		//先运行tls
		//然后根据exe还是dll进行dllmain和winmain的运行处理！！
		DWORD cookie = 0;
		typedef LONG(__stdcall *RtlActivateActivationContext_)(int, HANDLE, DWORD *);
		typedef LONG(__stdcall *RtlDeactivateActivationContext_)(int, DWORD);
		auto call_2 = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDeactivateActivationContext");
		auto call_ = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlActivateActivationContext");
		auto fnRtlActivateActivationContext = reinterpret_cast<RtlActivateActivationContext_>(call_);
		auto fnRtlDeactivateActivationContext = reinterpret_cast<RtlDeactivateActivationContext_>(call_2);
		if(_hctx !=INVALID_HANDLE_VALUE)
			fnRtlActivateActivationContext(0, _hctx, &cookie);
		if (!_isExe)
		{
			int size_ = 0;
			auto tls_dir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(get_section(IMAGE_DIRECTORY_ENTRY_TLS, size_));
			if (tls_dir)
			{
				auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls_dir->AddressOfCallBacks);
				if (callback) {
					while (*callback) {
						(*callback)((LPVOID)m_image.data(), DLL_PROCESS_ATTACH, NULL);
						callback++;
					}
				}
			}
			typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE, DWORD , LPVOID);
			auto ep = reinterpret_cast<DllEntryProc>(reinterpret_cast<char *>(m_image.data()) + _ep_offset);
			ep(reinterpret_cast<HINSTANCE>(m_image.data()), DLL_PROCESS_ATTACH, 0);
		}
		else
		{
#ifndef _WIN64
			DWORD dwMapBase = DWORD(m_image.data());
			DWORD dwEp = dwMapBase + _ep_offset;
			__asm
			{
				mov eax, dword ptr fs : [0x18]//设置imagebase
				mov eax, dword ptr ds : [eax + 0x30]
				mov ebx, dwMapBase
				mov[eax + 0x8], ebx
				mov eax, dwEp
					//__asm int 3
				call eax
			}
#endif
		}
		if (_hctx)
		{
			fnRtlDeactivateActivationContext(0, cookie);
		}
	}


	bool CPeLibEx::_is64()
	{
		return m_pelib.is_image64();
	}


	void CPeLibEx::reloc_image()
	{
		int sec_size = 0;
		auto reloc_ = reinterpret_cast<PIMAGE_BASE_RELOCATION>(get_section(IMAGE_DIRECTORY_ENTRY_BASERELOC, sec_size));
		auto reloc_offset = reinterpret_cast<UINT_PTR>(m_image.data()) - reinterpret_cast<UINT_PTR>(_imgBase);
		if (reloc_ != nullptr)
		{
			while ((reloc_->SizeOfBlock+reloc_->VirtualAddress) != 0)
			{
				auto reloc_data = reinterpret_cast<PIMAGE_RELOCATE>(reinterpret_cast<char*>(reloc_) + sizeof(IMAGE_BASE_RELOCATION));
				//计算本节需要修正的重定位项（地址）的数目
				int nNumberOfReloc = (reloc_->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATE);

				for (int i = 0; i < nNumberOfReloc; i++)
				{
					auto x = reinterpret_cast<char*>(m_image.data()) + reloc_->VirtualAddress;
					switch (reloc_data[i].type) {
					case IMAGE_REL_BASED_DIR64:
						*((UINT_PTR*)(x + reloc_data[i].offset)) += reloc_offset;
						break;
					case IMAGE_REL_BASED_HIGHLOW:
						*((DWORD*)(x + reloc_data[i].offset)) += (DWORD)reloc_offset;
						break;

					case IMAGE_REL_BASED_HIGH:
						*((WORD*)(x + reloc_data[i].offset)) += HIWORD(reloc_offset);
						break;

					case IMAGE_REL_BASED_LOW:
						*((WORD*)(x + reloc_data[i].offset)) += LOWORD(reloc_offset);
						break;

					case IMAGE_REL_BASED_ABSOLUTE:
						break;

					default:
						break;
					}
				}
				reloc_ = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<char *>(reloc_) + reloc_->SizeOfBlock);
			}
		}
	}


	void CPeLibEx::rebuild_import()
	{
		int sec_size = 0;
		auto image_base = reinterpret_cast<char *>(m_image.data());
		auto iat_dir = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(get_section(IMAGE_DIRECTORY_ENTRY_IMPORT, sec_size));
		if (iat_dir == nullptr)
		{
			//理论上这里有问题，如果IAT不行就要使用应该使用delay import
			return;
		}
		while (iat_dir->Characteristics != 0)
		{

			if (!_is64())
			{
				auto real_iat = reinterpret_cast<PIMAGE_THUNK_DATA32>(image_base + iat_dir->FirstThunk);
				auto orig_iat = reinterpret_cast<PIMAGE_THUNK_DATA32>(image_base + iat_dir->OriginalFirstThunk);
				//获取dll的名字
#define NAME_BUF_SIZE 256

				char dll_name[NAME_BUF_SIZE + 1] = { 0 }; //dll name;
				auto p_name = reinterpret_cast<BYTE*>(image_base + iat_dir->Name);
				for (auto i = 0; i < NAME_BUF_SIZE; i++)
				{
					if (p_name[i] == 0)
					{
						break;
					}
					dll_name[i] = p_name[i];
				}
				{
					dll_name[NAME_BUF_SIZE] = 0;
				}
				//std::cout << "import dll name = " << dll_name << std::endl;
				auto h_dll = LoadLibraryA(dll_name);
				for (auto i = 0; ; i++)
				{
					auto function_address = FARPROC(NULL);
					if (orig_iat[i].u1.Function == 0)
					{
						break;
					}
					if (orig_iat[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
					{
						function_address = GetProcAddress(h_dll, reinterpret_cast<LPCSTR>(orig_iat[i].u1.Ordinal & 0x0000FFFF));
						//std::cout << "import by ordinal " << int(orig_iat[i].u1.Ordinal) << std::endl;
					}
					else //按照名字导入
					{
						//获取此IAT项所描述的函数名称
						auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + orig_iat[i].u1.AddressOfData);
						//std::cout << "import by name " << std::string(by_name->Name) << std::endl;
						function_address = GetProcAddress(h_dll, by_name->Name);
					}
					if (function_address)
					{
						real_iat[i].u1.Function = reinterpret_cast<DWORD>(function_address);
					}
				}
			}
			else
			{
				auto real_iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + iat_dir->FirstThunk);
				auto orig_iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(image_base + iat_dir->OriginalFirstThunk);
				//获取dll的名字
#define NAME_BUF_SIZE 256

				char dll_name[NAME_BUF_SIZE + 1] = { 0 }; //dll name;
				auto p_name = reinterpret_cast<BYTE*>(image_base + iat_dir->Name);
				for (auto i = 0; i < NAME_BUF_SIZE; i++)
				{
					if (p_name[i] == 0)
					{
						break;
					}
					dll_name[i] = p_name[i];
				}
				{
					dll_name[NAME_BUF_SIZE] = 0;
				}
				//std::cout << "import dll name = " << dll_name << std::endl;
				auto h_dll = LoadLibraryA(dll_name);
				for (auto i = 0; ; i++)
				{
					auto function_address = FARPROC(NULL);
					if (orig_iat[i].u1.Function == 0)
					{
						break;
					}
					if (orig_iat[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
					{
						function_address = GetProcAddress(h_dll, reinterpret_cast<LPCSTR>(orig_iat[i].u1.Ordinal & 0x0000FFFF));
						//std::cout << "import by ordinal " << int(orig_iat[i].u1.Ordinal) << std::endl;
					}
					else //按照名字导入
					{
						//获取此IAT项所描述的函数名称
						auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image_base + orig_iat[i].u1.AddressOfData);
						//std::cout << "import by name " << std::string(by_name->Name) << std::endl;
						function_address = GetProcAddress(h_dll, by_name->Name);
					}
					if (function_address)
					{
						real_iat[i].u1.Function = reinterpret_cast<ULONGLONG>(function_address);
					}
				}
			}
			iat_dir = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<char *>(iat_dir) + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
	}


	void CPeLibEx::parse_image()
	{
		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_image.data());
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char *>(dos_header) + dos_header->e_lfanew);
		_isExe = !(nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL);
		if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			m_nt_header64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_header);
			_imgBase = reinterpret_cast<PVOID>(m_nt_header64->OptionalHeader.ImageBase);
			_ep_offset = m_nt_header64->OptionalHeader.AddressOfEntryPoint;
		}
		else
		{
			m_nt_header32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_header);
			_imgBase = reinterpret_cast<PVOID>(m_nt_header32->OptionalHeader.ImageBase);
			_ep_offset = m_nt_header32->OptionalHeader.AddressOfEntryPoint;
		}
	}


	PVOID CPeLibEx::get_section(int index, int &sec_size)
	{
		auto dir_header = _is64() ? m_nt_header64->OptionalHeader.DataDirectory : m_nt_header32->OptionalHeader.DataDirectory;
		auto dir_ptr = dir_header[index];
		if (dir_ptr.Size == 0 || dir_ptr.VirtualAddress == 0)
		{
			return nullptr;
		}
		auto pheader = reinterpret_cast<PVOID>(reinterpret_cast<char *>(m_image.data()) + dir_ptr.VirtualAddress);
		sec_size = dir_ptr.Size;
		return pheader;
	}


	void CPeLibEx::load_manifest()
	{
		int size_ = 0;
		int id_ = 0;
		auto _mainfest = get_manifest(size_, id_);
		if (_mainfest != nullptr)
		{
			wchar_t tempDir[256] = { 0 };
			ACTCTXW act = { 0 };
			act.cbSize = sizeof(act);
			GetTempPathW(ARRAYSIZE(tempDir), tempDir);
			wchar_t tempPath[256] = { 0 };
			if (GetTempFileNameW(tempDir, L"ImageManifest", 0, tempPath) == 0)
				return;

			HANDLE hTmpFile = CreateFileW(tempPath, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
			if (hTmpFile != INVALID_HANDLE_VALUE)
			{
				DWORD bytes = 0;
				WriteFile(hTmpFile, _mainfest, size_, &bytes, NULL);
				CloseHandle(hTmpFile);

				act.lpSource = tempPath;
				_manifestPath = tempPath;

				_hctx = CreateActCtxW(&act);
			}
		}
	}


	PVOID CPeLibEx::get_manifest(int & _size, int & _id)
	{
		// 3 levels of pointers to nodes
		const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode1 = nullptr;
		const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode2 = nullptr;
		const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode3 = nullptr;

		// 3 levels of nodes
		const IMAGE_RESOURCE_DIRECTORY       *pDirNodePtr1 = nullptr;
		const IMAGE_RESOURCE_DIRECTORY       *pDirNodePtr2 = nullptr;
		const IMAGE_RESOURCE_DIRECTORY       *pDirNodePtr3 = nullptr;

		// resource entry data
		const IMAGE_RESOURCE_DATA_ENTRY      *pDataNode = nullptr;

		size_t ofst_1 = 0;  // first level nodes offset
		size_t ofst_2 = 0;  // second level nodes offset
		size_t ofst_3 = 0;  // third level nodes offset

		int size_ = 0;
		// Get section base
		auto secBase = reinterpret_cast<char*>(get_section(IMAGE_DIRECTORY_ENTRY_RESOURCE, size_));
		if (secBase == nullptr)
		{
			_size = 0;
			_size = 0;
			return nullptr;
		}

		pDirNodePtr1 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(secBase);
		ofst_1 += sizeof(IMAGE_RESOURCE_DIRECTORY);

		// first-level nodes
		for (int i = 0; i < pDirNodePtr1->NumberOfIdEntries + pDirNodePtr1->NumberOfNamedEntries; ++i)
		{
			pDirNode1 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_1);

			// Not a manifest directory
			if (!pDirNode1->DataIsDirectory || pDirNode1->Id != 0x18)
			{
				ofst_1 += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
				continue;
			}

			pDirNodePtr2 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(secBase + pDirNode1->OffsetToDirectory);
			ofst_2 = pDirNode1->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);

			// second-level nodes
			for (int j = 0; j < pDirNodePtr2->NumberOfIdEntries + pDirNodePtr2->NumberOfNamedEntries; ++j)
			{
				pDirNode2 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_2);

				if (!pDirNode2->DataIsDirectory)
				{
					ofst_2 += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
					continue;
				}

				// Check if this is a valid manifest resource
				if (pDirNode2->Id == 1 || pDirNode2->Id == 2 || pDirNode2->Id == 3)
				{
					pDirNodePtr3 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(secBase + pDirNode2->OffsetToDirectory);
					ofst_3 = pDirNode2->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
					pDirNode3 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_3);
					pDataNode = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(secBase + pDirNode3->OffsetToData);

					_id = pDirNode2->Id;
					_size = pDataNode->Size;

					return reinterpret_cast<void*>(reinterpret_cast<char*>(m_image.data()) + pDataNode->OffsetToData);
				}

				ofst_2 += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
			}

			ofst_1 += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		}

		return nullptr;
	}


	void CPeLibEx::load_exception()
	{
		//这是一个大问题在win8 win10 win7上处理方式非常复杂
		int size_ = 0;
		auto exception_header = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(get_section(IMAGE_DIRECTORY_ENTRY_EXCEPTION, size_));
		if (exception_header != nullptr)
		{
#ifdef _WIN64
			//64系统就是这么简单的！
			RtlAddFunctionTable((PRUNTIME_FUNCTION)(exception_header), size_ / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)m_image.data());
#else
			//32位...复杂到爆炸的开始了
			InsertInvertedFunctionTable();
#endif
		}
	}


	void CPeLibEx::FindLdrpHashTable()
	{
		using namespace magic;
		PEB_LDR_DATA_T *Ldr =
			reinterpret_cast<PEB_LDR_DATA_T*>(
				reinterpret_cast<PEB_T*>(
					reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock)->Ldr);

		LDR_DATA_TABLE_ENTRY_BASE_T *Ntdll = CONTAINING_RECORD(Ldr->InInitializationOrderModuleList.Flink,
			LDR_DATA_TABLE_ENTRY_BASE_T, InInitializationOrderLinks);

		ULONG NtdllHashIndex = HashString(reinterpret_cast<wchar_t*>(Ntdll->BaseDllName.Buffer)) & 0x1F;

		ULONG_PTR NtdllBase = static_cast<ULONG_PTR>(Ntdll->DllBase);
		ULONG_PTR NtdllEndAddress = NtdllBase + Ntdll->SizeOfImage - 1;

		// scan hash list to the head (head is located within ntdll)
		bool bHeadFound = false;
		PLIST_ENTRY pNtdllHashHead = NULL;

		for (PLIST_ENTRY e = reinterpret_cast<PLIST_ENTRY>(Ntdll->HashLinks.Flink);
		e != reinterpret_cast<PLIST_ENTRY>(&Ntdll->HashLinks);
			e = e->Flink)
		{
			if (reinterpret_cast<ULONG_PTR>(e) >= NtdllBase &&
				reinterpret_cast<ULONG_PTR>(e) < NtdllEndAddress)
			{
				bHeadFound = true;
				pNtdllHashHead = e;
				break;
			}
		}

		if (bHeadFound)
			_LdrpHashTable = reinterpret_cast<uintptr_t>(pNtdllHashHead - NtdllHashIndex);

		return;
	}

	ULONG CPeLibEx::HashString(const std::wstring& str)
	{
		ULONG hash = 0;
		using namespace magic;
		if (IsWindows8OrGreater())
		{
			UNICODE_STRING ustr;
			SAFE_CALL(RtlInitUnicodeString, &ustr, str.c_str());
			SAFE_NATIVE_CALL(RtlHashUnicodeString, &ustr, (BOOLEAN)TRUE, 0, &hash);
		}
		else
		{
			for (auto& ch : str)
				hash += 0x1003F * static_cast<unsigned short>(SAFE_CALL(RtlUpcaseUnicodeChar, ch));
		}

		return hash;
	}

	void CPeLibEx::init()
	{
		using namespace magic;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

		DynImport::load("RtlInitUnicodeString", hNtdll);
		DynImport::load("RtlHashUnicodeString", hNtdll);
		DynImport::load("RtlUpcaseUnicodeChar", hNtdll);
		DynImport::load("RtlEncodeSystemPointer", hNtdll);

		FindLdrpHashTable();
		FindLdrHeap();

		if (IsWindows8OrGreater())
			FindLdrpModuleIndexBase();

		ScanPatterns();
		_nodeMap.clear();

	}


	void CPeLibEx::FindLdrHeap()
	{
		using namespace magic;
		int32_t retries = 10;
		MEMORY_BASIC_INFORMATION64 mbi = { 0 };
		{
			auto Ldr = reinterpret_cast<PEB_LDR_DATA_T *>(
				reinterpret_cast<PEB_T*>(
					reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock)->Ldr);
			auto NtdllEntry = CONTAINING_RECORD(Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY_BASE_T, InMemoryOrderLinks);
			VirtualQueryEx(
				GetCurrentProcess(), reinterpret_cast<LPCVOID>(NtdllEntry),
				reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&mbi),
				sizeof(MEMORY_BASIC_INFORMATION)
				);
			{
				_LdrHeapBase = static_cast<uintptr_t>(mbi.AllocationBase);
			}
		}
		return;
	}


	void CPeLibEx::FindLdrpModuleIndexBase()
	{
		using namespace magic;
		PEB_T* pPeb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);

		if (pPeb)
		{
			PRTL_BALANCED_NODE lastNode = 0;
			PEB_LDR_DATA_T* Ldr = reinterpret_cast<PEB_LDR_DATA_T*>(pPeb->Ldr);
			_LDR_DATA_TABLE_ENTRY_W8 *Ntdll = CONTAINING_RECORD(Ldr->InInitializationOrderModuleList.Flink,
				_LDR_DATA_TABLE_ENTRY_W8, InInitializationOrderLinks);

			PRTL_BALANCED_NODE pNode = &Ntdll->BaseAddressIndexNode;

			// Get root node
			for (; pNode->ParentValue; )
			{
				// Ignore last few bits
				lastNode = reinterpret_cast<PRTL_BALANCED_NODE>(pNode->ParentValue & uintptr_t(-8));
				pNode = lastNode;
			}

			// Get pointer to root
			pe::PEImage ntdll;
			uintptr_t* pStart = nullptr;
			uintptr_t* pEnd = nullptr;

			ntdll.Parse(reinterpret_cast<void*>(Ntdll->DllBase));

			for (auto& section : ntdll.sections())
				if (_stricmp(reinterpret_cast<LPCSTR>(section.Name), ".data") == 0)
				{
					pStart = reinterpret_cast<uintptr_t*>(Ntdll->DllBase + section.VirtualAddress);
					pEnd = reinterpret_cast<uintptr_t*>(Ntdll->DllBase + section.VirtualAddress + section.Misc.VirtualSize);

					break;
				}

			auto iter = std::find(pStart, pEnd, reinterpret_cast<uintptr_t>(lastNode));

			if (iter != pEnd)
			{
				_LdrpModuleIndexBase = reinterpret_cast<uintptr_t>(iter);
				return;
			}
		}

		return;
	}


	void CPeLibEx::ScanPatterns()
	{
		using namespace magic;
		std::vector<ptr_t> foundData;
		pe::PEImage ntdll;
		void* pStart = nullptr;
		size_t scanSize = 0;

		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		ntdll.Parse(hNtdll);

		// Find ntdll code section
		for (auto& section : ntdll.sections())
		{
			if (_stricmp(reinterpret_cast<LPCSTR>(section.Name), ".text") == 0)
			{
				pStart = reinterpret_cast<void*>(reinterpret_cast<size_t>(hNtdll) + section.VirtualAddress);
				scanSize = section.Misc.VirtualSize;

				break;
			}
		}

		// Code section not found
		if (pStart == nullptr)
			return;

		// Win 8.1 and later
		if (IsWindows8Point1OrGreater())
		{
#ifdef _WIN64
			// LdrpHandleTlsData
			// 44 8D 43 09 4C 8D 4C 24 38
			PatternSearch ps("\x44\x8d\x43\x09\x4c\x8d\x4c\x24\x38");
			ps.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0x43);
#else
			// RtlInsertInvertedFunctionTable
			// 53 56 57 8B DA 8B F9 50 
			PatternSearch ps1("\x53\x56\x57\x8b\xda\x8b\xf9\x50");
			ps1.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_RtlInsertInvertedFunctionTable = static_cast<size_t>(foundData.front() - 0xB);

				if (IsWindows10OrGreater())
					_LdrpInvertedFunctionTable = *reinterpret_cast<uintptr_t*>(foundData.front() + 0x22);
				else
					_LdrpInvertedFunctionTable = *reinterpret_cast<uintptr_t*>(foundData.front() + 0x23);

				foundData.clear();
			}
			// Rescan using old pattern
			else
			{
				// RtlInsertInvertedFunctionTable
				// 8D 45 F4 89 55 F8 50 8D 55 FC
				PatternSearch ps12("\x8d\x45\xf4\x89\x55\xf8\x50\x8d\x55\xfc");
				ps12.Search(pStart, scanSize, foundData);

				if (!foundData.empty())
				{
					_RtlInsertInvertedFunctionTable = static_cast<uintptr_t>(foundData.front() - 0xB);
					_LdrpInvertedFunctionTable = *reinterpret_cast<uintptr_t*>(foundData.front() + 0x1D);
					foundData.clear();
				}
			}

			// LdrpHandleTlsData
			// 8D 45 ?? 50 6A 09 6A 01 8B C1
			PatternSearch ps2("\x8d\x45\xcc\x50\x6a\x09\x6a\x01\x8b\xc1");
			ps2.Search(0xCC, pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0x18);
				foundData.clear();
			}

			// LdrProtectMrdata
			// 83 7D 08 00 8B 35    
			PatternSearch ps3("\x83\x7d\x08\x00\x8b\x35", 6);
			ps3.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
				_LdrProtectMrdata = static_cast<uintptr_t>(foundData.front() - 0x12);
#endif
		}
		// Win 8
		else if (IsWindows8OrGreater())
		{
#ifdef _WIN64
			// LdrpHandleTlsData
			// 48 8B 79 30 45 8D 66 01
			PatternSearch ps("\x48\x8b\x79\x30\x45\x8d\x66\x01");
			ps.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0x49);
#else
			// RtlInsertInvertedFunctionTable
			// 8B FF 55 8B EC 51 51 53 57 8B 7D 08 8D
			PatternSearch ps1("\x8b\xff\x55\x8b\xec\x51\x51\x53\x57\x8b\x7d\x08\x8d");
			ps1.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_RtlInsertInvertedFunctionTable = static_cast<uintptr_t>(foundData.front());
				_LdrpInvertedFunctionTable = *reinterpret_cast<uintptr_t*>(_RtlInsertInvertedFunctionTable + 0x26);
				foundData.clear();
			}

			// LdrpHandleTlsData
			// 8B 45 08 89 45 A0
			PatternSearch ps2("\x8b\x45\x08\x89\x45\xa0");
			ps2.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0xC);
#endif
		}
		// Win 7
		else if (IsWindows7OrGreater())
		{
#ifdef _WIN64
			// LdrpHandleTlsData
			// 41 B8 09 00 00 00 48 8D 44 24 38
			PatternSearch ps1("\x41\xb8\x09\x00\x00\x00\x48\x8d\x44\x24\x38", 11);
			ps1.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0x27);
				foundData.clear();
			}

			// LdrpFindOrMapDll patch address
			// 48 8D 8C 24 98 00 00 00 41 b0 01
			PatternSearch ps2("\x48\x8D\x8C\x24\x98\x00\x00\x00\x41\xb0\x01", 11);
			ps2.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_LdrKernel32PatchAddress = static_cast<uintptr_t>(foundData.front() + 0x12);
				foundData.clear();
			}

			// KiUserApcDispatcher patch address
			// 48 8B 4C 24 18 48 8B C1 4C
			PatternSearch ps3("\x48\x8b\x4c\x24\x18\x48\x8b\xc1\x4c");
			ps3.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_APC64PatchAddress = static_cast<uintptr_t>(foundData.front());
				foundData.clear();
			}
#else
			// RtlInsertInvertedFunctionTable
			// 8B FF 55 8B EC 56 68
			PatternSearch ps1("\x8b\xff\x55\x8b\xec\x56\x68");
			ps1.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_RtlInsertInvertedFunctionTable = static_cast<size_t>(foundData.front());
				foundData.clear();
			}

			// RtlLookupFunctionTable + 0x11
			// 89 5D E0 38
			PatternSearch ps2("\x89\x5D\xE0\x38");
			ps2.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
			{
				_LdrpInvertedFunctionTable = *reinterpret_cast<uintptr_t*>(foundData.front() + 0x1B);
				foundData.clear();
			}

			// LdrpHandleTlsData
			// 74 20 8D 45 D4 50 6A 09 
			PatternSearch ps3("\x74\x20\x8d\x45\xd4\x50\x6a\x09");
			ps3.Search(pStart, scanSize, foundData);

			if (!foundData.empty())
				_LdrpHandleTlsData = static_cast<uintptr_t>(foundData.front() - 0x14);

#endif
		}
	}


	void CPeLibEx::InsertInvertedFunctionTable()
	{
		using namespace magic;
		auto ModBase = m_image.data();
		RTL_INVERTED_FUNCTION_TABLE7 table = { 0 };
		PRTL_INVERTED_FUNCTION_TABLE_ENTRY Entries = nullptr;
		// Invalid addresses. Probably pattern scan has failed
		if (_RtlInsertInvertedFunctionTable == 0 || _LdrpInvertedFunctionTable == 0)
			return;

		if (IsWindows8OrGreater())
			Entries = reinterpret_cast<decltype(Entries)>(GET_FIELD_PTR(reinterpret_cast<PRTL_INVERTED_FUNCTION_TABLE8>(&table), Entries));
		else
			Entries = reinterpret_cast<decltype(Entries)>(GET_FIELD_PTR(&table, Entries));

		RtlCopyMemory(&table, (PVOID)_LdrpInvertedFunctionTable, sizeof(table));
		for (DWORD i = 0; i < table.Count; i++)
			if (Entries[i].ImageBase == ModBase)
				return;

		typedef void(__fastcall *_RtlInsertInvertedFunctionTable_w10)(uintptr_t, size_t);
		typedef void(__stdcall *_RtlInsertInvertedFunctionTable_w8)(uintptr_t, size_t);
		typedef void(__stdcall *_RtlInsertInvertedFunctionTable_w7)(uintptr_t, uintptr_t, size_t);
		//a.GenPrologue();

		if (IsWindows8Point1OrGreater())
		{
			auto func = reinterpret_cast<_RtlInsertInvertedFunctionTable_w10>(_RtlInsertInvertedFunctionTable);
			func(reinterpret_cast<uintptr_t>(ModBase), m_image.size());
		
		}
		else if (IsWindows8OrGreater())
		{
			auto func = reinterpret_cast<_RtlInsertInvertedFunctionTable_w8>(_RtlInsertInvertedFunctionTable);
			func(reinterpret_cast<uintptr_t>(ModBase), m_image.size());
			
		}
		else
		{
			auto func = reinterpret_cast<_RtlInsertInvertedFunctionTable_w7>(_RtlInsertInvertedFunctionTable);
			func(_LdrpInvertedFunctionTable, reinterpret_cast<uintptr_t>(ModBase), m_image.size());
		}

		RtlCopyMemory(&table, (PVOID)_LdrpInvertedFunctionTable, sizeof(table));
		for (DWORD i = 0; i < table.Count; i++)
		{
			if (Entries[i].ImageBase != ModBase)
				continue;

			// If Image has SAFESEH, RtlInsertInvertedFunctionTable is enough
			if (Entries[i].SizeOfTable != 0)
				return;

			//
			// Create fake Exception directory
			// Directory will be filled later, during exception handling
			//
			PIMAGE_RUNTIME_FUNCTION_ENTRY pImgEntry = nullptr;

			// Allocate memory for 512 possible handlers
			auto block = malloc(sizeof(DWORD) * 0x200);
			pImgEntry = reinterpret_cast<decltype(pImgEntry)>(block);

			auto pEncoded = EncodeSystemPointer(pImgEntry);

			// m_LdrpInvertedFunctionTable->Entries[i].ExceptionDirectory
			uintptr_t field_ofst = reinterpret_cast<uintptr_t>(&Entries[i].ExceptionDirectory)
				- reinterpret_cast<uintptr_t>(&table);

			// In Win10 _LdrpInvertedFunctionTable is located in mrdata section
			// mrdata is read-only by default 
			// LdrProtectMrdata is used to make it writable when needed
			DWORD flOld = 0;
			VirtualProtect((LPVOID)(_LdrpInvertedFunctionTable + field_ofst), sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &flOld);
			*(uintptr_t *)(_LdrpInvertedFunctionTable + field_ofst) = reinterpret_cast<uintptr_t>(pEncoded);
			VirtualProtect((LPVOID)(_LdrpInvertedFunctionTable + field_ofst), sizeof(uintptr_t), flOld, &flOld);

			//TODO：注册一个VEH处理的nonsafe的seh...

			return;
		}

		return;
	}


	void CPeLibEx::init_security_cookie()
	{
		int size_ = 0;
		auto sec64 = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY64>(get_section(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, size_));
		auto sec32 = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY32>(get_section(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, size_));
		FILETIME systime = { 0 };
		LARGE_INTEGER PerformanceCount = { { 0 } };
		uintptr_t cookie = 0;

		GetSystemTimeAsFileTime(&systime);
		QueryPerformanceCounter(&PerformanceCount);

		cookie = GetCurrentProcessId() ^ GetCurrentThreadId() ^ reinterpret_cast<uintptr_t>(&cookie);

#ifdef _WIN64
		cookie ^= *reinterpret_cast<uint64_t*>(&systime);
		cookie ^= (PerformanceCount.QuadPart << 32) ^ PerformanceCount.QuadPart;
		cookie &= 0xFFFFFFFFFFFF;

		if (cookie == 0x2B992DDFA232)
			cookie++;
#else

		cookie ^= systime.dwHighDateTime ^ systime.dwLowDateTime;
		cookie ^= PerformanceCount.LowPart;
		cookie ^= PerformanceCount.HighPart;

		if (cookie == 0xBB40E64E)
			cookie++;
		else if (!(cookie & 0xFFFF0000))
			cookie |= (cookie | 0x4711) << 16;
#endif
		if (!_is64())
		{
			//sec->SecurityCookie
			if (sec32 && sec32->SecurityCookie)
			{
				auto rva = sec32->SecurityCookie - reinterpret_cast<ULONG_PTR>(_imgBase);
				auto write_address = sec32->SecurityCookie;//reinterpret_cast<char *>(m_image.data()) + rva;
				*(uintptr_t *)(write_address) = cookie;
			}
		}
		else
		{
			if (sec64 && sec64->SecurityCookie)
			{
				auto rva = sec64->SecurityCookie - reinterpret_cast<ULONG_PTR>(_imgBase);
				auto write_address = sec64->SecurityCookie;// reinterpret_cast<char *>(m_image.data()) + rva;
				*(uintptr_t *)(write_address) = cookie;
			}
		}
	}


	void CPeLibEx::init_tls()
	{
		int size_ = 0;
		auto pModule = m_image.data();
		IMAGE_TLS_DIRECTORY *pTls = reinterpret_cast<decltype(pTls)>(get_section(IMAGE_DIRECTORY_ENTRY_TLS, size_));
		if (pTls && pTls->AddressOfIndex)
		{
			using namespace magic;
			auto teb = reinterpret_cast<TEB_T*>(NtCurrentTeb());
			bool wxp = IsWindowsXPOrGreater() && !IsWindowsVistaOrGreater();

			void* pNode = _nodeMap.count(reinterpret_cast<HMODULE>(pModule)) ?
				_nodeMap[reinterpret_cast<HMODULE>(pModule)] : nullptr;

			// Allocate appropriate structure
			if ((pNode = SetNode(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pNode), pModule)) == nullptr)
				return;

			// Use native method
			if (_LdrpHandleTlsData)
			{
				typedef void(__stdcall *_LdrpHandleTlsData_w7)(uintptr_t);
				typedef void(__thiscall *_LdrpHandleTlsData_w10)(uintptr_t);
				if (IsWindows8Point1OrGreater())
				{
					auto func = reinterpret_cast<_LdrpHandleTlsData_w10>(_LdrpHandleTlsData);
					func(reinterpret_cast<uintptr_t>(pNode));
				}
				else
				{
					auto func = reinterpret_cast<_LdrpHandleTlsData_w7>(_LdrpHandleTlsData);
					func(reinterpret_cast<uintptr_t>(pNode));
				}

			}
		}
	}

	template<typename T>
	T* CPeLibEx::SetNode(T* ptr, void* pModule)
	{
		if (ptr == nullptr)
		{
			auto rgn = VirtualAlloc(nullptr, sizeof(T), MEM_COMMIT, PAGE_READWRITE);
			if (rgn)
			{
				ptr = reinterpret_cast<T*>(rgn);
				ptr->DllBase = pModule;
			}
		}

		return ptr;
	}

	void CPeLibEx::init_ldr_ref()
	{
		using namespace magic;
		auto ImageSize = m_image.size();
		auto hMod = m_image.data();
		std::wstring DllBasePath;
		wchar_t tempDir[256] = { 0 };
		ACTCTXW act = { 0 };
		act.cbSize = sizeof(act);
		GetTempPathW(ARRAYSIZE(tempDir), tempDir);
		wchar_t tempPath[256] = { 0 };
		StringCbPrintfW(tempPath, sizeof(tempPath), L"%ws%x.dll", tempDir, GetTickCount());
		DllBasePath = std::wstring(tempPath);
		auto ep = reinterpret_cast<uintptr_t>(hMod) + _ep_offset;
		if (IsWindows8OrGreater())
		{
			ULONG hash = 0;
			_LDR_DATA_TABLE_ENTRY_W8 *pEntry = InitW8Node(reinterpret_cast<void*>(hMod), ImageSize, DllBasePath, ep, hash);
			_nodeMap[reinterpret_cast<HMODULE>(hMod)]=reinterpret_cast<void *>(pEntry);

			// Insert into LdrpHashTable
			InsertHashNode(GET_FIELD_PTR(pEntry, HashLinks), hash);

			// Insert into module graph
			InsertTreeNode(pEntry, reinterpret_cast<uintptr_t>(hMod));

			//插入到THREADXX
			{
				pEntry->Flags = 0x80004;
				InsertMemModuleNode(0, GET_FIELD_PTR(pEntry, InLoadOrderLinks),
					GET_FIELD_PTR(pEntry, InInitializationOrderLinks));
			}
		}
		// Windows 7 and earlier
		else
		{
			ULONG hash = 0;
			_LDR_DATA_TABLE_ENTRY_W7 *pEntry = InitW7Node(reinterpret_cast<void*>(hMod), ImageSize, DllBasePath, ep, hash);
			_nodeMap[reinterpret_cast<HMODULE>(hMod)] = reinterpret_cast<void *>(pEntry);
			
			InsertHashNode(GET_FIELD_PTR(pEntry, HashLinks), hash);

			{
				pEntry->Flags = 0x80004;
				InsertMemModuleNode(0, GET_FIELD_PTR(pEntry, InLoadOrderLinks), 0);
			}
		}
	}

	_LDR_DATA_TABLE_ENTRY_W8* CPeLibEx::InitW8Node(
		void* ModuleBase,
		size_t ImageSize,
		const std::wstring& dllpath,
		uintptr_t entryPoint,
		ULONG& outHash
		)
	{
		std::wstring dllname = Utils::StripPath(dllpath);
		UNICODE_STRING strLocal = { 0 };
		uint64_t result = 0;

		_LDR_DATA_TABLE_ENTRY_W8 *pEntry = nullptr;
		_LDR_DDAG_NODE *pDdagNode = nullptr;


		auto StringBuf = malloc(0x1000);

		{
			auto block = malloc(sizeof(_LDR_DATA_TABLE_ENTRY_W8));
			pEntry = reinterpret_cast<_LDR_DATA_TABLE_ENTRY_W8*>(block);
		}

		if (pEntry)
		{
			
			{
				auto block = malloc(sizeof(_LDR_DDAG_NODE));
				pDdagNode = reinterpret_cast<_LDR_DDAG_NODE*>(block);
			}

			if (pDdagNode)
			{
				 pEntry->DllBase = reinterpret_cast<decltype(pEntry->DllBase)>(ModuleBase);
			
				 pEntry->SizeOfImage = ImageSize;
				
				 pEntry->EntryPoint = entryPoint;
			
				// Dll name and name hash
				SAFE_CALL(RtlInitUnicodeString, &strLocal, dllname.c_str());
				outHash = HashString(dllname);

				// Write into buffer
				strLocal.Buffer = reinterpret_cast<PWSTR>(StringBuf);
				
				RtlCopyMemory(StringBuf, dllname.c_str(), dllname.length() * sizeof(wchar_t) + 2);
				
				RtlCopyMemory(&pEntry->BaseDllName, &strLocal, sizeof(strLocal));
			
				// Dll full path
				SAFE_CALL(RtlInitUnicodeString, &strLocal, dllpath.c_str());
				strLocal.Buffer = reinterpret_cast<PWSTR>(reinterpret_cast<uint8_t*>(StringBuf) + 0x800);
				RtlCopyMemory(reinterpret_cast<uint8_t*>(StringBuf) + 0x800, dllpath.c_str(), dllpath.length() * sizeof(wchar_t) + 2);

				
				RtlCopyMemory(&pEntry->FullDllName, &strLocal, sizeof(strLocal));
				
				 pEntry->BaseNameHashValue = outHash;

				//
				// Ddag node
				//

				 pEntry->DdagNode = pDdagNode;
		
				 pDdagNode->State = LdrModulesReadyToRun;

				 pDdagNode->ReferenceCount = 1;

				 pDdagNode->LoadCount = -1;

				return pEntry;
			}

			return nullptr;
		}

		return nullptr;
	}
	void CPeLibEx::InsertHashNode(uintptr_t pNodeLink, ULONG hash)
	{
		if (pNodeLink)
		{
			// LrpHashTable record
			auto pHashList =*(reinterpret_cast<uintptr_t *>(_LdrpHashTable + sizeof(LIST_ENTRY)*(hash & 0x1F)));
			InsertTailList(pHashList, pNodeLink);
		}
	}
	void CPeLibEx::InsertTailList(uintptr_t ListHead, uintptr_t Entry)
	{
		auto PrevEntry = reinterpret_cast<PLIST_ENTRY>(ListHead)->Blink;
		
		auto entry = reinterpret_cast<PLIST_ENTRY>(Entry);
		entry->Flink = reinterpret_cast<PLIST_ENTRY>(ListHead);
		entry->Blink = PrevEntry;
	
		 PrevEntry->Flink = entry;
		 reinterpret_cast<PLIST_ENTRY>(ListHead)->Blink  = entry;
	
	}

	void CPeLibEx::InsertTreeNode(_LDR_DATA_TABLE_ENTRY_W8* pNode, uintptr_t modBase)
	{
		//
		// Win8 module tree
		//
		uintptr_t root = *(reinterpret_cast<uintptr_t *>(_LdrpModuleIndexBase));

		_LDR_DATA_TABLE_ENTRY_W8 *pLdrNode = CONTAINING_RECORD(root, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
		_LDR_DATA_TABLE_ENTRY_W8 *LdrNode = reinterpret_cast<_LDR_DATA_TABLE_ENTRY_W8 *>(reinterpret_cast<ptr_t>(pLdrNode));

		bool bRight = false;

		// Walk tree
		for (;;)
		{
			if (modBase < LdrNode->DllBase)
			{
				if (LdrNode->BaseAddressIndexNode.Left)
				{
					pLdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Left, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
					LdrNode = pLdrNode;
				}
				else
					break;
			}
			else if (modBase  > LdrNode->DllBase)
			{
				if (LdrNode->BaseAddressIndexNode.Right)
				{
					pLdrNode = CONTAINING_RECORD(LdrNode->BaseAddressIndexNode.Right, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
					
					LdrNode = pLdrNode;
				}
				else
				{
					bRight = true;
					break;
				}
			}
			// Already in tree (increase ref counter)
			else
			{
				pLdrNode->DdagNode->ReferenceCount++;
				
				return;
			}
		}

		// Insert using RtlRbInsertNodeEx

	
		typedef void(__stdcall *RtlRbInsertNodeEx_w10)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
		auto RtlRbInsertNodeEx = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRbInsertNodeEx");
		auto func = reinterpret_cast<RtlRbInsertNodeEx_w10>(RtlRbInsertNodeEx);
		func(_LdrpModuleIndexBase,
			GET_FIELD_PTR(pLdrNode, BaseAddressIndexNode),
			static_cast<uintptr_t>(bRight), GET_FIELD_PTR(pNode, BaseAddressIndexNode));
	}

	void CPeLibEx::InsertMemModuleNode(uintptr_t pNodeMemoryOrderLink, uintptr_t pNodeLoadOrderLink, uintptr_t pNodeInitOrderLink)
	{
		PEB_T* pPeb = reinterpret_cast<PEB_T*>(reinterpret_cast<TEB_T*>(NtCurrentTeb())->ProcessEnvironmentBlock);
		PEB_LDR_DATA_T* pLdr = nullptr;

		if (pPeb)
			pLdr = reinterpret_cast<decltype(pLdr)>(pPeb->Ldr);

		if (pLdr)
		{
			// pLdr->InMemoryOrderModuleList
			if (pNodeMemoryOrderLink)
				InsertTailList(GET_FIELD_PTR(pLdr, InMemoryOrderModuleList), pNodeMemoryOrderLink);

			// pLdr->InLoadOrderModuleList
			if (pNodeLoadOrderLink)
				InsertTailList(GET_FIELD_PTR(pLdr, InLoadOrderModuleList), pNodeLoadOrderLink);

			// pLdr->InInitializationOrderModuleList
			if (pNodeInitOrderLink)
				InsertTailList(GET_FIELD_PTR(pLdr, InInitializationOrderModuleList), pNodeInitOrderLink);
		}
	}
	_LDR_DATA_TABLE_ENTRY_W7* CPeLibEx::InitW7Node(
		void* ModuleBase,
		size_t ImageSize,
		const std::wstring& dllpath,
		uintptr_t entryPoint,
		ULONG& outHash
		)
	{
		std::wstring dllname = Utils::StripPath(dllpath);
		UNICODE_STRING strLocal = { 0 };
		uint64_t result = 0;

		_LDR_DATA_TABLE_ENTRY_W7 *pEntry = nullptr;


		// Allocate space for Unicode string
		auto StringBuf = malloc(0x1000);
		
		{
			auto block = malloc(sizeof(_LDR_DATA_TABLE_ENTRY_W7));
			pEntry = reinterpret_cast<_LDR_DATA_TABLE_ENTRY_W7*>(block);
		}

		if (pEntry)
		{
			 pEntry->DllBase = reinterpret_cast<decltype(pEntry->DllBase)>(ModuleBase);

			 pEntry->SizeOfImage = ImageSize;
		
			 pEntry->EntryPoint = entryPoint;

			 pEntry->LoadCount = -1;

			// Dll name
			SAFE_CALL(RtlInitUnicodeString, &strLocal, dllname.c_str());

			// Name hash
			outHash = HashString(dllname);

			strLocal.Buffer = reinterpret_cast<PWSTR>(StringBuf);
			
			RtlCopyMemory(StringBuf, dllname.c_str(), dllname.length() * sizeof(wchar_t) + 2);

			RtlCopyMemory(&pEntry->BaseDllName, &strLocal, sizeof(strLocal));

			// Dll full path
			SAFE_CALL(RtlInitUnicodeString, &strLocal, dllpath.c_str());
			strLocal.Buffer = reinterpret_cast<PWSTR>(reinterpret_cast<uint8_t*>(StringBuf) + 0x800);
			RtlCopyMemory(reinterpret_cast<uint8_t*>(StringBuf) + 0x800, dllpath.c_str(), dllpath.length() * sizeof(wchar_t) + 2);

			
			RtlCopyMemory(&pEntry->FullDllName, &strLocal, sizeof(strLocal));
			

			// Forward Links
			pEntry->ForwarderLinks.Blink = pEntry->ForwarderLinks.Blink;
			pEntry->ForwarderLinks.Flink = pEntry->ForwarderLinks.Blink;
			
			return pEntry;
		}

		return nullptr;
	}
}

