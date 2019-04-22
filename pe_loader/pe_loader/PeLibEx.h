#pragma once
#include "PeLib.h"
#include "NtLdr.h"
struct alignas(2) _IMAGE_RELOCATE_
{
	WORD	offset : 12;
	WORD	type : 4;
};
using IMAGE_RELOCATE = _IMAGE_RELOCATE_;
using PIMAGE_RELOCATE = IMAGE_RELOCATE *;
namespace magic
{
	class CPeLibEx
	{
	public:
		CPeLibEx();
		~CPeLibEx();
	private:
		CPeLib m_pelib;
		std::vector<BYTE> m_image;
		PIMAGE_NT_HEADERS32 m_nt_header32;
		PIMAGE_NT_HEADERS64 m_nt_header64;
	private:
		PVOID _imgBase;
		DWORD _ep_offset;
		bool _isExe;
		HANDLE _hctx;
		std::wstring _manifestPath;
	private:
		ULONG HashString(const std::wstring& str);
	public:
		bool load_pe_file(std::string file_name);
		void run_image();
	private:
		bool _is64();
		void reloc_image();
		void rebuild_import();
		void parse_image();
		PVOID get_section(int index, int & sec_size);
		void load_manifest();
		PVOID get_manifest(int & _size, int & _id);
		void load_exception();
		void FindLdrpHashTable();

	private:
		uintptr_t _LdrpHashTable = 0;                        // LdrpHashTable address
		uintptr_t _LdrpModuleIndexBase = 0;                  // LdrpModuleIndex address
		uintptr_t _LdrHeapBase = 0;                          // Loader heap base address
		uintptr_t _LdrKernel32PatchAddress = 0;              // Address to patch to enable kernel32 loading under win7
		uintptr_t _APC64PatchAddress = 0;                    // Address to patch for x64->WOW64 APC dispatching under win7
		uintptr_t _LdrpHandleTlsData = 0;                    // LdrpHandleTlsData address
		uintptr_t _LdrpInvertedFunctionTable = 0;            // LdrpInvertedFunctionTable address
		uintptr_t _RtlInsertInvertedFunctionTable = 0;       // RtlInsertInvertedFunctionTable address
		uintptr_t _LdrProtectMrdata = 0;                     // LdrProtectMrdata address

		std::map<HMODULE, void*> _nodeMap;                  // Allocated native structures
	private:
		void init();
	private:
		void FindLdrHeap();
		void FindLdrpModuleIndexBase();
	private:
		void ScanPatterns();
		void InsertInvertedFunctionTable();
		void init_security_cookie();
	private:
		void init_tls();
		template<typename T>
		T* SetNode(T* ptr, void* pModule);
		void init_ldr_ref();
	private:
		_LDR_DATA_TABLE_ENTRY_W8* InitW8Node(
			void* ModuleBase,
			size_t ImageSize,
			const std::wstring& dllpath,
			uintptr_t entryPoint,
			ULONG& outHash
			);
		_LDR_DATA_TABLE_ENTRY_W7* InitW7Node(
			void* ModuleBase,
			size_t ImageSize,
			const std::wstring& dllpath,
			uintptr_t entryPoint,
			ULONG& outHash
			);
		void InsertHashNode(uintptr_t pNodeLink, ULONG hash);
		void InsertTailList(uintptr_t ListHead, uintptr_t Entry);
		void InsertTreeNode(_LDR_DATA_TABLE_ENTRY_W8* pNode, uintptr_t modBase);
		void InsertMemModuleNode(uintptr_t pNodeMemoryOrderLink, uintptr_t pNodeLoadOrderLink, uintptr_t pNodeInitOrderLink);
	};

}