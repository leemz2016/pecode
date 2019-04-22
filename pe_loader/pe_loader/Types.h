#pragma once
#include "NtLdr.h"
#include "functionTypes.h"

#include <stdint.h>
#include <string>

namespace magic
{

typedef uint64_t ptr_t;     // Generic pointer in remote process
typedef ptr_t    module_t;  // Module base pointer

// PEB helper
template<typename T>
struct _PEB_T2
{
    typedef typename std::conditional<std::is_same<T, DWORD>::value, _PEB32, _PEB64>::type type;
};

// Type of barrier
enum WoW64Type
{
    wow_32_32 = 0,  // Both processes are WoW64 
    wow_64_64,      // Both processes are x64
    wow_32_64,      // Managing x64 process from WoW64 process
    wow_64_32,      // Managing WOW64 process from x64 process
};

struct Wow64Barrier
{
    WoW64Type type = wow_32_32;
    bool sourceWow64 = false;
    bool targetWow64 = false;
    bool x86OS = false;
};

// Module type
enum eModType
{
    mt_mod32,       // 64 bit module
    mt_mod64,       // 32 bit module
    mt_default,     // type is deduced from target process
    mt_unknown      // Failed to detect type
};

// Module search method
enum eModSeachType
{
    LdrList,        // InLoadOrder list
    Sections,       // Scan for section objects
    PEHeaders,      // Scan for PE headers in memory
};

// Wow64 register helper
union reg64
{
    uint32_t dw[2];
    uint64_t v;
};


}
