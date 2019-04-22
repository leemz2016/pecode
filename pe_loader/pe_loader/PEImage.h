#pragma once
#include "NtLdr.h"
#include "DynImport.h"
#include "Types.h"
#include "ImageNET.h"

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <list>

namespace magic
{

namespace pe
{

// Relocation block information
struct RelocData
{
    ULONG PageRVA;
    ULONG BlockSize;

    struct
    {
        WORD Offset : 12; 
        WORD Type   : 4; 
    }Item[1];
};
 
/// <summary>
/// Import information
/// </summary>
struct ImportData
{
    std::string importName;     // Function name
    uintptr_t ptrRVA;            // Function pointer RVA in
    WORD importOrdinal;         // Function ordinal
    bool importByOrd;           // Function is imported by ordinal
};

/// <summary>
/// Export function info
/// </summary>
struct ExportData
{
    std::string name;
    uint32_t RVA = 0;

    ExportData( const std::string& name_, uint32_t rva_ )
        : name( name_ )
        , RVA( rva_ ) { }

    bool operator == (const ExportData& other)
    {
        return name == other.name;
    }

    bool operator < (const ExportData& other)
    {
        return name < other.name;
    }
};

// Imports and sections related
typedef std::unordered_map<std::wstring, std::vector<ImportData>> mapImports;
typedef std::vector<IMAGE_SECTION_HEADER> vecSections;
typedef std::vector<ExportData> vecExports;

/// <summary>
/// Primitive PE parsing class
/// </summary>
class PEImage
{
    typedef const IMAGE_NT_HEADERS32* PCHDR32;
    typedef const IMAGE_NT_HEADERS64* PCHDR64;
    
public:
     PEImage( void );
     ~PEImage( void );

    /// <summary>
    /// Load image from file
    /// </summary>
    /// <param name="path">File path</param>
    /// <param name="skipActx">If true - do not initialize activation context</param>
    /// <returns>Status code</returns>
     NTSTATUS Load( const std::wstring& path, bool skipActx = false );

    /// <summary>
    /// Load image from memory location
    /// </summary>
    /// <param name="pData">Image data</param>
    /// <param name="size">Data size.</param>
    /// <param name="plainData">If false - data has image layout</param>
    /// <returns>Status code</returns>
     NTSTATUS Load( void* pData, size_t size, bool plainData = true );

    /// <summary>
    /// Reload closed image
    /// </summary>
    /// <returns>Status code</returns>
     NTSTATUS Reload();

    /// <summary>
    /// Release mapping, if any
    /// </summary>
    /// <param name="temporary">Preserve file paths for file reopening</param>
     void Release( bool temporary = false );

    /// <summary>
    /// Parses PE image
    /// </summary>
    /// <returns>Status code</returns>
     NTSTATUS Parse( void* pImageBase = nullptr );

    /// <summary>
    /// Processes image imports
    /// </summary>
    /// <param name="useDelayed">Process delayed import instead</param>
    /// <returns>Import data</returns>
     mapImports& GetImports( bool useDelayed = false );

    /// <summary>
    /// Retrieve all exported functions with names
    /// </summary>
    /// <param name="names">Found exports</param>
     void GetExports( vecExports& exports );

    /// <summary>
    /// Retrieve image TLS callbacks
    /// Callbacks are rebased for target image
    /// </summary>
    /// <param name="targetBase">Target image base</param>
    /// <param name="result">Found callbacks</param>
    /// <returns>Number of TLS callbacks in image</returns>
     int GetTLSCallbacks( module_t targetBase, std::vector<ptr_t>& result ) const;

    /// <summary>
    /// Retrieve data directory address
    /// </summary>
    /// <param name="index">Directory index</param>
    /// <param name="keepRelative">Keep address relative to image base</param>
    /// <returns>Directory address</returns>
     size_t DirectoryAddress( int index, bool keepRelative = false ) const;

    /// <summary>
    /// Get data directory size
    /// </summary>
    /// <param name="index">Data directory index</param>
    /// <returns>Data directory size</returns>
     size_t DirectorySize( int index ) const;

    /// <summary>
    /// Resolve virtual memory address to physical file offset
    /// </summary>
    /// <param name="Rva">Memory address</param>
    /// <param name="keepRelative">Keep address relative to file start</param>
    /// <returns>Resolved address</returns>
     uintptr_t ResolveRVAToVA( uintptr_t Rva, bool keepRelative = false ) const;

    /// <summary>
    /// Get image path
    /// </summary>
    /// <returns>Image path</returns>
     inline const std::wstring& path() const { return _imagePath; }

    /// <summary>
    /// Get image name
    /// </summary>
    /// <returns>Image name</returns>
     inline std::wstring name() const { return Utils::StripPath( _imagePath ); }

    /// <summary>
    /// Get image load address
    /// </summary>
    /// <returns>Image base</returns>
     inline void* base() const { return _pFileBase; }

    /// <summary>
    /// Get image base address
    /// </summary>
    /// <returns>Image base</returns>
     inline module_t imageBase() const { return _imgBase; }

    /// <summary>
    /// Get image size in bytes
    /// </summary>
    /// <returns>Image size</returns>
     inline size_t imageSize() const { return _imgSize; }

    /// <summary>
    /// Get size of image headers
    /// </summary>
    /// <returns>Size of image headers</returns>
     inline size_t headersSize() const { return _hdrSize; }

    /// <summary>
    /// Get image entry point rebased to another image base
    /// </summary>
    /// <param name="base">New image base</param>
    /// <returns>New entry point address</returns>
     inline ptr_t entryPoint( module_t base ) const { return ((_epRVA != 0) ? (_epRVA + base) : 0); };

    /// <summary>
    /// Get image sections
    /// </summary>
    /// <returns>Image sections</returns>
     inline const vecSections& sections() const { return _sections; }

    /// <summary>
    /// Check if image is an executable file and not a dll
    /// </summary>
    /// <returns>true if image is an *.exe</returns>
     inline bool isExe() const { return _isExe; }

    /// <summary>
    /// Check if image is pure IL image
    /// </summary>
    /// <returns>true on success</returns>
     inline bool pureIL() const  { return _isPureIL; }
     inline int32_t ilFlagOffset() const { return _ILFlagOffset; }

    /// <summary>
    /// Get image type. 32/64 bit
    /// </summary>
    /// <returns>Image type</returns>
     inline eModType mType() const { return _is64 ? mt_mod64 : mt_mod32; }

    /// <summary>
    /// Get activation context handle
    /// </summary>
    /// <returns>Actx handle</returns>
     inline HANDLE actx() const { return _hctx; }

    /// <summary>
    /// true if image is mapped as plain data file
    /// </summary>
    /// <returns>true if mapped as plain data file, false if mapped as image</returns>
     inline bool isPlainData() const { return _isPlainData; }

    /// <summary>
    /// Get manifest resource ID
    /// </summary>
    /// <returns>Manifest resource ID</returns>
     inline int manifestID() const { return _manifestIdx; }

    /// <summary>
    /// Get image subsystem
    /// </summary>
    /// <returns>Image subsystem</returns>
     inline uint32_t subsystem() const { return _subsystem; }

    /// <summary>
    /// Get manifest resource file
    /// </summary>
    /// <returns>Manifest resource file</returns>
     inline const std::wstring& manifestFile() const { return _manifestPath; }

    /// <summary>
    /// If true - no actual PE file available on disk
    /// </summary>
    /// <returns></returns>
     inline bool noPhysFile() const { return _noFile; }

#ifdef COMPILER_MSVC
    /// <summary>
    /// .NET image parser
    /// </summary>
    /// <returns>.NET image parser</returns>
     ImageNET& net() { return _netImage; }
#endif

private:
    /// <summary>
    /// Prepare activation context
    /// </summary>
    /// <param name="filepath">Path to PE file. If nullptr - manifest is extracted from memory to disk</param>
    /// <returns>Status code</returns>
    NTSTATUS PrepareACTX( const wchar_t* filepath = nullptr );

    /// <summary>
    /// Get manifest from image data
    /// </summary>
    /// <param name="size">Manifest size</param>
    /// <param name="manifestID">Mmanifest ID</param>
    /// <returns>Manifest data</returns>
    void* GetManifest( uint32_t& size, int32_t& manifestID );

private:
    HANDLE      _hFile = INVALID_HANDLE_VALUE;  // Target file HANDLE
    HANDLE      _hMapping = NULL;               // Memory mapping object
    void*       _pFileBase = nullptr;           // Mapping base
    bool        _isPlainData = false;           // File mapped as plain data file
    bool        _is64 = false;                  // Image is 64 bit
    bool        _isExe = false;                 // Image is an .exe file
    bool        _isPureIL = false;              // Pure IL image
    bool        _noFile = false;                // Parsed from memory, no underlying PE file available        
    PCHDR32     _pImageHdr32 = nullptr;         // PE header info
    PCHDR64     _pImageHdr64 = nullptr;         // PE header info
    ptr_t       _imgBase = 0;                   // Image base
    uint32_t    _imgSize = 0;                   // Image size
    uint32_t    _epRVA = 0;                     // Entry point RVA
    uint32_t    _hdrSize = 0;                   // Size of headers
    HANDLE      _hctx = INVALID_HANDLE_VALUE;   // Activation context
    int32_t     _manifestIdx = 0;               // Manifest resource ID
    uint32_t    _subsystem = 0;                 // Image subsystem
    int32_t     _ILFlagOffset = 0;              // Offset of pure IL flag

    vecSections _sections;                      // Section info
    mapImports  _imports;                       // Import functions
    mapImports  _delayImports;                  // Import functions

    std::wstring _imagePath;                    // Image path
    std::wstring _manifestPath;                 // Image manifest container

    ImageNET    _netImage;                  // .net image info
};

}
}
