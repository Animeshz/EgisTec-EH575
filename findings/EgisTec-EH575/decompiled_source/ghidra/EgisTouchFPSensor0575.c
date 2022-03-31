typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef unsigned short    wchar16;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo * LPCPINFO;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_538 _union_538, *P_union_538;

typedef void * HANDLE;

typedef struct _struct_539 _struct_539, *P_struct_539;

typedef void * PVOID;

struct _struct_539 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_538 {
    struct _struct_539 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_538 u;
    HANDLE hEvent;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef ushort WORD;

typedef BYTE * LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _STARTUPINFOW * LPSTARTUPINFOW;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulonglong DWORD64;

typedef union _union_52 _union_52, *P_union_52;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_53 _struct_53, *P_struct_53;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_53 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_52 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_53 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_52 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _CONTEXT CONTEXT;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_236 _union_236, *P_union_236;

union _union_236 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_236 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionCollidedUnwind=3,
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef struct _IMAGE_SECTION_HEADER * PIMAGE_SECTION_HEADER;

typedef struct _EXCEPTION_POINTERS EXCEPTION_POINTERS;

typedef WCHAR * LPWCH;

typedef WCHAR * LPCWSTR;

typedef struct _M128A * PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef ulonglong * PDWORD64;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_61 {
    PDWORD64 IntegerContext[16];
    struct _struct_62 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef struct _struct_60 _struct_60, *P_struct_60;

struct _struct_60 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef union _union_59 _union_59, *P_union_59;

union _union_59 {
    PM128A FloatingContext[16];
    struct _struct_60 s;
};

typedef LARGE_INTEGER * PLARGE_INTEGER;

typedef CHAR * LPSTR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_59 u;
    union _union_61 u2;
};

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef longlong INT_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbname[25];
};

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char * mantissa;
};

typedef struct _strflt * STRFLT;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef INT_PTR (* FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef WORD * LPWORD;

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef BOOL * LPBOOL;

typedef BYTE * PBYTE;

typedef struct HINSTANCE__ * HINSTANCE;

typedef HINSTANCE HMODULE;

typedef void * LPCVOID;

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_WRITE=2147483648,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_TYPE_NO_PAD=8
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef LONG LSTATUS;

typedef char * va_list;

typedef ulonglong uintptr_t;

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct _tiddata * _ptiddata;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct * pthreadmbcinfo;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct * pthreadlocinfo;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct setloc_struct _setloc_struct;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct lconv lconv, *Plconv;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct lconv {
    char * decimal_point;
    char * thousands_sep;
    char * grouping;
    char * int_curr_symbol;
    char * currency_symbol;
    char * mon_decimal_point;
    char * mon_thousands_sep;
    char * mon_grouping;
    char * positive_sign;
    char * negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t * _W_decimal_point;
    wchar_t * _W_thousands_sep;
    wchar_t * _W_int_curr_symbol;
    wchar_t * _W_currency_symbol;
    wchar_t * _W_mon_decimal_point;
    wchar_t * _W_mon_thousands_sep;
    wchar_t * _W_positive_sign;
    wchar_t * _W_negative_sign;
};

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t * pchLanguage;
    wchar_t * pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t * mblocalename;
};

struct localerefcount {
    char * locale;
    wchar_t * wlocale;
    int * refcount;
    int * wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int * lconv_intl_refcount;
    int * lconv_num_refcount;
    int * lconv_mon_refcount;
    struct lconv * lconv;
    int * ctype1_refcount;
    ushort * ctype1;
    ushort * pctype;
    uchar * pclmap;
    uchar * pcumap;
    struct __lc_time_data * lc_time_curr;
    wchar_t * locale_name[6];
};

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char * _token;
    wchar_t * _wtoken;
    uchar * _mtoken;
    char * _errmsg;
    wchar_t * _werrmsg;
    char * _namebuf0;
    wchar_t * _wnamebuf0;
    char * _namebuf1;
    wchar_t * _wnamebuf1;
    char * _asctimebuf;
    wchar_t * _wasctimebuf;
    void * _gmtimebuf;
    char * _cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void * _initaddr;
    void * _initarg;
    void * _pxcptacttab;
    void * _tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void * _terminate;
    void * _unexpected;
    void * _translator;
    void * _purecall;
    void * _curexception;
    void * _curcontext;
    int _ProcessingThrow;
    void * _curexcspec;
    void * _pExitContext;
    void * _pUnwindContext;
    void * _pFrameInfoChain;
    ulonglong _ImageBase;
    ulonglong _ThrowImageBase;
    void * _pForeignException;
    _setloc_struct _setloc_data;
    void * _reserved1;
    void * _reserved2;
    void * _reserved3;
    void * _reserved4;
    void * _reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

struct __lc_time_data {
    char * wday_abbr[7];
    char * wday[7];
    char * month_abbr[12];
    char * month[12];
    char * ampm[2];
    char * ww_sdatefmt;
    char * ww_ldatefmt;
    char * ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t * _W_wday_abbr[7];
    wchar_t * _W_wday[7];
    wchar_t * _W_month_abbr[12];
    wchar_t * _W_month[12];
    wchar_t * _W_ampm[2];
    wchar_t * _W_ww_sdatefmt;
    wchar_t * _W_ww_ldatefmt;
    wchar_t * _W_ww_timefmt;
    wchar_t * _W_ww_locale_name;
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef struct _CRT_FLOAT _CRT_FLOAT, *P_CRT_FLOAT;

struct _CRT_FLOAT {
    float f;
};

typedef ushort wint_t;

typedef ulonglong size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef size_t rsize_t;

typedef struct localeinfo_struct * _locale_t;




// WARNING: Globals starting with '_' overlap smaller symbols at the same address

DWORD FUN_180001000(void)

{
  DWORD DVar1;
  LSTATUS LVar2;
  DWORD local_res8 [2];
  DWORD local_res10 [2];
  HKEY local_res18;
  
  DVar1 = RegOpenKeyA((HKEY)0xffffffff80000002,"SOFTWARE\\EgisSDKDBG",(PHKEY)&local_res18);
  if (DVar1 == 0) {
    local_res8[0] = 4;
    LVar2 = RegQueryValueExA(local_res18,"EnableBlock",(LPDWORD)0x0,local_res10,&DAT_180018664,
                             local_res8);
    DVar1 = local_res8[0];
    if (LVar2 == 0) {
      DVar1 = 1;
    }
    local_res8[0] = 4;
    LVar2 = RegQueryValueExA(local_res18,"DisplayFlag ",(LPDWORD)0x0,local_res10,
                             (LPBYTE)&DAT_180018668,local_res8);
    if (LVar2 == 0) {
      DVar1 = 1;
    }
    RegCloseKey(local_res18);
    _DAT_180018660 = 1;
  }
  return DVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800010e0(uint param_1,longlong param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  longlong lVar2;
  char *_Src;
  undefined8 local_res18;
  undefined8 local_res20;
  undefined auStack888 [32];
  uint local_358;
  uint local_350;
  uint local_348;
  uint local_340;
  DWORD local_338;
  DWORD local_330;
  longlong local_328;
  _SYSTEMTIME local_318;
  char local_308 [31];
  char cStack745;
  undefined2 local_2e8;
  char acStack742 [350];
  char local_188 [352];
  ulonglong local_28;
  
  local_28 = DAT_1800170a0 ^ (ulonglong)auStack888;
  local_res18 = param_3;
  local_res20 = param_4;
  if (_DAT_180018660 == 0) {
    FUN_180001000();
  }
  if (((_DAT_180018664 & param_1) != 0) && (param_2 != 0)) {
    GetLocalTime((LPSYSTEMTIME)&local_318);
    if (param_1 == 1) {
      _Src = "EngineAdapter";
    }
    else {
      _Src = "SensorAdapter";
      if (param_1 != 2) {
        _Src = "WBF";
      }
    }
    strcpy_s(local_308,0x1e,_Src);
    local_330 = GetCurrentThreadId();
    local_338 = GetCurrentProcessId();
    local_340 = (uint)local_318.wMilliseconds;
    local_348 = (uint)local_318.wSecond;
    local_350 = (uint)local_318.wMinute;
    local_358 = (uint)local_318.wHour;
    local_328 = param_2;
    sprintf_s(local_188,0x15e,"[%s] %02d:%02d:%02d:%03d [%04d] [%04d] %s",local_308);
    iVar1 = vsprintf_s(&cStack745 + 1,0x15e,local_188,(va_list)&local_res18);
    lVar2 = (longlong)iVar1;
    if ((&cStack745)[lVar2] != '\n') {
      *(undefined2 *)(&cStack745 + lVar2 + 1) = 0xa0d;
      (&cStack745)[lVar2 + 3] = '\0';
    }
    if (0 < DAT_180018668) {
      OutputDebugStringA(&cStack745 + 1);
    }
    if (1 < DAT_180018668) {
      FUN_180001290(param_1,&cStack745 + 1);
    }
  }
  FUN_180002f40(local_28 ^ (ulonglong)auStack888);
  return;
}



void FUN_180001290(int param_1,LPCSTR param_2)

{
  DWORD nNumberOfBytesToWrite;
  BOOL BVar1;
  HANDLE hFile;
  char *_Src;
  DWORD local_158 [2];
  char local_150 [40];
  char local_128 [272];
  ulonglong local_18;
  
  if (param_2 != (LPCSTR)0x0) {
    local_18 = DAT_1800170a0 ^ (ulonglong)&stack0xfffffffffffffe68;
    if (param_1 == 1) {
      _Src = "EngineAdapter";
    }
    else {
      _Src = "SensorAdapter";
      if (param_1 != 2) {
        _Src = "WBF";
      }
    }
    strcpy_s(local_150,0x1e,_Src);
    sprintf_s(local_128,0x104,"%s\\%s.txt","C:\\Temp2\\WBF");
    hFile = CreateFileA(local_128,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,4,0x80,(HANDLE)0x0);
    if (hFile != (HANDLE)0xffffffffffffffff) {
      SetFilePointer(hFile,0,(PLONG)0x0,2);
      nNumberOfBytesToWrite = lstrlenA(param_2);
      BVar1 = WriteFile(hFile,param_2,nNumberOfBytesToWrite,local_158,(LPOVERLAPPED)0x0);
      if (BVar1 == 0) {
        OutputDebugStringA("=SDK-DBG= Write File fail\r\n");
      }
      CloseHandle(hFile);
    }
    FUN_180002f40(local_18 ^ (ulonglong)&stack0xfffffffffffffe68);
  }
  return;
}


// https://docs.microsoft.com/en-us/windows/win32/api/winbio_adapter/nc-winbio_adapter-pibio_sensor_attach_fn#examples
uint FUN_1800013d0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  HANDLE pvVar2;
  HANDLE *lpMem;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterAttach",param_3,param_4);
  DVar1 = 0;
  if (param_1 == 0) {
    DVar1 = 0x80004003;
  }
  else {
    if (*(longlong *)(param_1 + 0x30) == 0) {
      pvVar2 = GetProcessHeap();
      lpMem = (HANDLE *)HeapAlloc(pvVar2,8,0x60);
      if (lpMem == (HANDLE *)0x0) {
        DVar1 = 0x8007000e;
      }
      else {
        param_4 = 0;
        lpMem[5] = (HANDLE)0x0;
        lpMem[6] = (HANDLE)0x0;
        lpMem[7] = (HANDLE)0x0;
        lpMem[8] = (HANDLE)0x0;
        pvVar2 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCSTR)0x0);
        *lpMem = pvVar2;   // lpMem[0] == Event
        if (pvVar2 == (HANDLE)0x0) {
          DVar1 = GetLastError();
          if (0 < (int)DVar1) {
            DVar1 = DVar1 & 0xffff | 0x80070000;
          }
          if ((int)DVar1 < 0) {
            pvVar2 = GetProcessHeap();
            HeapFree(pvVar2,0,lpMem);
          }
        }
        else {
          *(HANDLE **)(param_1 + 0x30) = lpMem;  // Pipeline->SensorContext
        }
      }
    }
    else {
      DVar1 = 0x8009800f;
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterAttach : ErrorCode [0x%08X]",(ulonglong)DVar1,param_4)
  ;
  return (uint)DVar1;
}



uint FUN_1800015b0(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  longlong lVar2;
  uint uVar3;
  undefined *puVar4;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterClearContext",param_3,param_4);
  if (param_1 == 0) {
    uVar3 = 0x80004003;
  }
  else {
    lVar1 = *(longlong *)(param_1 + 0x30);  // Pipeline->SensorContext
    if (lVar1 == 0) {
      uVar3 = 0x8009800f;
    }
    else {
      // Puts 0 everywhere
      *(undefined4 *)(lVar1 + 0x48) = 0;
      if (*(undefined **)(lVar1 + 0x28) != (undefined *)0x0) {
        puVar4 = *(undefined **)(lVar1 + 0x28);
        for (lVar2 = *(longlong *)(lVar1 + 0x30); lVar2 != 0; lVar2 = lVar2 + -1) {
          *puVar4 = 0;
          puVar4 = puVar4 + 1;
        }
      }
      uVar3 = 0;
      if (*(undefined **)(lVar1 + 0x38) != (undefined *)0x0) {
        puVar4 = *(undefined **)(lVar1 + 0x38);
        for (lVar2 = *(longlong *)(lVar1 + 0x40); uVar3 = 0, lVar2 != 0; lVar2 = lVar2 + -1) {
          *puVar4 = 0;
          puVar4 = puVar4 + 1;
        }
      }
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterClearContext : ErrorCode [0x%08X]",(ulonglong)uVar3,
                param_4);
  return uVar3;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180001640(HANDLE *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  BOOL BVar2;
  DWORD DVar3;
  uint uVar4;
  uint local_58 [2];
  _OVERLAPPED local_50;
  undefined8 local_30;
  ulonglong local_28;
  undefined4 local_20;
  ulonglong local_18;
  
  local_18 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff68;
  FUN_1800010e0(2,(longlong)">>> SensorAdapterQueryStatus",param_3,param_4);
  DVar1 = 0;
  local_58[0] = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_50.Internal = 0;
  local_50.InternalHigh = 0;
  local_50.u = 0;
  local_50.hEvent = (HANDLE)0x0;
  if ((param_1 == (HANDLE *)0x0) || (param_2 == (undefined4 *)0x0)) {
    DVar1 = 0x80004003;
    goto LAB_1800017fe;
  }
  if ((param_1[6] == (HANDLE)0x0) || (*param_1 == (HANDLE)0xffffffffffffffff)) {
    DVar1 = 0x8009800f;
    goto LAB_1800017fe;
  }
  param_4 = 0;
  local_50.hEvent = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCSTR)0x0);
  if (local_50.hEvent == (HANDLE)0x0) {
LAB_1800016e6:
    DVar1 = GetLastError();
    if ((int)DVar1 < 1) {
      DVar1 = GetLastError();
    }
    else {
      DVar1 = GetLastError();
      DVar1 = DVar1 & 0xffff | 0x80070000;
    }
    goto LAB_1800017fe;
  }
  param_4 = 0;
  BVar2 = DeviceIoControl(*param_1,0x440010,(LPVOID)0x0,0,&local_30,0x14,local_58,
                          (LPOVERLAPPED)&local_50);
  if (BVar2 == 0) {
    DVar3 = GetLastError();
    if (DVar3 == 0x3e5) {
      SetLastError(0);
      param_4 = 1;
      uVar4 = GetOverlappedResult(*param_1,(LPOVERLAPPED)&local_50,local_58,1);
      if ((uVar4 == 0) || (local_58[0] != 0x14)) goto LAB_1800016e6;
      param_4 = 0x14;
      FUN_1800010e0(2,(longlong)
                      "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_SENSOR_STATUS GetOverlappedResult result = [%d], bytesReturned = [%d]"
                    ,(ulonglong)uVar4,0x14);
      goto LAB_18000179d;
    }
  }
  else {
LAB_18000179d:
    if (3 < local_58[0]) {
      *param_2 = (undefined4)local_28;
      FUN_1800010e0(2,(longlong)"SensorAdapterQueryStatus : Sensor Status = %d",
                    local_28 & 0xffffffff,param_4);
      goto LAB_1800017fe;
    }
  }
  DVar1 = GetLastError();
  if ((DVar1 == 0x4c7) || (DVar1 == 0x3e3)) {
    DVar1 = 0x80098004;
  }
  else {
    DVar1 = 0x80098036;
  }
LAB_1800017fe:
  if (local_50.hEvent != (HANDLE)0x0) {
    CloseHandle(local_50.hEvent);
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterQueryStatus : ErrorCode [0x%08X]",(ulonglong)DVar1,
                param_4);
  FUN_180002f40(local_18 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}




/* WARNING: Could not reconcile some variable overlaps */

void UndefinedFunction_180001e40
               (longlong /* struct WINBIO_PIPELINE */ *param_1,char param_2,undefined8 *param_3,ulonglong param_4)

{
  undefined8 *puVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  undefined8 uVar5;
  longlong lVar6;
  ulonglong uVar7;
  uint uVar8;
  char *pcVar9;
  undefined8 *puVar10;
  ulonglong uVar11;
  undefined auStack216 [32];
  undefined8 *puStack184;
  undefined4 uStack176;
  uint *puStack168;
  undefined8 *puStack160;
  uint uStack152;
  uint uStack148;
  undefined8 uStack144;
  undefined8 uStack136;
  undefined8 uStack128;
  longlong lStack120;
  ulonglong uStack112;
  undefined8 uStack104;
  undefined8 uStack96;
  ulonglong uStack88;
  undefined8 uStack80;
  undefined8 uStack72;
  ulonglong uStack64;
  
  uStack64 = DAT_1800170a0 ^ (ulonglong)auStack216;
  puVar10 = param_3;
  FUN_1800010e0(2,(longlong)">>> SensorAdapterStartCapture",param_3,param_4);
  uVar7 = 0;
  uStack148 = 6;
  uStack112 = 0;
  uStack104 = 0;
  uStack96 = 0;
  uStack88 = 0;
  uStack152 = 0;
  uStack144 = 0;
  uStack136 = 0;
  uStack128 = 0;
  lStack120 = 0;
  if (((param_1 == (longlong *)0x0) || (param_2 == '\0')) || (param_3 == (undefined8 *)0x0)) {
    uVar3 = 0x80004003;
    goto LAB_180002449;
  }
  puVar1 = (undefined8 *)param_1[6];  // SensorContext
  if ((puVar1 == (undefined8 *)0x0) || (*param_1 == -1)) {
LAB_18000206a:
    uVar3 = 0x8009800f;
    goto LAB_180002449;
  }
  *param_3 = 0;
  uVar3 = FUN_180001640(param_1,&uStack148,puVar10,param_4);
  uVar8 = uStack148;
  if ((int)uVar3 < 0) goto LAB_180002449;
  uVar11 = (ulonglong)uStack148;
  FUN_1800010e0(2,(longlong)"SensorAdapterStartCapture : called SensorAdapterQueryStatus(1) = %d",
                uVar11,param_4);
  if (uVar8 == 5) {
    uStack80 = 0;
    uStack72 = 0;
    FUN_1800010e0(2,(longlong)"SensorAdapterStartCapture : call IOCTL_BIOMETRIC_CALIBRATE = %d",5,
                  param_4);
    param_4 = 0;
    lStack120 = CreateEventA(0,1);
    if (lStack120 != 0) {
      puStack160 = &uStack144;
      param_4 = 0;
      puStack168 = &uStack152;
      uVar11 = 0;
      puStack184 = &uStack80;
      uStack176 = 0x10;
      iVar4 = DeviceIoControl(*param_1,0x44000c);
      if (iVar4 == 0) {
        iVar4 = GetLastError();
        if (iVar4 == 0x3e5) {
          SetLastError(0);
          param_4 = 1;
          uVar3 = GetOverlappedResult(*param_1,&uStack144);
          if ((uVar3 == 0) || (uStack152 != 0x10)) goto LAB_180001f65;
          param_4 = 0x10;
          uVar11 = (ulonglong)uVar3;
          FUN_1800010e0(2,(longlong)
                          "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CALIBRATE GetOverlappedResult result = [%d], bytesReturned = [%d]"
                        ,uVar11,0x10);
        }
      }
      uVar3 = FUN_180001640(param_1,&uStack148,uVar11,param_4);
      uVar8 = uStack148;
      uVar11 = (ulonglong)uStack148;
      FUN_1800010e0(2,(longlong)
                      "SensorAdapterStartCapture : called SensorAdapterQueryStatus(2) = %d",uVar11,
                    param_4);
      if ((int)uVar3 < 0) goto LAB_180002449;
      goto LAB_180002040;
    }
LAB_180001f65:
    iVar4 = GetLastError();
    if (iVar4 < 1) {
      uVar3 = GetLastError();
      goto LAB_180002449;
    }
  }
  else {
LAB_180002040:
    if (uVar8 == 4) {
      uVar3 = 0x80098010;
      goto LAB_180002449;
    }
    if (uVar8 != 3) {
      FUN_1800010e0(2,(longlong)
                      "SensorAdapterStartCapture : sensorStatus != WINBIO_SENSOR_READY, sensorStatus = %d. "
                    ,(ulonglong)uVar8,param_4);
      goto LAB_18000206a;
    }
    if ((*(short *)((longlong)puVar1 + 0x4c) != 0) || (*(short *)((longlong)puVar1 + 0x4e) != 0)) {
LAB_1800021ef:
      uStack112._0_5_ = CONCAT14(param_2,0x20);
      uStack112 = uStack112 & 0xff0000000000 | (ulonglong)(uint5)uStack112 |
                  (ulonglong)*(ushort *)((longlong)puVar1 + 0x4c) << 0x30;
      uStack96 = *(undefined8 *)((longlong)puVar1 + 0x54);
      uStack104 = CONCAT44(*(undefined4 *)(puVar1 + 10),
                           (uint)uStack104 & 0xffff0000 | (uint)*(ushort *)((longlong)puVar1 + 0x4e)
                          );
      uStack88 = uStack88 & 0xffffff0000000000 | (ulonglong)*(uint *)((longlong)puVar1 + 0x5c) |
                 0x2000000000;
      if (puVar1[5] == 0) {
        uVar5 = GetProcessHeap();
        lVar6 = HeapAlloc(uVar5);  // bytes = puVar1[0x4c]
        puVar1[5] = lVar6;
        if (lVar6 == 0) {
          puVar1[6] = 0;
          uVar3 = 0x8007000e;
          goto LAB_180002449;
        }
        puVar1[6] = 0x18;
        puVar10 = puVar1 + 1;
        *puVar10 = 0;
        puVar1[2] = 0;
        puVar1[3] = 0;
        puVar1[4] = 0;
        ResetEvent(*puVar1);
        puVar1[4] = *puVar1;                      // [rdi]

        puStack160 = puVar10;                     // puVar1[1], [rdi+8] 8th param
        puStack168 = &uStack152;                  // [rbp - 0x39] 7th param
        uStack176 = *(undefined4 *)(puVar1 + 6);  // 0x18 = 24, [rdi + 0x30] 6th param
        puStack184 = (undefined8 *)puVar1[5];     // HeapAlloc returned ptr, [rdi + 0x28] 5th param
        param_4 = 0x20;

        iVar4 = DeviceIoControl(*param_1,0x440014, [rbp /* &stack209 */ - 0x11] /* &stack192, auStack216[24] */, param_4 /* 32 */, ...);
        if (iVar4 == 0) {
          iVar4 = GetLastError();
          if (iVar4 == 0x3e5) {
            SetLastError(0);
            param_4 = 1;
            uVar3 = GetOverlappedResult(*param_1,puVar10);
            if ((uVar3 == 0) || (uStack152 != 4 /* return bytes should be 4? */)) goto LAB_180001f65;
            param_4 = 4;
            FUN_1800010e0(2,(longlong)
                            "SensorAdapterStartCapture : IOCTL_BIOMETRIC_CAPTURE_DATA GetOverlappedResult result = [%d], bytesReturned = [%d]"
                          ,(ulonglong)uVar3,4);
          }
        }
        uVar7 = (ulonglong)*(uint *)puVar1[5];
        if (((ulonglong)puVar1[6] < uVar7) && (puVar1[6] = uVar7, (uint *)puVar1[5] != (uint *)0x0))
        {
          uVar5 = GetProcessHeap();
          HeapFree(uVar5,0);
          puVar1[5] = 0;
        }
        lVar6 = FUN_180002bb0(puVar1[6]);
        puVar1[5] = lVar6;
        if (lVar6 == 0) {
          puVar1[6] = 0;
          uVar3 = 0x8007000e;
          goto LAB_180002449;
        }
      }
      else {
        pcVar9 = "SensorAdapterStartCapture : Call SensorAdapterClearContext";
        FUN_1800010e0(2,(longlong)"SensorAdapterStartCapture : Call SensorAdapterClearContext",
                      uVar11,param_4);
        FUN_1800015b0((longlong)param_1,pcVar9,uVar11,param_4);
      }
      puVar10 = puVar1 + 1;
      *puVar10 = 0;
      puVar1[2] = 0;
      puVar1[3] = 0;
      puVar1[4] = 0;
      ResetEvent(*puVar1);
      puVar1[4] = *puVar1;  // Original event set by SensorAdapterAttach is reset and attached to index 4
      SetLastError(0);
      puStack168 = &uStack152;
      uStack176 = *(undefined4 *)(puVar1 + 6);
      param_4 = 0x20;
      puStack184 = (undefined8 *)puVar1[5];
      puStack160 = puVar10;
      uVar3 = DeviceIoControl(*param_1,0x440014);
      if (uVar3 == 0) {
        iVar4 = GetLastError();
        if (iVar4 != 0x3e5) {
          iVar4 = GetLastError();
          if ((iVar4 == 0x4c7) || (iVar4 == 0x3e3)) {
            uVar3 = 0x80098004;
          }
          else {
            uVar3 = 0x80098036;
          }
          goto LAB_180002449;
        }
      }
      uVar8 = GetLastError();
      param_4 = (ulonglong)uVar3;
      FUN_1800010e0(2,(longlong)
                      "SensorAdapterStartCapture : Call DeviceIoControl, GetLastError() = [%d], result = [%d]"
                    ,(ulonglong)uVar8,param_4);
      *param_3 = puVar10;
      uVar3 = 0;
      goto LAB_180002449;
    }
    uVar3 = (**(code **)(param_1[4] + 0x38))(param_1,(longlong)puVar1 + 0x4c);
    if ((int)uVar3 < 0) goto LAB_180002449;
    puVar1[8] = 0x62c;
    puVar1[7] = &DAT_180018670;
    if (lStack120 != 0) {
      CloseHandle();
    }
    param_4 = 0;
    uStack144 = 0;
    uStack136 = 0;
    uStack128 = 0;
    lStack120 = 0;
    lStack120 = CreateEventA(0,1);
    if (lStack120 != 0) {
      puStack160 = &uStack144;
      puStack168 = &uStack152;
      uStack176 = *(undefined4 *)(puVar1 + 8);
      puStack184 = (undefined8 *)puVar1[7];
      iVar4 = DeviceIoControl(*param_1,0x440004,0);
      if (iVar4 == 0) {
        iVar4 = GetLastError();
        if (iVar4 == 0x3e5) {
          SetLastError(0);
          param_4 = 1;
          uVar3 = GetOverlappedResult(*param_1,&uStack144);
          if ((uVar3 == 0) || (param_4 = (ulonglong)uStack152, uStack152 != *(uint *)(puVar1 + 8)))
          goto LAB_180001f65;
          FUN_1800010e0(2,(longlong)
                          "SensorAdapterStartCapture : IOCTL_BIOMETRIC_GET_ATTRIBUTES GetOverlappedResult result = [%d], bytesReturned = [%d]"
                        ,(ulonglong)uVar3,param_4);
        }
      }
      uVar11 = puVar1[7];
      uVar3 = *(uint *)(uVar11 + 0x624);
      param_4 = (ulonglong)uVar3;
      uVar8 = 0;
      if (uVar3 != 0) {
        do {
          uVar8 = (uint)uVar7;
          if ((*(short *)(uVar11 + 0x628 + uVar7 * 4) == *(short *)((longlong)puVar1 + 0x4c)) &&
             (*(short *)(uVar11 + 0x62a + uVar7 * 4) == *(short *)((longlong)puVar1 + 0x4e))) break;
          uVar8 = uVar8 + 1;
          uVar7 = (ulonglong)uVar8;
        } while (uVar8 < uVar3);
      }
      if (uVar8 == uVar3) {
        *(undefined4 *)((longlong)puVar1 + 0x4c) = 0x401001b;
      }
      goto LAB_1800021ef;
    }
    iVar4 = GetLastError();
    if (iVar4 < 1) {
      uVar3 = GetLastError();
      goto LAB_180002449;
    }
  }
  uVar2 = GetLastError();
  uVar3 = uVar2 | 0x80070000;
LAB_180002449:
  if (lStack120 != 0) {
    CloseHandle();
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterStartCapture : ErrorCode [0x%08X]",(ulonglong)uVar3,
                param_4);
  FUN_180002f40(uStack64 ^ (ulonglong)auStack216);
  return;
}



uint FUN_180001850(HANDLE *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  DWORD DVar1;
  BOOL BVar2;
  uint uVar3;
  uint local_res8 [2];
  undefined8 local_res10;
  _OVERLAPPED local_28;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterReset",param_3,param_4);
  local_res10 = 0;
  local_res8[0] = 0;
  local_28.Internal = 0;
  local_28.InternalHigh = 0;
  local_28.u = 0;
  local_28.hEvent = (HANDLE)0x0;
  if (param_1 == (HANDLE *)0x0) {
    local_res10._4_4_ = 0x80004003;
    goto LAB_1800019da;
  }
  if ((param_1[6] == (HANDLE)0x0) || (*param_1 == (HANDLE)0xffffffffffffffff)) {
    local_res10._4_4_ = 0x8009800f;
    goto LAB_1800019da;
  }
  param_4 = 0;
  local_28.hEvent = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCSTR)0x0);
  if (local_28.hEvent == (HANDLE)0x0) {
LAB_1800018c8:
    DVar1 = GetLastError();
    if ((int)DVar1 < 1) {
      local_res10._4_4_ = GetLastError();
    }
    else {
      DVar1 = GetLastError();
      local_res10._4_4_ = DVar1 & 0xffff | 0x80070000;
    }
    goto LAB_1800019da;
  }
  param_4 = 0;
  BVar2 = DeviceIoControl(*param_1,0x440008,(LPVOID)0x0,0,&local_res10,8,local_res8,
                          (LPOVERLAPPED)&local_28);
  if (BVar2 == 0) {
    DVar1 = GetLastError();
    if (DVar1 == 0x3e5) {
      SetLastError(0);
      param_4 = 1;
      uVar3 = GetOverlappedResult(*param_1,(LPOVERLAPPED)&local_28,local_res8,1);
      if ((uVar3 == 0) || (local_res8[0] != 8)) goto LAB_1800018c8;
      param_4 = 8;
      FUN_1800010e0(2,(longlong)
                      "SensorAdapterStartCapture : IOCTL_BIOMETRIC_RESET GetOverlappedResult result = [%d], bytesReturned = [%d]"
                    ,(ulonglong)uVar3,8);
      goto LAB_18000197b;
    }
  }
  else {
LAB_18000197b:
    if (7 < local_res8[0]) {
      goto LAB_1800019da;
    }
  }
  DVar1 = GetLastError();
  FUN_1800010e0(2,(longlong)"SensorAdapterReset : call IOCTL_BIOMETRIC_RESET GetLastError() [%d]",
                (ulonglong)DVar1,param_4);
  DVar1 = GetLastError();
  if ((DVar1 == 0x4c7) || (DVar1 == 0x3e3)) {
    local_res10._4_4_ = 0x80098004;
  }
  else {
    local_res10._4_4_ = 0x80098036;
  }
LAB_1800019da:
  if (local_28.hEvent != (HANDLE)0x0) {
    CloseHandle(local_28.hEvent);
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterReset : ErrorCode [0x%08X]",
                (ulonglong)local_res10._4_4_,param_4);
  return (uint)local_res10._4_4_;
}



uint FUN_180001a10(longlong *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  uint uVar1;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterSetMode",param_3,param_4);
  uVar1 = 0;
  if (param_1 == (longlong *)0x0) {
    uVar1 = 0x80004003;
  }
  else {
    if ((param_1[6] /* Pipeline->SensorContext */ == 0) || (*param_1 == -1)) {
      uVar1 = 0x8009800f;
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterSetMode : ErrorCode [0x%08X]",(ulonglong)uVar1,param_4
               );
  return uVar1;
}



uint FUN_1800024c0(HANDLE *param_1,undefined4 *param_2,undefined8 param_3,undefined8 param_4)

{
  HANDLE pvVar1;
  longlong lVar2;
  DWORD DVar3;
  BOOL BVar4;
  uint uVar5;
  ulonglong uVar6;
  uint local_res8 [2];
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterFinishCapture",param_3,param_4);
  local_res8[0] = 0;
  if ((param_1 == (HANDLE *)0x0) || (param_2 == (undefined4 *)0x0)) {
    uVar5 = 0x80004003;
  }
  else {
    pvVar1 = param_1[6];
    if ((pvVar1 == (HANDLE)0x0) || (*param_1 == (HANDLE)0xffffffffffffffff)) {
      FUN_1800010e0(2,(longlong)" SensorAdapterFinishCapture Verify the state of the pipeline",
                    param_3,param_4);
      uVar5 = 0x8009800f;
    }
    else {
      *param_2 = 0;
      DVar3 = GetLastError();
      FUN_1800010e0(2,(longlong)" SensorAdapterFinishCapture call  GetLastError() = [%d]",
                    (ulonglong)DVar3,param_4);
      SetLastError(0);
      param_4 = 1;
      BVar4 = GetOverlappedResult(*param_1,(LPOVERLAPPED)((longlong)pvVar1 + 8),local_res8,1);
      if ((BVar4 == 0) ||
         ((local_res8[0] != *(uint *)((longlong)pvVar1 + 0x30) && (local_res8[0] != 0x18)))) {
        DVar3 = GetLastError();
        if (local_res8[0] == 4) {
          *param_2 = 7;
          uVar5 = 0x80098008;
        }
        else {
          if ((DVar3 == 0x4c7) || (DVar3 == 0x3e3)) {
            uVar5 = 0x80098004;
          }
          else {
            uVar5 = 0x80098036;
          }
        }
      }
      else {
        GetLastError();
        param_4 = *(undefined8 *)((longlong)pvVar1 + 0x30);
        FUN_1800010e0(2,(longlong)
                        " SensorAdapterFinishCapture call GetOverlappedResult success : bytesReturned = [0x%08X], sensorContext->CaptureBufferSize = [0x%08X], GetLastError()=[%d]"
                      ,(ulonglong)local_res8[0],param_4);
        lVar2 = *(longlong *)((longlong)pvVar1 + 0x28);
        if (((lVar2 == 0) || (*(ulonglong *)((longlong)pvVar1 + 0x30) < 0x18)) ||
           (*(int *)(lVar2 + 4) != 0)) {
          uVar5 = 0x8009800f;
          if (*(uint *)(lVar2 + 4) != 0) {
            uVar5 = *(uint *)(lVar2 + 4);
          }
        }
        else {
          uVar5 = *(uint *)(lVar2 + 8);
          uVar6 = (ulonglong)uVar5;
          if (uVar5 - 1 < 6) {
            param_4 = 0x180000000;
            switch(uVar5) {
            case 2:
              *(undefined4 *)(lVar2 + 4) = 0x80098008;
              *param_2 = *(undefined4 *)(*(longlong *)((longlong)pvVar1 + 0x28) + 0xc);
              FUN_1800010e0(2,(longlong)
                              " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_REJECT"
                            ,uVar6,0x180000000);
              break;
            case 3:
              FUN_1800010e0(2,(longlong)
                              " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_READY"
                            ,uVar6,0x180000000);
              break;
            case 4:
              *(undefined4 *)(lVar2 + 4) = 0x80098010;
              break;
            case 5:
              FUN_1800010e0(2,(longlong)
                              " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_NOT_CALIBRATED"
                            ,uVar6,0x180000000);
              break;
            case 6:
              FUN_1800010e0(2,(longlong)
                              " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = WINBIO_SENSOR_FAILURE"
                            ,uVar6,0x180000000);
            }
          }
          else {
            FUN_1800010e0(2,(longlong)
                            " SensorAdapterFinishCapture sensorContext->CaptureBuffer->SensorStatus = [%d]?"
                          ,uVar6,param_4);
            *(undefined4 *)(*(longlong *)((longlong)pvVar1 + 0x28) + 4) = 0x8009800f;
          }
          *param_2 = *(undefined4 *)(*(longlong *)((longlong)pvVar1 + 0x28) + 0xc);
          uVar5 = *(uint *)(*(longlong *)((longlong)pvVar1 + 0x28) + 4);
        }
      }
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterFinishCapture : ErrorCode [0x%08X]",(ulonglong)uVar5,
                param_4);
  return uVar5;
}



uint FUN_180002710(longlong param_1,undefined8 *param_2,ulonglong *param_3,undefined8 param_4)

{
  uint uVar1;
  longlong lVar2;
  undefined8 *puVar3;
  uint uVar4;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterExportSensorData",param_3,param_4);
  uVar4 = 0;
  if (((param_1 == 0) || (param_2 == (undefined8 *)0x0)) || (param_3 == (ulonglong *)0x0)) {
    uVar4 = 0x80004003;
  }
  else {
    lVar2 = *(longlong *)(param_1 + 0x30);
    if (lVar2 == 0) {
      uVar4 = 0x8009800f;
    }
    else {
      if ((*(longlong *)(lVar2 + 0x28) == 0) ||
         (uVar1 = *(uint *)(*(longlong *)(lVar2 + 0x28) + 0x10), uVar1 == 0)) {
        uVar4 = 0x80098026;
      }
      else {
        puVar3 = (undefined8 *)FUN_180002bb0((ulonglong)uVar1);
        if (puVar3 == (undefined8 *)0x0) {
          uVar4 = 0x8007000e;
        }
        else {
          FUN_180002f70(puVar3,(undefined8 *)(*(longlong *)(lVar2 + 0x28) + 0x14),
                        (ulonglong)*(uint *)(*(longlong *)(lVar2 + 0x28) + 0x10));
          *param_2 = puVar3;
          *param_3 = (ulonglong)
                     *(uint *)(*(longlong *)(*(longlong *)(param_1 + 0x30) + 0x28) + 0x10);
        }
      }
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterExportSensorData : ErrorCode [0x%08X]",
                (ulonglong)uVar4,param_4);
  return uVar4;
}



uint FUN_1800027f0(HANDLE *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  uint uVar3;
  
  FUN_1800010e0(2,(longlong)">>> SensorAdapterCancel",param_3,param_4);
  if (param_1 == (HANDLE *)0x0) {
    uVar3 = 0x80004003;
  }
  else {
    if (*param_1 == (HANDLE)0xffffffffffffffff) {
      uVar3 = 0x8009800f;
    }
    else {
      BVar1 = CancelIoEx(*param_1,(LPOVERLAPPED)0x0);
      uVar3 = 0;
      if (BVar1 == 0) {
        DVar2 = GetLastError();
        uVar3 = 0;
        if ((DVar2 != 0x490) && ((DVar2 == 0x4c7 || (uVar3 = 0x80098036, DVar2 == 0x3e3)))) {
          uVar3 = 0x80098004;
        }
      }
    }
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterCancel : ErrorCode [0x%08X]",(ulonglong)uVar3,param_4)
  ;
  return uVar3;
}



ulonglong FUN_180002970(HANDLE *param_1,DWORD param_2,LPVOID param_3,ulonglong param_4,
                       LPVOID param_5,ulonglong param_6,ulonglong *param_7,longlong param_8)

{
  DWORD DVar1;
  BOOL BVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  _OVERLAPPED local_38;
  
  uVar4 = param_4;
  FUN_1800010e0(2,(longlong)">>> SensorAdapterControlUnit",param_3,param_4);
  local_38.Internal = 0;
  local_38.InternalHigh = 0;
  local_38.u = 0;
  local_38.hEvent = (HANDLE)0x0;
  if (((param_1 == (HANDLE *)0x0) || (param_7 == (ulonglong *)0x0)) || (param_8 == 0)) {
    uVar3 = 0x80004003;
  }
  else {
    if ((param_1[6] == (HANDLE)0x0) || (*param_1 == (HANDLE)0xffffffffffffffff)) {
      uVar3 = 0x8009800f;
    }
    else {
      if (((param_2 == 0x442010) || (param_2 == 0x442014)) ||
         ((param_2 == 0x442018 || ((param_2 == 0x44201c || (uVar3 = 0, param_2 == 0x442020)))))) {
        uVar4 = 0;
        local_38.hEvent = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCSTR)0x0);
        if (local_38.hEvent != (HANDLE)0x0) {
          uVar4 = param_4 & 0xffffffff;
          BVar2 = DeviceIoControl(*param_1,param_2,param_3,(DWORD)uVar4,param_5,(DWORD)param_6,
                                  (LPDWORD)param_7,(LPOVERLAPPED)&local_38);
          uVar3 = 0;
          if (BVar2 != 0) goto LAB_180002b26;
          DVar1 = GetLastError();
          uVar3 = (ulonglong)DVar1;
          if (DVar1 != 0x3e5) goto LAB_180002b26;
          SetLastError(0);
          uVar4 = 1;
          BVar2 = GetOverlappedResult(*param_1,(LPOVERLAPPED)&local_38,(LPDWORD)param_7,1);
          if (BVar2 != 0) {
            uVar4 = *param_7;
            if (uVar4 == param_6) {
              uVar3 = local_38.Internal;
              if (0 < (int)(uint)local_38.Internal) {
                uVar3 = (ulonglong)((uint)local_38.Internal & 0xffff | 0x80070000);
              }
            }
            else {
              uVar3 = 0x800705b6;
            }
            FUN_1800010e0(2,(longlong)
                            "SensorAdapterStartCapture : IOCTL_BIOMETRIC_VENDOR GetOverlappedResult ReceiveBufferSize = [%d], ReceiveDataSize = [%d]"
                          ,param_6,uVar4);
            goto LAB_180002b26;
          }
        }
        DVar1 = GetLastError();
        if ((int)DVar1 < 1) {
          DVar1 = GetLastError();
          uVar3 = (ulonglong)DVar1;
        }
        else {
          DVar1 = GetLastError();
          uVar3 = (ulonglong)(DVar1 & 0xffff | 0x80070000);
        }
      }
    }
  }
LAB_180002b26:
  if (local_38.hEvent != (HANDLE)0x0) {
    CloseHandle(local_38.hEvent);
  }
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterControlUnit : ErrorCode [0x%08X]",0,uVar4);
  return uVar3 & 0xffffffff;
}



undefined8
FUN_180002b80(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  FUN_1800010e0(2,(longlong)">>> SensorAdapterControlUnitPrivileged",param_3,param_4);
  FUN_1800010e0(2,(longlong)"<<< SensorAdapterControlUnitPrivileged : ErrorCode [0x%08X]",0,param_4)
  ;
  return 0;
}



void FUN_180002bb0(SIZE_T param_1)

{
  HANDLE hHeap;
  
  hHeap = GetProcessHeap();
                    // WARNING: Could not recover jumptable at 0x000180002bcf. Too many branches
                    // WARNING: Treating indirect jump as call
  HeapAlloc(hHeap,8,param_1);
  return;
}



undefined8 FUN_180002be0(void)

{
  return 1;
}



undefined8
WbioQuerySensorInterface
          (undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
                    // 0x2bf0  1  WbioQuerySensorInterface
  if (param_1 == (undefined8 *)0x0) {
    return 0x80004003;
  }
  FUN_1800010e0(2,(longlong)">>> WbioQuerySensorInterface",param_3,param_4);
  *param_1 = &DAT_180017000;
  FUN_1800010e0(2,(longlong)"<<< WbioQuerySensorInterface",param_3,param_4);
  return 0;
}



// Library Function - Single Match
//  strcpy_s
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

errno_t strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  longlong lVar2;
  errno_t *peVar3;
  errno_t eVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    if (_Src != (char *)0x0) {
      lVar2 = -(longlong)_Src;
      do {
        cVar1 = *_Src;
        (_Dst + lVar2)[(longlong)_Src] = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      peVar3 = _errno();
      eVar4 = 0x22;
      goto LAB_180002c62;
    }
    *_Dst = '\0';
  }
  peVar3 = _errno();
  eVar4 = 0x16;
LAB_180002c62:
  *peVar3 = eVar4;
  FUN_1800038fc();
  return eVar4;
}



// Library Function - Single Match
//  wcscpy_s
// 
// Library: Visual Studio 2012 Release

errno_t wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  errno_t *peVar2;
  errno_t eVar3;
  wchar_t *pwVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    if (_Src != (wchar_t *)0x0) {
      pwVar4 = (wchar_t *)((longlong)_Dst - (longlong)_Src);
      do {
        wVar1 = *_Src;
        *(wchar_t *)((longlong)pwVar4 + (longlong)_Src) = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      peVar2 = _errno();
      eVar3 = 0x22;
      goto LAB_180002cca;
    }
    *_Dst = L'\0';
  }
  peVar2 = _errno();
  eVar3 = 0x16;
LAB_180002cca:
  *peVar2 = eVar3;
  FUN_1800038fc();
  return eVar3;
}



// Library Function - Single Match
//  sprintf_s
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

int sprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,...)

{
  int iVar1;
  undefined8 in_R9;
  undefined8 local_res20;
  
  local_res20 = in_R9;
  iVar1 = _vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,(va_list)&local_res20);
  return iVar1;
}



// Library Function - Single Match
//  _vsnprintf_helper
// 
// Library: Visual Studio 2012 Release

ulonglong _vsnprintf_helper(undefined *param_1,char *param_2,ulonglong param_3,longlong param_4,
                           undefined8 param_5,undefined8 param_6)

{
  int *piVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  undefined local_48 [8];
  int local_40;
  char *local_38;
  int local_30;
  
  local_48 = (char *)0x0;
  FUN_180003c80((undefined (*) [16])&local_40,0,0x28);
  if ((param_4 == 0) || ((param_3 != 0 && (param_2 == (char *)0x0)))) {
    piVar1 = _errno();
    *piVar1 = 0x16;
    FUN_1800038fc();
    uVar2 = 0xffffffff;
  }
  else {
    local_40 = (int)param_3;
    if (0x7fffffff < param_3) {
      local_40 = 0x7fffffff;
    }
    local_30 = 0x42;
    local_48 = param_2;
    local_38 = param_2;
    uVar2 = (*(code *)param_1)(local_48,param_4,param_5,param_6);
    if (param_2 != (char *)0x0) {
      if (-1 < (int)uVar2) {
        local_40 = local_40 + -1;
        if (-1 < local_40) {
          *local_48 = '\0';
          return uVar2 & 0xffffffff;
        }
        uVar3 = FUN_180003a38(0,(FILE *)local_48);
        if ((int)uVar3 != -1) {
          return uVar2 & 0xffffffff;
        }
      }
      param_2[param_3 - 1] = '\0';
      uVar2 = (ulonglong)((-1 < local_40) - 2);
    }
  }
  return uVar2;
}



// Library Function - Single Match
//  _vsprintf_s_l
// 
// Library: Visual Studio 2012 Release

int _vsprintf_s_l(char *_DstBuf,size_t _DstSize,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  int iVar1;
  ulonglong uVar2;
  int *piVar3;
  
  if (((_Format == (char *)0x0) || (_DstBuf == (char *)0x0)) || (_DstSize == 0)) {
    piVar3 = _errno();
    *piVar3 = 0x16;
  }
  else {
    uVar2 = _vsnprintf_helper(&LAB_180003eac,_DstBuf,_DstSize,(longlong)_Format,_Locale,_ArgList);
    iVar1 = (int)uVar2;
    if (iVar1 < 0) {
      *_DstBuf = '\0';
    }
    if (iVar1 != -2) {
      return iVar1;
    }
    piVar3 = _errno();
    *piVar3 = 0x22;
  }
  FUN_1800038fc();
  return -1;
}



// Library Function - Single Match
//  vsprintf_s
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

int vsprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = _vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,_ArgList);
  return iVar1;
}



// Library Function - Single Match
//  __GSHandlerCheckCommon
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2019 Release

void __GSHandlerCheckCommon(ulonglong param_1,longlong param_2,uint *param_3)

{
  longlong lVar1;
  ulonglong uVar2;
  
  uVar2 = param_1;
  if ((*(byte *)param_3 & 4) != 0) {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  lVar1 = (ulonglong)*(uint *)(*(longlong *)(param_2 + 0x10) + 8) + *(longlong *)(param_2 + 8);
  if ((*(byte *)(lVar1 + 3) & 0xf) != 0) {
    param_1 = param_1 + (longlong)(int)(*(byte *)(lVar1 + 3) & 0xfffffff0);
  }
  FUN_180002f40(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180002f40(longlong param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack56 [8];
  undefined auStack48 [48];
  
  if ((param_1 == DAT_1800170a0) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  puVar3 = auStack56;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack48;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180004a7a;
  __crtCapturePreviousContext((CONTEXT *)&DAT_18001ce10);
  _DAT_18001cd80 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18001cea8 = puVar3 + 0x40;
  _DAT_18001ce90 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18001cd70 = 0xc0000409;
  _DAT_18001cd74 = 1;
  _DAT_18001cd88 = 1;
  DAT_18001cd90 = 2;
  *(longlong *)(puVar3 + 0x20) = DAT_1800170a0;
  *(undefined8 *)(puVar3 + 0x28) = DAT_1800170a8;
  *(undefined8 *)(puVar3 + -8) = 0x180004b1c;
  DAT_18001cf08 = _DAT_18001cd80;
  __raise_securityfailure((EXCEPTION_POINTERS *)&PTR_DAT_180010360);
  return;
}



undefined8 * FUN_180002f70(undefined8 *param_1,undefined8 *param_2,ulonglong param_3)

{
  undefined4 *puVar1;
  longlong lVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined8 *puVar8;
  undefined8 *puVar9;
  undefined (*pauVar10) [16];
  undefined4 *puVar11;
  undefined (*pauVar12) [16];
  undefined8 *puVar13;
  undefined (*pauVar14) [16];
  ulonglong uVar15;
  ulonglong uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  
  if (0x10 < param_3) {
    puVar13 = (undefined8 *)((longlong)param_2 - (longlong)param_1);
    if ((param_2 < param_1) && ((longlong)param_1 < (longlong)((longlong)param_2 + param_3))) {
      if ((DAT_18001d2e4 >> 2 & 1) != 0) {
        if (0x20 < param_3) {
          uVar15 = (longlong)param_1 + param_3;
          if ((uVar15 & 0xf) == 0) {
            pauVar10 = (undefined (*) [16])(uVar15 - 0x10);
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)pauVar10);
            uVar17 = *puVar1;
            uVar18 = puVar1[1];
            uVar19 = puVar1[2];
            uVar20 = puVar1[3];
            pauVar14 = (undefined (*) [16])(param_3 - 0x10);
          }
          else {
            puVar11 = (undefined4 *)(uVar15 - 0x10);
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)puVar11);
            uVar5 = puVar1[1];
            uVar6 = puVar1[2];
            uVar7 = puVar1[3];
            pauVar10 = (undefined (*) [16])((ulonglong)puVar11 & 0xfffffffffffffff0);
            puVar3 = (undefined4 *)((longlong)puVar13 + (longlong)pauVar10);
            uVar17 = *puVar3;
            uVar18 = puVar3[1];
            uVar19 = puVar3[2];
            uVar20 = puVar3[3];
            *puVar11 = *puVar1;
            *(undefined4 *)(uVar15 - 0xc) = uVar5;
            *(undefined4 *)(uVar15 - 8) = uVar6;
            *(undefined4 *)(uVar15 - 4) = uVar7;
            pauVar14 = (undefined (*) [16])((longlong)pauVar10 - (longlong)param_1);
          }
          uVar15 = (ulonglong)pauVar14 >> 7;
          if (uVar15 != 0) {
            *pauVar10 = CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
            pauVar12 = pauVar10;
            while( true ) {
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + -0x10) + (longlong)pauVar12);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + -0x20) + (longlong)pauVar12);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              pauVar10 = pauVar12[-8];
              *(undefined4 *)pauVar12[-1] = *puVar1;
              *(undefined4 *)(pauVar12[-1] + 4) = uVar17;
              *(undefined4 *)(pauVar12[-1] + 8) = uVar18;
              *(undefined4 *)(pauVar12[-1] + 0xc) = uVar19;
              *(undefined4 *)pauVar12[-2] = uVar20;
              *(undefined4 *)(pauVar12[-2] + 4) = uVar5;
              *(undefined4 *)(pauVar12[-2] + 8) = uVar6;
              *(undefined4 *)(pauVar12[-2] + 0xc) = uVar7;
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + 0x50) + (longlong)pauVar10);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + 0x40) + (longlong)pauVar10);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              uVar15 = uVar15 - 1;
              *(undefined4 *)pauVar12[-3] = *puVar1;
              *(undefined4 *)(pauVar12[-3] + 4) = uVar17;
              *(undefined4 *)(pauVar12[-3] + 8) = uVar18;
              *(undefined4 *)(pauVar12[-3] + 0xc) = uVar19;
              *(undefined4 *)pauVar12[-4] = uVar20;
              *(undefined4 *)(pauVar12[-4] + 4) = uVar5;
              *(undefined4 *)(pauVar12[-4] + 8) = uVar6;
              *(undefined4 *)(pauVar12[-4] + 0xc) = uVar7;
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + 0x30) + (longlong)pauVar10);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + 0x20) + (longlong)pauVar10);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              *(undefined4 *)pauVar12[-5] = *puVar1;
              *(undefined4 *)(pauVar12[-5] + 4) = uVar17;
              *(undefined4 *)(pauVar12[-5] + 8) = uVar18;
              *(undefined4 *)(pauVar12[-5] + 0xc) = uVar19;
              *(undefined4 *)pauVar12[-6] = uVar20;
              *(undefined4 *)(pauVar12[-6] + 4) = uVar5;
              *(undefined4 *)(pauVar12[-6] + 8) = uVar6;
              *(undefined4 *)(pauVar12[-6] + 0xc) = uVar7;
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + 0x10) + (longlong)pauVar10);
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)pauVar10);
              uVar17 = *puVar1;
              uVar18 = puVar1[1];
              uVar19 = puVar1[2];
              uVar20 = puVar1[3];
              if (uVar15 == 0) break;
              *(undefined4 *)pauVar12[-7] = *puVar3;
              *(undefined4 *)(pauVar12[-7] + 4) = uVar5;
              *(undefined4 *)(pauVar12[-7] + 8) = uVar6;
              *(undefined4 *)(pauVar12[-7] + 0xc) = uVar7;
              *(undefined4 *)*pauVar10 = uVar17;
              *(undefined4 *)(pauVar12[-8] + 4) = uVar18;
              *(undefined4 *)(pauVar12[-8] + 8) = uVar19;
              *(undefined4 *)(pauVar12[-8] + 0xc) = uVar20;
              pauVar12 = pauVar10;
            }
            *(undefined4 *)pauVar12[-7] = *puVar3;
            *(undefined4 *)(pauVar12[-7] + 4) = uVar5;
            *(undefined4 *)(pauVar12[-7] + 8) = uVar6;
            *(undefined4 *)(pauVar12[-7] + 0xc) = uVar7;
            pauVar14 = (undefined (*) [16])((ulonglong)pauVar14 & 0x7f);
          }
          for (uVar15 = (ulonglong)pauVar14 >> 4; uVar15 != 0; uVar15 = uVar15 - 1) {
            *pauVar10 = CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
            pauVar10 = pauVar10[-1];
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)pauVar10);
            uVar17 = *puVar1;
            uVar18 = puVar1[1];
            uVar19 = puVar1[2];
            uVar20 = puVar1[3];
          }
          if (((ulonglong)pauVar14 & 0xf) != 0) {
            uVar5 = *(undefined4 *)((longlong)param_2 + 4);
            uVar6 = *(undefined4 *)(param_2 + 1);
            uVar7 = *(undefined4 *)((longlong)param_2 + 0xc);
            *(undefined4 *)param_1 = *(undefined4 *)param_2;
            *(undefined4 *)((longlong)param_1 + 4) = uVar5;
            *(undefined4 *)(param_1 + 1) = uVar6;
            *(undefined4 *)((longlong)param_1 + 0xc) = uVar7;
          }
          *pauVar10 = CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
          return param_1;
        }
LAB_180003300:
        uVar17 = *(undefined4 *)((longlong)param_2 + 4);
        uVar18 = *(undefined4 *)(param_2 + 1);
        uVar19 = *(undefined4 *)((longlong)param_2 + 0xc);
        puVar3 = (undefined4 *)((param_3 - 0x10) + (longlong)param_1);
        puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)puVar3);
        uVar20 = *puVar1;
        uVar5 = puVar1[1];
        uVar6 = puVar1[2];
        uVar7 = puVar1[3];
        *(undefined4 *)param_1 = *(undefined4 *)param_2;
        *(undefined4 *)((longlong)param_1 + 4) = uVar17;
        *(undefined4 *)(param_1 + 1) = uVar18;
        *(undefined4 *)((longlong)param_1 + 0xc) = uVar19;
        *puVar3 = uVar20;
        puVar3[1] = uVar5;
        puVar3[2] = uVar6;
        puVar3[3] = uVar7;
        return param_1;
      }
      puVar8 = (undefined8 *)((longlong)param_1 + param_3);
      if (((ulonglong)puVar8 & 7) != 0) {
        if (((ulonglong)puVar8 & 1) != 0) {
          puVar8 = (undefined8 *)((longlong)puVar8 + -1);
          param_3 = param_3 - 1;
          *(undefined *)puVar8 = *(undefined *)((longlong)puVar13 + (longlong)puVar8);
        }
        if (((ulonglong)puVar8 & 2) != 0) {
          puVar8 = (undefined8 *)((longlong)puVar8 + -2);
          param_3 = param_3 - 2;
          *(undefined2 *)puVar8 = *(undefined2 *)((longlong)puVar13 + (longlong)puVar8);
        }
        if (((ulonglong)puVar8 & 4) != 0) {
          puVar8 = (undefined8 *)((longlong)puVar8 + -4);
          param_3 = param_3 - 4;
          *(undefined4 *)puVar8 = *(undefined4 *)((longlong)puVar13 + (longlong)puVar8);
        }
      }
      uVar15 = param_3 >> 5;
      puVar9 = puVar8;
      if (uVar15 != 0) {
        do {
          uVar4 = *(undefined8 *)((longlong)((longlong)puVar13 + -0x10) + (longlong)puVar9);
          puVar8 = puVar9 + -4;
          puVar9[-1] = *(undefined8 *)((longlong)((longlong)puVar13 + -8) + (longlong)puVar9);
          puVar9[-2] = uVar4;
          uVar4 = *(undefined8 *)((longlong)puVar13 + (longlong)puVar8);
          uVar15 = uVar15 - 1;
          puVar9[-3] = *(undefined8 *)((longlong)((longlong)puVar13 + 8) + (longlong)puVar8);
          *puVar8 = uVar4;
          puVar9 = puVar8;
        } while (uVar15 != 0);
        param_3 = param_3 & 0x1f;
      }
      uVar15 = param_3 >> 3;
      if (uVar15 != 0) {
        do {
          puVar8 = puVar8 + -1;
          uVar15 = uVar15 - 1;
          *puVar8 = *(undefined8 *)((longlong)puVar13 + (longlong)puVar8);
        } while (uVar15 != 0);
        param_3 = param_3 & 7;
      }
      if (param_3 == 0) {
        return param_1;
      }
      param_1 = (undefined8 *)((longlong)puVar8 - param_3);
      param_2 = (undefined8 *)((longlong)puVar13 + (longlong)param_1);
    }
    else {
      puVar8 = param_1;
      if ((DAT_18001d2e4 >> 1 & 1) != 0) {
        for (; param_3 != 0; param_3 = param_3 - 1) {
          *(undefined *)puVar8 = *(undefined *)param_2;
          param_2 = (undefined8 *)((longlong)param_2 + 1);
          puVar8 = (undefined8 *)((longlong)puVar8 + 1);
        }
        return param_1;
      }
      if ((DAT_18001d2e4 >> 2 & 1) != 0) {
        if (0x20 < param_3) {
          if (((ulonglong)param_1 & 0xf) == 0) {
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)param_1);
            uVar17 = *puVar1;
            uVar18 = puVar1[1];
            uVar19 = puVar1[2];
            uVar20 = puVar1[3];
            puVar8 = param_1 + 2;
            uVar15 = param_3 - 0x10;
          }
          else {
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)param_1);
            uVar5 = puVar1[1];
            uVar6 = puVar1[2];
            uVar7 = puVar1[3];
            puVar8 = (undefined8 *)((ulonglong)(param_1 + 4) & 0xfffffffffffffff0);
            puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + -0x10) + (longlong)puVar8);
            uVar17 = *puVar3;
            uVar18 = puVar3[1];
            uVar19 = puVar3[2];
            uVar20 = puVar3[3];
            *(undefined4 *)param_1 = *puVar1;
            *(undefined4 *)((longlong)param_1 + 4) = uVar5;
            *(undefined4 *)(param_1 + 1) = uVar6;
            *(undefined4 *)((longlong)param_1 + 0xc) = uVar7;
            uVar15 = param_3 - (longlong)((longlong)puVar8 - (longlong)param_1);
          }
          uVar16 = uVar15 >> 7;
          if (uVar16 != 0) {
            *(undefined (*) [16])(puVar8 + -2) =
                 CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
            puVar9 = puVar8;
            while( true ) {
              puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)puVar9);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + 0x10) + (longlong)puVar9);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              puVar8 = puVar9 + 0x10;
              *(undefined4 *)puVar9 = *puVar1;
              *(undefined4 *)((longlong)puVar9 + 4) = uVar17;
              *(undefined4 *)(puVar9 + 1) = uVar18;
              *(undefined4 *)((longlong)puVar9 + 0xc) = uVar19;
              *(undefined4 *)(puVar9 + 2) = uVar20;
              *(undefined4 *)((longlong)puVar9 + 0x14) = uVar5;
              *(undefined4 *)(puVar9 + 3) = uVar6;
              *(undefined4 *)((longlong)puVar9 + 0x1c) = uVar7;
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + -0x60) + (longlong)puVar8);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + -0x50) + (longlong)puVar8);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              uVar16 = uVar16 - 1;
              *(undefined4 *)(puVar9 + 4) = *puVar1;
              *(undefined4 *)((longlong)puVar9 + 0x24) = uVar17;
              *(undefined4 *)(puVar9 + 5) = uVar18;
              *(undefined4 *)((longlong)puVar9 + 0x2c) = uVar19;
              *(undefined4 *)(puVar9 + 6) = uVar20;
              *(undefined4 *)((longlong)puVar9 + 0x34) = uVar5;
              *(undefined4 *)(puVar9 + 7) = uVar6;
              *(undefined4 *)((longlong)puVar9 + 0x3c) = uVar7;
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + -0x40) + (longlong)puVar8);
              uVar17 = puVar1[1];
              uVar18 = puVar1[2];
              uVar19 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + -0x30) + (longlong)puVar8);
              uVar20 = *puVar3;
              uVar5 = puVar3[1];
              uVar6 = puVar3[2];
              uVar7 = puVar3[3];
              *(undefined4 *)(puVar9 + 8) = *puVar1;
              *(undefined4 *)((longlong)puVar9 + 0x44) = uVar17;
              *(undefined4 *)(puVar9 + 9) = uVar18;
              *(undefined4 *)((longlong)puVar9 + 0x4c) = uVar19;
              *(undefined4 *)(puVar9 + 10) = uVar20;
              *(undefined4 *)((longlong)puVar9 + 0x54) = uVar5;
              *(undefined4 *)(puVar9 + 0xb) = uVar6;
              *(undefined4 *)((longlong)puVar9 + 0x5c) = uVar7;
              puVar1 = (undefined4 *)((longlong)((longlong)puVar13 + -0x20) + (longlong)puVar8);
              uVar5 = puVar1[1];
              uVar6 = puVar1[2];
              uVar7 = puVar1[3];
              puVar3 = (undefined4 *)((longlong)((longlong)puVar13 + -0x10) + (longlong)puVar8);
              uVar17 = *puVar3;
              uVar18 = puVar3[1];
              uVar19 = puVar3[2];
              uVar20 = puVar3[3];
              if (uVar16 == 0) break;
              *(undefined4 *)(puVar9 + 0xc) = *puVar1;
              *(undefined4 *)((longlong)puVar9 + 100) = uVar5;
              *(undefined4 *)(puVar9 + 0xd) = uVar6;
              *(undefined4 *)((longlong)puVar9 + 0x6c) = uVar7;
              *(undefined4 *)(puVar9 + 0xe) = uVar17;
              *(undefined4 *)((longlong)puVar9 + 0x74) = uVar18;
              *(undefined4 *)(puVar9 + 0xf) = uVar19;
              *(undefined4 *)((longlong)puVar9 + 0x7c) = uVar20;
              puVar9 = puVar8;
            }
            *(undefined4 *)(puVar9 + 0xc) = *puVar1;
            *(undefined4 *)((longlong)puVar9 + 100) = uVar5;
            *(undefined4 *)(puVar9 + 0xd) = uVar6;
            *(undefined4 *)((longlong)puVar9 + 0x6c) = uVar7;
            uVar15 = uVar15 & 0x7f;
          }
          for (uVar16 = uVar15 >> 4; uVar16 != 0; uVar16 = uVar16 - 1) {
            *(undefined (*) [16])(puVar8 + -2) =
                 CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
            puVar1 = (undefined4 *)((longlong)puVar13 + (longlong)puVar8);
            uVar17 = *puVar1;
            uVar18 = puVar1[1];
            uVar19 = puVar1[2];
            uVar20 = puVar1[3];
            puVar8 = puVar8 + 2;
          }
          if ((uVar15 & 0xf) != 0) {
            lVar2 = (uVar15 & 0xf) + (longlong)puVar8;
            puVar1 = (undefined4 *)((longlong)puVar13 + lVar2 + -0x10);
            uVar5 = puVar1[1];
            uVar6 = puVar1[2];
            uVar7 = puVar1[3];
            *(undefined4 *)(lVar2 + -0x10) = *puVar1;
            *(undefined4 *)(lVar2 + -0xc) = uVar5;
            *(undefined4 *)(lVar2 + -8) = uVar6;
            *(undefined4 *)(lVar2 + -4) = uVar7;
          }
          *(undefined (*) [16])(puVar8 + -2) =
               CONCAT412(uVar20,CONCAT48(uVar19,CONCAT44(uVar18,uVar17)));
          return param_1;
        }
        goto LAB_180003300;
      }
      if (((ulonglong)param_1 & 7) != 0) {
        if (((ulonglong)param_1 & 1) != 0) {
          param_3 = param_3 - 1;
          *(undefined *)param_1 = *(undefined *)((longlong)puVar13 + (longlong)param_1);
          puVar8 = (undefined8 *)((longlong)param_1 + 1);
        }
        if (((ulonglong)puVar8 & 2) != 0) {
          param_3 = param_3 - 2;
          *(undefined2 *)puVar8 = *(undefined2 *)((longlong)puVar13 + (longlong)puVar8);
          puVar8 = (undefined8 *)((longlong)puVar8 + 2);
        }
        if (((ulonglong)puVar8 & 4) != 0) {
          param_3 = param_3 - 4;
          *(undefined4 *)puVar8 = *(undefined4 *)((longlong)puVar13 + (longlong)puVar8);
          puVar8 = (undefined8 *)((longlong)puVar8 + 4);
        }
      }
      uVar15 = param_3 >> 5;
      puVar9 = puVar8;
      if (uVar15 != 0) {
        do {
          uVar4 = *(undefined8 *)((longlong)((longlong)puVar13 + 8) + (longlong)puVar9);
          puVar8 = puVar9 + 4;
          *puVar9 = *(undefined8 *)((longlong)puVar13 + (longlong)puVar9);
          puVar9[1] = uVar4;
          uVar4 = *(undefined8 *)((longlong)((longlong)puVar13 + -8) + (longlong)puVar8);
          uVar15 = uVar15 - 1;
          puVar9[2] = *(undefined8 *)((longlong)((longlong)puVar13 + -0x10) + (longlong)puVar8);
          puVar9[3] = uVar4;
          puVar9 = puVar8;
        } while (uVar15 != 0);
        param_3 = param_3 & 0x1f;
      }
      uVar15 = param_3 >> 3;
      if (uVar15 != 0) {
        do {
          *puVar8 = *(undefined8 *)((longlong)puVar13 + (longlong)puVar8);
          puVar8 = puVar8 + 1;
          uVar15 = uVar15 - 1;
        } while (uVar15 != 0);
        param_3 = param_3 & 7;
      }
      if (param_3 == 0) {
        return param_1;
      }
      param_2 = (undefined8 *)((longlong)puVar13 + (longlong)puVar8);
      param_1 = puVar8;
    }
  }
                    // WARNING: Could not recover jumptable at 0x00018000304e. Too many branches
                    // WARNING: Treating indirect jump as call
  puVar13 = (undefined8 *)
            (*(code *)((ulonglong)*(uint *)(&DAT_180003050 + param_3 * 4) + 0x180000000))
                      (param_1,param_2);
  return puVar13;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_1800034d8(undefined8 param_1,int param_2,longlong param_3)

{
  bool bVar1;
  int iVar2;
  DWORD DVar3;
  undefined7 extraout_var;
  undefined8 uVar4;
  longlong lVar5;
  DWORD *_Memory;
  
  if (param_2 == 1) {
    bVar1 = FUN_180005740();
    if ((int)CONCAT71(extraout_var,bVar1) != 0) {
      iVar2 = _mtinit();
      if (iVar2 != 0) {
        FUN_180006870();
        DAT_18001f110 = GetCommandLineA();
        DAT_18001cd58 = __crtGetEnvironmentStringsA();
        uVar4 = FUN_18000576c();
        if (-1 < (int)uVar4) {
          iVar2 = _setargv();
          if (((-1 < iVar2) && (iVar2 = _setenvp(), -1 < iVar2)) &&
             (uVar4 = FUN_180005404(), (int)uVar4 == 0)) {
            DAT_18001cd50 = DAT_18001cd50 + 1;
            goto LAB_18000362c;
          }
          _ioterm();
        }
        FUN_180005204();
      }
      FUN_180005760();
    }
LAB_1800034f3:
    uVar4 = 0;
  }
  else {
    if (param_2 == 0) {
      if (DAT_18001cd50 < 1) goto LAB_1800034f3;
      DAT_18001cd50 = DAT_18001cd50 + -1;
      if (_DAT_18001d328 == 0) {
        FUN_1800053f4();
      }
      FUN_180005284();
      if (param_3 == 0) {
        _ioterm();
        FUN_180005204();
        FUN_180005760();
        if (DAT_180017238 != -1) {
          FUN_180005204();
        }
      }
    }
    else {
      if (param_2 == 2) {
        lVar5 = FUN_1800061fc();
        if (lVar5 == 0) {
          _Memory = (DWORD *)FUN_1800066f0(1,0x478);
          if (_Memory != (DWORD *)0x0) {
            iVar2 = FUN_180006218();
            if (iVar2 != 0) {
              FUN_1800050c0((longlong)_Memory,0);
              DVar3 = GetCurrentThreadId();
              *_Memory = DVar3;
              *(undefined8 *)(_Memory + 2) = 0xffffffffffffffff;
              goto LAB_18000362c;
            }
            free(_Memory);
          }
          goto LAB_1800034f3;
        }
      }
      else {
        if (param_2 == 3) {
          _freeptd((_ptiddata)0x0);
        }
      }
    }
LAB_18000362c:
    uVar4 = 1;
  }
  return uVar4;
}



// WARNING: Removing unreachable block (ram,0x000180003737)
// WARNING: Removing unreachable block (ram,0x0001800036c9)
// WARNING: Removing unreachable block (ram,0x000180003771)

ulonglong entry(undefined8 param_1,int param_2,longlong param_3,undefined8 param_4)

{
  ulonglong uVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  
  if (param_2 == 1) {
    FUN_180005f40();
  }
  if ((param_2 == 0) && (DAT_18001cd50 == 0)) {
    uVar1 = 0;
  }
  else {
    if ((param_2 - 1U < 2) && (uVar2 = FUN_1800034d8(param_1,param_2,param_3), (int)uVar2 == 0)) {
      uVar1 = 0;
    }
    else {
      uVar3 = FUN_180002be0();
      uVar1 = uVar3 & 0xffffffff;
      if ((param_2 == 1) && ((int)uVar3 == 0)) {
        FUN_180002be0();
        FUN_1800034d8(param_1,0,param_3);
      }
      if ((param_2 == 0) || (param_2 == 3)) {
        uVar2 = FUN_1800034d8(param_1,param_2,param_3);
        uVar1 = (ulonglong)(-(uint)((int)uVar2 != 0) & (uint)uVar1);
      }
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  _call_reportfault
// 
// Library: Visual Studio 2012 Release

void _call_reportfault(int nDbgHookCode,DWORD dwExceptionCode,DWORD dwExceptionFlags)

{
  BOOL BVar1;
  LONG LVar2;
  undefined auStackX8 [8];
  undefined auStack1464 [32];
  EXCEPTION_POINTERS local_598;
  undefined local_588 [4];
  DWORD local_584;
  CONTEXT local_4e8;
  ulonglong local_18;
  
  local_18 = DAT_1800170a0 ^ (ulonglong)auStack1464;
  if (nDbgHookCode != -1) {
    FUN_180006ac4();
  }
  local_588 = 0;
  FUN_180003c80((undefined (*) [16])&local_584,0,0x94);
  local_598.ExceptionRecord = (PEXCEPTION_RECORD)local_588;
  local_598.ContextRecord = (PCONTEXT)&local_4e8;
  __crtCaptureCurrentContext(&local_4e8);
  local_4e8.Rsp = (DWORD64)auStackX8;
  local_588 = dwExceptionCode;
  local_584 = dwExceptionFlags;
  BVar1 = IsDebuggerPresent();
  LVar2 = __crtUnhandledException(&local_598);
  if (((LVar2 == 0) && (BVar1 == 0)) && (nDbgHookCode != -1)) {
    FUN_180006ac4();
  }
  FUN_180002f40(local_18 ^ (ulonglong)auStack1464);
  return;
}



void FUN_18000388c(undefined8 param_1)

{
  DAT_18001cd68 = param_1;
  return;
}



// Library Function - Single Match
//  _invalid_parameter
// 
// Library: Visual Studio 2012 Release

void _invalid_parameter(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                       undefined8 param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(DAT_18001cd68);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800038e6. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4);
    return;
  }
  FUN_18000391c();
  UNRECOVERED_JUMPTABLE = (code *)swi(3);
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_1800038fc(void)

{
  _invalid_parameter(0,0,0,0,0);
  return;
}



void FUN_18000391c(void)

{
  code *pcVar1;
  BOOL BVar2;
  HANDLE hProcess;
  undefined8 unaff_RBX;
  undefined *puVar3;
  undefined auStack40 [8];
  undefined auStack32 [32];
  
  puVar3 = auStack40;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
    puVar3 = auStack32;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180003949;
  _call_reportfault(2,0xc0000417,1);
  *(undefined8 *)(puVar3 + 0x20) = unaff_RBX;
  *(undefined8 *)(puVar3 + -8) = 0x1800066be;
  hProcess = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x0001800066c8. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess,0xc0000417);
  return;
}



// Library Function - Single Match
//  __doserrno
// 
// Library: Visual Studio 2012 Release

ulong * __doserrno(void)

{
  _ptiddata p_Var1;
  ulong *puVar2;
  
  p_Var1 = _getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    puVar2 = &DAT_18001721c;
  }
  else {
    puVar2 = &p_Var1->_tdoserrno;
  }
  return puVar2;
}



// Library Function - Single Match
//  _dosmaperr
// 
// Library: Visual Studio 2012 Release

void _dosmaperr(ulong param_1)

{
  int iVar1;
  _ptiddata p_Var2;
  ulong *puVar3;
  int *piVar4;
  
  p_Var2 = _getptd_noexit();
  if (p_Var2 == (_ptiddata)0x0) {
    puVar3 = &DAT_18001721c;
  }
  else {
    puVar3 = &p_Var2->_tdoserrno;
  }
  *puVar3 = param_1;
  p_Var2 = _getptd_noexit();
  piVar4 = (int *)&DAT_180017218;
  if (p_Var2 != (_ptiddata)0x0) {
    piVar4 = &p_Var2->_terrno;
  }
  iVar1 = _get_errno_from_oserr(param_1);
  *piVar4 = iVar1;
  return;
}



// Library Function - Single Match
//  _errno
// 
// Library: Visual Studio 2012 Release

int * _errno(void)

{
  _ptiddata p_Var1;
  int *piVar2;
  
  p_Var1 = _getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    piVar2 = (int *)&DAT_180017218;
  }
  else {
    piVar2 = &p_Var1->_terrno;
  }
  return piVar2;
}



// Library Function - Single Match
//  _get_errno_from_oserr
// 
// Library: Visual Studio 2012 Release

int _get_errno_from_oserr(ulong param_1)

{
  int iVar1;
  uint uVar2;
  ulong *puVar3;
  
  uVar2 = 0;
  puVar3 = &DAT_1800170b0;
  do {
    if (param_1 == *puVar3) {
      return *(int *)((longlong)&DAT_1800170b4 + (longlong)(int)uVar2 * 8);
    }
    uVar2 = uVar2 + 1;
    puVar3 = puVar3 + 2;
  } while (uVar2 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  iVar1 = 0x16;
  if (param_1 - 0xbc < 0xf) {
    iVar1 = 8;
  }
  return iVar1;
}



// WARNING: Could not reconcile some variable overlaps

ulonglong FUN_180003a38(undefined4 param_1,FILE *param_2)

{
  uint _FileHandle;
  int iVar1;
  uint uVar2;
  int *piVar3;
  undefined **ppuVar4;
  longlong lVar5;
  undefined *puVar6;
  uint uVar7;
  undefined4 local_res8 [2];
  
  local_res8[0] = param_1;
  _FileHandle = _fileno(param_2);
  uVar7 = param_2->_flag;
  if ((uVar7 & 0x82) == 0) {
    piVar3 = _errno();
    *piVar3 = 9;
  }
  else {
    if ((uVar7 & 0x40) == 0) {
      uVar2 = 0;
      if ((uVar7 & 1) != 0) {
        param_2->_cnt = 0;
        if ((uVar7 & 0x10) == 0) {
          param_2->_flag = uVar7 | 0x20;
          return 0xffffffff;
        }
        param_2->_ptr = param_2->_base;
        param_2->_flag = uVar7 & 0xfffffffe;
      }
      uVar7 = param_2->_flag;
      param_2->_cnt = 0;
      param_2->_flag = uVar7 & 0xffffffef | 2;
      if (((uVar7 & 0x10c) == 0) &&
         (((ppuVar4 = FUN_180006b94(), param_2 != (FILE *)(ppuVar4 + 6) &&
           (ppuVar4 = FUN_180006b94(), param_2 != (FILE *)(ppuVar4 + 0xc))) ||
          (iVar1 = _isatty(_FileHandle), iVar1 == 0)))) {
        _getbuf(param_2);
      }
      if ((param_2->_flag & 0x108U) == 0) {
        uVar7 = 1;
        uVar2 = FUN_180006d30(_FileHandle,(wint_t *)local_res8,1);
      }
      else {
        uVar7 = *(int *)&param_2->_ptr - *(int *)&param_2->_base;
        param_2->_ptr = (char *)((longlong)param_2->_base + 1);
        param_2->_cnt = param_2->_bufsiz + -1;
        if ((int)uVar7 < 1) {
          if (_FileHandle + 2 < 2) {
            puVar6 = &DAT_180017240;
          }
          else {
            puVar6 = (undefined *)
                     ((ulonglong)(_FileHandle & 0x1f) * 0x58 +
                     *(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)_FileHandle >> 5) * 8)
                     );
          }
          if (((puVar6[8] & 0x20) != 0) && (lVar5 = FUN_180007608(_FileHandle,0,2), lVar5 == -1))
          goto LAB_180003a70;
        }
        else {
          uVar2 = FUN_180006d30(_FileHandle,(wint_t *)param_2->_base,uVar7);
        }
        *param_2->_base = (byte)local_res8[0];
      }
      if (uVar2 == uVar7) {
        return (ulonglong)(byte)local_res8[0];
      }
    }
    else {
      piVar3 = _errno();
      *piVar3 = 0x22;
    }
  }
LAB_180003a70:
  param_2->_flag = param_2->_flag | 0x20;
  return 0xffffffff;
}



// Library Function - Single Match
//  public: __cdecl _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct * __ptr64) __ptr64
// 
// Library: Visual Studio 2012 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  _ptiddata p_Var5;
  pthreadlocinfo ptVar6;
  pthreadmbcinfo ptVar7;
  
  this[0x18] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    p_Var5 = _getptd();
    *(_ptiddata *)(this + 0x10) = p_Var5;
    ptVar6 = p_Var5->ptlocinfo;
    *(pthreadlocinfo *)this = ptVar6;
    *(pthreadmbcinfo *)(this + 8) = p_Var5->ptmbcinfo;
    if ((ptVar6 != (pthreadlocinfo)PTR_DAT_180017e70) && ((DAT_180017fd8 & p_Var5->_ownlocale) == 0)
       ) {
      ptVar6 = __updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar6;
    }
    if ((*(undefined **)(this + 8) != PTR_DAT_180017b90) &&
       ((DAT_180017fd8 & *(uint *)(*(longlong *)(this + 0x10) + 200)) == 0)) {
      ptVar7 = __updatetmbcinfo();
      *(pthreadmbcinfo *)(this + 8) = ptVar7;
    }
    uVar1 = *(uint *)(*(longlong *)(this + 0x10) + 200);
    if ((uVar1 & 2) == 0) {
      *(uint *)(*(longlong *)(this + 0x10) + 200) = uVar1 | 2;
      this[0x18] = (_LocaleUpdate)0x1;
    }
  }
  else {
    uVar2 = *(undefined4 *)((longlong)&param_1->locinfo + 4);
    uVar3 = *(undefined4 *)&param_1->mbcinfo;
    uVar4 = *(undefined4 *)((longlong)&param_1->mbcinfo + 4);
    *(undefined4 *)this = *(undefined4 *)&param_1->locinfo;
    *(undefined4 *)(this + 4) = uVar2;
    *(undefined4 *)(this + 8) = uVar3;
    *(undefined4 *)(this + 0xc) = uVar4;
  }
  return this;
}



undefined (*) [16] FUN_180003c80(undefined (*param_1) [16],byte param_2,ulonglong param_3)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  undefined (*pauVar3) [16];
  undefined *puVar4;
  undefined2 uVar5;
  ulonglong uVar7;
  longlong lVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  undefined auVar11 [12];
  undefined4 uVar6;
  undefined auVar12 [13];
  undefined auVar13 [16];
  undefined uVar14;
  
  if (0xf < param_3) {
    pauVar2 = param_1;
    if ((DAT_18001d2e4 >> 1 & 1) == 0) {
      uVar7 = (ulonglong)param_2 * 0x101010101010101;
      if ((DAT_18001d2e4 >> 2 & 1) != 0) {
        uVar14 = SUB141(ZEXT814(uVar7) >> 0x30,0);
        auVar12 = ZEXT813(uVar7);
        auVar11 = ZEXT812(uVar7);
        auVar13 = CONCAT142(SUB1614(CONCAT133(SUB1613(CONCAT124(SUB1612(CONCAT115(SUB1611(CONCAT106(
                                                  SUB1610(CONCAT97(SUB169(CONCAT88(SUB168(CONCAT79(
                                                  SUB167(CONCAT610(SUB166(CONCAT511(SUB165(CONCAT412
                                                  (SUB164(CONCAT313(SUB163(CONCAT214(SUB162(
                                                  CONCAT115(SUB161(ZEXT816(uVar7) >> 0x38,0),
                                                            CONCAT114(SUB151(ZEXT815(uVar7) >> 0x38,
                                                                             0),ZEXT814(uVar7))) >>
                                                  0x70,0),CONCAT113(uVar14,auVar12)) >> 0x68,0),
                                                  CONCAT112(uVar14,auVar11)) >> 0x60,0),
                                                  CONCAT111(SUB131(auVar12 >> 0x28,0),ZEXT811(uVar7)
                                                           )) >> 0x58,0),
                                                  CONCAT110(SUB121(auVar11 >> 0x28,0),
                                                            (unkuint10)uVar7)) >> 0x50,0),
                                                  CONCAT19(SUB131(auVar12 >> 0x20,0),(unkuint9)uVar7
                                                          )) >> 0x48,0),
                                                  CONCAT18(SUB121(auVar11 >> 0x20,0),uVar7)) >> 0x40
                                                  ,0),(uVar7 >> 0x18) << 0x38) >> 0x38,0),
                                                  ((uint7)uVar7 >> 0x18) << 0x30) >> 0x30,0),
                                                  ((uint6)uVar7 >> 0x10) << 0x28) >> 0x28,0),
                                                  ((uint5)uVar7 >> 0x10) << 0x20) >> 0x20,0),
                                                  ((uint)uVar7 >> 8) << 0x18) >> 0x18,0),
                                              ((uint3)uVar7 >> 8) << 0x10) >> 0x10,0),
                            (ushort)uVar7 & 0xff | (ushort)uVar7 << 8);
        if (((ulonglong)param_1 & 0xf) != 0) {
          *param_1 = auVar13;
          pauVar2 = (undefined (*) [16])((longlong)param_1 + (0x10 - ((ulonglong)param_1 & 0xf)));
          param_3 = (((ulonglong)param_1 & 0xf) - 0x10) + param_3;
        }
        uVar7 = param_3 >> 7;
        pauVar3 = pauVar2;
        if (uVar7 != 0) {
          do {
            *pauVar2 = auVar13;
            pauVar2[1] = auVar13;
            pauVar3 = pauVar2[8];
            pauVar2[2] = auVar13;
            pauVar2[3] = auVar13;
            uVar7 = uVar7 - 1;
            pauVar2[4] = auVar13;
            pauVar2[5] = auVar13;
            pauVar2[6] = auVar13;
            pauVar2[7] = auVar13;
            pauVar2 = pauVar3;
          } while (uVar7 != 0);
          param_3 = param_3 & 0x7f;
        }
        for (uVar7 = param_3 >> 4; uVar7 != 0; uVar7 = uVar7 - 1) {
          *pauVar3 = auVar13;
          pauVar3 = pauVar3[1];
        }
        if ((param_3 & 0xf) != 0) {
          *(undefined (*) [16])(pauVar3[-1] + (param_3 & 0xf)) = auVar13;
        }
        return param_1;
      }
      if (0x3f < param_3) {
        uVar1 = -(int)param_1 & 7;
        uVar9 = param_3;
        if (uVar1 != 0) {
          uVar9 = param_3 - uVar1;
          *(ulonglong *)*param_1 = uVar7;
        }
        param_3 = uVar9 & 0x3f;
        pauVar2 = (undefined (*) [16])(*param_1 + uVar1);
        for (uVar9 = uVar9 >> 6; uVar9 != 0; uVar9 = uVar9 - 1) {
          *(ulonglong *)*pauVar2 = uVar7;
          *(ulonglong *)(*pauVar2 + 8) = uVar7;
          *(ulonglong *)pauVar2[1] = uVar7;
          *(ulonglong *)(pauVar2[1] + 8) = uVar7;
          *(ulonglong *)pauVar2[2] = uVar7;
          *(ulonglong *)(pauVar2[2] + 8) = uVar7;
          *(ulonglong *)pauVar2[3] = uVar7;
          *(ulonglong *)(pauVar2[3] + 8) = uVar7;
          pauVar2 = pauVar2[4];
        }
      }
      uVar10 = param_3 & 7;
      for (uVar9 = param_3 >> 3; uVar9 != 0; uVar9 = uVar9 - 1) {
        *(ulonglong *)*pauVar2 = uVar7;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 8);
      }
      for (; uVar10 != 0; uVar10 = uVar10 - 1) {
        (*pauVar2)[0] = (char)uVar7;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
      }
    }
    else {
      for (; param_3 != 0; param_3 = param_3 - 1) {
        (*pauVar2)[0] = param_2;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
      }
    }
    return param_1;
  }
  lVar8 = (ulonglong)param_2 * 0x101010101010101;
  puVar4 = *param_1 + param_3;
  uVar14 = (undefined)lVar8;
  uVar5 = (undefined2)lVar8;
  uVar6 = (undefined4)lVar8;
  switch(param_3) {
  case 0:
    return param_1;
  case 1:
    goto switchD_180003e12_caseD_1;
  case 8:
    *(longlong *)(puVar4 + -8) = lVar8;
    return param_1;
  case 9:
    *(longlong *)(puVar4 + -9) = lVar8;
    puVar4[-1] = uVar14;
    return param_1;
  case 10:
    *(longlong *)(puVar4 + -10) = lVar8;
    *(undefined2 *)(puVar4 + -2) = uVar5;
    return param_1;
  case 0xb:
    *(longlong *)(puVar4 + -0xb) = lVar8;
    break;
  case 0xc:
    *(longlong *)(puVar4 + -0xc) = lVar8;
  case 4:
    *(undefined4 *)(puVar4 + -4) = uVar6;
    return param_1;
  case 0xd:
    *(longlong *)(puVar4 + -0xd) = lVar8;
  case 5:
    *(undefined4 *)(puVar4 + -5) = uVar6;
    puVar4[-1] = uVar14;
    return param_1;
  case 0xe:
    *(longlong *)(puVar4 + -0xe) = lVar8;
  case 6:
    *(undefined4 *)(puVar4 + -6) = uVar6;
  case 2:
    *(undefined2 *)(puVar4 + -2) = uVar5;
    return param_1;
  case 0xf:
    *(longlong *)(puVar4 + -0xf) = lVar8;
  case 7:
    *(undefined4 *)(puVar4 + -7) = uVar6;
  }
  *(undefined2 *)(puVar4 + -3) = uVar5;
switchD_180003e12_caseD_1:
  puVar4[-1] = uVar14;
  return param_1;
}



// Library Function - Single Match
//  write_char
// 
// Library: Visual Studio 2012 Release

void write_char(byte param_1,FILE *param_2,int *param_3)

{
  int *piVar1;
  uint uVar2;
  ulonglong uVar3;
  
  if (((*(byte *)&param_2->_flag & 0x40) == 0) || (param_2->_base != (char *)0x0)) {
    piVar1 = &param_2->_cnt;
    *piVar1 = *piVar1 + -1;
    if (*piVar1 < 0) {
      uVar3 = FUN_180003a38((int)(char)param_1,param_2);
      uVar2 = (uint)uVar3;
    }
    else {
      *param_2->_ptr = param_1;
      param_2->_ptr = param_2->_ptr + 1;
      uVar2 = (uint)param_1;
    }
    if (uVar2 == 0xffffffff) {
      *param_3 = -1;
    }
    else {
      *param_3 = *param_3 + 1;
    }
  }
  else {
    *param_3 = *param_3 + 1;
  }
  return;
}



// Library Function - Single Match
//  write_multi_char
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void write_multi_char(byte param_1,int param_2,FILE *param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      write_char(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



// Library Function - Single Match
//  write_string
// 
// Library: Visual Studio 2012 Release

void write_string(byte *param_1,int param_2,FILE *param_3,int *param_4,int *param_5)

{
  int iVar1;
  
  iVar1 = *param_5;
  if (((*(byte *)&param_3->_flag & 0x40) == 0) || (param_3->_base != (char *)0x0)) {
    *param_5 = 0;
    if (0 < param_2) {
      do {
        param_2 = param_2 + -1;
        write_char(*param_1,param_3,param_4);
        param_1 = param_1 + 1;
        if (*param_4 == -1) {
          if (*param_5 != 0x2a) break;
          write_char(0x3f,param_3,param_4);
        }
      } while (0 < param_2);
      if (*param_5 != 0) {
        return;
      }
    }
    *param_5 = iVar1;
  }
  else {
    *param_4 = *param_4 + param_2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __raise_securityfailure
// 
// Library: Visual Studio 2012 Release

void __raise_securityfailure(EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  
  _DAT_18001d2e0 = IsDebuggerPresent();
  FUN_180006ac4();
  __crtUnhandledException(param_1);
  if (_DAT_18001d2e0 == 0) {
    FUN_180006ac4();
  }
  hProcess = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x0001800066c8. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess,0xc0000409);
  return;
}



// WARNING: Removing unreachable block (ram,0x000180004c3a)
// WARNING: Removing unreachable block (ram,0x000180004ba4)
// WARNING: Removing unreachable block (ram,0x000180004b3e)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180004b24(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar6 = 0;
  piVar1 = (int *)cpuid_basic_info(0);
  _DAT_180017234 = 2;
  _DAT_180017230 = 1;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  if (((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) &&
     ((((uVar5 = *puVar2 & 0xfff3ff0, uVar5 == 0x106c0 || (uVar5 == 0x20660)) || (uVar5 == 0x20670))
      || ((uVar5 - 0x30650 < 0x21 &&
          ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0)))))) {
    DAT_18001d2e4 = DAT_18001d2e4 | 1;
  }
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x600eff < (*puVar2 & 0xff00f00))) {
    DAT_18001d2e4 = DAT_18001d2e4 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar6 = *(uint *)(lVar3 + 4);
    if ((uVar6 >> 9 & 1) != 0) {
      DAT_18001d2e4 = DAT_18001d2e4 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180017230 = 2;
    _DAT_180017234 = 6;
    if (((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) {
      _DAT_180017230 = 3;
      _DAT_180017234 = 0xe;
      if ((uVar6 & 0x20) != 0) {
        _DAT_180017230 = 5;
        _DAT_180017234 = 0x2e;
      }
    }
  }
  return 0;
}



undefined4 FUN_180004e94(int param_1,void *param_2)

{
  int iVar1;
  int *piVar2;
  code *pcVar3;
  void *pvVar4;
  _ptiddata p_Var5;
  int *piVar6;
  longlong lVar7;
  longlong lVar8;
  
  if (param_1 != -0x1f928c9d) {
    return 0;
  }
  p_Var5 = _getptd_noexit();
  if (p_Var5 != (_ptiddata)0x0) {
    piVar2 = (int *)p_Var5->_pxcptacttab;
    piVar6 = piVar2;
    do {
      if (*piVar6 == -0x1f928c9d) break;
      piVar6 = piVar6 + 4;
    } while (piVar6 < piVar2 + 0x30);
    if ((piVar2 + 0x30 <= piVar6) || (*piVar6 != -0x1f928c9d)) {
      piVar6 = (int *)0x0;
    }
    if ((piVar6 != (int *)0x0) && (pcVar3 = *(code **)(piVar6 + 2), pcVar3 != (code *)0x0)) {
      if (pcVar3 == (code *)0x5) {
        *(undefined8 *)(piVar6 + 2) = 0;
        return 1;
      }
      if (pcVar3 != (code *)0x1) {
        pvVar4 = p_Var5->_tpxcptinfoptrs;
        p_Var5->_tpxcptinfoptrs = param_2;
        if (piVar6[1] == 8) {
          lVar7 = 0x30;
          do {
            lVar8 = lVar7 + 0x10;
            *(undefined8 *)(lVar7 + 8 + (longlong)p_Var5->_pxcptacttab) = 0;
            lVar7 = lVar8;
          } while (lVar8 < 0xc0);
          iVar1 = p_Var5->_tfpecode;
          if (*piVar6 == -0x3fffff72) {
            p_Var5->_tfpecode = 0x83;
          }
          else {
            if (*piVar6 == -0x3fffff70) {
              p_Var5->_tfpecode = 0x81;
            }
            else {
              if (*piVar6 == -0x3fffff6f) {
                p_Var5->_tfpecode = 0x84;
              }
              else {
                if (*piVar6 == -0x3fffff6d) {
                  p_Var5->_tfpecode = 0x85;
                }
                else {
                  if (*piVar6 == -0x3fffff73) {
                    p_Var5->_tfpecode = 0x82;
                  }
                  else {
                    if (*piVar6 == -0x3fffff71) {
                      p_Var5->_tfpecode = 0x86;
                    }
                    else {
                      if (*piVar6 == -0x3fffff6e) {
                        p_Var5->_tfpecode = 0x8a;
                      }
                      else {
                        if (*piVar6 == -0x3ffffd4b) {
                          p_Var5->_tfpecode = 0x8d;
                        }
                        else {
                          if (*piVar6 == -0x3ffffd4c) {
                            p_Var5->_tfpecode = 0x8e;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          (*pcVar3)(8,p_Var5->_tfpecode);
          p_Var5->_tfpecode = iVar1;
        }
        else {
          *(undefined8 *)(piVar6 + 2) = 0;
          (*pcVar3)(piVar6[1]);
        }
        p_Var5->_tpxcptinfoptrs = pvVar4;
      }
      return 0xffffffff;
    }
  }
  return 0;
}



// Library Function - Single Match
//  _freefls
// 
// Library: Visual Studio 2012 Release

void _freefls(void *_PerFiberData)

{
  int *piVar1;
  
  if (_PerFiberData != (void *)0x0) {
    if (*(void **)((longlong)_PerFiberData + 0x38) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x38));
    }
    if (*(void **)((longlong)_PerFiberData + 0x48) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x48));
    }
    if (*(void **)((longlong)_PerFiberData + 0x58) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x58));
    }
    if (*(void **)((longlong)_PerFiberData + 0x68) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x68));
    }
    if (*(void **)((longlong)_PerFiberData + 0x70) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x70));
    }
    if (*(void **)((longlong)_PerFiberData + 0x78) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x78));
    }
    if (*(void **)((longlong)_PerFiberData + 0x80) != (void *)0x0) {
      free(*(void **)((longlong)_PerFiberData + 0x80));
    }
    if (*(undefined **)((longlong)_PerFiberData + 0xa0) != &DAT_180010370) {
      free(*(undefined **)((longlong)_PerFiberData + 0xa0));
    }
    _lock(0xd);
    piVar1 = *(int **)((longlong)_PerFiberData + 0xb8);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      if ((*piVar1 == 0) && (piVar1 != &DAT_180017870)) {
        free(piVar1);
      }
    }
    FUN_180008ad8(0xd);
    _lock(0xc);
    piVar1 = *(int **)((longlong)_PerFiberData + 0xc0);
    if (piVar1 != (int *)0x0) {
      __removelocaleref(piVar1);
      if (((piVar1 != (int *)PTR_DAT_180017e70) && (piVar1 != (int *)&DAT_180017e80)) &&
         (*piVar1 == 0)) {
        __freetlocinfo(piVar1);
      }
    }
    FUN_180008ad8(0xc);
    free(_PerFiberData);
  }
  return;
}



// Library Function - Single Match
//  _freeptd
// 
// Library: Visual Studio 2012 Release

void _freeptd(_ptiddata _Ptd)

{
  if (DAT_180017238 != -1) {
    if (_Ptd == (_ptiddata)0x0) {
      _Ptd = (_ptiddata)FUN_1800061fc();
    }
    FUN_180006218();
    _freefls(_Ptd);
  }
  return;
}



// Library Function - Single Match
//  _getptd
// 
// Library: Visual Studio 2012 Release

_ptiddata _getptd(void)

{
  _ptiddata p_Var1;
  
  p_Var1 = _getptd_noexit();
  if (p_Var1 == (_ptiddata)0x0) {
    _amsg_exit(0x10);
  }
  return p_Var1;
}



// Library Function - Single Match
//  _getptd_noexit
// 
// Library: Visual Studio 2012 Release

_ptiddata _getptd_noexit(void)

{
  DWORD dwErrCode;
  int iVar1;
  DWORD DVar2;
  _ptiddata _Memory;
  
  dwErrCode = GetLastError();
  _Memory = (_ptiddata)FUN_1800061fc();
  if (_Memory == (_ptiddata)0x0) {
    _Memory = (_ptiddata)FUN_1800066f0(1,0x478);
    if (_Memory != (_ptiddata)0x0) {
      iVar1 = FUN_180006218();
      if (iVar1 == 0) {
        free(_Memory);
        _Memory = (_ptiddata)0x0;
      }
      else {
        FUN_1800050c0((longlong)_Memory,0);
        DVar2 = GetCurrentThreadId();
        _Memory->_thandle = 0xffffffffffffffff;
        _Memory->_tid = DVar2;
      }
    }
  }
  SetLastError(dwErrCode);
  return _Memory;
}



void FUN_1800050c0(longlong param_1,longlong param_2)

{
  *(undefined **)(param_1 + 0xa0) = &DAT_180010370;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 1;
  *(undefined4 *)(param_1 + 200) = 1;
  *(undefined2 *)(param_1 + 0x164) = 0x43;
  *(undefined2 *)(param_1 + 0x26a) = 0x43;
  *(undefined4 **)(param_1 + 0xb8) = &DAT_180017870;
  *(undefined8 *)(param_1 + 0x470) = 0;
  _lock(0xd);
  LOCK();
  **(int **)(param_1 + 0xb8) = **(int **)(param_1 + 0xb8) + 1;
  FUN_180008ad8(0xd);
  _lock(0xc);
  *(longlong *)(param_1 + 0xc0) = param_2;
  if (param_2 == 0) {
    *(undefined **)(param_1 + 0xc0) = PTR_DAT_180017e70;
  }
  __addlocaleref(*(int **)(param_1 + 0xc0));
  FUN_180008ad8(0xc);
  return;
}



// Library Function - Single Match
//  _mtinit
// 
// Library: Visual Studio 2012 Release

int _mtinit(void)

{
  int iVar1;
  DWORD DVar2;
  DWORD *pDVar3;
  
  FUN_1800054a8();
  iVar1 = FUN_180008a74();
  if ((((iVar1 != 0) && (DAT_180017238 = FUN_1800061c4(), DAT_180017238 != -1)) &&
      (pDVar3 = (DWORD *)FUN_1800066f0(1,0x478), pDVar3 != (DWORD *)0x0)) &&
     (iVar1 = FUN_180006218(), iVar1 != 0)) {
    FUN_1800050c0((longlong)pDVar3,0);
    DVar2 = GetCurrentThreadId();
    *(undefined8 *)(pDVar3 + 2) = 0xffffffffffffffff;
    *pDVar3 = DVar2;
    return 1;
  }
  FUN_180005204();
  return 0;
}



void FUN_180005204(void)

{
  LPCRITICAL_SECTION lpCriticalSection;
  LPCRITICAL_SECTION *pp_Var1;
  int *piVar2;
  longlong lVar3;
  longlong lVar4;
  
  if (DAT_180017238 != -1) {
    FUN_1800061e0();
    DAT_180017238 = -1;
  }
  lVar4 = 0x24;
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_180018030;
  lVar3 = 0x24;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (*(int *)(pp_Var1 + 1) != 1)) {
      DeleteCriticalSection(lpCriticalSection);
      free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  piVar2 = &DAT_180018038;
  do {
    if ((*(LPCRITICAL_SECTION *)(piVar2 + -2) != (LPCRITICAL_SECTION)0x0) && (*piVar2 == 1)) {
      DeleteCriticalSection(*(LPCRITICAL_SECTION *)(piVar2 + -2));
    }
    piVar2 = piVar2 + 4;
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  return;
}



// Library Function - Single Match
//  __crtCorExitProcess
// 
// Library: Visual Studio 2012 Release

void __crtCorExitProcess(int param_1)

{
  BOOL BVar1;
  FARPROC pFVar2;
  HMODULE local_res10 [3];
  uint extraout_var;
  
  BVar1 = GetModuleHandleExW(0,L"mscoree.dll",local_res10);
  if (BVar1 != 0) {
    pFVar2 = GetProcAddress(local_res10[0],"CorExitProcess");
    extraout_var = (uint)((ulonglong)pFVar2 >> 0x20);
    if (((ulonglong)pFVar2 & 0xffffffff | (ulonglong)extraout_var << 0x20) != 0) {
      (*(code *)((ulonglong)pFVar2 & 0xffffffff | (ulonglong)extraout_var << 0x20))(param_1);
    }
  }
  return;
}



void FUN_18000526c(UINT param_1)

{
  __crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_180005284(void)

{
  int iVar1;
  PVOID _Memory;
  void **ppvVar2;
  
  _Memory = DecodePointer(DAT_18001f100);
  for (ppvVar2 = DAT_18001d308; (ppvVar2 != (void **)0x0 && (*ppvVar2 != (void *)0x0));
      ppvVar2 = ppvVar2 + 1) {
    free(*ppvVar2);
  }
  free(DAT_18001d308);
  DAT_18001d308 = (void **)0x0;
  for (ppvVar2 = DAT_18001d300; (ppvVar2 != (void **)0x0 && (*ppvVar2 != (void *)0x0));
      ppvVar2 = ppvVar2 + 1) {
    free(*ppvVar2);
  }
  free(DAT_18001d300);
  DAT_18001d300 = (void **)0x0;
  free(DAT_18001d2f8);
  free(DAT_18001d2f0);
  DAT_18001d2f8 = (void *)0x0;
  DAT_18001d2f0 = (void *)0x0;
  if ((_Memory != (PVOID)0xffffffffffffffff) && (DAT_18001f100 != (PVOID)0x0)) {
    free(_Memory);
  }
  DAT_18001f100 = EncodePointer((PVOID)0xffffffffffffffff);
  if (DAT_18001df40 != (void *)0x0) {
    free(DAT_18001df40);
    DAT_18001df40 = (void *)0x0;
  }
  if (DAT_18001df48 != (void *)0x0) {
    free(DAT_18001df48);
    DAT_18001df48 = (void *)0x0;
  }
  LOCK();
  iVar1 = *(int *)PTR_DAT_180017b90;
  *(int *)PTR_DAT_180017b90 = *(int *)PTR_DAT_180017b90 + -1;
  if ((iVar1 == 1) && ((undefined4 *)PTR_DAT_180017b90 != &DAT_180017870)) {
    free(PTR_DAT_180017b90);
    PTR_DAT_180017b90 = (undefined *)&DAT_180017870;
  }
  return;
}



// Library Function - Single Match
//  _amsg_exit
// 
// Library: Visual Studio 2012 Release

void _amsg_exit(int param_1)

{
  code *pcVar1;
  
  _FF_MSGBANNER();
  _NMSG_WRITE(param_1);
  FUN_1800055a8(0xff,1,0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_1800053f4(void)

{
  FUN_1800055a8(0,0,1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180005404(void)

{
  BOOL BVar1;
  undefined8 uVar2;
  
  BVar1 = _IsNonwritableInCurrentImage((PBYTE)&PTR_thunk_FUN_18000b418_180015350);
  if (BVar1 != 0) {
    thunk_FUN_18000b418();
  }
  _initp_misc_cfltcvt_tab();
  uVar2 = _initterm_e((undefined **)&DAT_18000f280,(undefined **)&DAT_18000f2a8);
  if ((int)uVar2 == 0) {
    atexit(&LAB_1800068a8);
    FUN_1800054f4((undefined **)&DAT_18000f270,(undefined **)&DAT_18000f278);
    if ((_DAT_18001f0f0 != (code *)0x0) &&
       (BVar1 = _IsNonwritableInCurrentImage(&DAT_18001f0f0), BVar1 != 0)) {
      (*_DAT_18001f0f0)(0,2);
    }
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_18000549c(UINT param_1)

{
  FUN_1800055a8(param_1,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800054a8(void)

{
  PVOID pvVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  
  pvVar1 = EncodePointer((PVOID)0x0);
  FUN_18000908c(pvVar1);
  FUN_18000388c(pvVar1);
  FUN_180009094(pvVar1);
  FUN_1800090ac(pvVar1);
  FUN_180009038();
  FUN_180009300(pvVar1);
  hModule = GetModuleHandleW(L"kernel32.dll");
  pFVar2 = GetProcAddress(hModule,"FlsAlloc");
  DAT_18001efe0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"FlsFree");
  DAT_18001efe8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"FlsGetValue");
  DAT_18001eff0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"FlsSetValue");
  DAT_18001eff8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"InitializeCriticalSectionEx");
  DAT_18001f000 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CreateEventExW");
  _DAT_18001f008 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CreateSemaphoreExW");
  _DAT_18001f010 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"SetThreadStackGuarantee");
  _DAT_18001f018 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CreateThreadpoolTimer");
  _DAT_18001f020 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"SetThreadpoolTimer");
  _DAT_18001f028 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"WaitForThreadpoolTimerCallbacks");
  _DAT_18001f030 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CloseThreadpoolTimer");
  _DAT_18001f038 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CreateThreadpoolWait");
  _DAT_18001f040 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"SetThreadpoolWait");
  _DAT_18001f048 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CloseThreadpoolWait");
  _DAT_18001f050 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"FlushProcessWriteBuffers");
  _DAT_18001f058 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"FreeLibraryWhenCallbackReturns");
  _DAT_18001f060 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetCurrentProcessorNumber");
  _DAT_18001f068 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetLogicalProcessorInformation");
  _DAT_18001f070 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CreateSymbolicLinkW");
  _DAT_18001f078 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"SetDefaultDllDirectories");
  _DAT_18001f080 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"EnumSystemLocalesEx");
  _DAT_18001f090 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"CompareStringEx");
  _DAT_18001f088 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetDateFormatEx");
  _DAT_18001f098 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetLocaleInfoEx");
  _DAT_18001f0a0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetTimeFormatEx");
  _DAT_18001f0a8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetUserDefaultLocaleName");
  _DAT_18001f0b0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"IsValidLocaleName");
  _DAT_18001f0b8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"LCMapStringEx");
  DAT_18001f0c0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetCurrentPackageId");
  DAT_18001f0c8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetTickCount64");
  _DAT_18001f0d0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"GetFileInformationByHandleExW");
  _DAT_18001f0d8 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  pFVar2 = GetProcAddress(hModule,"SetFileInformationByHandleW");
  _DAT_18001f0e0 = (ulonglong)pFVar2 ^ DAT_1800170a0;
  return;
}



void FUN_1800054f4(undefined **param_1,undefined **param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  uVar2 = 0;
  uVar1 = (ulonglong)((longlong)param_2 + (7 - (longlong)param_1)) >> 3;
  if (param_2 < param_1) {
    uVar1 = uVar2;
  }
  if (uVar1 != 0) {
    do {
      if ((code *)*param_1 != (code *)0x0) {
        (*(code *)*param_1)();
      }
      uVar2 = uVar2 + 1;
      param_1 = (code **)param_1 + 1;
    } while (uVar2 < uVar1);
  }
  return;
}



// Library Function - Single Match
//  _initterm_e
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void _initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_1 < param_2) {
    do {
      if (iVar1 != 0) {
        return;
      }
      if ((code *)*param_1 != (code *)0x0) {
        iVar1 = (*(code *)*param_1)();
      }
      param_1 = (code **)param_1 + 1;
    } while (param_1 < param_2);
  }
  return;
}



void FUN_180005590(void)

{
  _lock(8);
  return;
}



void FUN_18000559c(void)

{
  FUN_180008ad8(8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800055a8(UINT param_1,int param_2,int param_3)

{
  PVOID *ppvVar1;
  PVOID *ppvVar2;
  PVOID pvVar3;
  code *pcVar4;
  PVOID *ppvVar5;
  PVOID *ppvVar6;
  PVOID *ppvVar7;
  PVOID *ppvVar8;
  
  _lock(8);
  if (_DAT_18001d2e8 != 1) {
    _DAT_18001d328 = 1;
    DAT_18001d324 = (undefined)param_3;
    if (param_2 == 0) {
      ppvVar1 = (PVOID *)DecodePointer(DAT_18001f100);
      if (ppvVar1 != (PVOID *)0x0) {
        ppvVar2 = (PVOID *)DecodePointer(DAT_18001f0f8);
        ppvVar7 = ppvVar1;
        ppvVar8 = ppvVar2;
        while (ppvVar2 = ppvVar2 + -1, ppvVar1 <= ppvVar2) {
          pvVar3 = EncodePointer((PVOID)0x0);
          if (*ppvVar2 != pvVar3) {
            if (ppvVar2 < ppvVar1) break;
            pcVar4 = (code *)DecodePointer(*ppvVar2);
            pvVar3 = EncodePointer((PVOID)0x0);
            *ppvVar2 = pvVar3;
            (*pcVar4)();
            ppvVar5 = (PVOID *)DecodePointer(DAT_18001f100);
            ppvVar6 = (PVOID *)DecodePointer(DAT_18001f0f8);
            if ((ppvVar7 != ppvVar5) || (ppvVar8 != ppvVar6)) {
              ppvVar1 = ppvVar5;
              ppvVar2 = ppvVar6;
              ppvVar7 = ppvVar5;
              ppvVar8 = ppvVar6;
            }
          }
        }
      }
      FUN_1800054f4((undefined **)&DAT_18000f2b0,(undefined **)&DAT_18000f2d0);
    }
    FUN_1800054f4((undefined **)&DAT_18000f2d8,(undefined **)&DAT_18000f2e0);
  }
  if ((param_3 != 0) && (FUN_180008ad8(8), param_3 != 0)) {
    return;
  }
  _DAT_18001d2e8 = 1;
  FUN_180008ad8(8);
  __crtCorExitProcess(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



bool FUN_180005740(void)

{
  DAT_18001d340 = GetProcessHeap();
  return DAT_18001d340 != (HANDLE)0x0;
}



void FUN_180005760(void)

{
  DAT_18001d340 = 0;
  return;
}



undefined8 FUN_18000576c(void)

{
  uint uVar1;
  byte bVar2;
  DWORD DVar3;
  undefined8 uVar4;
  HANDLE hFile;
  int iVar5;
  HANDLE *ppvVar6;
  HANDLE *ppvVar7;
  longlong lVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  undefined auStack216 [32];
  uint local_b8;
  HANDLE *local_b0;
  int local_a8;
  int *local_a0;
  HANDLE *local_98;
  undefined *local_90;
  _STARTUPINFOW local_88;
  
  local_90 = auStack216;
  _lock(0xb);
  local_b0 = (HANDLE *)FUN_1800066f0(0x20,0x58);
  if (local_b0 == (HANDLE *)0x0) {
    FUN_180009320(auStack216,(PVOID)0x1800057d0);
    uVar4 = 0xffffffff;
  }
  else {
    DAT_18001f0e8 = 0x20;
    DAT_18001d350 = local_b0;
    for (; local_b0 < DAT_18001d350 + 0x160; local_b0 = local_b0 + 0xb) {
      *(undefined2 *)(local_b0 + 1) = 0xa00;
      *local_b0 = (HANDLE)0xffffffffffffffff;
      *(undefined4 *)((longlong)local_b0 + 0xc) = 0;
      *(byte *)(local_b0 + 7) = *(byte *)(local_b0 + 7) & 0x80;
      *(byte *)(local_b0 + 7) = *(byte *)(local_b0 + 7) & 0x7f;
      *(undefined2 *)((longlong)local_b0 + 0x39) = 0xa0a;
      *(undefined4 *)(local_b0 + 10) = 0;
      *(undefined *)((longlong)local_b0 + 0x4c) = 0;
    }
    GetStartupInfoW((LPSTARTUPINFOW)&local_88);
    if ((local_88.cbReserved2 != 0) && ((int *)local_88.lpReserved2 != (int *)0x0)) {
      piVar9 = (int *)((longlong)local_88.lpReserved2 + 4);
      ppvVar7 = (HANDLE *)((longlong)*(int *)local_88.lpReserved2 + (longlong)piVar9);
      iVar10 = 0x800;
      if (*(int *)local_88.lpReserved2 < 0x800) {
        iVar10 = *(int *)local_88.lpReserved2;
      }
      iVar5 = 1;
      local_a0 = piVar9;
      local_98 = ppvVar7;
      while ((iVar11 = iVar10, local_a8 = iVar5, DAT_18001f0e8 < iVar10 &&
             (local_b0 = (HANDLE *)FUN_1800066f0(0x20,0x58), iVar11 = DAT_18001f0e8,
             local_b0 != (HANDLE *)0x0))) {
        *(HANDLE **)((longlong)&DAT_18001d350 + (longlong)iVar5 * 8) = local_b0;
        DAT_18001f0e8 = DAT_18001f0e8 + 0x20;
        for (; local_b0 <
               (HANDLE *)(*(longlong *)((longlong)&DAT_18001d350 + (longlong)iVar5 * 8) + 0xb00);
            local_b0 = local_b0 + 0xb) {
          *(undefined2 *)(local_b0 + 1) = 0xa00;
          *local_b0 = (HANDLE)0xffffffffffffffff;
          *(undefined4 *)((longlong)local_b0 + 0xc) = 0;
          *(byte *)(local_b0 + 7) = *(byte *)(local_b0 + 7) & 0x80;
          *(undefined2 *)((longlong)local_b0 + 0x39) = 0xa0a;
          *(undefined4 *)(local_b0 + 10) = 0;
          *(undefined *)((longlong)local_b0 + 0x4c) = 0;
        }
        iVar5 = iVar5 + 1;
      }
      local_b8 = 0;
      while (uVar1 = local_b8, (int)local_b8 < iVar11) {
        if (((1 < (longlong)*ppvVar7 + 2U) && ((*(byte *)piVar9 & 1) != 0)) &&
           (((*(byte *)piVar9 & 8) != 0 || (DVar3 = GetFileType(*ppvVar7), DVar3 != 0)))) {
          ppvVar6 = (HANDLE *)
                    ((ulonglong)(uVar1 & 0x1f) * 0x58 +
                    *(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)uVar1 >> 5) * 8));
          *ppvVar6 = *ppvVar7;
          *(byte *)(ppvVar6 + 1) = *(byte *)piVar9;
          local_b0 = ppvVar6;
          FUN_180006234((LPCRITICAL_SECTION)(ppvVar6 + 2),4000);
          *(int *)((longlong)ppvVar6 + 0xc) = *(int *)((longlong)ppvVar6 + 0xc) + 1;
        }
        piVar9 = (int *)((longlong)piVar9 + 1);
        ppvVar7 = ppvVar7 + 1;
        local_a0 = piVar9;
        local_98 = ppvVar7;
        local_b8 = uVar1 + 1;
      }
    }
    local_b8 = 0;
    while (iVar10 = local_b8, (int)local_b8 < 3) {
      lVar8 = (longlong)(int)local_b8;
      ppvVar7 = DAT_18001d350 + lVar8 * 0xb;
      local_b0 = ppvVar7;
      if ((longlong)*ppvVar7 + 2U < 2) {
        *(undefined *)(ppvVar7 + 1) = 0x81;
        DVar3 = 0xfffffff5 - (local_b8 != 1);
        if (local_b8 == 0) {
          DVar3 = 0xfffffff6;
        }
        hFile = GetStdHandle(DVar3);
        if (((longlong)hFile + 1U < 2) || (DVar3 = GetFileType(hFile), DVar3 == 0)) {
          *(byte *)(ppvVar7 + 1) = *(byte *)(ppvVar7 + 1) | 0x40;
          *ppvVar7 = (HANDLE)0xfffffffffffffffe;
          if (DAT_18001dfa0 != 0) {
            *(undefined4 *)(*(longlong *)(DAT_18001dfa0 + lVar8 * 8) + 0x1c) = 0xfffffffe;
          }
        }
        else {
          *ppvVar7 = hFile;
          if ((DVar3 & 0xff) == 2) {
            bVar2 = *(byte *)(ppvVar7 + 1) | 0x40;
LAB_180005a26:
            *(byte *)(ppvVar7 + 1) = bVar2;
          }
          else {
            if ((DVar3 & 0xff) == 3) {
              bVar2 = *(byte *)(ppvVar7 + 1) | 8;
              goto LAB_180005a26;
            }
          }
          FUN_180006234((LPCRITICAL_SECTION)(ppvVar7 + 2),4000);
          *(int *)((longlong)ppvVar7 + 0xc) = *(int *)((longlong)ppvVar7 + 0xc) + 1;
        }
      }
      else {
        *(byte *)(ppvVar7 + 1) = *(byte *)(ppvVar7 + 1) | 0x80;
      }
      local_b8 = iVar10 + 1;
    }
    FUN_180008ad8(0xb);
    uVar4 = 0;
  }
  return uVar4;
}



// Library Function - Single Match
//  _ioterm
// 
// Library: Visual Studio 2012 Release

void _ioterm(void)

{
  void *pvVar1;
  void *pvVar2;
  longlong lVar3;
  void **ppvVar4;
  
  ppvVar4 = (void **)&DAT_18001d350;
  lVar3 = 0x40;
  do {
    pvVar2 = *ppvVar4;
    pvVar1 = pvVar2;
    if (pvVar2 != (void *)0x0) {
      for (; pvVar2 < (void *)((longlong)pvVar1 + 0xb00); pvVar2 = (void *)((longlong)pvVar2 + 0x58)
          ) {
        if (*(int *)((longlong)pvVar2 + 0xc) != 0) {
          DeleteCriticalSection((LPCRITICAL_SECTION)((longlong)pvVar2 + 0x10));
        }
        pvVar1 = *ppvVar4;
      }
      free(*ppvVar4);
      *ppvVar4 = (void *)0x0;
    }
    ppvVar4 = ppvVar4 + 1;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _setargv
// 
// Library: Visual Studio 2012 Release

int _setargv(void)

{
  ulonglong uVar1;
  byte **ppbVar2;
  ulonglong uVar3;
  byte *pbVar4;
  ulonglong uVar5;
  int local_res8 [2];
  int local_res10 [2];
  
  if (_DAT_18001f108 == 0) {
    __initmbctable();
  }
  DAT_18001d654 = 0;
  GetModuleFileNameA((HMODULE)0x0,&DAT_18001d550,0x104);
  _DAT_18001d310 = &DAT_18001d550;
  if ((DAT_18001f110 == (byte *)0x0) || (pbVar4 = DAT_18001f110, *DAT_18001f110 == 0)) {
    pbVar4 = &DAT_18001d550;
  }
  parse_cmdline(pbVar4,(byte **)0x0,(byte *)0x0,local_res8,local_res10);
  uVar5 = SEXT48(local_res8[0]);
  if ((((uVar5 < 0x1fffffffffffffff) &&
       (uVar3 = SEXT48(local_res10[0]), uVar3 != 0xffffffffffffffff)) &&
      (uVar1 = uVar3 + uVar5 * 8, uVar3 <= uVar1)) &&
     (ppbVar2 = (byte **)FUN_180006770(uVar1), ppbVar2 != (byte **)0x0)) {
    parse_cmdline(pbVar4,ppbVar2,(byte *)(ppbVar2 + uVar5),local_res8,local_res10);
    _DAT_18001d2ec = local_res8[0] + -1;
    DAT_18001d2f0 = ppbVar2;
    return 0;
  }
  return -1;
}



// Library Function - Single Match
//  parse_cmdline
// 
// Library: Visual Studio 2012 Release

void parse_cmdline(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  undefined8 uVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte bVar7;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  bVar2 = false;
  do {
    if (*param_1 == 0x22) {
      bVar2 = !bVar2;
      bVar7 = 0x22;
      pbVar5 = param_1 + 1;
    }
    else {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar7 = *param_1;
      pbVar5 = param_1 + 1;
      uVar3 = FUN_180009400((uint)bVar7);
      if ((int)uVar3 != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar5;
          param_3 = param_3 + 1;
        }
        pbVar5 = param_1 + 2;
      }
      if (bVar7 == 0) {
        pbVar5 = pbVar5 + -1;
        goto LAB_180005cb6;
      }
    }
    param_1 = pbVar5;
  } while ((bVar2) || ((bVar7 != 0x20 && (bVar7 != 9))));
  if (param_3 != (byte *)0x0) {
    param_3[-1] = 0;
  }
LAB_180005cb6:
  bVar2 = false;
  while (pbVar6 = pbVar5, *pbVar5 != 0) {
    for (; (*pbVar6 == 0x20 || (*pbVar6 == 9)); pbVar6 = pbVar6 + 1) {
    }
    if (*pbVar6 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar1 = true;
      uVar4 = 0;
      for (; *pbVar6 == 0x5c; pbVar6 = pbVar6 + 1) {
        uVar4 = uVar4 + 1;
      }
      pbVar5 = pbVar6;
      if (*pbVar6 == 0x22) {
        if (((uVar4 & 1) == 0) && ((!bVar2 || (pbVar5 = pbVar6 + 1, *pbVar5 != 0x22)))) {
          bVar1 = false;
          bVar2 = !bVar2;
          pbVar5 = pbVar6;
        }
        uVar4 = uVar4 >> 1;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar7 = *pbVar5;
      if ((bVar7 == 0) || ((!bVar2 && ((bVar7 == 0x20 || (bVar7 == 9)))))) break;
      if (bVar1) {
        uVar3 = FUN_180009400((int)(char)bVar7);
        if (param_3 == (byte *)0x0) {
          if ((int)uVar3 != 0) {
            pbVar5 = pbVar5 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if ((int)uVar3 != 0) {
            bVar7 = *pbVar5;
            pbVar5 = pbVar5 + 1;
            *param_3 = bVar7;
            param_3 = param_3 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *pbVar5;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pbVar6 = pbVar5 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _setenvp
// 
// Library: Visual Studio 2012 Release

int _setenvp(void)

{
  char cVar1;
  code *pcVar2;
  errno_t eVar3;
  size_t sVar4;
  char *_Dst;
  char *pcVar5;
  int iVar6;
  char **ppcVar7;
  
  if (_DAT_18001f108 == 0) {
    __initmbctable();
  }
  iVar6 = 0;
  pcVar5 = DAT_18001cd58;
  if (DAT_18001cd58 != (char *)0x0) {
    for (; *pcVar5 != '\0'; pcVar5 = pcVar5 + sVar4 + 1) {
      if (*pcVar5 != '=') {
        iVar6 = iVar6 + 1;
      }
      sVar4 = strlen(pcVar5);
    }
    DAT_18001d300 = (char **)FUN_1800066f0((longlong)(iVar6 + 1),8);
    if (DAT_18001d300 != (char **)0x0) {
      cVar1 = *DAT_18001cd58;
      ppcVar7 = DAT_18001d300;
      pcVar5 = DAT_18001cd58;
      do {
        if (cVar1 == '\0') {
          free(DAT_18001cd58);
          DAT_18001cd58 = (char *)0x0;
          *ppcVar7 = (char *)0x0;
          _DAT_18001f10c = 1;
          return 0;
        }
        sVar4 = strlen(pcVar5);
        iVar6 = (int)sVar4 + 1;
        if (*pcVar5 != '=') {
          _Dst = (char *)FUN_1800066f0((longlong)iVar6,1);
          *ppcVar7 = _Dst;
          if (_Dst == (char *)0x0) {
            free(DAT_18001d300);
            DAT_18001d300 = (char **)0x0;
            return -1;
          }
          eVar3 = strcpy_s(_Dst,(longlong)iVar6,pcVar5);
          if (eVar3 != 0) {
            FUN_18000391c();
            pcVar2 = (code *)swi(3);
            iVar6 = (*pcVar2)();
            return iVar6;
          }
          ppcVar7 = ppcVar7 + 1;
        }
        pcVar5 = pcVar5 + iVar6;
        cVar1 = *pcVar5;
      } while( true );
    }
  }
  return -1;
}



// Library Function - Single Match
//  free
// 
// Library: Visual Studio 2012 Release

void free(void *_Memory)

{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  int *piVar4;
  
  if ((_Memory != (void *)0x0) && (BVar1 = HeapFree(DAT_18001d340,0,_Memory), BVar1 == 0)) {
    piVar4 = _errno();
    DVar2 = GetLastError();
    iVar3 = _get_errno_from_oserr(DVar2);
    *piVar4 = iVar3;
  }
  return;
}



void FUN_180005f40(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  uint local_res18;
  undefined4 uStackX28;
  
  local_res10 = (_FILETIME)0x0;
  if (DAT_1800170a0 == 0x2b992ddfa232) {
    GetSystemTimeAsFileTime((LPFILETIME)&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_1800170a0 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX28,local_res18) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_1800170a0 == 0x2b992ddfa232) {
      DAT_1800170a0 = 0x2b992ddfa233;
    }
  }
  DAT_1800170a8 = ~DAT_1800170a0;
  return;
}



// Library Function - Single Match
//  __crtGetEnvironmentStringsA
// 
// Library: Visual Studio 2012 Release

LPVOID __crtGetEnvironmentStringsA(void)

{
  WCHAR WVar1;
  int cbMultiByte;
  int iVar2;
  LPWCH lpWideCharStr;
  LPSTR lpMultiByteStr;
  WCHAR *pWVar3;
  WCHAR *pWVar4;
  
  lpWideCharStr = GetEnvironmentStringsW();
  if (lpWideCharStr != (LPWCH)0x0) {
    WVar1 = *lpWideCharStr;
    pWVar3 = lpWideCharStr;
    while (WVar1 != L'\0') {
      do {
        pWVar4 = pWVar3;
        pWVar3 = pWVar4 + 1;
      } while (*pWVar3 != L'\0');
      pWVar3 = pWVar4 + 2;
      WVar1 = *pWVar3;
    }
    iVar2 = (int)((longlong)((longlong)pWVar3 - (longlong)lpWideCharStr) >> 1);
    cbMultiByte = WideCharToMultiByte(0,0,lpWideCharStr,iVar2 + 1,(LPSTR)0x0,0,(LPCSTR)0x0,
                                      (LPBOOL)0x0);
    if ((cbMultiByte != 0) &&
       (lpMultiByteStr = (LPSTR)FUN_180006770((longlong)cbMultiByte), lpMultiByteStr != (LPSTR)0x0))
    {
      iVar2 = WideCharToMultiByte(0,0,lpWideCharStr,iVar2 + 1,lpMultiByteStr,cbMultiByte,(LPCSTR)0x0
                                  ,(LPBOOL)0x0);
      if (iVar2 == 0) {
        free(lpMultiByteStr);
        lpMultiByteStr = (LPSTR)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return lpMultiByteStr;
    }
    FreeEnvironmentStringsW(lpWideCharStr);
  }
  return (LPSTR)0x0;
}



// Library Function - Single Match
//  __crtCaptureCurrentContext
// 
// Library: Visual Studio 2012 Release

void __crtCaptureCurrentContext(CONTEXT *pContextRecord)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18;
  
  RtlCaptureContext();
  ControlPc = pContextRecord->Rip;
  FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,(PCONTEXT)pContextRecord,&local_res18,
                     &local_res10,(PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  return;
}



// Library Function - Single Match
//  __crtCapturePreviousContext
// 
// Library: Visual Studio 2012 Release

void __crtCapturePreviousContext(CONTEXT *pContextRecord)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = pContextRecord->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,(PCONTEXT)pContextRecord,local_res18,
                     &local_res10,(PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



void FUN_1800061c4(void)

{
  if ((code *)(DAT_18001efe0 ^ DAT_1800170a0) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800061d4. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(DAT_18001efe0 ^ DAT_1800170a0))();
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0001800061d7. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsAlloc();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void FUN_1800061e0(void)

{
  if ((code *)(DAT_18001efe8 ^ DAT_1800170a0) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0001800061f0. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(DAT_18001efe8 ^ DAT_1800170a0))();
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0001800061f3. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsFree();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void FUN_1800061fc(void)

{
  if ((code *)(DAT_18001eff0 ^ DAT_1800170a0) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00018000620c. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(DAT_18001eff0 ^ DAT_1800170a0))();
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00018000620f. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsGetValue();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void FUN_180006218(void)

{
  if ((code *)(DAT_18001eff8 ^ DAT_1800170a0) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x000180006228. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)(DAT_18001eff8 ^ DAT_1800170a0))();
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00018000622b. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsSetValue();
  return;
}



undefined8 FUN_180006234(LPCRITICAL_SECTION param_1,DWORD param_2)

{
  undefined8 uVar1;
  
  if ((code *)(DAT_18001f000 ^ DAT_1800170a0) != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00018000624c. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*(code *)(DAT_18001f000 ^ DAT_1800170a0))();
    return uVar1;
  }
  InitializeCriticalSectionAndSpinCount(param_1,param_2);
  return 1;
}



bool FUN_180006260(void)

{
  int iVar1;
  bool bVar2;
  undefined4 local_res8 [8];
  
  bVar2 = DAT_180017298 < 0;
  if (!bVar2) goto LAB_1800062a1;
  local_res8[0] = 0;
  if ((code *)(DAT_18001f0c8 ^ DAT_1800170a0) == (code *)0x0) {
LAB_180006297:
    DAT_180017298 = 0;
  }
  else {
    iVar1 = (*(code *)(DAT_18001f0c8 ^ DAT_1800170a0))(local_res8,0);
    DAT_180017298 = 1;
    if (iVar1 != 0x7a) goto LAB_180006297;
  }
  bVar2 = false;
LAB_1800062a1:
  return DAT_180017298 != 0 && !bVar2;
}



void Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x0001800066a8. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



// Library Function - Single Match
//  __crtUnhandledException
// 
// Library: Visual Studio 2012 Release

LONG __crtUnhandledException(EXCEPTION_POINTERS *exceptionInfo)

{
  LONG LVar1;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
                    // WARNING: Could not recover jumptable at 0x0001800066e9. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)exceptionInfo);
  return LVar1;
}



LPVOID FUN_1800066f0(ulonglong param_1,ulonglong param_2)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = _calloc_impl(param_1,param_2,(undefined4 *)0x0);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_18001d658 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_18001d658 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (LPVOID)0x0;
    }
  }
  return (LPVOID)0x0;
}



void * FUN_180006770(size_t param_1)

{
  uint uVar1;
  void *pvVar2;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    uVar1 = DAT_18001d658;
    pvVar2 = malloc(param_1);
    if (pvVar2 != (void *)0x0) {
      return pvVar2;
    }
    if (uVar1 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_18001d658 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



void * FUN_1800067ec(void *param_1,size_t param_2)

{
  void *pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = realloc(param_1,param_2);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (param_2 == 0) {
      return (void *)0x0;
    }
    if (DAT_18001d658 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_18001d658 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
}



void FUN_180006870(void)

{
  code **ppcVar1;
  
  for (ppcVar1 = (code **)&DAT_1800154c0; ppcVar1 < &DAT_1800154c0; ppcVar1 = ppcVar1 + 1) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180006ac4(void)

{
  _DAT_18001efc0 = 0;
  return;
}



undefined ** FUN_180006b94(void)

{
  return &PTR_DAT_1800172a0;
}



// Library Function - Single Match
//  _lock_file
// 
// Library: Visual Studio 2012 Release

void _lock_file(FILE *_File)

{
  if (((FILE *)0x18001729f < _File) && (_File < (FILE *)0x180017631)) {
    _lock((int)((longlong)&_File[-0x80007b9]._base / 0x30) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
    return;
  }
                    // WARNING: Could not recover jumptable at 0x000180006bfa. Too many branches
                    // WARNING: Treating indirect jump as call
  EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  _lock_file2
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void _lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    _lock(_Index + 0x10);
    *(uint *)((longlong)_File + 0x18) = *(uint *)((longlong)_File + 0x18) | 0x8000;
    return;
  }
                    // WARNING: Could not recover jumptable at 0x000180006c2e. Too many branches
                    // WARNING: Treating indirect jump as call
  EnterCriticalSection((LPCRITICAL_SECTION)((longlong)_File + 0x30));
  return;
}



// Library Function - Single Match
//  _unlock_file
// 
// Library: Visual Studio 2012 Release

void _unlock_file(FILE *_File)

{
  if (((FILE *)0x18001729f < _File) && (_File < (FILE *)0x180017631)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_180008ad8((int)((longlong)&_File[-0x80007b9]._base / 0x30) + 0x10);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x000180006c7f. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



void FUN_180006c88(int param_1,longlong param_2)

{
  if (param_1 < 0x14) {
    *(uint *)(param_2 + 0x18) = *(uint *)(param_2 + 0x18) & 0xffff7fff;
    FUN_180008ad8(param_1 + 0x10);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x000180006c9e. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x30));
  return;
}



// Library Function - Single Match
//  _fileno
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

int _fileno(FILE *_File)

{
  int iVar1;
  int *piVar2;
  
  if (_File == (FILE *)0x0) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    FUN_1800038fc();
    iVar1 = -1;
  }
  else {
    iVar1 = _File->_file;
  }
  return iVar1;
}



// Library Function - Single Match
//  _isatty
// 
// Library: Visual Studio 2010 Release

int _isatty(int _FileHandle)

{
  int *piVar1;
  
  if (_FileHandle == -2) {
    piVar1 = _errno();
    *piVar1 = 9;
  }
  else {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_18001f0e8)) {
      return (int)*(char *)(*(longlong *)
                             ((longlong)&DAT_18001d350 + ((longlong)_FileHandle >> 5) * 8) + 8 +
                           (ulonglong)(_FileHandle & 0x1f) * 0x58) & 0x40;
    }
    piVar1 = _errno();
    *piVar1 = 9;
    FUN_1800038fc();
  }
  return (int)0;
}



undefined4 FUN_180006d30(uint param_1,wint_t *param_2,uint param_3)

{
  undefined4 uVar1;
  ulong *puVar2;
  int *piVar3;
  longlong lVar4;
  
  if (param_1 == 0xfffffffe) {
    puVar2 = __doserrno();
    *puVar2 = 0;
    piVar3 = _errno();
    *piVar3 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
      lVar4 = (ulonglong)(param_1 & 0x1f) * 0x58;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                    + lVar4) & 1) != 0) {
        FUN_1800098a0(param_1);
        if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) +
                       8 + lVar4) & 1) == 0) {
          piVar3 = _errno();
          *piVar3 = 9;
          puVar2 = __doserrno();
          *puVar2 = 0;
          uVar1 = 0xffffffff;
        }
        else {
          uVar1 = FUN_180006e14(param_1,param_2,param_3);
        }
        FUN_180009a58(param_1);
        return uVar1;
      }
    }
    puVar2 = __doserrno();
    *puVar2 = 0;
    piVar3 = _errno();
    *piVar3 = 9;
    FUN_1800038fc();
  }
  return 0xffffffff;
}



// WARNING: Function: __chkstk replaced with injection: alloca_probe

void FUN_180006e14(uint param_1,wint_t *param_2,uint param_3)

{
  char cVar1;
  wchar_t *pwVar2;
  uint uVar3;
  wint_t wVar4;
  int iVar5;
  BOOL BVar6;
  int iVar7;
  DWORD nNumberOfBytesToWrite;
  DWORD DVar8;
  ulong *puVar9;
  int *piVar10;
  _ptiddata p_Var11;
  uint uVar12;
  ulong uVar13;
  int iVar14;
  wint_t *pwVar15;
  longlong lVar16;
  wint_t *pwVar17;
  ulonglong uVar18;
  char cVar19;
  longlong lVar20;
  int iVar21;
  bool bVar22;
  int local_1b40;
  wint_t local_1b3c [2];
  longlong local_1b38;
  uint local_1b30 [2];
  longlong local_1b28;
  DWORD local_1b20;
  uint local_1b1c;
  UINT local_1b18;
  undefined local_1b14;
  char local_1b13;
  wint_t local_1af8 [856];
  wint_t local_1448 [2560];
  ulonglong local_48;
  undefined8 uStack64;
  
  iVar7 = (int)register0x00000020;
  uStack64 = 0x180006e36;
  local_48 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffe480;
  uVar12 = 0;
  local_1b40 = 0;
  uVar13 = 0;
  if (param_3 == 0) goto LAB_1800075db;
  if (param_2 == (wint_t *)0x0) {
    puVar9 = __doserrno();
    *puVar9 = 0;
LAB_180006e7a:
    piVar10 = _errno();
    *piVar10 = 0x16;
    FUN_1800038fc();
    goto LAB_1800075db;
  }
  local_1b38 = (longlong)(int)param_1 >> 5;
  lVar20 = (ulonglong)(param_1 & 0x1f) * 0x58;
  cVar19 = (char)(*(char *)(lVar20 + 0x38 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)
                           ) * '\x02') >> 1;
  local_1b28 = lVar20;
  if (((byte)(cVar19 - 1U) < 2) && ((~param_3 & 1) == 0)) {
    puVar9 = __doserrno();
    *puVar9 = 0;
    goto LAB_180006e7a;
  }
  if ((*(byte *)(lVar20 + 8 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)) & 0x20) != 0
     ) {
    _lseeki64_nolock(param_1,0,2);
  }
  iVar5 = _isatty(param_1);
  iVar21 = (int)param_2;
  if ((iVar5 != 0) &&
     ((*(byte *)(lVar20 + 8 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)) & 0x80) != 0
     )) {
    p_Var11 = _getptd();
    pwVar2 = p_Var11->ptlocinfo->locale_name[2];
    BVar6 = GetConsoleMode(*(HANDLE *)
                            (lVar20 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)),
                           &local_1b1c);
    if ((BVar6 == 0) || ((pwVar2 == (wchar_t *)0x0 && (cVar19 == '\0')))) goto LAB_18000724b;
    local_1b18 = GetConsoleCP();
    wVar4 = 0;
    local_1b3c[0] = 0;
    local_1b20 = 0;
    pwVar15 = param_2;
    lVar16 = local_1b38;
    if (param_3 != 0) {
      do {
        lVar20 = local_1b28;
        bVar22 = false;
        uVar3 = uVar12;
        if (cVar19 == '\0') {
          cVar1 = *(char *)pwVar15;
          local_1b1c = (uint)(cVar1 == '\n');
          lVar16 = *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8);
          if (*(int *)(local_1b28 + 0x50 + lVar16) == 0) {
            iVar7 = isleadbyte((int)cVar1);
            if (iVar7 == 0) {
              uVar18 = 1;
              pwVar17 = pwVar15;
              goto LAB_180007037;
            }
            if ((longlong)(((ulonglong)param_3 - (longlong)pwVar15) + (longlong)param_2) < 2) {
              uVar12 = uVar12 + 1;
              *(undefined *)
               (lVar20 + 0x4c + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)) =
                   *(undefined *)pwVar15;
              *(undefined4 *)
               (lVar20 + 0x50 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)) = 1;
              lVar16 = local_1b38;
              DVar8 = 0;
              break;
            }
            iVar7 = FUN_1800088e0(local_1b3c,(byte *)pwVar15,2);
            lVar16 = local_1b38;
            DVar8 = uVar13;
            if (iVar7 == -1) break;
            pwVar15 = (wint_t *)((longlong)pwVar15 + 1);
          }
          else {
            local_1b14 = *(undefined *)(local_1b28 + 0x4c + lVar16);
            *(undefined4 *)(local_1b28 + 0x50 + lVar16) = 0;
            uVar18 = 2;
            pwVar17 = (wint_t *)&local_1b14;
            local_1b13 = cVar1;
LAB_180007037:
            iVar7 = FUN_1800088e0(local_1b3c,(byte *)pwVar17,uVar18);
            lVar16 = local_1b38;
            DVar8 = 0;
            if (iVar7 == -1) break;
          }
          pwVar15 = (wint_t *)((longlong)pwVar15 + 1);
          nNumberOfBytesToWrite =
               WideCharToMultiByte(local_1b18,0,(LPCWSTR)local_1b3c,1,&local_1b14,5,(LPCSTR)0x0,
                                   (LPBOOL)0x0);
          lVar16 = local_1b38;
          lVar20 = local_1b28;
          DVar8 = 0;
          if (nNumberOfBytesToWrite == 0) break;
          BVar6 = WriteFile(*(HANDLE *)
                             (local_1b28 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8))
                            ,&local_1b14,nNumberOfBytesToWrite,&local_1b20,(LPOVERLAPPED)0x0);
          lVar20 = local_1b28;
          if (BVar6 == 0) goto LAB_1800071f5;
          uVar12 = ((int)pwVar15 - iVar21) + local_1b40;
          lVar16 = local_1b38;
          DVar8 = 0;
          if ((int)local_1b20 < (int)nNumberOfBytesToWrite) break;
          wVar4 = local_1b3c[0];
          uVar3 = uVar12;
          if (local_1b1c != 0) {
            local_1b14 = 0xd;
            BVar6 = WriteFile(*(HANDLE *)
                               (local_1b28 +
                               *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)),&local_1b14
                              ,1,&local_1b20,(LPOVERLAPPED)0x0);
            if (BVar6 == 0) goto LAB_1800071eb;
            lVar16 = local_1b38;
            DVar8 = uVar13;
            if ((int)local_1b20 < 1) break;
            local_1b40 = local_1b40 + 1;
            wVar4 = local_1b3c[0];
            uVar3 = uVar12 + 1;
          }
        }
        else {
          if ((byte)(cVar19 - 1U) < 2) {
            wVar4 = *pwVar15;
            bVar22 = wVar4 == 10;
            pwVar15 = pwVar15 + 1;
            local_1b3c[0] = wVar4;
          }
          if ((byte)(cVar19 - 1U) < 2) {
            wVar4 = _putwch_nolock(wVar4);
            if (wVar4 != local_1b3c[0]) goto LAB_1800071f5;
            lVar20 = local_1b28;
            wVar4 = local_1b3c[0];
            uVar3 = uVar12 + 2;
            if (bVar22) {
              local_1b3c[0] = 0xd;
              wVar4 = _putwch_nolock(L'\r');
              if (wVar4 != local_1b3c[0]) goto LAB_1800071f5;
              local_1b40 = local_1b40 + 1;
              lVar20 = local_1b28;
              wVar4 = local_1b3c[0];
              uVar3 = uVar12 + 3;
            }
          }
        }
        uVar12 = uVar3;
        lVar16 = local_1b38;
        DVar8 = uVar13;
      } while ((uint)((int)pwVar15 - iVar21) < param_3);
      goto LAB_18000720b;
    }
    goto LAB_1800075a3;
  }
LAB_18000724b:
  lVar16 = local_1b38;
  DVar8 = 0;
  if ((*(byte *)(lVar20 + 8 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)) & 0x80) == 0
     ) {
    BVar6 = WriteFile(*(HANDLE *)(lVar20 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8))
                      ,param_2,param_3,local_1b30,(LPOVERLAPPED)0x0);
    uVar12 = local_1b30[0];
    DVar8 = 0;
    if (BVar6 == 0) {
      DVar8 = GetLastError();
      uVar12 = 0;
    }
    goto LAB_18000720b;
  }
  uVar13 = 0;
  if (cVar19 == '\0') {
    pwVar15 = param_2;
    if (param_3 == 0) goto LAB_1800075a3;
    do {
      lVar20 = local_1b28;
      uVar18 = 0;
      pwVar17 = local_1448;
      do {
        if (param_3 <= (uint)((int)pwVar15 - iVar21)) break;
        cVar19 = *(char *)pwVar15;
        pwVar15 = (wint_t *)((longlong)pwVar15 + 1);
        if (cVar19 == '\n') {
          *(char *)pwVar17 = '\r';
          local_1b40 = local_1b40 + 1;
          pwVar17 = (wint_t *)((longlong)pwVar17 + 1);
          uVar18 = uVar18 + 1;
        }
        uVar18 = uVar18 + 1;
        *(char *)pwVar17 = cVar19;
        pwVar17 = (wint_t *)((longlong)pwVar17 + 1);
      } while (uVar18 < 0x13ff);
      BVar6 = WriteFile(*(HANDLE *)
                         (local_1b28 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)),
                        local_1448,(int)pwVar17 - (iVar7 + -0x1448),local_1b30,(LPOVERLAPPED)0x0);
      if (BVar6 == 0) goto LAB_1800071eb;
      uVar12 = uVar12 + local_1b30[0];
      lVar16 = local_1b38;
      DVar8 = uVar13;
    } while (((longlong)((longlong)pwVar17 - (longlong)local_1448) <= (longlong)(int)local_1b30[0])
            && ((uint)((int)pwVar15 - iVar21) < param_3));
    goto LAB_18000720b;
  }
  if (cVar19 == '\x02') {
    pwVar15 = param_2;
    if (param_3 != 0) {
      do {
        lVar20 = local_1b28;
        uVar18 = 0;
        pwVar17 = local_1448;
        do {
          if (param_3 <= (uint)((int)pwVar15 - iVar21)) break;
          wVar4 = *pwVar15;
          pwVar15 = pwVar15 + 1;
          if (wVar4 == 10) {
            *pwVar17 = 0xd;
            local_1b40 = local_1b40 + 2;
            pwVar17 = pwVar17 + 1;
            uVar18 = uVar18 + 2;
          }
          uVar18 = uVar18 + 2;
          *pwVar17 = wVar4;
          pwVar17 = pwVar17 + 1;
        } while (uVar18 < 0x13fe);
        BVar6 = WriteFile(*(HANDLE *)
                           (local_1b28 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8)),
                          local_1448,(int)pwVar17 - (iVar7 + -0x1448),local_1b30,(LPOVERLAPPED)0x0);
        if (BVar6 == 0) goto LAB_1800071eb;
        uVar12 = uVar12 + local_1b30[0];
        lVar16 = local_1b38;
        DVar8 = uVar13;
      } while (((longlong)((longlong)pwVar17 - (longlong)local_1448) <= (longlong)(int)local_1b30[0]
               ) && ((uint)((int)pwVar15 - iVar21) < param_3));
      goto LAB_18000720b;
    }
  }
  else {
    pwVar15 = param_2;
    if (param_3 != 0) {
      do {
        uVar18 = 0;
        pwVar17 = local_1af8;
        do {
          if (param_3 <= (uint)((int)pwVar15 - iVar21)) break;
          wVar4 = *pwVar15;
          pwVar15 = pwVar15 + 1;
          if (wVar4 == 10) {
            *pwVar17 = 0xd;
            pwVar17 = pwVar17 + 1;
            uVar18 = uVar18 + 2;
          }
          uVar18 = uVar18 + 2;
          *pwVar17 = wVar4;
          pwVar17 = pwVar17 + 1;
        } while (uVar18 < 0x6a8);
        iVar14 = 0;
        iVar5 = WideCharToMultiByte(0xfde9,0,(LPCWSTR)local_1af8,
                                    ((int)pwVar17 - (iVar7 + -0x1af8)) / 2,(LPSTR)local_1448,0xd55,
                                    (LPCSTR)0x0,(LPBOOL)0x0);
        uVar3 = uVar12;
        if (iVar5 == 0) goto LAB_1800071f5;
        do {
          BVar6 = WriteFile(*(HANDLE *)
                             (local_1b28 + *(longlong *)((longlong)&DAT_18001d350 + local_1b38 * 8))
                            ,(LPCVOID)((longlong)local_1448 + (longlong)iVar14),iVar5 - iVar14,
                            local_1b30,(LPOVERLAPPED)0x0);
          if (BVar6 == 0) {
            DVar8 = GetLastError();
            break;
          }
          iVar14 = iVar14 + local_1b30[0];
        } while (iVar14 < iVar5);
        lVar16 = local_1b38;
        lVar20 = local_1b28;
      } while ((iVar5 <= iVar14) && (uVar12 = (int)pwVar15 - iVar21, uVar12 < param_3));
      goto LAB_18000720b;
    }
  }
  goto LAB_1800075a3;
LAB_1800071f5:
  uVar12 = uVar3;
  DVar8 = GetLastError();
  lVar16 = local_1b38;
  lVar20 = local_1b28;
  goto LAB_18000720b;
LAB_1800071eb:
  DVar8 = GetLastError();
  lVar16 = local_1b38;
LAB_18000720b:
  if (uVar12 == 0) {
    if (DVar8 == 0) {
LAB_1800075a3:
      if (((*(byte *)(lVar20 + 8 + *(longlong *)((longlong)&DAT_18001d350 + lVar16 * 8)) & 0x40) ==
           0) || (*(char *)param_2 != '\x1a')) {
        piVar10 = _errno();
        *piVar10 = 0x1c;
        puVar9 = __doserrno();
        *puVar9 = 0;
      }
    }
    else {
      if (DVar8 == 5) {
        piVar10 = _errno();
        *piVar10 = 9;
        puVar9 = __doserrno();
        *puVar9 = 5;
      }
      else {
        _dosmaperr(DVar8);
      }
    }
  }
LAB_1800075db:
  FUN_180002f40(local_48 ^ (ulonglong)&stack0xffffffffffffe480);
  return;
}



longlong FUN_180007608(uint param_1,longlong param_2,int param_3)

{
  ulong *puVar1;
  int *piVar2;
  longlong lVar3;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
      lVar3 = (ulonglong)(param_1 & 0x1f) * 0x58;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                    + lVar3) & 1) != 0) {
        FUN_1800098a0(param_1);
        if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) +
                       8 + lVar3) & 1) == 0) {
          piVar2 = _errno();
          *piVar2 = 9;
          puVar1 = __doserrno();
          *puVar1 = 0;
          lVar3 = -1;
        }
        else {
          lVar3 = _lseeki64_nolock(param_1,param_2,param_3);
        }
        FUN_180009a58(param_1);
        return lVar3;
      }
    }
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
    FUN_1800038fc();
  }
  return -1;
}



// Library Function - Single Match
//  _lseeki64_nolock
// 
// Library: Visual Studio 2012 Release

longlong _lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  int *piVar4;
  longlong local_res20;
  
  hFile = (HANDLE)FUN_1800099e4(_FileHandle);
  if (hFile == (HANDLE)0xffffffffffffffff) {
    piVar4 = _errno();
    *piVar4 = 9;
  }
  else {
    BVar2 = SetFilePointerEx(hFile,_Offset,&local_res20,_Origin);
    if (BVar2 != 0) {
      pbVar1 = (byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)_FileHandle >> 5) * 8) +
                        8 + (ulonglong)(_FileHandle & 0x1f) * 0x58);
      *pbVar1 = *pbVar1 & 0xfd;
      return local_res20;
    }
    DVar3 = GetLastError();
    _dosmaperr(DVar3);
  }
  return -1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _getbuf
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void _getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_18001d65c = _DAT_18001d65c + 1;
  pcVar1 = (char *)FUN_180006770(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_bufsiz = 2;
    _File->_base = (char *)&_File->_charbuf;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



// Library Function - Single Match
//  __addlocaleref
// 
// Library: Visual Studio 2012 Release

void __addlocaleref(int *param_1)

{
  int *piVar1;
  int **ppiVar2;
  longlong lVar3;
  
  LOCK();
  *param_1 = *param_1 + 1;
  piVar1 = *(int **)(param_1 + 0x36);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = *(int **)(param_1 + 0x3a);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = *(int **)(param_1 + 0x38);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  piVar1 = *(int **)(param_1 + 0x3e);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
  }
  ppiVar2 = (int **)(param_1 + 10);
  lVar3 = 6;
  do {
    if ((ppiVar2[-2] != (int *)&DAT_180017ba4) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
    }
    if ((ppiVar2[-3] != (int *)0x0) && (piVar1 = ppiVar2[-1], piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
    }
    ppiVar2 = ppiVar2 + 4;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  LOCK();
  *(int *)(*(longlong *)(param_1 + 0x48) + 0x15c) =
       *(int *)(*(longlong *)(param_1 + 0x48) + 0x15c) + 1;
  return;
}



// Library Function - Single Match
//  __freetlocinfo
// 
// Library: Visual Studio 2012 Release

void __freetlocinfo(void *param_1)

{
  int *piVar1;
  undefined **ppuVar2;
  longlong lVar3;
  void **ppvVar4;
  int **ppiVar5;
  
  if ((((*(undefined ***)((longlong)param_1 + 0xf0) != (undefined **)0x0) &&
       (*(undefined ***)((longlong)param_1 + 0xf0) != &PTR_DAT_180018270)) &&
      (*(int **)((longlong)param_1 + 0xd8) != (int *)0x0)) &&
     (**(int **)((longlong)param_1 + 0xd8) == 0)) {
    piVar1 = *(int **)((longlong)param_1 + 0xe8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      free(piVar1);
      __free_lconv_mon(*(longlong *)((longlong)param_1 + 0xf0));
    }
    piVar1 = *(int **)((longlong)param_1 + 0xe0);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      free(piVar1);
      __free_lconv_num(*(void ***)((longlong)param_1 + 0xf0));
    }
    free(*(void **)((longlong)param_1 + 0xd8));
    free(*(void **)((longlong)param_1 + 0xf0));
  }
  if ((*(int **)((longlong)param_1 + 0xf8) != (int *)0x0) &&
     (**(int **)((longlong)param_1 + 0xf8) == 0)) {
    free((void *)(*(longlong *)((longlong)param_1 + 0x100) + -0xfe));
    free((void *)(*(longlong *)((longlong)param_1 + 0x110) + -0x80));
    free((void *)(*(longlong *)((longlong)param_1 + 0x118) + -0x80));
    free(*(void **)((longlong)param_1 + 0xf8));
  }
  ppuVar2 = *(undefined ***)((longlong)param_1 + 0x120);
  if ((ppuVar2 != &PTR_DAT_180017bb0) && (*(int *)((longlong)ppuVar2 + 0x15c) == 0)) {
    __free_lc_time(ppuVar2);
    free(*(void **)((longlong)param_1 + 0x120));
  }
  ppvVar4 = (void **)((longlong)param_1 + 0x128);
  ppiVar5 = (int **)((longlong)param_1 + 0x28);
  lVar3 = 6;
  do {
    if (((ppiVar5[-2] != (int *)&DAT_180017ba4) && (piVar1 = *ppiVar5, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      free(piVar1);
      free(*ppvVar4);
    }
    if (((ppiVar5[-3] != (int *)0x0) && (piVar1 = ppiVar5[-1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      free(piVar1);
    }
    ppvVar4 = ppvVar4 + 1;
    ppiVar5 = ppiVar5 + 4;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  free(param_1);
  return;
}



// Library Function - Single Match
//  __removelocaleref
// 
// Library: Visual Studio 2012 Release

int * __removelocaleref(int *param_1)

{
  int *piVar1;
  int **ppiVar2;
  longlong lVar3;
  
  if (param_1 != (int *)0x0) {
    LOCK();
    *param_1 = *param_1 + -1;
    piVar1 = *(int **)(param_1 + 0x36);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0x3a);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0x38);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0x3e);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    ppiVar2 = (int **)(param_1 + 10);
    lVar3 = 6;
    do {
      if ((ppiVar2[-2] != (int *)&DAT_180017ba4) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      if ((ppiVar2[-3] != (int *)0x0) && (piVar1 = ppiVar2[-1], piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      ppiVar2 = ppiVar2 + 4;
      lVar3 = lVar3 + -1;
    } while (lVar3 != 0);
    LOCK();
    *(int *)(*(longlong *)(param_1 + 0x48) + 0x15c) =
         *(int *)(*(longlong *)(param_1 + 0x48) + 0x15c) + -1;
  }
  return param_1;
}



// Library Function - Single Match
//  __updatetlocinfo
// 
// Library: Visual Studio 2012 Release

pthreadlocinfo __updatetlocinfo(void)

{
  _ptiddata p_Var1;
  pthreadlocinfo ptVar2;
  
  p_Var1 = _getptd();
  if (((p_Var1->_ownlocale & DAT_180017fd8) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    _lock(0xc);
    ptVar2 = (pthreadlocinfo)
             _updatetlocinfoEx_nolock((int **)&p_Var1->ptlocinfo,(int *)PTR_DAT_180017e70);
    FUN_180008ad8(0xc);
  }
  else {
    p_Var1 = _getptd();
    ptVar2 = p_Var1->ptlocinfo;
  }
  if (ptVar2 == (pthreadlocinfo)0x0) {
    _amsg_exit(0x20);
  }
  return ptVar2;
}



// Library Function - Single Match
//  _updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2012 Release

int * _updatetlocinfoEx_nolock(int **param_1,int *param_2)

{
  int *piVar1;
  
  if ((param_2 == (int *)0x0) || (param_1 == (int **)0x0)) {
    param_2 = (int *)0x0;
  }
  else {
    piVar1 = *param_1;
    if (piVar1 != param_2) {
      *param_1 = param_2;
      __addlocaleref(param_2);
      if (((piVar1 != (int *)0x0) && (__removelocaleref(piVar1), *piVar1 == 0)) &&
         (piVar1 != (int *)&DAT_180017e80)) {
        __freetlocinfo(piVar1);
      }
    }
  }
  return param_2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __initmbctable
// 
// Library: Visual Studio 2012 Release

undefined8 __initmbctable(void)

{
  if (_DAT_18001f108 == 0) {
    FUN_180007f54(-3);
    _DAT_18001f108 = 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2012 Release

int getSystemCP(int param_1)

{
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)0x0);
  _DAT_18001d680 = 0;
  if (param_1 == -2) {
    _DAT_18001d680 = 1;
    param_1 = GetOEMCP();
  }
  else {
    if (param_1 == -3) {
      _DAT_18001d680 = 1;
      param_1 = GetACP();
    }
    else {
      if (param_1 == -4) {
        _DAT_18001d680 = 1;
        param_1 = *(UINT *)(local_28[0] + 4);
      }
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return param_1;
}



// Library Function - Single Match
//  void __cdecl setSBCS(struct threadmbcinfostruct * __ptr64)
// 
// Library: Visual Studio 2012 Release

void setSBCS(threadmbcinfostruct *param_1)

{
  longlong lVar1;
  uchar *puVar2;
  undefined (*pauVar3) [16];
  longlong lVar4;
  ushort *puVar5;
  
  pauVar3 = (undefined (*) [16])param_1->mbctype;
  lVar4 = 0x101;
  FUN_180003c80(pauVar3,0,0x101);
  *(undefined8 *)&param_1->mbcodepage = 0;
  param_1->mblocalename = (wchar_t *)0x0;
  puVar5 = param_1->mbulinfo;
  for (lVar1 = 6; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  do {
    (*pauVar3)[0] =
         ((undefined *)((longlong)&DAT_180017870 + -(longlong)param_1))[(longlong)pauVar3];
    pauVar3 = (undefined (*) [16])(*pauVar3 + 1);
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  puVar2 = param_1->mbcasemap;
  lVar1 = 0x100;
  do {
    *puVar2 = puVar2[(longlong)(undefined *)((longlong)&DAT_180017870 + -(longlong)param_1)];
    puVar2 = puVar2 + 1;
    lVar1 = lVar1 + -1;
  } while (lVar1 != 0);
  return;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct * __ptr64)
// 
// Library: Visual Studio 2012 Release

void setSBUpLow(threadmbcinfostruct *param_1)

{
  byte bVar1;
  BOOL BVar2;
  uint uVar3;
  CHAR *pCVar4;
  ulonglong uVar5;
  byte *pbVar6;
  WORD *pWVar7;
  longlong lVar8;
  _cpinfo local_538;
  CHAR local_518 [232];
  byte abStack1072 [24];
  CHAR local_418 [232];
  byte abStack816 [24];
  CHAR local_318 [256];
  WORD local_218 [256];
  ulonglong local_18;
  
  local_18 = DAT_1800170a0 ^ (ulonglong)&stack0xfffffffffffffa78;
  BVar2 = GetCPInfo(param_1->mbcodepage,(LPCPINFO)&local_538);
  lVar8 = 0x100;
  if (BVar2 == 0) {
    uVar3 = 0;
    pbVar6 = param_1->mbctype;
    do {
      pbVar6 = pbVar6 + 1;
      if (uVar3 - 0x41 < 0x1a) {
        *pbVar6 = *pbVar6 | 0x10;
        bVar1 = (char)uVar3 + 0x20;
LAB_180007e59:
        pbVar6[0x100] = bVar1;
      }
      else {
        if (uVar3 - 0x61 < 0x1a) {
          *pbVar6 = *pbVar6 | 0x20;
          bVar1 = (char)uVar3 - 0x20;
          goto LAB_180007e59;
        }
        pbVar6[0x100] = 0;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x100);
  }
  else {
    uVar3 = 0;
    pCVar4 = local_518;
    do {
      *pCVar4 = (CHAR)uVar3;
      uVar3 = uVar3 + 1;
      pCVar4 = pCVar4 + 1;
    } while (uVar3 < 0x100);
    local_518[0] = ' ';
    pbVar6 = local_538.LeadByte;
    while (local_538.LeadByte[0] != 0) {
      bVar1 = pbVar6[1];
      uVar5 = (ulonglong)local_538.LeadByte[0];
      while ((uVar3 = (uint)uVar5, uVar3 <= bVar1 && (uVar3 < 0x100))) {
        local_518[uVar5] = ' ';
        uVar5 = (ulonglong)(uVar3 + 1);
      }
      pbVar6 = pbVar6 + 2;
      local_538.LeadByte[0] = *pbVar6;
    }
    __crtGetStringTypeA((_locale_t)0x0,1,local_518,0x100,local_218,param_1->mbcodepage,0);
    __crtLCMapStringA((_locale_t)0x0,param_1->mblocalename,0x100,local_518,0x100,local_418,0x100,
                      param_1->mbcodepage,0);
    __crtLCMapStringA((_locale_t)0x0,param_1->mblocalename,0x200,local_518,0x100,local_318,0x100,
                      param_1->mbcodepage,0);
    pWVar7 = local_218;
    pbVar6 = param_1->mbctype;
    do {
      pbVar6 = pbVar6 + 1;
      if ((*(byte *)pWVar7 & 1) == 0) {
        if ((*(byte *)pWVar7 & 2) != 0) {
          *pbVar6 = *pbVar6 | 0x20;
          bVar1 = pbVar6[(longlong)(local_418 + (0xe7 - (longlong)param_1))];
          goto LAB_180007e15;
        }
        pbVar6[0x100] = 0;
      }
      else {
        *pbVar6 = *pbVar6 | 0x10;
        bVar1 = pbVar6[(longlong)(local_518 + (0xe7 - (longlong)param_1))];
LAB_180007e15:
        pbVar6[0x100] = bVar1;
      }
      pWVar7 = pWVar7 + 1;
      lVar8 = lVar8 + -1;
    } while (lVar8 != 0);
  }
  FUN_180002f40(local_18 ^ (ulonglong)&stack0xfffffffffffffa78);
  return;
}



// Library Function - Single Match
//  __updatetmbcinfo
// 
// Library: Visual Studio 2012 Release

pthreadmbcinfo __updatetmbcinfo(void)

{
  _ptiddata p_Var1;
  pthreadmbcinfo _Memory;
  
  p_Var1 = _getptd();
  if (((p_Var1->_ownlocale & DAT_180017fd8) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    _lock(0xd);
    _Memory = p_Var1->ptmbcinfo;
    if (_Memory != (pthreadmbcinfo)PTR_DAT_180017b90) {
      if (_Memory != (pthreadmbcinfo)0x0) {
        LOCK();
        _Memory->refcount = _Memory->refcount + -1;
        if ((_Memory->refcount == 0) && (_Memory != (pthreadmbcinfo)&DAT_180017870)) {
          free(_Memory);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_180017b90;
      _Memory = (pthreadmbcinfo)PTR_DAT_180017b90;
      LOCK();
      *(int *)PTR_DAT_180017b90 = *(int *)PTR_DAT_180017b90 + 1;
    }
    FUN_180008ad8(0xd);
  }
  else {
    _Memory = p_Var1->ptmbcinfo;
  }
  if (_Memory == (pthreadmbcinfo)0x0) {
    _amsg_exit(0x20);
  }
  return _Memory;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_180007f54(int param_1)

{
  pthreadmbcinfo ptVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  threadmbcinfostruct *ptVar5;
  int iVar6;
  int iVar7;
  _ptiddata p_Var8;
  threadmbcinfostruct *_Memory;
  pthreadmbcinfo ptVar9;
  int *piVar10;
  threadmbcinfostruct *ptVar11;
  int iVar12;
  longlong lVar13;
  int iVar14;
  
  iVar7 = -1;
  p_Var8 = _getptd();
  __updatetmbcinfo();
  ptVar1 = p_Var8->ptmbcinfo;
  iVar6 = getSystemCP(param_1);
  if (iVar6 == ptVar1->mbcodepage) {
    iVar7 = 0;
  }
  else {
    _Memory = (threadmbcinfostruct *)FUN_180006770(0x228);
    iVar14 = 0;
    if (_Memory != (threadmbcinfostruct *)0x0) {
      lVar13 = 4;
      ptVar1 = p_Var8->ptmbcinfo;
      ptVar5 = _Memory;
      do {
        ptVar11 = ptVar5;
        ptVar9 = ptVar1;
        iVar7 = ptVar9->mbcodepage;
        iVar12 = ptVar9->ismbcodepage;
        uVar2 = *(undefined4 *)ptVar9->mbulinfo;
        ptVar11->refcount = ptVar9->refcount;
        ptVar11->mbcodepage = iVar7;
        ptVar11->ismbcodepage = iVar12;
        *(undefined4 *)ptVar11->mbulinfo = uVar2;
        uVar2 = *(undefined4 *)(ptVar9->mbulinfo + 4);
        uVar3 = *(undefined4 *)ptVar9->mbctype;
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 4);
        *(undefined4 *)(ptVar11->mbulinfo + 2) = *(undefined4 *)(ptVar9->mbulinfo + 2);
        *(undefined4 *)(ptVar11->mbulinfo + 4) = uVar2;
        *(undefined4 *)ptVar11->mbctype = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 4) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0xc);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x10);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x14);
        *(undefined4 *)(ptVar11->mbctype + 8) = *(undefined4 *)(ptVar9->mbctype + 8);
        *(undefined4 *)(ptVar11->mbctype + 0xc) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x10) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 0x14) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x1c);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x20);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x24);
        *(undefined4 *)(ptVar11->mbctype + 0x18) = *(undefined4 *)(ptVar9->mbctype + 0x18);
        *(undefined4 *)(ptVar11->mbctype + 0x1c) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x20) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 0x24) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x2c);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x30);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x34);
        *(undefined4 *)(ptVar11->mbctype + 0x28) = *(undefined4 *)(ptVar9->mbctype + 0x28);
        *(undefined4 *)(ptVar11->mbctype + 0x2c) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x30) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 0x34) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x3c);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x40);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x44);
        *(undefined4 *)(ptVar11->mbctype + 0x38) = *(undefined4 *)(ptVar9->mbctype + 0x38);
        *(undefined4 *)(ptVar11->mbctype + 0x3c) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x40) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 0x44) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x4c);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x50);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x54);
        *(undefined4 *)(ptVar11->mbctype + 0x48) = *(undefined4 *)(ptVar9->mbctype + 0x48);
        *(undefined4 *)(ptVar11->mbctype + 0x4c) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x50) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 0x54) = uVar4;
        uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x5c);
        uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x60);
        uVar4 = *(undefined4 *)(ptVar9->mbctype + 100);
        *(undefined4 *)(ptVar11->mbctype + 0x58) = *(undefined4 *)(ptVar9->mbctype + 0x58);
        *(undefined4 *)(ptVar11->mbctype + 0x5c) = uVar2;
        *(undefined4 *)(ptVar11->mbctype + 0x60) = uVar3;
        *(undefined4 *)(ptVar11->mbctype + 100) = uVar4;
        lVar13 = lVar13 + -1;
        ptVar1 = (pthreadmbcinfo)(ptVar9->mbctype + 0x68);
        ptVar5 = (threadmbcinfostruct *)(ptVar11->mbctype + 0x68);
      } while (lVar13 != 0);
      uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x6c);
      uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x70);
      uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x74);
      ((threadmbcinfostruct *)(ptVar11->mbctype + 0x68))->refcount =
           ((pthreadmbcinfo)(ptVar9->mbctype + 0x68))->refcount;
      *(undefined4 *)(ptVar11->mbctype + 0x6c) = uVar2;
      *(undefined4 *)(ptVar11->mbctype + 0x70) = uVar3;
      *(undefined4 *)(ptVar11->mbctype + 0x74) = uVar4;
      uVar2 = *(undefined4 *)(ptVar9->mbctype + 0x7c);
      uVar3 = *(undefined4 *)(ptVar9->mbctype + 0x80);
      uVar4 = *(undefined4 *)(ptVar9->mbctype + 0x84);
      *(undefined4 *)(ptVar11->mbctype + 0x78) = *(undefined4 *)(ptVar9->mbctype + 0x78);
      *(undefined4 *)(ptVar11->mbctype + 0x7c) = uVar2;
      *(undefined4 *)(ptVar11->mbctype + 0x80) = uVar3;
      *(undefined4 *)(ptVar11->mbctype + 0x84) = uVar4;
      *(undefined8 *)(ptVar11->mbctype + 0x88) = *(undefined8 *)(ptVar9->mbctype + 0x88);
      _Memory->refcount = 0;
      iVar7 = FUN_180008198(iVar6,_Memory);
      if (iVar7 == 0) {
        ptVar1 = p_Var8->ptmbcinfo;
        LOCK();
        ptVar1->refcount = ptVar1->refcount + -1;
        if ((ptVar1->refcount == 0) && (p_Var8->ptmbcinfo != (pthreadmbcinfo)&DAT_180017870)) {
          free(p_Var8->ptmbcinfo);
        }
        p_Var8->ptmbcinfo = (pthreadmbcinfo)_Memory;
        LOCK();
        _Memory->refcount = _Memory->refcount + 1;
        if (((*(byte *)&p_Var8->_ownlocale & 2) == 0) && (((byte)DAT_180017fd8 & 1) == 0)) {
          _lock(0xd);
          _DAT_18001d660 = _Memory->mbcodepage;
          _DAT_18001d664 = _Memory->ismbcodepage;
          _DAT_18001d678 = _Memory->mblocalename;
          for (iVar6 = iVar14; iVar12 = iVar14, iVar6 < 5; iVar6 = iVar6 + 1) {
            *(ushort *)((longlong)&DAT_18001d668 + (longlong)iVar6 * 2) = _Memory->mbulinfo[iVar6];
          }
          for (; iVar12 < 0x101; iVar12 = iVar12 + 1) {
            (&DAT_180017660)[iVar12] = _Memory->mbctype[iVar12];
          }
          for (; iVar14 < 0x100; iVar14 = iVar14 + 1) {
            (&DAT_180017770)[iVar14] = _Memory->mbcasemap[iVar14];
          }
          LOCK();
          iVar6 = *(int *)PTR_DAT_180017b90;
          *(int *)PTR_DAT_180017b90 = *(int *)PTR_DAT_180017b90 + -1;
          if ((iVar6 == 1) && ((undefined4 *)PTR_DAT_180017b90 != &DAT_180017870)) {
            free(PTR_DAT_180017b90);
          }
          LOCK();
          PTR_DAT_180017b90 = (undefined *)_Memory;
          _Memory->refcount = _Memory->refcount + 1;
          FUN_180008ad8(0xd);
        }
      }
      else {
        if (iVar7 == -1) {
          if (_Memory != (threadmbcinfostruct *)&DAT_180017870) {
            free(_Memory);
          }
          piVar10 = _errno();
          *piVar10 = 0x16;
        }
      }
    }
  }
  return iVar7;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180008198(int param_1,threadmbcinfostruct *param_2)

{
  byte bVar1;
  int iVar2;
  uint CodePage;
  BOOL BVar3;
  uint *puVar4;
  byte *pbVar5;
  wchar_t *pwVar6;
  ulonglong uVar7;
  longlong lVar8;
  ushort *puVar9;
  byte *pbVar10;
  byte *pbVar11;
  uint uVar12;
  uint uVar14;
  undefined auStack104 [32];
  _cpinfo local_48;
  ulonglong local_30;
  wchar_t *pwVar13;
  
  local_30 = DAT_1800170a0 ^ (ulonglong)auStack104;
  CodePage = getSystemCP(param_1);
  pwVar6 = (wchar_t *)0x0;
  if (CodePage != 0) {
    puVar4 = &DAT_180017aa0;
    pwVar13 = pwVar6;
LAB_1800081ec:
    if (*puVar4 != CodePage) goto code_r0x0001800081f4;
    FUN_180003c80((undefined (*) [16])param_2->mbctype,0,0x101);
    pbVar5 = &DAT_180017a98;
    lVar8 = 4;
    pbVar10 = &DAT_180017ab0 + (longlong)pwVar13 * 0x30;
    do {
      bVar1 = *pbVar10;
      pbVar11 = pbVar10;
      while ((bVar1 != 0 && (pbVar11[1] != 0))) {
        bVar1 = *pbVar11;
        uVar12 = (uint)bVar1;
        if (bVar1 <= pbVar11[1]) {
          uVar14 = (uint)bVar1;
          do {
            uVar14 = uVar14 + 1;
            if (0x100 < uVar14) break;
            uVar12 = uVar12 + 1;
            param_2->mbctype[uVar14] = param_2->mbctype[uVar14] | *pbVar5;
          } while (uVar12 <= pbVar11[1]);
        }
        pbVar11 = pbVar11 + 2;
        bVar1 = *pbVar11;
      }
      pbVar10 = pbVar10 + 8;
      pbVar5 = pbVar5 + 1;
      lVar8 = lVar8 + -1;
    } while (lVar8 != 0);
    param_2->mbcodepage = CodePage;
    param_2->ismbcodepage = 1;
    if (CodePage == 0x3a4) {
      pwVar6 = L"ja-JP";
    }
    else {
      if (CodePage == 0x3a8) {
        pwVar6 = L"zh-CN";
      }
      else {
        if (CodePage == 0x3b5) {
          pwVar6 = L"ko-KR";
        }
        else {
          if (CodePage == 0x3b6) {
            pwVar6 = L"zh-TW";
          }
        }
      }
    }
    param_2->mblocalename = pwVar6;
    puVar9 = param_2->mbulinfo;
    lVar8 = 6;
    do {
      *puVar9 = *(ushort *)
                 ((longlong)&DAT_180017a98 + ((longlong)pwVar13 * 0x30 - (longlong)param_2) +
                 (longlong)puVar9);
      puVar9 = puVar9 + 1;
      lVar8 = lVar8 + -1;
    } while (lVar8 != 0);
    goto LAB_180008416;
  }
LAB_1800081cd:
  setSBCS(param_2);
LAB_180008420:
  FUN_180002f40(local_30 ^ (ulonglong)auStack104);
  return;
code_r0x0001800081f4:
  uVar12 = (int)pwVar13 + 1;
  pwVar13 = (wchar_t *)(ulonglong)uVar12;
  puVar4 = puVar4 + 0xc;
  if (4 < uVar12) goto code_r0x000180008200;
  goto LAB_1800081ec;
code_r0x000180008200:
  if ((CodePage - 65000 < 2) || (BVar3 = IsValidCodePage(CodePage & 0xffff), BVar3 == 0))
  goto LAB_180008420;
  BVar3 = GetCPInfo(CodePage,(LPCPINFO)&local_48);
  if (BVar3 != 0) {
    FUN_180003c80((undefined (*) [16])param_2->mbctype,0,0x101);
    param_2->mbcodepage = CodePage;
    param_2->mblocalename = (wchar_t *)0x0;
    if (local_48.MaxCharSize < 2) {
      param_2->ismbcodepage = 0;
    }
    else {
      pbVar10 = local_48.LeadByte;
      while ((local_48.LeadByte[0] != 0 && (pbVar10[1] != 0))) {
        bVar1 = *pbVar10;
        if (bVar1 <= pbVar10[1]) {
          pbVar5 = param_2->mbctype + (bVar1 + 1);
          uVar7 = (ulonglong)(((uint)pbVar10[1] - (uint)bVar1) + 1);
          do {
            *pbVar5 = *pbVar5 | 4;
            pbVar5 = pbVar5 + 1;
            uVar7 = uVar7 - 1;
          } while (uVar7 != 0);
        }
        pbVar10 = pbVar10 + 2;
        local_48.LeadByte[0] = *pbVar10;
      }
      pbVar10 = param_2->mbctype + 2;
      lVar8 = 0xfe;
      do {
        *pbVar10 = *pbVar10 | 8;
        pbVar10 = pbVar10 + 1;
        lVar8 = lVar8 + -1;
      } while (lVar8 != 0);
      iVar2 = param_2->mbcodepage;
      if (iVar2 == 0x3a4) {
        pwVar6 = L"ja-JP";
      }
      else {
        if (iVar2 == 0x3a8) {
          pwVar6 = L"zh-CN";
        }
        else {
          if (iVar2 == 0x3b5) {
            pwVar6 = L"ko-KR";
          }
          else {
            if (iVar2 == 0x3b6) {
              pwVar6 = L"zh-TW";
            }
          }
        }
      }
      param_2->mblocalename = pwVar6;
      param_2->ismbcodepage = 1;
    }
    puVar9 = param_2->mbulinfo;
    for (lVar8 = 6; lVar8 != 0; lVar8 = lVar8 + -1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
LAB_180008416:
    setSBUpLow(param_2);
    goto LAB_180008420;
  }
  if (_DAT_18001d680 == 0) goto LAB_180008420;
  goto LAB_1800081cd;
}



// Library Function - Single Match
//  _isleadbyte_l
// 
// Library: Visual Studio 2012 Release

int _isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Locale);
  uVar1 = *(ushort *)(*(longlong *)(local_28[0] + 0x108) + (ulonglong)(_C & 0xff) * 2);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return (int)(uVar1 & 0x8000);
}



// Library Function - Single Match
//  isleadbyte
// 
// Library: Visual Studio 2012 Release

int isleadbyte(int _C)

{
  ushort uVar1;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)0x0);
  uVar1 = *(ushort *)(*(longlong *)(local_28[0] + 0x108) + (ulonglong)(_C & 0xff) * 2);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return (int)(uVar1 & 0x8000);
}



// Library Function - Single Match
//  strlen
// 
// Library: Visual Studio

size_t strlen(char *_Str)

{
  char cVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  longlong lVar4;
  
  lVar4 = -(longlong)_Str;
  uVar2 = (ulonglong)_Str & 7;
  while (uVar2 != 0) {
    cVar1 = *_Str;
    _Str = (char *)((longlong)_Str + 1);
    if (cVar1 == '\0') goto LAB_180008568;
    uVar2 = (ulonglong)_Str & 7;
  }
  do {
    do {
      puVar3 = (ulonglong *)_Str;
      _Str = (char *)(puVar3 + 1);
    } while (((~*puVar3 ^ *puVar3 + 0x7efefefefefefeff) & 0x8101010101010100) == 0);
    uVar2 = *puVar3;
    if ((char)uVar2 == '\0') {
      return lVar4 + -8 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return lVar4 + -7 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x10) == '\0') {
      return lVar4 + -6 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x18) == '\0') {
      return lVar4 + -5 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x20) == '\0') {
      return lVar4 + -4 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x28) == '\0') {
      return lVar4 + -3 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x30) == '\0') {
      return lVar4 + -2 + (longlong)_Str;
    }
  } while ((char)(uVar2 >> 0x38) != '\0');
LAB_180008568:
  return lVar4 + -1 + (longlong)_Str;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_180008598(void)

{
  return _DAT_18001d688 == (DAT_1800170a0 | 1);
}



// Library Function - Single Match
//  _wctomb_s_l
// 
// Library: Visual Studio 2012 Release

errno_t _wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,
                   _locale_t _Locale)

{
  int iVar1;
  DWORD DVar2;
  int *piVar3;
  errno_t eVar4;
  int local_res10 [2];
  ushort local_res20 [4];
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = 0;
    }
    return 0;
  }
  if (_SizeConverted != (int *)0x0) {
    *_SizeConverted = -1;
  }
  local_res20[0] = _WCh;
  if (0x7fffffff < _SizeInBytes) {
    piVar3 = _errno();
    *piVar3 = 0x16;
    FUN_1800038fc();
    return 0x16;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Locale);
  if (*(longlong *)(local_28[0] + 0x138) == 0) {
    if (local_res20[0] < 0x100) {
      if (_MbCh != (char *)0x0) {
        if (_SizeInBytes == 0) goto LAB_180008724;
        *_MbCh = (char)local_res20[0];
      }
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = 1;
      }
LAB_1800086f7:
      eVar4 = 0;
      goto LAB_180008666;
    }
    if ((_MbCh != (char *)0x0) && (_SizeInBytes != 0)) {
      FUN_180003c80((undefined (*) [16])_MbCh,0,_SizeInBytes);
    }
  }
  else {
    local_res10[0] = 0;
    iVar1 = WideCharToMultiByte(*(UINT *)(local_28[0] + 4),0,(LPCWSTR)local_res20,1,_MbCh,
                                (int)_SizeInBytes,(LPCSTR)0x0,local_res10);
    if (iVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x7a) {
        if ((_MbCh != (char *)0x0) && (_SizeInBytes != 0)) {
          FUN_180003c80((undefined (*) [16])_MbCh,0,_SizeInBytes);
        }
LAB_180008724:
        piVar3 = _errno();
        eVar4 = 0x22;
        *piVar3 = 0x22;
        FUN_1800038fc();
        goto LAB_180008666;
      }
    }
    else {
      if (local_res10[0] == 0) {
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = iVar1;
        }
        goto LAB_1800086f7;
      }
    }
  }
  piVar3 = _errno();
  *piVar3 = 0x2a;
  piVar3 = _errno();
  eVar4 = *piVar3;
LAB_180008666:
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return eVar4;
}



// Library Function - Single Match
//  wctomb_s
// 
// Library: Visual Studio 2012 Release

errno_t wctomb_s(int *_SizeConverted,char *_MbCh,rsize_t _SizeInBytes,wchar_t _WCh)

{
  errno_t eVar1;
  
  eVar1 = _wctomb_s_l(_SizeConverted,_MbCh,_SizeInBytes,_WCh,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  _initp_misc_cfltcvt_tab
// 
// Library: Visual Studio 2012 Release

void _initp_misc_cfltcvt_tab(void)

{
  undefined *puVar1;
  undefined **ppuVar2;
  uint uVar3;
  
  uVar3 = 0;
  ppuVar2 = &PTR_LAB_180017fe0;
  do {
    puVar1 = (undefined *)EncodePointer(*ppuVar2);
    uVar3 = uVar3 + 1;
    *ppuVar2 = puVar1;
    ppuVar2 = ppuVar2 + 1;
  } while (uVar3 < 10);
  return;
}



undefined4 FUN_1800088e0(ushort *param_1,byte *param_2,ulonglong param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  localeinfo_struct local_28;
  longlong local_18;
  char local_10;
  
  if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
    if (*param_2 != 0) {
      _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(localeinfo_struct *)0x0);
      if ((local_28.locinfo)->locale_name[2] == (wchar_t *)0x0) {
        if (param_1 != (ushort *)0x0) {
          *param_1 = (ushort)*param_2;
        }
        iVar2 = 1;
      }
      else {
        iVar1 = _isleadbyte_l((uint)*param_2,(_locale_t)&local_28);
        iVar2 = 1;
        if (iVar1 == 0) {
          iVar1 = MultiByteToWideChar((local_28.locinfo)->lc_codepage,9,(LPCSTR)param_2,1,
                                      (LPWSTR)param_1,(uint)(param_1 != (ushort *)0x0));
          if (iVar1 != 0) goto LAB_1800088c3;
        }
        else {
          iVar2 = (local_28.locinfo)->mb_cur_max;
          if ((((1 < iVar2) && (iVar2 <= (int)param_3)) &&
              (iVar2 = MultiByteToWideChar((local_28.locinfo)->lc_codepage,9,(LPCSTR)param_2,iVar2,
                                           (LPWSTR)param_1,(uint)(param_1 != (ushort *)0x0)),
              iVar2 != 0)) ||
             (((ulonglong)(longlong)(local_28.locinfo)->mb_cur_max <= param_3 && (param_2[1] != 0)))
             ) {
            iVar2 = (local_28.locinfo)->mb_cur_max;
            goto LAB_1800088c3;
          }
        }
        piVar3 = _errno();
        iVar2 = -1;
        *piVar3 = 0x2a;
      }
LAB_1800088c3:
      if (local_10 == '\0') {
        return iVar2;
      }
      *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
      return iVar2;
    }
    if (param_1 != (ushort *)0x0) {
      *param_1 = 0;
    }
  }
  return 0;
}



// Library Function - Single Match
//  _lock
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void _lock(int _File)

{
  undefined8 uVar1;
  
  if (*(longlong *)((longlong)&DAT_180018030 + (longlong)_File * 0x10) == 0) {
    uVar1 = FUN_1800089b4(_File);
    if ((int)uVar1 == 0) {
      _amsg_exit(0x11);
    }
  }
                    // WARNING: Could not recover jumptable at 0x000180008925. Too many branches
                    // WARNING: Treating indirect jump as call
  EnterCriticalSection(*(LPCRITICAL_SECTION *)((longlong)&DAT_180018030 + (longlong)_File * 0x10));
  return;
}



undefined8 FUN_1800089b4(int param_1)

{
  LPCRITICAL_SECTION _Memory;
  int *piVar1;
  longlong lVar2;
  
  lVar2 = (longlong)param_1;
  if (DAT_18001d340 == 0) {
    _FF_MSGBANNER();
    _NMSG_WRITE(0x1e);
    FUN_18000526c(0xff);
  }
  if (*(longlong *)((longlong)&DAT_180018030 + lVar2 * 0x10) == 0) {
    _Memory = (LPCRITICAL_SECTION)FUN_180006770(0x28);
    if (_Memory == (LPCRITICAL_SECTION)0x0) {
      piVar1 = _errno();
      *piVar1 = 0xc;
      return 0;
    }
    _lock(10);
    if (*(longlong *)((longlong)&DAT_180018030 + lVar2 * 0x10) == 0) {
      FUN_180006234(_Memory,4000);
      *(LPCRITICAL_SECTION *)((longlong)&DAT_180018030 + lVar2 * 0x10) = _Memory;
    }
    else {
      free(_Memory);
    }
    LeaveCriticalSection(DAT_1800180d0);
  }
  return 1;
}



undefined4 FUN_180008a74(void)

{
  longlong lVar1;
  LPCRITICAL_SECTION *pp_Var2;
  int iVar3;
  longlong lVar4;
  
  iVar3 = 0;
  pp_Var2 = (LPCRITICAL_SECTION *)&DAT_180018030;
  lVar4 = 0x24;
  do {
    if (*(int *)(pp_Var2 + 1) == 1) {
      lVar1 = (longlong)iVar3;
      iVar3 = iVar3 + 1;
      *pp_Var2 = (LPCRITICAL_SECTION)(&DAT_18001d690 + lVar1 * 0x28);
      FUN_180006234((LPCRITICAL_SECTION)(&DAT_18001d690 + lVar1 * 0x28),4000);
    }
    pp_Var2 = pp_Var2 + 2;
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  return 1;
}



void FUN_180008ad8(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180008ae9. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection(*(LPCRITICAL_SECTION *)((longlong)&DAT_180018030 + (longlong)param_1 * 0x10))
  ;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _FF_MSGBANNER
// 
// Library: Visual Studio 2012 Release

void _FF_MSGBANNER(void)

{
  int iVar1;
  
  iVar1 = _set_error_mode(3);
  if (iVar1 != 1) {
    iVar1 = _set_error_mode(3);
    if (iVar1 != 0) {
      return;
    }
    if (_DAT_18001d8c0 != 1) {
      return;
    }
  }
  _NMSG_WRITE(0xfc);
  _NMSG_WRITE(0xff);
  return;
}



// Library Function - Single Match
//  _GET_RTERRMSG
// 
// Library: Visual Studio 2012 Release

wchar_t * _GET_RTERRMSG(int param_1)

{
  uint uVar1;
  int *piVar2;
  
  uVar1 = 0;
  piVar2 = &DAT_180010bb0;
  do {
    if (param_1 == *piVar2) {
      return (wchar_t *)
             (&PTR_u_R6002___floating_point_support_n_180010bb8)[(longlong)(int)uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
    piVar2 = piVar2 + 4;
  } while (uVar1 < 0x17);
  return (wchar_t *)0x0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _NMSG_WRITE
// 
// Library: Visual Studio 2012 Release

void _NMSG_WRITE(int param_1)

{
  code *pcVar1;
  int iVar2;
  errno_t eVar3;
  DWORD DVar4;
  wchar_t *_Src;
  longlong lVar5;
  HANDLE hFile;
  size_t sVar6;
  char *pcVar7;
  uint uVar8;
  DWORD local_238 [4];
  char local_228 [499];
  undefined local_35;
  ulonglong local_28;
  
  local_28 = DAT_1800170a0 ^ (ulonglong)&stack0xfffffffffffffd98;
  _Src = _GET_RTERRMSG(param_1);
  uVar8 = 0;
  if (_Src != (wchar_t *)0x0) {
    iVar2 = _set_error_mode(3);
    if (iVar2 != 1) {
      iVar2 = _set_error_mode(3);
      if ((iVar2 != 0) || (_DAT_18001d8c0 != 1)) {
        if (param_1 != 0xfc) {
          eVar3 = wcscpy_s((wchar_t *)&DAT_18001d8d0,0x314,L"Runtime Error!\n\nProgram: ");
          if (eVar3 != 0) {
            FUN_18000391c();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          _DAT_18001db0a = 0;
          DVar4 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_18001d902,0x104);
          if (DVar4 == 0) {
            eVar3 = wcscpy_s((wchar_t *)&DAT_18001d902,0x2fb,L"<program name unknown>");
            if (eVar3 != 0) {
              FUN_18000391c();
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
          }
          lVar5 = FUN_18000a7e4((short *)&DAT_18001d902);
          if (0x3c < lVar5 + 1U) {
            lVar5 = FUN_18000a7e4((short *)&DAT_18001d902);
            eVar3 = wcsncpy_s((wchar_t *)(&DAT_18001d88c + lVar5 * 2),
                              0x2fb - (lVar5 * 2 + -0x76 >> 1),L"...",3);
            if (eVar3 != 0) {
              FUN_18000391c();
              pcVar1 = (code *)swi(3);
              (*pcVar1)();
              return;
            }
          }
          eVar3 = wcscat_s((wchar_t *)&DAT_18001d8d0,0x314,L"\n\n");
          if (eVar3 != 0) {
            FUN_18000391c();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          eVar3 = wcscat_s((wchar_t *)&DAT_18001d8d0,0x314,_Src);
          if (eVar3 != 0) {
            FUN_18000391c();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          FUN_18000a90c((LPCWSTR)&DAT_18001d8d0,L"Microsoft Visual C++ Runtime Library",0x12010);
        }
        goto LAB_180008d3f;
      }
    }
    hFile = GetStdHandle(0xfffffff4);
    if ((longlong)hFile - 1U < 0xfffffffffffffffe) {
      pcVar7 = local_228;
      do {
        *pcVar7 = *(char *)_Src;
        if (*_Src == L'\0') break;
        uVar8 = uVar8 + 1;
        pcVar7 = pcVar7 + 1;
        _Src = _Src + 1;
      } while (uVar8 < 500);
      local_35 = 0;
      sVar6 = strlen(local_228);
      WriteFile(hFile,local_228,(DWORD)sVar6,local_238,(LPOVERLAPPED)0x0);
    }
  }
LAB_180008d3f:
  FUN_180002f40(local_28 ^ (ulonglong)&stack0xfffffffffffffd98);
  return;
}



// Library Function - Single Match
//  _FindPESection
// 
// Library: Visual Studio 2019 Release

PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  PIMAGE_SECTION_HEADER p_Var1;
  PBYTE pBVar2;
  uint uVar3;
  
  uVar3 = 0;
  pBVar2 = pImageBase + *(int *)(pImageBase + 0x3c);
  p_Var1 = (PIMAGE_SECTION_HEADER)(pBVar2 + (ulonglong)*(ushort *)(pBVar2 + 0x14) + 0x18);
  if (*(ushort *)(pBVar2 + 6) != 0) {
    do {
      if ((p_Var1->VirtualAddress <= rva) && (rva < p_Var1->Misc + p_Var1->VirtualAddress)) {
        return p_Var1;
      }
      uVar3 = uVar3 + 1;
      p_Var1 = p_Var1 + 1;
    } while (uVar3 < *(ushort *)(pBVar2 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  _IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2019 Release

BOOL _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  uint uVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  
  uVar1 = _ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_180000000);
  p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)uVar1;
  if (uVar1 != 0) {
    p_Var2 = _FindPESection((PBYTE)&IMAGE_DOS_HEADER_180000000,(DWORD_PTR)(pTarget + -0x180000000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)(~(p_Var2->Characteristics >> 0x1f) & 1);
    }
  }
  return (BOOL)p_Var2;
}



// Library Function - Single Match
//  _ValidateImageBase
// 
// Library: Visual Studio 2015 Release

BOOL _ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)(*(short *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b)
    ;
  }
  return (BOOL)uVar1;
}



// Library Function - Single Match
//  __onexitinit
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

undefined4 __onexitinit(void)

{
  undefined4 uVar1;
  undefined8 *Ptr;
  
  Ptr = (undefined8 *)FUN_1800066f0(0x20,8);
  DAT_18001f0f8 = EncodePointer(Ptr);
  DAT_18001f100 = DAT_18001f0f8;
  if (Ptr == (undefined8 *)0x0) {
    uVar1 = 0x18;
  }
  else {
    *Ptr = 0;
    uVar1 = 0;
  }
  return uVar1;
}



// Library Function - Single Match
//  _onexit
// 
// Library: Visual Studio 2012 Release

_onexit_t _onexit(_onexit_t _Func)

{
  PVOID *_Memory;
  PVOID *ppvVar1;
  PVOID *ppvVar2;
  PVOID pvVar3;
  PVOID *ppvVar4;
  _onexit_t p_Var5;
  
  FUN_180005590();
  _Memory = (PVOID *)DecodePointer(DAT_18001f100);
  ppvVar1 = (PVOID *)DecodePointer(DAT_18001f0f8);
  if (_Memory <= ppvVar1) {
    ppvVar4 = (PVOID *)((longlong)ppvVar1 - (longlong)_Memory) + 1;
    if ((PVOID *)0x7 < ppvVar4) {
      ppvVar2 = (PVOID *)_msize(_Memory);
      if (ppvVar2 < ppvVar4) {
        ppvVar4 = (PVOID *)0x1000;
        if (ppvVar2 < (PVOID *)0x1000) {
          ppvVar4 = ppvVar2;
        }
        if (((PVOID *)((longlong)ppvVar4 + (longlong)ppvVar2) < ppvVar2) ||
           (pvVar3 = FUN_1800067ec(_Memory,(size_t)(PVOID *)((longlong)ppvVar4 + (longlong)ppvVar2))
           , pvVar3 == (void *)0x0)) {
          p_Var5 = (_onexit_t)0x0;
          if ((ppvVar2 + 4 < ppvVar2) ||
             (pvVar3 = FUN_1800067ec(_Memory,(size_t)(ppvVar2 + 4)), pvVar3 == (void *)0x0))
          goto LAB_180008fdc;
        }
        ppvVar1 = (PVOID *)((longlong)pvVar3 +
                           ((longlong)(PVOID *)((longlong)ppvVar1 - (longlong)_Memory) >> 3) * 8);
        DAT_18001f100 = EncodePointer(pvVar3);
      }
      pvVar3 = EncodePointer(_Func);
      *ppvVar1 = pvVar3;
      DAT_18001f0f8 = EncodePointer(ppvVar1 + 1);
      p_Var5 = _Func;
      goto LAB_180008fdc;
    }
  }
  p_Var5 = (_onexit_t)0x0;
LAB_180008fdc:
  FUN_18000559c();
  return p_Var5;
}



// Library Function - Single Match
//  atexit
// 
// Library: Visual Studio 2012 Release

int atexit(void *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (int)((p_Var1 != (_onexit_t)0x0) - 1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180009038(void)

{
  _DAT_18001def8 = EncodePointer(&DAT_180009018);
  return;
}



// Library Function - Single Match
//  _callnewh
// 
// Library: Visual Studio 2012 Release

int _callnewh(size_t _Size)

{
  int iVar1;
  code *pcVar2;
  
  pcVar2 = (code *)DecodePointer(DAT_18001df00);
  if ((pcVar2 != (code *)0x0) && (iVar1 = (*pcVar2)(_Size), iVar1 != 0)) {
    return 1;
  }
  return 0;
}



void FUN_18000908c(undefined8 param_1)

{
  DAT_18001df00 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180009094(undefined8 param_1)

{
  _DAT_18001df08 = param_1;
  return;
}



void FUN_18000909c(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800090a3. Too many branches
                    // WARNING: Treating indirect jump as call
  DecodePointer(DAT_18001df20);
  return;
}



void FUN_1800090ac(undefined8 param_1)

{
  DAT_18001df10 = param_1;
  DAT_18001df18 = param_1;
  DAT_18001df20 = param_1;
  DAT_18001df28 = param_1;
  return;
}



undefined8 FUN_1800090cc(uint param_1)

{
  void *pvVar1;
  bool bVar2;
  int *piVar3;
  _ptiddata p_Var4;
  code *pcVar5;
  undefined8 uVar6;
  code *pcVar7;
  void *pvVar8;
  PVOID Ptr;
  int iVar9;
  void *pvVar10;
  code **ppcVar11;
  int local_res10;
  
  pvVar10 = (void *)0x0;
  local_res10 = 0;
  bVar2 = false;
  p_Var4 = (_ptiddata)0x0;
  if (param_1 == 2) {
    ppcVar11 = (code **)&DAT_18001df10;
    Ptr = DAT_18001df10;
    goto LAB_1800091d2;
  }
  if (param_1 == 4) {
LAB_180009167:
    p_Var4 = _getptd_noexit();
    if (p_Var4 == (_ptiddata)0x0) {
      return 0xffffffff;
    }
    pvVar1 = p_Var4->_pxcptacttab;
    pvVar8 = pvVar1;
    do {
      if (*(uint *)((longlong)pvVar8 + 4) == param_1) break;
      pvVar8 = (void *)((longlong)pvVar8 + 0x10);
    } while (pvVar8 < (void *)((longlong)pvVar1 + 0xc0));
    if (((void *)((longlong)pvVar1 + 0xc0) <= pvVar8) ||
       (*(uint *)((longlong)pvVar8 + 4) != param_1)) {
      pvVar8 = (void *)0x0;
    }
    ppcVar11 = (code **)((longlong)pvVar8 + 8);
    pcVar5 = *ppcVar11;
  }
  else {
    if (param_1 == 6) {
LAB_180009157:
      ppcVar11 = (code **)&DAT_18001df20;
      Ptr = DAT_18001df20;
    }
    else {
      if ((param_1 == 8) || (param_1 == 0xb)) goto LAB_180009167;
      if (param_1 == 0xf) {
        ppcVar11 = (code **)&DAT_18001df28;
        Ptr = DAT_18001df28;
      }
      else {
        if (param_1 != 0x15) {
          if (param_1 != 0x16) {
            piVar3 = _errno();
            *piVar3 = 0x16;
            FUN_1800038fc();
            return 0xffffffff;
          }
          goto LAB_180009157;
        }
        ppcVar11 = (code **)&DAT_18001df18;
        Ptr = DAT_18001df18;
      }
    }
LAB_1800091d2:
    bVar2 = true;
    pcVar5 = (code *)DecodePointer(Ptr);
  }
  if (pcVar5 == (code *)0x1) {
    return 0;
  }
  if (pcVar5 == (code *)0x0) {
    FUN_18000549c(3);
    pcVar5 = (code *)swi(3);
    uVar6 = (*pcVar5)();
    return uVar6;
  }
  if (bVar2) {
    _lock(0);
  }
  if ((param_1 < 0xc) && ((0x910U >> (param_1 & 0x1f) & 1) != 0)) {
    pvVar10 = p_Var4->_tpxcptinfoptrs;
    p_Var4->_tpxcptinfoptrs = (void *)0x0;
    if (param_1 == 8) {
      local_res10 = p_Var4->_tfpecode;
      p_Var4->_tfpecode = 0x8c;
      goto LAB_18000924a;
    }
  }
  else {
LAB_18000924a:
    if (param_1 == 8) {
      for (iVar9 = 3; iVar9 < 0xc; iVar9 = iVar9 + 1) {
        *(undefined8 *)((longlong)p_Var4->_pxcptacttab + (longlong)iVar9 * 0x10 + 8) = 0;
      }
      goto LAB_180009293;
    }
  }
  pcVar7 = (code *)EncodePointer((PVOID)0x0);
  *ppcVar11 = pcVar7;
LAB_180009293:
  if (bVar2) {
    FUN_180008ad8(0);
  }
  if (param_1 == 8) {
    (*pcVar5)(8,p_Var4->_tfpecode);
  }
  else {
    (*pcVar5)(param_1);
  }
  if (((param_1 < 0xc) && ((0x910U >> (param_1 & 0x1f) & 1) != 0)) &&
     (p_Var4->_tpxcptinfoptrs = pvVar10, param_1 == 8)) {
    p_Var4->_tfpecode = local_res10;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180009300(undefined8 param_1)

{
  _DAT_18001df38 = param_1;
  return;
}



void FUN_180009320(PVOID param_1,PVOID param_2)

{
  RtlUnwindEx(param_1,param_2,(PEXCEPTION_RECORD)0x0,(PVOID)0x0,(PCONTEXT)&stack0xfffffffffffffb28,
              (PUNWIND_HISTORY_TABLE)0x0);
  return;
}



void FUN_180009350(void)

{
  return;
}



void FUN_180009380(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x0001800093bb)

ulonglong FUN_180009400(uint param_1)

{
  byte bVar1;
  _LocaleUpdate local_28 [8];
  longlong local_20;
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate(local_28,(localeinfo_struct *)0x0);
  bVar1 = *(byte *)(((ulonglong)param_1 & 0xff) + 0x19 + local_20);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return (ulonglong)((bVar1 & 4) != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  malloc
// 
// Library: Visual Studio 2012 Release

void * malloc(size_t _Size)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  SIZE_T dwBytes;
  
  if (_Size < 0xffffffffffffffe1) {
    dwBytes = 1;
    if (_Size != 0) {
      dwBytes = _Size;
    }
    do {
      if (DAT_18001d340 == (HANDLE)0x0) {
        _FF_MSGBANNER();
        _NMSG_WRITE(0x1e);
        FUN_18000526c(0xff);
      }
      pvVar2 = HeapAlloc(DAT_18001d340,0,dwBytes);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (_DAT_18001df90 == 0) {
        piVar3 = _errno();
        *piVar3 = 0xc;
        break;
      }
      iVar1 = _callnewh(_Size);
    } while (iVar1 != 0);
    piVar3 = _errno();
    *piVar3 = 0xc;
  }
  else {
    _callnewh(_Size);
    piVar3 = _errno();
    *piVar3 = 0xc;
    pvVar2 = (void *)0x0;
  }
  return pvVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  realloc
// 
// Library: Visual Studio 2012 Release

void * realloc(void *_Memory,size_t _NewSize)

{
  int iVar1;
  DWORD DVar2;
  void *pvVar3;
  LPVOID pvVar4;
  int *piVar5;
  
  if (_Memory == (void *)0x0) {
    pvVar3 = malloc(_NewSize);
  }
  else {
    if (_NewSize == 0) {
      free(_Memory);
    }
    else {
      if (_NewSize < 0xffffffffffffffe1) {
        do {
          if (_NewSize == 0) {
            _NewSize = 1;
          }
          pvVar4 = HeapReAlloc(DAT_18001d340,0,_Memory,_NewSize);
          if (pvVar4 != (LPVOID)0x0) {
            return pvVar4;
          }
          if (_DAT_18001df90 == 0) {
            piVar5 = _errno();
            DVar2 = GetLastError();
            iVar1 = _get_errno_from_oserr(DVar2);
            *piVar5 = iVar1;
            return (void *)0x0;
          }
          iVar1 = _callnewh(_NewSize);
          if (iVar1 == 0) {
            piVar5 = _errno();
            DVar2 = GetLastError();
            iVar1 = _get_errno_from_oserr(DVar2);
            *piVar5 = iVar1;
            goto LAB_180009558;
          }
        } while (_NewSize < 0xffffffffffffffe1);
      }
      _callnewh(_NewSize);
      piVar5 = _errno();
      *piVar5 = 0xc;
    }
LAB_180009558:
    pvVar3 = (void *)0x0;
  }
  return pvVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _calloc_impl
// 
// Library: Visual Studio 2012 Release

LPVOID _calloc_impl(ulonglong param_1,ulonglong param_2,undefined4 *param_3)

{
  int iVar1;
  int *piVar2;
  LPVOID pvVar3;
  ulonglong dwBytes;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffffffffffe0 / param_1)) {
    dwBytes = param_2 * param_1;
    if (dwBytes == 0) {
      dwBytes = 1;
    }
    do {
      pvVar3 = (LPVOID)0x0;
      if ((dwBytes < 0xffffffffffffffe1) &&
         (pvVar3 = HeapAlloc(DAT_18001d340,8,dwBytes), pvVar3 != (LPVOID)0x0)) {
        return pvVar3;
      }
      if (_DAT_18001df90 == 0) {
        if (param_3 == (undefined4 *)0x0) {
          return pvVar3;
        }
        *param_3 = 0xc;
        return pvVar3;
      }
      iVar1 = _callnewh(dwBytes);
    } while (iVar1 != 0);
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = 0xc;
    }
  }
  else {
    piVar2 = _errno();
    *piVar2 = 0xc;
  }
  return (LPVOID)0x0;
}



// Library Function - Single Match
//  _fcloseall
// 
// Library: Visual Studio 2012 Release

int _fcloseall(void)

{
  FILE *_File;
  int iVar1;
  int iVar2;
  longlong lVar3;
  int iVar4;
  
  iVar4 = 0;
  _lock(1);
  for (iVar2 = 3; iVar2 < DAT_18001dfa8; iVar2 = iVar2 + 1) {
    lVar3 = (longlong)iVar2;
    _File = *(FILE **)(DAT_18001dfa0 + lVar3 * 8);
    if (_File != (FILE *)0x0) {
      if ((*(byte *)&_File->_flag & 0x83) != 0) {
        iVar1 = fclose(_File);
        if (iVar1 != -1) {
          iVar4 = iVar4 + 1;
        }
      }
      if (0x13 < iVar2) {
        DeleteCriticalSection((LPCRITICAL_SECTION)(*(longlong *)(DAT_18001dfa0 + lVar3 * 8) + 0x30))
        ;
        free(*(void **)(DAT_18001dfa0 + lVar3 * 8));
        *(undefined8 *)(DAT_18001dfa0 + lVar3 * 8) = 0;
      }
    }
  }
  FUN_180008ad8(1);
  return iVar4;
}



// WARNING: Removing unreachable block (ram,0x00018000987f)
// WARNING: Removing unreachable block (ram,0x00018000982b)
// WARNING: Removing unreachable block (ram,0x000180009835)

int FUN_1800096e4(FILE *param_1)

{
  void *_File;
  FILE *pFVar1;
  uint uVar2;
  DWORD DVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  longlong lVar7;
  
  if (param_1 != (FILE *)0x0) {
    iVar5 = _flush(param_1);
    if (iVar5 == 0) {
      if ((param_1->_flag & 0x4000U) == 0) {
        iVar5 = 0;
      }
      else {
        uVar2 = _fileno(param_1);
        DVar3 = FUN_18000aea0(uVar2);
        iVar5 = -(uint)(DVar3 != 0);
      }
    }
    else {
      iVar5 = -1;
    }
    return iVar5;
  }
  iVar6 = 0;
  _lock(1);
  for (iVar5 = 0; iVar5 < DAT_18001dfa8; iVar5 = iVar5 + 1) {
    lVar7 = (longlong)iVar5;
    _File = *(void **)(DAT_18001dfa0 + lVar7 * 8);
    if ((_File != (void *)0x0) && ((*(byte *)((longlong)_File + 0x18) & 0x83) != 0)) {
      _lock_file2(iVar5,_File);
      pFVar1 = *(FILE **)(DAT_18001dfa0 + lVar7 * 8);
      if (((*(byte *)&pFVar1->_flag & 0x83) != 0) &&
         (((*(byte *)&pFVar1->_flag & 2) != 0 && (iVar4 = FUN_1800096e4(pFVar1), iVar4 == -1)))) {
        iVar6 = -1;
      }
      FUN_180006c88(iVar5,*(longlong *)(DAT_18001dfa0 + lVar7 * 8));
    }
  }
  FUN_180008ad8(1);
  return iVar6;
}



// Library Function - Single Match
//  _flush
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

int _flush(FILE *_File)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = 0;
  iVar3 = 0;
  if (((((byte)_File->_flag & 3) == 2) && (iVar3 = iVar2, (_File->_flag & 0x108U) != 0)) &&
     (uVar4 = *(int *)&_File->_ptr - *(int *)&_File->_base, 0 < (int)uVar4)) {
    uVar1 = _fileno(_File);
    uVar1 = FUN_180006d30(uVar1,(wint_t *)_File->_base,uVar4);
    if (uVar1 == uVar4) {
      if ((char)_File->_flag < '\0') {
        _File->_flag = _File->_flag & 0xfffffffd;
      }
    }
    else {
      _File->_flag = _File->_flag | 0x20;
      iVar3 = -1;
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar3;
}



// WARNING: Removing unreachable block (ram,0x00018000983d)
// WARNING: Removing unreachable block (ram,0x000180009842)
// WARNING: Removing unreachable block (ram,0x000180009848)
// WARNING: Removing unreachable block (ram,0x000180009850)
// WARNING: Removing unreachable block (ram,0x000180009854)

int FUN_1800097ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  void *_File;
  FILE *pFVar1;
  int iVar2;
  int _Index;
  int iVar3;
  longlong lVar4;
  
  iVar3 = 0;
  _lock(1);
  for (_Index = 0; _Index < DAT_18001dfa8; _Index = _Index + 1) {
    lVar4 = (longlong)_Index;
    _File = *(void **)(DAT_18001dfa0 + lVar4 * 8);
    if ((_File != (void *)0x0) && ((*(byte *)((longlong)_File + 0x18) & 0x83) != 0)) {
      _lock_file2(_Index,_File);
      pFVar1 = *(FILE **)(DAT_18001dfa0 + lVar4 * 8);
      if (((*(byte *)&pFVar1->_flag & 0x83) != 0) && (iVar2 = FUN_1800096e4(pFVar1), iVar2 != -1)) {
        iVar3 = iVar3 + 1;
      }
      FUN_180006c88(_Index,*(longlong *)(DAT_18001dfa0 + lVar4 * 8));
    }
  }
  FUN_180008ad8(1);
  return iVar3;
}



undefined8 FUN_1800098a0(uint param_1)

{
  int *piVar1;
  longlong lVar2;
  longlong lVar3;
  
  lVar3 = (ulonglong)(param_1 & 0x1f) * 0x58;
  lVar2 = *(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8);
  if (*(int *)(lVar3 + 0xc + lVar2) == 0) {
    _lock(10);
    if (*(int *)(lVar3 + 0xc + lVar2) == 0) {
      FUN_180006234((LPCRITICAL_SECTION)(lVar3 + 0x10 + lVar2),4000);
      piVar1 = (int *)(lVar3 + 0xc + lVar2);
      *piVar1 = *piVar1 + 1;
    }
    FUN_180008ad8(10);
  }
  EnterCriticalSection
            ((LPCRITICAL_SECTION)
             (*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 0x10 +
             lVar3));
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180009938(uint param_1)

{
  int *piVar1;
  ulong *puVar2;
  DWORD nStdHandle;
  longlong lVar3;
  
  if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
    lVar3 = (ulonglong)(param_1 & 0x1f) * 0x58;
    if (((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                   + lVar3) & 1) != 0) &&
       (*(longlong *)
         (*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + lVar3) != -1
       )) {
      if (_DAT_18001d8c0 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else {
          if (param_1 == 1) {
            nStdHandle = 0xfffffff5;
          }
          else {
            if (param_1 != 2) goto LAB_1800099ae;
            nStdHandle = 0xfffffff4;
          }
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_1800099ae:
      *(undefined8 *)
       (lVar3 + *(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8)) =
           0xffffffffffffffff;
      return 0;
    }
  }
  piVar1 = _errno();
  *piVar1 = 9;
  puVar2 = __doserrno();
  *puVar2 = 0;
  return 0xffffffff;
}



undefined8 FUN_1800099e4(uint param_1)

{
  ulong *puVar1;
  int *piVar2;
  longlong lVar3;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
      lVar3 = (ulonglong)(param_1 & 0x1f) * 0x58;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                    + lVar3) & 1) != 0) {
        return *(undefined8 *)
                (*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + lVar3
                );
      }
    }
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
    FUN_1800038fc();
  }
  return 0xffffffffffffffff;
}



void FUN_180009a58(uint param_1)

{
                    // WARNING: Could not recover jumptable at 0x000180009a7b. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((ulonglong)(param_1 & 0x1f) * 0x58 + 0x10 +
             *(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8)));
  return;
}



// Library Function - Single Match
//  _putwch_nolock
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

wint_t _putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  wint_t local_res8 [4];
  DWORD local_res10 [6];
  
  local_res8[0] = _WCh;
  if (DAT_180018338 == (HANDLE)0xfffffffffffffffe) {
    __initconout();
  }
  if ((DAT_180018338 == (HANDLE)0xffffffffffffffff) ||
     (BVar1 = WriteConsoleW(DAT_180018338,local_res8,1,local_res10,(LPVOID)0x0), BVar1 == 0)) {
    local_res8[0] = 0xffff;
  }
  return local_res8[0];
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __chkstk(void)

{
  undefined *in_RAX;
  undefined *puVar1;
  undefined *puVar2;
  longlong in_GS_OFFSET;
  undefined local_res8 [32];
  
  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX) {
    puVar1 = (undefined *)0x0;
  }
  puVar2 = *(undefined **)(in_GS_OFFSET + 0x10);
  if (puVar1 < puVar2) {
    do {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}



// Library Function - Single Match
//  __free_lconv_mon
// 
// Library: Visual Studio 2012 Release

void __free_lconv_mon(longlong param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_180018288) {
      free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_180018290) {
      free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x28) != PTR_DAT_180018298) {
      free(*(undefined **)(param_1 + 0x28));
    }
    if (*(undefined **)(param_1 + 0x30) != PTR_DAT_1800182a0) {
      free(*(undefined **)(param_1 + 0x30));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_1800182a8) {
      free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_1800182b0) {
      free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_1800182b8) {
      free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x68) != PTR_DAT_1800182d8) {
      free(*(undefined **)(param_1 + 0x68));
    }
    if (*(undefined **)(param_1 + 0x70) != PTR_DAT_1800182e0) {
      free(*(undefined **)(param_1 + 0x70));
    }
    if (*(undefined **)(param_1 + 0x78) != PTR_DAT_1800182e8) {
      free(*(undefined **)(param_1 + 0x78));
    }
    if (*(undefined **)(param_1 + 0x80) != PTR_DAT_1800182f0) {
      free(*(undefined **)(param_1 + 0x80));
    }
    if (*(undefined **)(param_1 + 0x88) != PTR_DAT_1800182f8) {
      free(*(undefined **)(param_1 + 0x88));
    }
    if (*(undefined **)(param_1 + 0x90) != PTR_DAT_180018300) {
      free(*(undefined **)(param_1 + 0x90));
    }
  }
  return;
}



// Library Function - Single Match
//  __free_lconv_num
// 
// Library: Visual Studio 2012 Release

void __free_lconv_num(void **param_1)

{
  if (param_1 != (void **)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_180018270) {
      free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_180018278) {
      free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_180018280) {
      free(param_1[2]);
    }
    if ((undefined *)param_1[0xb] != PTR_DAT_1800182c8) {
      free(param_1[0xb]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_1800182d0) {
      free(param_1[0xc]);
    }
  }
  return;
}



// Library Function - Single Match
//  __free_lc_time
// 
// Library: Visual Studio 2012 Release

void __free_lc_time(void **param_1)

{
  if (param_1 != (void **)0x0) {
    free(param_1[1]);
    free(param_1[2]);
    free(param_1[3]);
    free(param_1[4]);
    free(param_1[5]);
    free(param_1[6]);
    free(*param_1);
    free(param_1[8]);
    free(param_1[9]);
    free(param_1[10]);
    free(param_1[0xb]);
    free(param_1[0xc]);
    free(param_1[0xd]);
    free(param_1[7]);
    free(param_1[0xe]);
    free(param_1[0xf]);
    free(param_1[0x10]);
    free(param_1[0x11]);
    free(param_1[0x12]);
    free(param_1[0x13]);
    free(param_1[0x14]);
    free(param_1[0x15]);
    free(param_1[0x16]);
    free(param_1[0x17]);
    free(param_1[0x18]);
    free(param_1[0x19]);
    free(param_1[0x1a]);
    free(param_1[0x1b]);
    free(param_1[0x1c]);
    free(param_1[0x1d]);
    free(param_1[0x1e]);
    free(param_1[0x1f]);
    free(param_1[0x20]);
    free(param_1[0x21]);
    free(param_1[0x22]);
    free(param_1[0x23]);
    free(param_1[0x24]);
    free(param_1[0x25]);
    free(param_1[0x26]);
    free(param_1[0x27]);
    free(param_1[0x28]);
    free(param_1[0x29]);
    free(param_1[0x2a]);
    free(param_1[0x2d]);
    free(param_1[0x2e]);
    free(param_1[0x2f]);
    free(param_1[0x30]);
    free(param_1[0x31]);
    free(param_1[0x32]);
    free(param_1[0x2c]);
    free(param_1[0x34]);
    free(param_1[0x35]);
    free(param_1[0x36]);
    free(param_1[0x37]);
    free(param_1[0x38]);
    free(param_1[0x39]);
    free(param_1[0x33]);
    free(param_1[0x3a]);
    free(param_1[0x3b]);
    free(param_1[0x3c]);
    free(param_1[0x3d]);
    free(param_1[0x3e]);
    free(param_1[0x3f]);
    free(param_1[0x40]);
    free(param_1[0x41]);
    free(param_1[0x42]);
    free(param_1[0x43]);
    free(param_1[0x44]);
    free(param_1[0x45]);
    free(param_1[0x46]);
    free(param_1[0x47]);
    free(param_1[0x48]);
    free(param_1[0x49]);
    free(param_1[0x4a]);
    free(param_1[0x4b]);
    free(param_1[0x4c]);
    free(param_1[0x4d]);
    free(param_1[0x4e]);
    free(param_1[0x4f]);
    free(param_1[0x50]);
    free(param_1[0x51]);
    free(param_1[0x52]);
    free(param_1[0x53]);
    free(param_1[0x54]);
    free(param_1[0x55]);
    free(param_1[0x56]);
    free(param_1[0x57]);
  }
  return;
}



// WARNING: Function: __chkstk replaced with injection: alloca_probe

void FUN_18000a0b4(longlong *param_1,wchar_t *param_2,uint param_3,LPCSTR param_4,int param_5,
                  undefined8 param_6,int param_7,UINT param_8,int param_9)

{
  ulonglong _Size;
  size_t _Size_00;
  longlong lVar1;
  wchar_t *pwVar2;
  int iVar3;
  char *pcVar4;
  undefined4 *puVar5;
  undefined4 *lpWideCharStr;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  int iVar9;
  ulonglong uVar10;
  undefined4 auStack64 [2];
  wchar_t *local_38;
  ulonglong local_30;
  
  puVar7 = &stack0xffffffffffffff88;
  puVar6 = &stack0xffffffffffffff88;
  local_30 = DAT_1800170a0 ^ (ulonglong)&local_38;
  puVar5 = (undefined4 *)0x0;
  pcVar4 = param_4;
  iVar9 = param_5;
  if (0 < param_5) {
    do {
      iVar9 = iVar9 + -1;
      if (*pcVar4 == '\0') goto LAB_18000a10e;
      pcVar4 = pcVar4 + 1;
    } while (iVar9 != 0);
    iVar9 = -1;
LAB_18000a10e:
    iVar3 = (param_5 - iVar9) + -1;
    iVar9 = param_5 - iVar9;
    if (param_5 <= iVar3) {
      iVar9 = iVar3;
    }
  }
  if (param_8 == 0) {
    param_8 = *(UINT *)(*param_1 + 4);
  }
  local_38 = param_2;
  iVar3 = MultiByteToWideChar(param_8,(-(uint)(param_9 != 0) & 8) + 1,param_4,iVar9,(LPWSTR)0x0,0);
  uVar10 = SEXT48(iVar3);
  if (iVar3 == 0) goto LAB_18000a37a;
  puVar7 = &stack0xffffffffffffff88;
  if (((0 < iVar3) && (puVar7 = &stack0xffffffffffffff88, 1 < 0xffffffffffffffe0 / uVar10)) &&
     (puVar7 = &stack0xffffffffffffff88, uVar10 * 2 < uVar10 * 2 + 0x10)) {
    _Size = uVar10 * 2 + 0x10;
    if (_Size < 0x401) {
      uVar10 = uVar10 * 2 + 0x1f;
      if (uVar10 <= _Size) {
        uVar10 = 0xffffffffffffff0;
      }
      lVar1 = -(uVar10 & 0xfffffffffffffff0);
      puVar7 = &stack0xffffffffffffff80 + lVar1;
      puVar6 = &stack0xffffffffffffff80 + lVar1;
      puVar5 = (undefined4 *)((longlong)auStack64 + lVar1);
      if (puVar5 == (undefined4 *)0x0) goto LAB_18000a37a;
      *puVar5 = 0xcccc;
    }
    else {
      puVar5 = (undefined4 *)malloc(_Size);
      puVar7 = &stack0xffffffffffffff88;
      if (puVar5 == (undefined4 *)0x0) goto LAB_18000a1df;
      *puVar5 = 0xdddd;
    }
    puVar5 = puVar5 + 4;
    puVar7 = puVar6;
  }
LAB_18000a1df:
  if (puVar5 == (undefined4 *)0x0) goto LAB_18000a37a;
  *(int *)(puVar7 + 0x28) = iVar3;
  *(undefined4 **)(puVar7 + 0x20) = puVar5;
  *(undefined8 *)(puVar7 + -8) = 0x18000a206;
  iVar9 = MultiByteToWideChar(param_8,1,param_4,iVar9,*(LPWSTR *)(puVar7 + 0x20),
                              *(int *)(puVar7 + 0x28));
  pwVar2 = local_38;
  puVar8 = puVar7;
  if (iVar9 != 0) {
    *(undefined4 *)(puVar7 + 0x28) = 0;
    *(undefined8 *)(puVar7 + 0x20) = 0;
    *(undefined8 *)(puVar7 + -8) = 0x18000a22c;
    iVar9 = FUN_18000acd4(pwVar2,param_3,(LPCWSTR)puVar5,iVar3,*(LPWSTR *)(puVar7 + 0x20),
                          *(int *)(puVar7 + 0x28));
    uVar10 = SEXT48(iVar9);
    if (iVar9 != 0) {
      if ((param_3 & 0x400) == 0) {
        if (((iVar9 < 1) || (0xffffffffffffffe0 / uVar10 < 2)) || (uVar10 * 2 + 0x10 <= uVar10 * 2))
        {
          lpWideCharStr = (undefined4 *)0x0;
        }
        else {
          _Size_00 = uVar10 * 2 + 0x10;
          if (_Size_00 < 0x401) {
            uVar10 = uVar10 * 2 + 0x1f;
            if (uVar10 <= _Size_00) {
              uVar10 = 0xffffffffffffff0;
            }
            *(undefined8 *)(puVar7 + -8) = 0x18000a2c1;
            lVar1 = -(uVar10 & 0xfffffffffffffff0);
            puVar8 = puVar7 + lVar1 + -8;
            lpWideCharStr = (undefined4 *)(puVar7 + lVar1 + 0x38);
            if (lpWideCharStr == (undefined4 *)0x0) goto LAB_18000a367;
            *lpWideCharStr = 0xcccc;
            puVar7 = puVar7 + lVar1 + -8;
          }
          else {
            *(undefined8 *)(puVar7 + -8) = 0x18000a2df;
            lpWideCharStr = (undefined4 *)malloc(_Size_00);
            if (lpWideCharStr == (undefined4 *)0x0) goto LAB_18000a2f5;
            *lpWideCharStr = 0xdddd;
          }
          lpWideCharStr = lpWideCharStr + 4;
          puVar8 = puVar7;
        }
LAB_18000a2f5:
        if (lpWideCharStr != (undefined4 *)0x0) {
          *(int *)(puVar8 + 0x28) = iVar9;
          *(undefined4 **)(puVar8 + 0x20) = lpWideCharStr;
          *(undefined8 *)(puVar8 + -8) = 0x18000a314;
          iVar3 = FUN_18000acd4(pwVar2,param_3,(LPCWSTR)puVar5,iVar3,*(LPWSTR *)(puVar8 + 0x20),
                                *(int *)(puVar8 + 0x28));
          if (iVar3 != 0) {
            *(undefined8 *)(puVar8 + 0x38) = 0;
            *(undefined8 *)(puVar8 + 0x30) = 0;
            if (param_7 == 0) {
              *(undefined4 *)(puVar8 + 0x28) = 0;
              *(undefined8 *)(puVar8 + 0x20) = 0;
            }
            else {
              *(int *)(puVar8 + 0x28) = param_7;
              *(undefined8 *)(puVar8 + 0x20) = param_6;
            }
            *(undefined8 *)(puVar8 + -8) = 0x18000a354;
            WideCharToMultiByte(param_8,0,(LPCWSTR)lpWideCharStr,iVar9,*(LPSTR *)(puVar8 + 0x20),
                                *(int *)(puVar8 + 0x28),*(LPCSTR *)(puVar8 + 0x30),
                                *(LPBOOL *)(puVar8 + 0x38));
          }
          if (lpWideCharStr[-4] == 0xdddd) {
            *(undefined8 *)(puVar8 + -8) = 0x18000a367;
            free(lpWideCharStr + -4);
          }
        }
      }
      else {
        if ((param_7 != 0) && (iVar9 <= param_7)) {
          *(int *)(puVar7 + 0x28) = param_7;
          *(undefined8 *)(puVar7 + 0x20) = param_6;
          *(undefined8 *)(puVar7 + -8) = 0x18000a273;
          FUN_18000acd4(pwVar2,param_3,(LPCWSTR)puVar5,iVar3,*(LPWSTR *)(puVar7 + 0x20),
                        *(int *)(puVar7 + 0x28));
        }
      }
    }
  }
LAB_18000a367:
  puVar7 = puVar8;
  if (puVar5[-4] == 0xdddd) {
    *(undefined8 *)(puVar8 + -8) = 0x18000a378;
    free(puVar5 + -4);
  }
LAB_18000a37a:
  uVar10 = local_30 ^ (ulonglong)&local_38;
  *(undefined8 *)(puVar7 + -8) = 0x18000a386;
  FUN_180002f40(uVar10);
  return;
}



// Library Function - Single Match
//  __crtLCMapStringA
// 
// Library: Visual Studio 2012 Release

int __crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                     int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Plocinfo);
  iVar1 = FUN_18000a0b4(local_28,_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,
                        _Code_page,_BError);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Function: __chkstk replaced with injection: alloca_probe

void FUN_18000a438(longlong *param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,
                  UINT param_6,int param_7)

{
  ulonglong _Size;
  longlong lVar1;
  int iVar2;
  ulonglong uVar3;
  undefined (*lpSrcStr) [16];
  undefined *puVar4;
  undefined *puVar5;
  ulonglong uVar6;
  ulonglong local_38 [2];
  
  puVar5 = &stack0xffffffffffffff98;
  puVar4 = &stack0xffffffffffffff98;
  local_38[0] = DAT_1800170a0 ^ (ulonglong)local_38;
  lpSrcStr = (undefined (*) [16])0x0;
  if (param_6 == 0) {
    param_6 = *(UINT *)(*param_1 + 4);
  }
  iVar2 = MultiByteToWideChar(param_6,(-(uint)(param_7 != 0) & 8) + 1,param_3,param_4,(LPWSTR)0x0,0)
  ;
  uVar6 = SEXT48(iVar2);
  if (iVar2 == 0) goto LAB_18000a588;
  puVar5 = &stack0xffffffffffffff98;
  if (((0 < iVar2) && (puVar5 = &stack0xffffffffffffff98, uVar6 < 0x7ffffffffffffff1)) &&
     (puVar5 = &stack0xffffffffffffff98, uVar6 * 2 < uVar6 * 2 + 0x10)) {
    _Size = uVar6 * 2 + 0x10;
    if (_Size < 0x401) {
      uVar3 = uVar6 * 2 + 0x1f;
      if (uVar3 <= _Size) {
        uVar3 = 0xffffffffffffff0;
      }
      lVar1 = -(uVar3 & 0xfffffffffffffff0);
      puVar5 = &stack0xffffffffffffff90 + lVar1;
      puVar4 = &stack0xffffffffffffff90 + lVar1;
      lpSrcStr = (undefined (*) [16])(&stack0xffffffffffffffc0 + lVar1);
      if (lpSrcStr == (undefined (*) [16])0x0) goto LAB_18000a588;
      *(undefined4 *)*lpSrcStr = 0xcccc;
    }
    else {
      lpSrcStr = (undefined (*) [16])malloc(_Size);
      puVar5 = &stack0xffffffffffffff98;
      if (lpSrcStr == (undefined (*) [16])0x0) goto LAB_18000a526;
      *(undefined4 *)*lpSrcStr = 0xdddd;
    }
    lpSrcStr = lpSrcStr[1];
    puVar5 = puVar4;
  }
LAB_18000a526:
  if (lpSrcStr != (undefined (*) [16])0x0) {
    *(undefined8 *)(puVar5 + -8) = 0x18000a53f;
    FUN_180003c80(lpSrcStr,0,uVar6 * 2);
    *(int *)(puVar5 + 0x28) = iVar2;
    *(undefined (**) [16])(puVar5 + 0x20) = lpSrcStr;
    *(undefined8 *)(puVar5 + -8) = 0x18000a55c;
    iVar2 = MultiByteToWideChar(param_6,1,param_3,param_4,*(LPWSTR *)(puVar5 + 0x20),
                                *(int *)(puVar5 + 0x28));
    if (iVar2 != 0) {
      *(undefined8 *)(puVar5 + -8) = 0x18000a573;
      GetStringTypeW(param_2,(LPCWSTR)lpSrcStr,iVar2,param_5);
    }
    if (*(int *)lpSrcStr[-1] == 0xdddd) {
      *(undefined8 *)(puVar5 + -8) = 0x18000a586;
      free(lpSrcStr[-1]);
    }
  }
LAB_18000a588:
  uVar6 = local_38[0] ^ (ulonglong)local_38;
  *(undefined8 *)(puVar5 + -8) = 0x18000a594;
  FUN_180002f40(uVar6);
  return;
}



// Library Function - Single Match
//  __crtGetStringTypeA
// 
// Library: Visual Studio 2012 Release

BOOL __crtGetStringTypeA(_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,
                        LPWORD _LpCharType,int _Code_page,BOOL _BError)

{
  BOOL BVar1;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Plocinfo);
  BVar1 = FUN_18000a438(local_28,_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType,_Code_page,_BError);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return BVar1;
}



// Library Function - Single Match
//  _isctype_l
// 
// Library: Visual Studio 2012 Release

int _isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  BOOL BVar2;
  int _CchSrc;
  ushort local_res8 [4];
  CHAR local_res20;
  CHAR local_res21;
  undefined local_res22;
  localeinfo_struct local_38;
  longlong local_28;
  char local_20;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_38,(localeinfo_struct *)_Locale);
  if (_C + 1U < 0x101) {
    local_res8[0] = (local_38.locinfo)->pctype[_C];
  }
  else {
    iVar1 = _isleadbyte_l(_C >> 8 & 0xff,(_locale_t)&local_38);
    _CchSrc = 1;
    if (iVar1 == 0) {
      local_res21 = '\0';
      local_res20 = (CHAR)_C;
    }
    else {
      local_res22 = 0;
      _CchSrc = 2;
      local_res20 = (CHAR)((uint)_C >> 8);
      local_res21 = (CHAR)_C;
    }
    BVar2 = __crtGetStringTypeA((_locale_t)&local_38,1,&local_res20,_CchSrc,local_res8,
                                (local_38.locinfo)->lc_codepage,1);
    if (BVar2 == 0) {
      if (local_20 != '\0') {
        *(uint *)(local_28 + 200) = *(uint *)(local_28 + 200) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_20 != '\0') {
    *(uint *)(local_28 + 200) = *(uint *)(local_28 + 200) & 0xfffffffd;
  }
  return (int)((uint)local_res8[0] & _Type);
}



// Library Function - Single Match
//  _locterm
// 
// Library: Visual Studio 2012 Release

void _locterm(void)

{
  if (PTR_DAT_180017e70 != &DAT_180017e80) {
    _lock(0xc);
    PTR_DAT_180017e70 =
         (undefined *)_updatetlocinfoEx_nolock((int **)&PTR_DAT_180017e70,(int *)&DAT_180017e80);
    FUN_180008ad8(0xc);
  }
  return;
}



// Library Function - Single Match
//  wcscat_s
// 
// Library: Visual Studio 2012 Release

errno_t wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  errno_t *peVar2;
  wchar_t *pwVar3;
  errno_t eVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src == (wchar_t *)0x0) {
      *_Dst = L'\0';
    }
    else {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        pwVar3 = (wchar_t *)((longlong)pwVar3 - (longlong)_Src);
        do {
          wVar1 = *_Src;
          *(wchar_t *)((longlong)pwVar3 + (longlong)_Src) = wVar1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        peVar2 = _errno();
        eVar4 = 0x22;
        goto LAB_18000a785;
      }
      *_Dst = L'\0';
    }
  }
  peVar2 = _errno();
  eVar4 = 0x16;
LAB_18000a785:
  *peVar2 = eVar4;
  FUN_1800038fc();
  return eVar4;
}



longlong FUN_18000a7e4(short *param_1)

{
  short sVar1;
  short *psVar2;
  
  psVar2 = param_1;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  return ((longlong)((longlong)psVar2 - (longlong)param_1) >> 1) + -1;
}



// Library Function - Single Match
//  wcsncpy_s
// 
// Library: Visual Studio 2012 Release

errno_t wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  errno_t *peVar2;
  errno_t eVar3;
  rsize_t rVar4;
  wchar_t *pwVar5;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords == 0) {
        return 0;
      }
    }
    else {
LAB_18000a820:
      if (_SizeInWords != 0) {
        if (_MaxCount == 0) {
          *_Dst = L'\0';
          return 0;
        }
        if (_Src != (wchar_t *)0x0) {
          rVar4 = _SizeInWords;
          if (_MaxCount == 0xffffffffffffffff) {
            pwVar5 = (wchar_t *)((longlong)_Dst - (longlong)_Src);
            do {
              wVar1 = *_Src;
              *(wchar_t *)((longlong)pwVar5 + (longlong)_Src) = wVar1;
              _Src = _Src + 1;
              if (wVar1 == L'\0') break;
              rVar4 = rVar4 - 1;
            } while (rVar4 != 0);
          }
          else {
            pwVar5 = _Dst;
            do {
              wVar1 = *(wchar_t *)((longlong)((longlong)_Src - (longlong)_Dst) + (longlong)pwVar5);
              *pwVar5 = wVar1;
              pwVar5 = pwVar5 + 1;
              if ((wVar1 == L'\0') || (rVar4 = rVar4 - 1, rVar4 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pwVar5 = L'\0';
            }
          }
          if (rVar4 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffffffffffff) {
            _Dst[_SizeInWords - 1] = L'\0';
            return 0x50;
          }
          *_Dst = L'\0';
          peVar2 = _errno();
          eVar3 = 0x22;
          goto LAB_18000a841;
        }
        *_Dst = L'\0';
      }
    }
  }
  else {
    if (_Dst != (wchar_t *)0x0) goto LAB_18000a820;
  }
  peVar2 = _errno();
  eVar3 = 0x16;
LAB_18000a841:
  *peVar2 = eVar3;
  FUN_1800038fc();
  return eVar3;
}



// Library Function - Single Match
//  _set_error_mode
// 
// Library: Visual Studio 2012 Release

int _set_error_mode(int _Mode)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  if ((_Mode < 0) ||
     ((iVar2 = DAT_18001df5c, iVar1 = _Mode, 2 < _Mode && (iVar1 = DAT_18001df5c, _Mode != 3)))) {
    piVar3 = _errno();
    *piVar3 = 0x16;
    FUN_1800038fc();
    iVar2 = -1;
    iVar1 = DAT_18001df5c;
  }
  DAT_18001df5c = iVar1;
  return iVar2;
}



void FUN_18000a90c(LPCWSTR param_1,undefined8 param_2,uint param_3)

{
  bool bVar1;
  DWORD DVar2;
  BOOL BVar3;
  int iVar4;
  PVOID pvVar5;
  undefined7 extraout_var;
  HMODULE hModule;
  FARPROC pFVar6;
  code *pcVar7;
  code *pcVar8;
  longlong lVar9;
  longlong lVar10;
  undefined auStack136 [32];
  undefined *local_68;
  undefined local_58 [8];
  undefined local_50 [8];
  byte local_48;
  ulonglong local_40;
  
  local_40 = DAT_1800170a0 ^ (ulonglong)auStack136;
  pvVar5 = EncodePointer((PVOID)0x0);
  lVar10 = 0;
  bVar1 = FUN_180006260();
  iVar4 = (int)CONCAT71(extraout_var,bVar1);
  if (DAT_18001df60 == (PVOID)0x0) {
    hModule = LoadLibraryExW(L"USER32.DLL",(HANDLE)0x0,0x800);
    if (((hModule == (HMODULE)0x0) &&
        ((DVar2 = GetLastError(), DVar2 != 0x57 ||
         (hModule = LoadLibraryExW(L"USER32.DLL",(HANDLE)0x0,0), hModule == (HMODULE)0x0)))) ||
       (pFVar6 = GetProcAddress(hModule,"MessageBoxW"), pFVar6 == (FARPROC)0x0)) goto LAB_18000ab63;
    DAT_18001df60 = EncodePointer(pFVar6);
    pFVar6 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_18001df68 = EncodePointer(pFVar6);
    pFVar6 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_18001df70 = EncodePointer(pFVar6);
    pFVar6 = GetProcAddress(hModule,"GetUserObjectInformationW");
    DAT_18001df80 = EncodePointer(pFVar6);
    if (DAT_18001df80 != (PVOID)0x0) {
      pFVar6 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_18001df78 = EncodePointer(pFVar6);
    }
  }
  BVar3 = IsDebuggerPresent();
  if (BVar3 == 0) {
    if (iVar4 != 0) {
      DecodePointer(DAT_18001df60);
      goto LAB_18000ab63;
    }
  }
  else {
    if (param_1 != (LPCWSTR)0x0) {
      OutputDebugStringW(param_1);
    }
    if (iVar4 != 0) goto LAB_18000ab63;
  }
  if ((DAT_18001df78 == pvVar5) || (DAT_18001df80 == pvVar5)) {
LAB_18000aaff:
    if (((DAT_18001df68 != pvVar5) &&
        (((pcVar7 = (code *)DecodePointer(DAT_18001df68), pcVar7 != (code *)0x0 &&
          (lVar10 = (*pcVar7)(), lVar10 != 0)) && (DAT_18001df70 != pvVar5)))) &&
       (pcVar7 = (code *)DecodePointer(DAT_18001df70), pcVar7 != (code *)0x0)) {
      lVar10 = (*pcVar7)(lVar10);
    }
  }
  else {
    pcVar7 = (code *)DecodePointer(DAT_18001df78);
    pcVar8 = (code *)DecodePointer(DAT_18001df80);
    if ((pcVar7 == (code *)0x0) || (pcVar8 == (code *)0x0)) goto LAB_18000aaff;
    lVar9 = (*pcVar7)();
    if (lVar9 != 0) {
      local_68 = local_58;
      iVar4 = (*pcVar8)(lVar9,1,local_50);
      if ((iVar4 != 0) && ((local_48 & 1) != 0)) goto LAB_18000aaff;
    }
    param_3 = param_3 | 0x200000;
  }
  pcVar7 = (code *)DecodePointer(DAT_18001df60);
  if (pcVar7 != (code *)0x0) {
    (*pcVar7)(lVar10,param_1,param_2,param_3);
  }
LAB_18000ab63:
  FUN_180002f40(local_40 ^ (ulonglong)auStack136);
  return;
}



// Library Function - Single Match
//  _msize
// 
// Library: Visual Studio 2012 Release

size_t _msize(void *_Memory)

{
  int *piVar1;
  size_t sVar2;
  
  if (_Memory == (void *)0x0) {
    piVar1 = _errno();
    *piVar1 = 0x16;
    FUN_1800038fc();
    return 0xffffffffffffffff;
  }
                    // WARNING: Could not recover jumptable at 0x00018000abb2. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar2 = HeapSize(DAT_18001d340,0,_Memory);
  return sVar2;
}



// Library Function - Single Match
//  abort
// 
// Library: Visual Studio 2012 Release

void abort(void)

{
  code *pcVar1;
  BOOL BVar2;
  longlong lVar3;
  undefined *puVar4;
  undefined auStack40 [8];
  undefined auStack32 [32];
  
  puVar4 = auStack40;
  lVar3 = FUN_18000909c();
  if (lVar3 != 0) {
    FUN_1800090cc(0x16);
  }
  if ((DAT_180018330 & 2) != 0) {
    BVar2 = IsProcessorFeaturePresent(0x17);
    puVar4 = auStack40;
    if (BVar2 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
      puVar4 = auStack32;
    }
    *(undefined8 *)(puVar4 + -8) = 0x18000ac06;
    _call_reportfault(3,0x40000015,1);
  }
  *(undefined8 *)(puVar4 + -8) = 0x18000ac10;
  FUN_18000549c(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined4 FUN_18000ac14(wchar_t *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar3 = 0xe3;
  do {
    iVar1 = (iVar3 + iVar4) / 2;
    iVar2 = _wcsnicmp(param_1,(wchar_t *)(&PTR_DAT_180012e80)[(longlong)iVar1 * 2],0x55);
    if (iVar2 == 0) {
      return *(undefined4 *)(&UNK_180012e88 + (longlong)iVar1 * 0x10);
    }
    if (iVar2 < 0) {
      iVar3 = iVar1 + -1;
    }
    else {
      iVar4 = iVar1 + 1;
    }
  } while (iVar4 <= iVar3);
  return 0xffffffff;
}



undefined4 FUN_18000aca0(wchar_t *param_1)

{
  int iVar1;
  
  if (((param_1 != (wchar_t *)0x0) && (iVar1 = FUN_18000ac14(param_1), -1 < iVar1)) &&
     ((ulonglong)(longlong)iVar1 < 0xe4)) {
    return *(undefined4 *)(&DAT_180012040 + (longlong)iVar1 * 0x10);
  }
  return 0;
}



void FUN_18000acd4(wchar_t *param_1,DWORD param_2,LPCWSTR param_3,int param_4,LPWSTR param_5,
                  int param_6)

{
  LCID Locale;
  
  if ((code *)(DAT_18001f0c0 ^ DAT_1800170a0) == (code *)0x0) {
    Locale = FUN_18000aca0(param_1);
    LCMapStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  }
  else {
    (*(code *)(DAT_18001f0c0 ^ DAT_1800170a0))();
  }
  return;
}



// Library Function - Single Match
//  _wcsnicmp
// 
// Library: Visual Studio 2019 Release

int _wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  wchar_t *pwVar4;
  
  iVar3 = 0;
  if (_MaxCount != 0) {
    pwVar4 = (wchar_t *)((longlong)_Str1 - (longlong)_Str2);
    do {
      uVar1 = *(ushort *)((longlong)pwVar4 + (longlong)_Str2);
      if ((ushort)(uVar1 - 0x41) < 0x1a) {
        uVar1 = uVar1 + 0x20;
      }
      uVar2 = *_Str2;
      if ((ushort)(uVar2 - 0x41) < 0x1a) {
        uVar2 = uVar2 + 0x20;
      }
      _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
      _MaxCount = _MaxCount - 1;
    } while (((_MaxCount != 0) && (uVar1 != 0)) && (uVar1 == uVar2));
    iVar3 = (uint)uVar1 - (uint)uVar2;
  }
  return iVar3;
}



// Library Function - Single Match
//  _fclose_nolock
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

int _fclose_nolock(FILE *_File)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  ulonglong uVar4;
  
  iVar1 = -1;
  if (_File == (FILE *)0x0) {
    piVar3 = _errno();
    *piVar3 = 0x16;
    FUN_1800038fc();
    iVar1 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar1 = _flush(_File);
      _freebuf(_File);
      uVar2 = _fileno(_File);
      uVar4 = FUN_18000b0b8(uVar2);
      if ((int)uVar4 < 0) {
        iVar1 = -1;
      }
      else {
        if (_File->_tmpfname != (char *)0x0) {
          free(_File->_tmpfname);
          _File->_tmpfname = (char *)0x0;
        }
      }
    }
    _File->_flag = 0;
  }
  return iVar1;
}



// Library Function - Single Match
//  fclose
// 
// Library: Visual Studio 2012 Release

int fclose(FILE *_File)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = -1;
  if (_File == (FILE *)0x0) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    FUN_1800038fc();
    iVar1 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      _lock_file(_File);
      iVar1 = _fclose_nolock(_File);
      _unlock_file(_File);
    }
    else {
      _File->_flag = 0;
    }
  }
  return iVar1;
}



DWORD FUN_18000aea0(uint param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  int *piVar3;
  HANDLE hFile;
  ulong *puVar4;
  longlong lVar5;
  
  if (param_1 == 0xfffffffe) {
    piVar3 = _errno();
    *piVar3 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
      lVar5 = (ulonglong)(param_1 & 0x1f) * 0x58;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                    + lVar5) & 1) != 0) {
        FUN_1800098a0(param_1);
        if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) +
                       8 + lVar5) & 1) != 0) {
          hFile = (HANDLE)FUN_1800099e4(param_1);
          BVar1 = FlushFileBuffers(hFile);
          if (BVar1 == 0) {
            DVar2 = GetLastError();
          }
          else {
            DVar2 = 0;
          }
          if (DVar2 == 0) goto LAB_18000af4b;
          puVar4 = __doserrno();
          *puVar4 = DVar2;
        }
        piVar3 = _errno();
        *piVar3 = 9;
        DVar2 = 0xffffffff;
LAB_18000af4b:
        FUN_180009a58(param_1);
        return DVar2;
      }
    }
    piVar3 = _errno();
    *piVar3 = 9;
    FUN_1800038fc();
  }
  return 0xffffffff;
}



// Library Function - Single Match
//  __initconout
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __initconout(void)

{
  DAT_180018338 = CreateFileW(L"CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



ulonglong FUN_18000b0b8(uint param_1)

{
  ulong *puVar1;
  int *piVar2;
  ulonglong uVar3;
  longlong lVar4;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_18001f0e8)) {
      lVar4 = (ulonglong)(param_1 & 0x1f) * 0x58;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8
                    + lVar4) & 1) != 0) {
        FUN_1800098a0(param_1);
        if ((*(byte *)(*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) +
                       8 + lVar4) & 1) == 0) {
          piVar2 = _errno();
          *piVar2 = 9;
          uVar3 = 0xffffffff;
        }
        else {
          uVar3 = FUN_18000b17c(param_1);
          uVar3 = uVar3 & 0xffffffff;
        }
        FUN_180009a58(param_1);
        return uVar3;
      }
    }
    puVar1 = __doserrno();
    *puVar1 = 0;
    piVar2 = _errno();
    *piVar2 = 9;
    FUN_1800038fc();
  }
  return 0xffffffff;
}



undefined8 FUN_18000b17c(uint param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  longlong lVar3;
  longlong lVar4;
  HANDLE hObject;
  undefined8 uVar5;
  
  lVar3 = FUN_1800099e4(param_1);
  if (lVar3 != -1) {
    if (((param_1 == 1) && ((*(byte *)(DAT_18001d350 + 0xb8) & 1) != 0)) ||
       ((param_1 == 2 && ((*(byte *)(DAT_18001d350 + 0x60) & 1) != 0)))) {
      lVar3 = FUN_1800099e4(2);
      lVar4 = FUN_1800099e4(1);
      if (lVar4 == lVar3) goto LAB_18000b1ef;
    }
    hObject = (HANDLE)FUN_1800099e4(param_1);
    BVar1 = CloseHandle(hObject);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      goto LAB_18000b1f1;
    }
  }
LAB_18000b1ef:
  DVar2 = 0;
LAB_18000b1f1:
  FUN_180009938(param_1);
  *(undefined *)
   (*(longlong *)((longlong)&DAT_18001d350 + ((longlong)(int)param_1 >> 5) * 8) + 8 +
   (ulonglong)(param_1 & 0x1f) * 0x58) = 0;
  if (DVar2 == 0) {
    uVar5 = 0;
  }
  else {
    _dosmaperr(DVar2);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// Library Function - Single Match
//  _freebuf
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void _freebuf(FILE *_File)

{
  if (((*(byte *)&_File->_flag & 0x83) != 0) && ((*(byte *)&_File->_flag & 8) != 0)) {
    free(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  _atodbl_l
//  _atoflt_l
// 
// Library: Visual Studio 2012 Release

int FID_conflict__atoflt_l(_CRT_FLOAT *_Result,char *_Str,_locale_t _Locale)

{
  int iVar1;
  longlong local_48 [2];
  longlong local_38;
  char local_30;
  byte *local_28;
  ushort local_20 [8];
  ulonglong local_10;
  
  local_10 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff78;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_48,(localeinfo_struct *)_Locale);
  FUN_18000c010(local_20,&local_28,(byte *)_Str,0,0,0,0,local_48);
  FUN_18000b4a0(local_20,(uint *)_Result);
  if (local_30 != '\0') {
    *(uint *)(local_38 + 200) = *(uint *)(local_38 + 200) & 0xfffffffd;
  }
  iVar1 = FUN_180002f40(local_10 ^ (ulonglong)&stack0xffffffffffffff78);
  return iVar1;
}



// WARNING: Removing unreachable block (ram,0x00018000b2d5)

void FUN_18000b408(uint *param_1,byte *param_2,localeinfo_struct *param_3)

{
  byte *local_58;
  longlong local_50 [2];
  longlong local_40;
  char local_38;
  ushort local_30 [8];
  ulonglong local_20;
  
  local_20 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff68;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_50,param_3);
  FUN_18000c010(local_30,&local_58,param_2,0,0,0,0,local_50);
  FUN_18000ba58(local_30,param_1);
  if (local_38 != '\0') {
    *(uint *)(local_40 + 200) = *(uint *)(local_40 + 200) & 0xfffffffd;
  }
  FUN_180002f40(local_20 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



void thunk_FUN_18000b418(void)

{
  PTR_LAB_180017fe0 = _cfltcvt;
  PTR_LAB_180017fe8 = &LAB_18000d328;
  PTR_LAB_180017ff0 = &DAT_18000d3c8;
  PTR_LAB_180017ff8 = &LAB_18000d410;
  PTR_LAB_180018000 = &LAB_18000d498;
  PTR_LAB_180018008 = _cfltcvt;
  PTR_LAB_180018010 = _cfltcvt_l;
  PTR_LAB_180018018 = &LAB_18000d3d0;
  PTR_LAB_180018020 = _cropzeros_l;
  PTR_LAB_180018028 = _forcdecpt_l;
  return;
}



void FUN_18000b418(void)

{
  PTR_LAB_180017fe0 = _cfltcvt;
  PTR_LAB_180017fe8 = &LAB_18000d328;
  PTR_LAB_180017ff0 = &DAT_18000d3c8;
  PTR_LAB_180017ff8 = &LAB_18000d410;
  PTR_LAB_180018000 = &LAB_18000d498;
  PTR_LAB_180018008 = _cfltcvt;
  PTR_LAB_180018010 = _cfltcvt_l;
  PTR_LAB_180018018 = &LAB_18000d3d0;
  PTR_LAB_180018020 = _cropzeros_l;
  PTR_LAB_180018028 = _forcdecpt_l;
  return;
}



void FUN_18000b4a0(ushort *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  ulonglong uVar3;
  byte bVar4;
  longlong lVar5;
  ulonglong uVar6;
  uint uVar7;
  uint uVar8;
  ulonglong uVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  undefined8 *puVar13;
  int iVar14;
  int iVar15;
  longlong lVar16;
  longlong lVar17;
  longlong lVar18;
  bool bVar19;
  undefined auStack136 [32];
  int local_68;
  uint local_64;
  int local_60;
  uint *local_58;
  int local_50;
  uint local_4c;
  ulonglong local_48;
  undefined8 local_40;
  int local_38;
  ulonglong local_30;
  
  local_30 = DAT_1800170a0 ^ (ulonglong)auStack136;
  uVar3 = 0;
  local_64 = param_1[5] & 0x8000;
  local_50 = (uint)*param_1 << 0x10;
  uVar10 = param_1[5] & 0x7fff;
  iVar11 = uVar10 - 0x3fff;
  local_40 = CONCAT44(*(undefined4 *)(param_1 + 1),*(undefined4 *)(param_1 + 3));
  local_38 = local_50;
  uVar9 = 1;
  lVar17 = 3;
  iVar2 = 0;
  local_58 = param_2;
  if (iVar11 == -0x3fff) {
    do {
      if (*(int *)((longlong)&local_40 + uVar3 * 4) != 0) {
        local_40 = 0;
        local_38 = 0;
        iVar2 = 0;
        break;
      }
      uVar3 = uVar3 + 1;
    } while ((longlong)uVar3 < 3);
  }
  else {
    local_48 = local_40;
    local_60 = DAT_180018360 + -1;
    uVar7 = DAT_180018360 >> 0x1f & 0x1f;
    uVar1 = DAT_180018360 + uVar7;
    iVar14 = (int)uVar1 >> 5;
    local_4c = 0x1f - ((uVar1 & 0x1f) - uVar7);
    iVar15 = 0;
    if ((*(uint *)((longlong)&local_40 + (longlong)iVar14 * 4) >> (local_4c & 0x1f) & 1) != 0) {
      if ((*(uint *)((longlong)&local_40 + (longlong)iVar14 * 4) & ~(-1 << ((byte)local_4c & 0x1f)))
          == 0) {
        for (lVar5 = (longlong)(iVar14 + 1); iVar15 = iVar2, lVar5 < 3; lVar5 = lVar5 + 1) {
          if (*(int *)((longlong)&local_40 + lVar5 * 4) != 0) goto LAB_18000b5c1;
        }
      }
      else {
LAB_18000b5c1:
        uVar1 = local_60 >> 0x1f & 0x1f;
        iVar2 = local_60 + uVar1;
        iVar12 = iVar2 >> 5;
        uVar7 = *(uint *)((longlong)&local_40 + (longlong)iVar12 * 4);
        uVar8 = 1 << (0x1f - (((byte)iVar2 & 0x1f) - (char)uVar1) & 0x1f);
        uVar1 = uVar7 + uVar8;
        if ((uVar1 < uVar7) || (uVar6 = uVar3, uVar1 < uVar8)) {
          uVar6 = 1;
        }
        *(uint *)((longlong)&local_40 + (longlong)iVar12 * 4) = uVar1;
        lVar5 = (longlong)(iVar12 + -1);
        iVar15 = (int)uVar6;
        if (-1 < iVar12 + -1) {
          do {
            iVar15 = (int)uVar6;
            if ((int)uVar6 == 0) break;
            uVar7 = *(uint *)((longlong)&local_40 + lVar5 * 4);
            uVar1 = uVar7 + 1;
            if ((uVar1 < uVar7) || (uVar6 = uVar3, uVar1 == 0)) {
              uVar6 = uVar9;
            }
            *(uint *)((longlong)&local_40 + lVar5 * 4) = uVar1;
            lVar5 = lVar5 + -1;
            iVar15 = (int)uVar6;
          } while (-1 < lVar5);
        }
      }
    }
    puVar13 = (undefined8 *)((longlong)&local_40 + (longlong)iVar14 * 4);
    *(uint *)puVar13 = *(uint *)puVar13 & -1 << ((byte)local_4c & 0x1f);
    lVar5 = (longlong)(iVar14 + 1);
    local_68 = iVar11;
    if (lVar5 < 3) {
      FUN_180003c80((undefined (*) [16])((longlong)&local_40 + lVar5 * 4),0,(3 - lVar5) * 4);
    }
    if (iVar15 != 0) {
      iVar11 = uVar10 - 0x3ffe;
    }
    if (iVar11 < DAT_18001835c - DAT_180018360) {
      local_40 = 0;
      local_38 = 0;
      iVar2 = 0;
    }
    else {
      if (DAT_18001835c < iVar11) {
        uVar10 = DAT_180018364 >> 0x1f & 0x1f;
        iVar15 = DAT_180018364 + uVar10;
        bVar4 = ((byte)iVar15 & 0x1f) - (char)uVar10;
        iVar15 = iVar15 >> 5;
        uVar10 = ~(-1 << (bVar4 & 0x1f));
        if (iVar11 < DAT_180018358) {
          local_40 = local_40 & 0xffffffff7fffffff;
          iVar2 = DAT_18001836c + iVar11;
          puVar13 = &local_40;
          do {
            uVar1 = *(uint *)puVar13;
            *(uint *)puVar13 = uVar1 >> (bVar4 & 0x1f) | (uint)uVar3;
            puVar13 = (undefined8 *)((longlong)puVar13 + 4);
            uVar3 = (ulonglong)((uVar1 & uVar10) << (0x20 - bVar4 & 0x1f));
            lVar17 = lVar17 + -1;
          } while (lVar17 != 0);
          lVar17 = 2;
          do {
            if (lVar17 < iVar15) {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
            }
            else {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                   *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + (longlong)iVar15 * -4);
            }
            lVar17 = lVar17 + -1;
          } while (-1 < lVar17);
        }
        else {
          local_40 = 0x80000000;
          local_38 = 0;
          puVar13 = &local_40;
          do {
            uVar1 = (uint)uVar3;
            uVar3 = (ulonglong)((uVar10 & *(uint *)puVar13) << (0x20 - bVar4 & 0x1f));
            *(uint *)puVar13 = *(uint *)puVar13 >> (bVar4 & 0x1f) | uVar1;
            puVar13 = (undefined8 *)((longlong)puVar13 + 4);
            lVar17 = lVar17 + -1;
          } while (lVar17 != 0);
          lVar17 = 2;
          do {
            if (lVar17 < iVar15) {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
            }
            else {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                   *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + (longlong)iVar15 * -4);
            }
            lVar17 = lVar17 + -1;
          } while (-1 < lVar17);
          iVar2 = DAT_18001836c + DAT_180018358;
        }
      }
      else {
        local_40 = local_48;
        local_38 = local_50;
        uVar10 = DAT_18001835c - local_68 >> 0x1f & 0x1f;
        puVar13 = &local_40;
        iVar2 = (DAT_18001835c - local_68) + uVar10;
        bVar4 = ((byte)iVar2 & 0x1f) - (char)uVar10;
        uVar6 = uVar3;
        do {
          uVar10 = *(uint *)puVar13;
          *(uint *)puVar13 = uVar10 >> (bVar4 & 0x1f) | (uint)uVar6;
          puVar13 = (undefined8 *)((longlong)puVar13 + 4);
          uVar6 = (ulonglong)((uVar10 & ~(-1 << (bVar4 & 0x1f))) << (0x20 - bVar4 & 0x1f));
          lVar17 = lVar17 + -1;
        } while (lVar17 != 0);
        lVar16 = (longlong)(iVar2 >> 5);
        lVar17 = 2;
        lVar18 = 3;
        lVar5 = 2;
        do {
          if (lVar5 < lVar16) {
            *(undefined4 *)((longlong)&local_40 + lVar5 * 4) = 0;
          }
          else {
            *(undefined4 *)((longlong)&local_40 + lVar5 * 4) =
                 *(undefined4 *)((longlong)&local_40 + lVar5 * 4 + lVar16 * -4);
          }
          lVar5 = lVar5 + -1;
        } while (-1 < lVar5);
        uVar1 = local_60 + 1 >> 0x1f & 0x1f;
        uVar10 = local_60 + 1 + uVar1;
        iVar2 = (int)uVar10 >> 5;
        uVar10 = 0x1f - ((uVar10 & 0x1f) - uVar1);
        bVar4 = (byte)uVar10;
        if ((*(uint *)((longlong)&local_40 + (longlong)iVar2 * 4) >> (uVar10 & 0x1f) & 1) != 0) {
          if ((*(uint *)((longlong)&local_40 + (longlong)iVar2 * 4) & ~(-1 << (bVar4 & 0x1f))) == 0)
          {
            for (lVar5 = (longlong)(iVar2 + 1); lVar5 < 3; lVar5 = lVar5 + 1) {
              if (*(int *)((longlong)&local_40 + lVar5 * 4) != 0) goto LAB_18000b79b;
            }
          }
          else {
LAB_18000b79b:
            uVar10 = local_60 >> 0x1f & 0x1f;
            iVar11 = local_60 + uVar10;
            iVar15 = iVar11 >> 5;
            uVar1 = *(uint *)((longlong)&local_40 + (longlong)iVar15 * 4);
            uVar7 = 1 << (0x1f - (((byte)iVar11 & 0x1f) - (char)uVar10) & 0x1f);
            uVar10 = uVar1 + uVar7;
            if ((uVar10 < uVar1) || (uVar6 = uVar3, uVar10 < uVar7)) {
              uVar6 = uVar9;
            }
            *(uint *)((longlong)&local_40 + (longlong)iVar15 * 4) = uVar10;
            lVar5 = (longlong)(iVar15 + -1);
            if (-1 < iVar15 + -1) {
              do {
                if ((int)uVar6 == 0) break;
                uVar1 = *(uint *)((longlong)&local_40 + lVar5 * 4);
                uVar10 = uVar1 + 1;
                if ((uVar10 < uVar1) || (uVar6 = uVar3, uVar10 == 0)) {
                  uVar6 = uVar9;
                }
                *(uint *)((longlong)&local_40 + lVar5 * 4) = uVar10;
                lVar5 = lVar5 + -1;
              } while (-1 < lVar5);
            }
          }
        }
        puVar13 = (undefined8 *)((longlong)&local_40 + (longlong)iVar2 * 4);
        *(uint *)puVar13 = *(uint *)puVar13 & -1 << (bVar4 & 0x1f);
        lVar5 = (longlong)(iVar2 + 1);
        if (lVar5 < 3) {
          FUN_180003c80((undefined (*) [16])((longlong)&local_40 + lVar5 * 4),0,(3 - lVar5) * 4);
        }
        puVar13 = &local_40;
        uVar10 = DAT_180018364 + 1 >> 0x1f & 0x1f;
        iVar2 = DAT_180018364 + 1 + uVar10;
        bVar4 = ((byte)iVar2 & 0x1f) - (char)uVar10;
        do {
          uVar10 = *(uint *)puVar13;
          *(uint *)puVar13 = uVar10 >> (bVar4 & 0x1f) | (uint)uVar3;
          puVar13 = (undefined8 *)((longlong)puVar13 + 4);
          uVar3 = (ulonglong)((uVar10 & ~(-1 << (bVar4 & 0x1f))) << (0x20 - bVar4 & 0x1f));
          lVar18 = lVar18 + -1;
        } while (lVar18 != 0);
        lVar5 = (longlong)(iVar2 >> 5);
        do {
          if (lVar17 < lVar5) {
            *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
          }
          else {
            *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                 *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + lVar5 * -4);
          }
          lVar17 = lVar17 + -1;
        } while (-1 < lVar17);
        iVar2 = 0;
      }
    }
  }
  bVar19 = local_64 != 0;
  local_64 = -local_64;
  local_40._0_4_ =
       iVar2 << (0x1fU - (char)DAT_180018364 & 0x1f) | -(uint)bVar19 & 0x80000000 | (uint)local_40;
  if (DAT_180018368 == 0x40) {
    local_58[1] = (uint)local_40;
    *local_58 = local_40._4_4_;
  }
  else {
    if (DAT_180018368 == 0x20) {
      *local_58 = (uint)local_40;
    }
  }
  FUN_180002f40(local_30 ^ (ulonglong)auStack136);
  return;
}



void FUN_18000ba58(ushort *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  ulonglong uVar3;
  byte bVar4;
  longlong lVar5;
  ulonglong uVar6;
  uint uVar7;
  uint uVar8;
  ulonglong uVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  undefined8 *puVar13;
  int iVar14;
  int iVar15;
  longlong lVar16;
  longlong lVar17;
  longlong lVar18;
  bool bVar19;
  undefined auStack136 [32];
  int local_68;
  uint local_64;
  int local_60;
  uint *local_58;
  int local_50;
  uint local_4c;
  ulonglong local_48;
  undefined8 local_40;
  int local_38;
  ulonglong local_30;
  
  local_30 = DAT_1800170a0 ^ (ulonglong)auStack136;
  uVar3 = 0;
  local_64 = param_1[5] & 0x8000;
  local_50 = (uint)*param_1 << 0x10;
  uVar10 = param_1[5] & 0x7fff;
  iVar11 = uVar10 - 0x3fff;
  local_40 = CONCAT44(*(undefined4 *)(param_1 + 1),*(undefined4 *)(param_1 + 3));
  local_38 = local_50;
  uVar9 = 1;
  lVar17 = 3;
  iVar2 = 0;
  local_58 = param_2;
  if (iVar11 == -0x3fff) {
    do {
      if (*(int *)((longlong)&local_40 + uVar3 * 4) != 0) {
        local_40 = 0;
        local_38 = 0;
        iVar2 = 0;
        break;
      }
      uVar3 = uVar3 + 1;
    } while ((longlong)uVar3 < 3);
  }
  else {
    local_48 = local_40;
    local_60 = DAT_180018378 + -1;
    uVar7 = DAT_180018378 >> 0x1f & 0x1f;
    uVar1 = DAT_180018378 + uVar7;
    iVar14 = (int)uVar1 >> 5;
    local_4c = 0x1f - ((uVar1 & 0x1f) - uVar7);
    iVar15 = 0;
    if ((*(uint *)((longlong)&local_40 + (longlong)iVar14 * 4) >> (local_4c & 0x1f) & 1) != 0) {
      if ((*(uint *)((longlong)&local_40 + (longlong)iVar14 * 4) & ~(-1 << ((byte)local_4c & 0x1f)))
          == 0) {
        for (lVar5 = (longlong)(iVar14 + 1); iVar15 = iVar2, lVar5 < 3; lVar5 = lVar5 + 1) {
          if (*(int *)((longlong)&local_40 + lVar5 * 4) != 0) goto LAB_18000bb79;
        }
      }
      else {
LAB_18000bb79:
        uVar1 = local_60 >> 0x1f & 0x1f;
        iVar2 = local_60 + uVar1;
        iVar12 = iVar2 >> 5;
        uVar7 = *(uint *)((longlong)&local_40 + (longlong)iVar12 * 4);
        uVar8 = 1 << (0x1f - (((byte)iVar2 & 0x1f) - (char)uVar1) & 0x1f);
        uVar1 = uVar7 + uVar8;
        if ((uVar1 < uVar7) || (uVar6 = uVar3, uVar1 < uVar8)) {
          uVar6 = 1;
        }
        *(uint *)((longlong)&local_40 + (longlong)iVar12 * 4) = uVar1;
        lVar5 = (longlong)(iVar12 + -1);
        iVar15 = (int)uVar6;
        if (-1 < iVar12 + -1) {
          do {
            iVar15 = (int)uVar6;
            if ((int)uVar6 == 0) break;
            uVar7 = *(uint *)((longlong)&local_40 + lVar5 * 4);
            uVar1 = uVar7 + 1;
            if ((uVar1 < uVar7) || (uVar6 = uVar3, uVar1 == 0)) {
              uVar6 = uVar9;
            }
            *(uint *)((longlong)&local_40 + lVar5 * 4) = uVar1;
            lVar5 = lVar5 + -1;
            iVar15 = (int)uVar6;
          } while (-1 < lVar5);
        }
      }
    }
    puVar13 = (undefined8 *)((longlong)&local_40 + (longlong)iVar14 * 4);
    *(uint *)puVar13 = *(uint *)puVar13 & -1 << ((byte)local_4c & 0x1f);
    lVar5 = (longlong)(iVar14 + 1);
    local_68 = iVar11;
    if (lVar5 < 3) {
      FUN_180003c80((undefined (*) [16])((longlong)&local_40 + lVar5 * 4),0,(3 - lVar5) * 4);
    }
    if (iVar15 != 0) {
      iVar11 = uVar10 - 0x3ffe;
    }
    if (iVar11 < DAT_180018374 - DAT_180018378) {
      local_40 = 0;
      local_38 = 0;
      iVar2 = 0;
    }
    else {
      if (DAT_180018374 < iVar11) {
        uVar10 = DAT_18001837c >> 0x1f & 0x1f;
        iVar15 = DAT_18001837c + uVar10;
        bVar4 = ((byte)iVar15 & 0x1f) - (char)uVar10;
        iVar15 = iVar15 >> 5;
        uVar10 = ~(-1 << (bVar4 & 0x1f));
        if (iVar11 < DAT_180018370) {
          local_40 = local_40 & 0xffffffff7fffffff;
          iVar2 = DAT_180018384 + iVar11;
          puVar13 = &local_40;
          do {
            uVar1 = *(uint *)puVar13;
            *(uint *)puVar13 = uVar1 >> (bVar4 & 0x1f) | (uint)uVar3;
            puVar13 = (undefined8 *)((longlong)puVar13 + 4);
            uVar3 = (ulonglong)((uVar1 & uVar10) << (0x20 - bVar4 & 0x1f));
            lVar17 = lVar17 + -1;
          } while (lVar17 != 0);
          lVar17 = 2;
          do {
            if (lVar17 < iVar15) {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
            }
            else {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                   *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + (longlong)iVar15 * -4);
            }
            lVar17 = lVar17 + -1;
          } while (-1 < lVar17);
        }
        else {
          local_40 = 0x80000000;
          local_38 = 0;
          puVar13 = &local_40;
          do {
            uVar1 = (uint)uVar3;
            uVar3 = (ulonglong)((uVar10 & *(uint *)puVar13) << (0x20 - bVar4 & 0x1f));
            *(uint *)puVar13 = *(uint *)puVar13 >> (bVar4 & 0x1f) | uVar1;
            puVar13 = (undefined8 *)((longlong)puVar13 + 4);
            lVar17 = lVar17 + -1;
          } while (lVar17 != 0);
          lVar17 = 2;
          do {
            if (lVar17 < iVar15) {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
            }
            else {
              *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                   *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + (longlong)iVar15 * -4);
            }
            lVar17 = lVar17 + -1;
          } while (-1 < lVar17);
          iVar2 = DAT_180018384 + DAT_180018370;
        }
      }
      else {
        local_40 = local_48;
        local_38 = local_50;
        uVar10 = DAT_180018374 - local_68 >> 0x1f & 0x1f;
        puVar13 = &local_40;
        iVar2 = (DAT_180018374 - local_68) + uVar10;
        bVar4 = ((byte)iVar2 & 0x1f) - (char)uVar10;
        uVar6 = uVar3;
        do {
          uVar10 = *(uint *)puVar13;
          *(uint *)puVar13 = uVar10 >> (bVar4 & 0x1f) | (uint)uVar6;
          puVar13 = (undefined8 *)((longlong)puVar13 + 4);
          uVar6 = (ulonglong)((uVar10 & ~(-1 << (bVar4 & 0x1f))) << (0x20 - bVar4 & 0x1f));
          lVar17 = lVar17 + -1;
        } while (lVar17 != 0);
        lVar16 = (longlong)(iVar2 >> 5);
        lVar17 = 2;
        lVar18 = 3;
        lVar5 = 2;
        do {
          if (lVar5 < lVar16) {
            *(undefined4 *)((longlong)&local_40 + lVar5 * 4) = 0;
          }
          else {
            *(undefined4 *)((longlong)&local_40 + lVar5 * 4) =
                 *(undefined4 *)((longlong)&local_40 + lVar5 * 4 + lVar16 * -4);
          }
          lVar5 = lVar5 + -1;
        } while (-1 < lVar5);
        uVar1 = local_60 + 1 >> 0x1f & 0x1f;
        uVar10 = local_60 + 1 + uVar1;
        iVar2 = (int)uVar10 >> 5;
        uVar10 = 0x1f - ((uVar10 & 0x1f) - uVar1);
        bVar4 = (byte)uVar10;
        if ((*(uint *)((longlong)&local_40 + (longlong)iVar2 * 4) >> (uVar10 & 0x1f) & 1) != 0) {
          if ((*(uint *)((longlong)&local_40 + (longlong)iVar2 * 4) & ~(-1 << (bVar4 & 0x1f))) == 0)
          {
            for (lVar5 = (longlong)(iVar2 + 1); lVar5 < 3; lVar5 = lVar5 + 1) {
              if (*(int *)((longlong)&local_40 + lVar5 * 4) != 0) goto LAB_18000bd53;
            }
          }
          else {
LAB_18000bd53:
            uVar10 = local_60 >> 0x1f & 0x1f;
            iVar11 = local_60 + uVar10;
            iVar15 = iVar11 >> 5;
            uVar1 = *(uint *)((longlong)&local_40 + (longlong)iVar15 * 4);
            uVar7 = 1 << (0x1f - (((byte)iVar11 & 0x1f) - (char)uVar10) & 0x1f);
            uVar10 = uVar1 + uVar7;
            if ((uVar10 < uVar1) || (uVar6 = uVar3, uVar10 < uVar7)) {
              uVar6 = uVar9;
            }
            *(uint *)((longlong)&local_40 + (longlong)iVar15 * 4) = uVar10;
            lVar5 = (longlong)(iVar15 + -1);
            if (-1 < iVar15 + -1) {
              do {
                if ((int)uVar6 == 0) break;
                uVar1 = *(uint *)((longlong)&local_40 + lVar5 * 4);
                uVar10 = uVar1 + 1;
                if ((uVar10 < uVar1) || (uVar6 = uVar3, uVar10 == 0)) {
                  uVar6 = uVar9;
                }
                *(uint *)((longlong)&local_40 + lVar5 * 4) = uVar10;
                lVar5 = lVar5 + -1;
              } while (-1 < lVar5);
            }
          }
        }
        puVar13 = (undefined8 *)((longlong)&local_40 + (longlong)iVar2 * 4);
        *(uint *)puVar13 = *(uint *)puVar13 & -1 << (bVar4 & 0x1f);
        lVar5 = (longlong)(iVar2 + 1);
        if (lVar5 < 3) {
          FUN_180003c80((undefined (*) [16])((longlong)&local_40 + lVar5 * 4),0,(3 - lVar5) * 4);
        }
        puVar13 = &local_40;
        uVar10 = DAT_18001837c + 1 >> 0x1f & 0x1f;
        iVar2 = DAT_18001837c + 1 + uVar10;
        bVar4 = ((byte)iVar2 & 0x1f) - (char)uVar10;
        do {
          uVar10 = *(uint *)puVar13;
          *(uint *)puVar13 = uVar10 >> (bVar4 & 0x1f) | (uint)uVar3;
          puVar13 = (undefined8 *)((longlong)puVar13 + 4);
          uVar3 = (ulonglong)((uVar10 & ~(-1 << (bVar4 & 0x1f))) << (0x20 - bVar4 & 0x1f));
          lVar18 = lVar18 + -1;
        } while (lVar18 != 0);
        lVar5 = (longlong)(iVar2 >> 5);
        do {
          if (lVar17 < lVar5) {
            *(undefined4 *)((longlong)&local_40 + lVar17 * 4) = 0;
          }
          else {
            *(undefined4 *)((longlong)&local_40 + lVar17 * 4) =
                 *(undefined4 *)((longlong)&local_40 + lVar17 * 4 + lVar5 * -4);
          }
          lVar17 = lVar17 + -1;
        } while (-1 < lVar17);
        iVar2 = 0;
      }
    }
  }
  bVar19 = local_64 != 0;
  local_64 = -local_64;
  local_40._0_4_ =
       iVar2 << (0x1fU - (char)DAT_18001837c & 0x1f) | -(uint)bVar19 & 0x80000000 | (uint)local_40;
  if (DAT_180018380 == 0x40) {
    local_58[1] = (uint)local_40;
    *local_58 = local_40._4_4_;
  }
  else {
    if (DAT_180018380 == 0x20) {
      *local_58 = (uint)local_40;
    }
  }
  FUN_180002f40(local_30 ^ (ulonglong)auStack136);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18000c010(undefined2 *param_1,byte **param_2,byte *param_3,int param_4,int param_5,
                  int param_6,int param_7,longlong *param_8)

{
  ushort uVar1;
  uint uVar2;
  int *piVar3;
  ushort uVar4;
  uint uVar5;
  byte bVar6;
  ulonglong uVar7;
  undefined2 uVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  undefined *puVar12;
  byte **ppbVar13;
  uint uVar14;
  byte *pbVar15;
  ushort *puVar16;
  ushort uVar17;
  byte *pbVar18;
  uint uVar19;
  uint *puVar20;
  int iVar21;
  char *pcVar22;
  int iVar23;
  ushort uVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  undefined auStack216 [32];
  int local_b8;
  int local_b4;
  uint local_b0;
  int local_ac;
  byte **local_a8;
  undefined *local_a0;
  undefined2 *local_98;
  byte local_90;
  undefined uStack143;
  undefined2 uStack142;
  ushort auStack140 [6];
  undefined8 local_80;
  undefined2 uStack120;
  ushort uStack118;
  byte *local_70;
  undefined4 local_68;
  char local_60 [23];
  char local_49;
  ulonglong local_40;
  
  local_40 = DAT_1800170a0 ^ (ulonglong)auStack216;
  uVar9 = 0;
  uVar2 = 0;
  pcVar22 = local_60;
  uVar8 = 0;
  local_b0 = local_b0 & 0xffff0000;
  iVar10 = 0;
  local_b4 = 1;
  local_b8 = 0;
  uVar27 = 0;
  pbVar15 = param_3;
  local_ac = param_4;
  local_a8 = param_2;
  local_98 = param_1;
  if (param_8 == (longlong *)0x0) {
    piVar3 = _errno();
    *piVar3 = 0x16;
    FUN_1800038fc();
    goto LAB_18000c84a;
  }
  while ((uVar14 = uVar9, uVar5 = uVar9, uVar11 = uVar9, uVar19 = uVar9, uVar25 = uVar9,
         *pbVar15 < 0x21 &&
         (uVar14 = 0, uVar5 = 0, uVar11 = 0, uVar19 = 0, uVar25 = 0,
         (0x100002600U >> ((longlong)(char)*pbVar15 & 0x3fU) & 1) != 0))) {
    pbVar15 = pbVar15 + 1;
  }
LAB_18000c0ad:
  do {
    bVar6 = *pbVar15;
    pbVar18 = pbVar15 + 1;
    uVar26 = uVar2;
    if (uVar5 < 6) {
      if (uVar5 == 5) {
        local_b8 = 1;
        pbVar15 = param_3;
        uVar26 = 0;
        if (9 < (byte)(bVar6 - 0x30)) break;
        uVar5 = 4;
      }
      else {
        if (uVar5 != 0) {
          if (uVar5 == 1) {
            uVar14 = 1;
            if ((byte)(bVar6 - 0x31) < 9) {
              uVar5 = 3;
              pbVar15 = param_3;
              goto LAB_18000c1d0;
            }
            if (bVar6 == ***(byte ***)(*param_8 + 0xf0)) {
LAB_18000c1b4:
              uVar14 = 1;
              uVar5 = 4;
              pbVar15 = pbVar18;
              goto LAB_18000c0ad;
            }
            if ((bVar6 - 0x2b & 0xfd) == 0) goto LAB_18000c164;
            if (bVar6 == 0x30) goto LAB_18000c208;
          }
          else {
            if (uVar5 == 2) {
              if ((byte)(bVar6 - 0x31) < 9) goto LAB_18000c1c5;
              if (bVar6 == ***(byte ***)(*param_8 + 0xf0)) goto LAB_18000c1e9;
              pbVar15 = param_3;
              if (bVar6 == 0x30) goto LAB_18000c208;
              break;
            }
            if (uVar5 == 3) {
              while (('/' < (char)bVar6 && ((char)bVar6 < ':'))) {
                if (uVar19 < 0x19) {
                  uVar19 = uVar19 + 1;
                  *pcVar22 = bVar6 - 0x30;
                  pcVar22 = pcVar22 + 1;
                }
                else {
                  uVar11 = uVar11 + 1;
                }
                bVar6 = *pbVar18;
                pbVar18 = pbVar18 + 1;
              }
              if (bVar6 == ***(byte ***)(*param_8 + 0xf0)) goto LAB_18000c1b4;
            }
            else {
              if (uVar5 != 4) goto LAB_18000c38b;
              local_b8 = 1;
              if (uVar19 == 0) {
                while (bVar6 == 0x30) {
                  uVar11 = uVar11 - 1;
                  bVar6 = *pbVar18;
                  pbVar18 = pbVar18 + 1;
                }
              }
              while (('/' < (char)bVar6 && ((char)bVar6 < ':'))) {
                if (uVar19 < 0x19) {
                  uVar19 = uVar19 + 1;
                  *pcVar22 = bVar6 - 0x30;
                  pcVar22 = pcVar22 + 1;
                  uVar11 = uVar11 - 1;
                }
                bVar6 = *pbVar18;
                pbVar18 = pbVar18 + 1;
              }
            }
            if ((bVar6 - 0x2b & 0xfd) == 0) {
LAB_18000c164:
              uVar14 = 1;
              uVar5 = 0xb;
              pbVar15 = pbVar18 + -1;
              goto LAB_18000c0ad;
            }
          }
          uVar14 = 1;
          uVar26 = 0;
          if (((char)bVar6 < 'D') ||
             (('E' < (char)bVar6 && (uVar26 = uVar27, bVar6 != 100 && bVar6 != 0x65))))
          goto LAB_18000c285;
          uVar5 = 6;
          pbVar15 = pbVar18;
          uVar14 = 1;
          goto LAB_18000c0ad;
        }
        if (8 < (byte)(bVar6 - 0x31)) {
          if (bVar6 == ***(byte ***)(*param_8 + 0xf0)) {
LAB_18000c1e9:
            uVar5 = 5;
            pbVar15 = pbVar18;
          }
          else {
            if (bVar6 == 0x2b) {
              uVar5 = 2;
              local_b0 = local_b0 & 0xffff0000;
              pbVar15 = pbVar18;
            }
            else {
              if (bVar6 == 0x2d) {
                uVar5 = 2;
                local_b0 = 0x8000;
                pbVar15 = pbVar18;
              }
              else {
                uVar26 = uVar27;
                if (bVar6 != 0x30) goto LAB_18000c285;
LAB_18000c208:
                uVar5 = 1;
                pbVar15 = pbVar18;
              }
            }
          }
          goto LAB_18000c0ad;
        }
LAB_18000c1c5:
        uVar5 = 3;
        pbVar15 = param_3;
      }
LAB_18000c1d0:
      param_3 = pbVar15;
      pbVar15 = pbVar18 + -1;
      goto LAB_18000c0ad;
    }
    if (uVar5 == 6) {
      pbVar15 = pbVar15 + -1;
      if ((byte)(bVar6 - 0x31) < 9) goto LAB_18000c352;
      if (bVar6 != 0x2b) {
        if (bVar6 != 0x2d) goto LAB_18000c35c;
LAB_18000c307:
        local_b4 = -1;
        uVar5 = 7;
        param_3 = pbVar15;
        pbVar15 = pbVar18;
        goto LAB_18000c0ad;
      }
      uVar5 = 7;
      param_3 = pbVar15;
    }
    else {
      if (uVar5 == 7) {
        pbVar15 = param_3;
        if ((byte)(bVar6 - 0x31) < 9) {
LAB_18000c352:
          uVar5 = 9;
          goto LAB_18000c1d0;
        }
LAB_18000c35c:
        if (bVar6 != 0x30) break;
        uVar5 = 8;
        param_3 = pbVar15;
        pbVar15 = pbVar18;
        goto LAB_18000c0ad;
      }
      if (uVar5 == 8) {
        uVar25 = 1;
        while (bVar6 == 0x30) {
          bVar6 = *pbVar18;
          pbVar18 = pbVar18 + 1;
        }
        uVar26 = uVar27;
        if ((byte)(bVar6 - 0x31) < 9) {
          uVar5 = 9;
          pbVar15 = param_3;
          uVar25 = 1;
          goto LAB_18000c1d0;
        }
        goto LAB_18000c285;
      }
      if (uVar5 == 9) {
        uVar25 = 1;
        uVar26 = uVar9;
        goto LAB_18000c3cc;
      }
      if (uVar5 == 0xb) {
        uVar26 = uVar27;
        if (param_7 == 0) goto LAB_18000c285;
        if (bVar6 != 0x2b) {
          uVar26 = uVar2;
          if (bVar6 == 0x2d) goto LAB_18000c307;
          break;
        }
        uVar5 = 7;
        param_3 = pbVar15;
        pbVar15 = pbVar18;
        goto LAB_18000c0ad;
      }
    }
LAB_18000c38b:
    pbVar15 = pbVar18;
  } while (uVar5 != 10);
  goto LAB_18000c3fd;
LAB_18000c3cc:
  if (((char)bVar6 < '0') || ('9' < (char)bVar6)) goto LAB_18000c3ea;
  uVar26 = (int)(char)bVar6 + (uVar26 * 5 + -0x18) * 2;
  if ((int)uVar26 < 0x1451) {
    bVar6 = *pbVar18;
    pbVar18 = pbVar18 + 1;
    goto LAB_18000c3cc;
  }
  uVar26 = 0x1451;
LAB_18000c3ea:
  while (('/' < (char)bVar6 && ((char)bVar6 < ':'))) {
    bVar6 = *pbVar18;
    pbVar18 = pbVar18 + 1;
  }
LAB_18000c285:
  pbVar15 = pbVar18 + -1;
LAB_18000c3fd:
  *param_2 = pbVar15;
  iVar21 = iVar10;
  if (uVar14 == 0) {
    uVar8 = 0;
    uVar1 = 0;
  }
  else {
    if (0x18 < uVar19) {
      if ('\x04' < local_49) {
        local_49 = local_49 + '\x01';
      }
      pcVar22 = pcVar22 + -1;
      uVar19 = 0x18;
      uVar11 = uVar11 + 1;
    }
    if (uVar19 == 0) {
      uVar1 = 0;
      uVar8 = 0;
    }
    else {
      while (pcVar22 = pcVar22 + -1, *pcVar22 == '\0') {
        uVar19 = uVar19 - 1;
        uVar11 = uVar11 + 1;
      }
      FUN_18000d4ac(local_60,uVar19,&local_80);
      if (local_b4 < 0) {
        uVar26 = -uVar26;
      }
      uVar26 = uVar26 + uVar11;
      if (uVar25 == 0) {
        uVar26 = uVar26 + param_5;
      }
      if (local_b8 == 0) {
        uVar26 = uVar26 - param_6;
      }
      if ((int)uVar26 < 0x1451) {
        if ((int)uVar26 < -0x1450) {
          uVar1 = 0;
        }
        else {
          puVar12 = &DAT_180018330;
          if (uVar26 != 0) {
            if ((int)uVar26 < 0) {
              uVar26 = -uVar26;
              puVar12 = (undefined *)0x180018490;
            }
            if (local_ac == 0) {
              local_80._0_2_ = 0;
            }
joined_r0x00018000c4c5:
            do {
              if (uVar26 == 0) break;
              puVar12 = puVar12 + 0x54;
              uVar27 = (int)uVar26 >> 3;
              uVar2 = uVar26 & 7;
              uVar26 = uVar27;
              local_a0 = puVar12;
              if (uVar2 != 0) {
                local_a8 = (byte **)(puVar12 + (longlong)(int)uVar2 * 0xc);
                if (0x7fff < *(ushort *)local_a8) {
                  ppbVar13 = local_a8 + 1;
                  pbVar15 = *local_a8;
                  local_a8 = &local_70;
                  local_68 = *(undefined4 *)ppbVar13;
                  local_70._0_6_ = CONCAT42((int)((ulonglong)pbVar15 >> 0x10) + -1,(short)pbVar15);
                  local_70 = (byte *)((ulonglong)pbVar15 & 0xffff000000000000 |
                                     (ulonglong)(uint6)local_70);
                }
                local_90 = 0;
                uStack143 = 0;
                uStack142 = 0;
                auStack140[0] = 0;
                auStack140[1] = 0;
                uVar1 = *(ushort *)((longlong)local_a8 + 10) & 0x7fff;
                auStack140[2] = 0;
                auStack140[3] = 0;
                uVar4 = uStack118 & 0x7fff;
                uVar24 = (*(ushort *)((longlong)local_a8 + 10) ^ uStack118) & 0x8000;
                uVar17 = uVar4 + uVar1;
                if (((0x7ffe < uVar4) || (0x7ffe < uVar1)) || (0xbffd < uVar17)) {
LAB_18000c7cb:
                  local_80._0_2_ = 0;
                  local_80._2_2_ = 0;
                  local_80._4_2_ = 0;
                  local_80._6_2_ = 0;
                  iVar21 = (-(uint)(uVar24 != 0) & 0x80000000) + 0x7fff8000;
                  uStack120 = (undefined2)iVar21;
                  uStack118 = (ushort)((uint)iVar21 >> 0x10);
                  goto joined_r0x00018000c4c5;
                }
                if (0x3fbf < uVar17) {
                  if (((uVar4 == 0) &&
                      (uVar17 = uVar17 + 1, (CONCAT22(uStack118,uStack120) & 0x7fffffff) == 0)) &&
                     ((CONCAT22(local_80._6_2_,local_80._4_2_) == 0 &&
                      (CONCAT22(local_80._2_2_,(undefined2)local_80) == 0)))) {
                    uStack118 = 0;
                    goto joined_r0x00018000c4c5;
                  }
                  if (((uVar1 != 0) ||
                      (uVar17 = uVar17 + 1, (*(uint *)(local_a8 + 1) & 0x7fffffff) != 0)) ||
                     ((*(int *)((longlong)local_a8 + 4) != 0 || (*(int *)local_a8 != 0)))) {
                    puVar20 = (uint *)&local_90;
                    iVar21 = 5;
                    uVar2 = uVar9;
                    do {
                      local_b8 = iVar21;
                      if (0 < iVar21) {
                        ppbVar13 = local_a8 + 1;
                        puVar16 = (ushort *)((longlong)&local_80 + (longlong)(int)(uVar2 * 2));
                        do {
                          uVar27 = *puVar20 + (uint)*(ushort *)ppbVar13 * (uint)*puVar16;
                          if ((uVar27 < *puVar20) ||
                             (iVar23 = iVar10, uVar27 < (uint)*(ushort *)ppbVar13 * (uint)*puVar16))
                          {
                            iVar23 = 1;
                          }
                          *puVar20 = uVar27;
                          if (iVar23 != 0) {
                            *(short *)(puVar20 + 1) = *(short *)(puVar20 + 1) + 1;
                          }
                          puVar16 = puVar16 + 1;
                          ppbVar13 = (byte **)((longlong)ppbVar13 + -2);
                          local_b8 = local_b8 + -1;
                        } while (0 < local_b8);
                      }
                      iVar21 = iVar21 + -1;
                      puVar20 = (uint *)((longlong)puVar20 + 2);
                      uVar2 = uVar2 + 1;
                    } while (0 < iVar21);
                    uVar27 = CONCAT22(auStack140[3],auStack140[2]);
                    uVar2 = CONCAT22(uStack142,CONCAT11(uStack143,local_90));
                    uVar17 = uVar17 + 0xc002;
                    uVar14 = uVar2;
                    if ((short)uVar17 < 1) {
LAB_18000c6cc:
                      uVar17 = uVar17 - 1;
                      if (-1 < (short)uVar17) goto LAB_18000c736;
                      uVar7 = (ulonglong)(ushort)-uVar17;
                      uVar17 = 0;
                      uVar14 = uVar9;
                      do {
                        uVar5 = uVar27;
                        if ((local_90 & 1) != 0) {
                          uVar14 = uVar14 + 1;
                        }
                        uVar11 = CONCAT22(auStack140[1],auStack140[0]);
                        uVar19 = uVar2 >> 1;
                        auStack140[1] = auStack140[1] >> 1 | (ushort)((uVar5 << 0x1f) >> 0x10);
                        uVar27 = uVar5 >> 1;
                        uVar2 = uVar19 | uVar11 << 0x1f;
                        auStack140[0] = (ushort)(uVar11 >> 1);
                        local_90 = (byte)uVar19;
                        uStack143 = (undefined)(uVar19 >> 8);
                        uStack142 = (undefined2)(uVar2 >> 0x10);
                        uVar7 = uVar7 - 1;
                      } while (uVar7 != 0);
                      auStack140[2] = (ushort)uVar27;
                      auStack140[3] = (ushort)(uVar5 >> 0x11);
                      if (uVar14 == 0) goto LAB_18000c736;
                      uVar1 = (ushort)uVar19 | 1;
                      local_90 = (byte)uVar1;
                      uVar2 = uVar19 | 1;
                    }
                    else {
                      do {
                        uVar2 = uVar14;
                        if ((uVar27 & 0x80000000) != 0) break;
                        uVar5 = uVar27 * 2;
                        uVar2 = uVar14 * 2;
                        iVar21 = CONCAT22(auStack140[1],auStack140[0]) * 2;
                        uVar17 = uVar17 - 1;
                        auStack140[0] = (ushort)iVar21 | (ushort)(uVar14 >> 0x1f);
                        uVar27 = uVar5 | auStack140[1] >> 0xf;
                        local_90 = (byte)uVar2;
                        uStack143 = (undefined)(uVar2 >> 8);
                        uStack142 = (undefined2)(uVar2 >> 0x10);
                        auStack140[1] = (ushort)((uint)iVar21 >> 0x10);
                        auStack140[2] = (ushort)uVar27;
                        auStack140[3] = (ushort)(uVar5 >> 0x10);
                        uVar14 = uVar2;
                      } while (0 < (short)uVar17);
                      if ((short)uVar17 < 1) goto LAB_18000c6cc;
LAB_18000c736:
                      uVar1 = CONCAT11(uStack143,local_90);
                    }
                    if ((0x8000 < uVar1) || ((uVar2 & 0x1ffff) == 0x18000)) {
                      if (CONCAT22(auStack140[0],uStack142) == -1) {
                        uStack142 = 0;
                        auStack140[0] = 0;
                        if (CONCAT22(auStack140[2],auStack140[1]) == -1) {
                          auStack140[1] = 0;
                          auStack140[2] = 0;
                          if (auStack140[3] == 0xffff) {
                            auStack140[3] = 0x8000;
                            uVar17 = uVar17 + 1;
                          }
                          else {
                            auStack140[3] = auStack140[3] + 1;
                          }
                        }
                        else {
                          iVar21 = CONCAT22(auStack140[2],auStack140[1]) + 1;
                          auStack140[1] = (ushort)iVar21;
                          auStack140[2] = (ushort)((uint)iVar21 >> 0x10);
                        }
                        uVar27 = CONCAT22(auStack140[3],auStack140[2]);
                      }
                      else {
                        iVar21 = CONCAT22(auStack140[0],uStack142) + 1;
                        uStack142 = (undefined2)iVar21;
                        auStack140[0] = (ushort)((uint)iVar21 >> 0x10);
                      }
                    }
                    if (0x7ffe < uVar17) goto LAB_18000c7cb;
                    local_80._6_2_ = (undefined2)uVar27;
                    uStack120 = (undefined2)(uVar27 >> 0x10);
                    local_80._0_2_ = uStack142;
                    uStack118 = uVar17 | uVar24;
                    local_80._2_2_ = auStack140[0];
                    local_80._4_2_ = auStack140[1];
                    goto joined_r0x00018000c4c5;
                  }
                }
                local_80._4_2_ = 0;
                local_80._6_2_ = 0;
                uStack120 = 0;
                uStack118 = 0;
                local_80._0_2_ = 0;
                local_80._2_2_ = 0;
              }
            } while( true );
          }
          iVar10 = CONCAT22(local_80._4_2_,local_80._2_2_);
          uVar1 = uStack118;
          uVar8 = (undefined2)local_80;
          iVar21 = CONCAT22(uStack120,local_80._6_2_);
        }
      }
      else {
        uVar8 = 0;
        uVar1 = 0x7fff;
        iVar21 = -0x80000000;
      }
    }
  }
  local_98[5] = uVar1 | (ushort)local_b0;
  *local_98 = uVar8;
  *(int *)(local_98 + 1) = iVar10;
  *(int *)(local_98 + 3) = iVar21;
LAB_18000c84a:
  FUN_180002f40(local_40 ^ (ulonglong)auStack216);
  return;
}



// Library Function - Single Match
//  _cfltcvt
// 
// Library: Visual Studio 2012 Release

errno_t _cfltcvt(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps)

{
  errno_t eVar1;
  
  eVar1 = _cfltcvt_l(arg,buffer,sizeInBytes,format,precision,caps,(_locale_t)0x0);
  return eVar1;
}



// Library Function - Single Match
//  _cfltcvt_l
// 
// Library: Visual Studio 2012 Release

errno_t _cfltcvt_l(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps,
                  _locale_t plocinfo)

{
  int iVar1;
  
  if ((format - 0x45U & 0xffffffdf) == 0) {
    iVar1 = _cftoe_l(arg,buffer,(undefined *)sizeInBytes,precision,caps,
                     (localeinfo_struct *)plocinfo);
  }
  else {
    if (format == 0x66) {
      iVar1 = _cftof_l(arg,(undefined8 *)buffer,sizeInBytes,precision,(localeinfo_struct *)plocinfo)
      ;
    }
    else {
      if ((format - 0x41U & 0xffffffdf) == 0) {
        iVar1 = FUN_18000c918((ulonglong *)arg,buffer,(undefined *)sizeInBytes,
                              (ulonglong)(uint)precision,caps,(localeinfo_struct *)plocinfo);
      }
      else {
        iVar1 = _cftog_l(arg,(undefined8 *)buffer,(undefined *)sizeInBytes,precision,caps,
                         (localeinfo_struct *)plocinfo);
      }
    }
  }
  return (errno_t)iVar1;
}



int FUN_18000c918(ulonglong *param_1,undefined *param_2,undefined *param_3,ulonglong param_4,
                 int param_5,localeinfo_struct *param_6)

{
  undefined (*pauVar1) [16];
  ushort uVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  undefined (*pauVar6) [16];
  longlong lVar7;
  short sVar8;
  longlong lVar9;
  ulonglong uVar10;
  short sVar11;
  undefined (*pauVar12) [16];
  undefined (*pauVar13) [16];
  char *pcVar14;
  undefined *puVar15;
  ulonglong uVar16;
  ulonglong uVar17;
  longlong local_48 [2];
  longlong local_38;
  char local_30;
  
  uVar17 = 0x3ff;
  sVar11 = 0x30;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_48,param_6);
  uVar10 = param_4 & 0xffffffff;
  if ((int)(param_4 & 0xffffffff) < 0) {
    uVar10 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == (undefined *)0x0)) {
    piVar4 = _errno();
    iVar3 = 0x16;
  }
  else {
    iVar3 = (int)uVar10;
    *param_2 = 0;
    if ((undefined *)(longlong)(iVar3 + 0xb) < param_3) {
      if ((*param_1 >> 0x34 & 0x7ff) == 0x7ff) {
        puVar15 = param_3 + -2;
        if (param_3 == (undefined *)0xffffffffffffffff) {
          puVar15 = param_3;
        }
        iVar3 = _cftoe_l(param_1,param_2 + 2,puVar15,iVar3,0,(localeinfo_struct *)0x0);
        if (iVar3 != 0) {
          *param_2 = 0;
          goto LAB_18000cc95;
        }
        if (param_2[2] == '-') {
          *param_2 = 0x2d;
          param_2 = param_2 + 1;
        }
        *param_2 = 0x30;
        param_2[1] = (-(param_5 != 0) & 0xe0U) + 0x78;
        pcVar5 = strrchr(param_2 + 2,0x65);
        if (pcVar5 != (char *)0x0) {
          *pcVar5 = (-(param_5 != 0) & 0xe0U) + 0x70;
          pcVar5[3] = '\0';
        }
      }
      else {
        if ((*param_1 & 0x8000000000000000) != 0) {
          *param_2 = 0x2d;
          param_2 = param_2 + 1;
        }
        *param_2 = 0x30;
        param_2[1] = (-(param_5 != 0) & 0xe0U) + 0x78;
        sVar8 = (-(ushort)(param_5 != 0) & 0xffe0) + 0x27;
        if ((*param_1 & 0x7ff0000000000000) == 0) {
          param_2[2] = 0x30;
          uVar17 = (ulonglong)(-(uint)((*param_1 & 0xfffffffffffff) != 0) & 0x3fe);
        }
        else {
          param_2[2] = 0x31;
        }
        pauVar12 = (undefined (*) [16])(param_2 + 3);
        pauVar13 = (undefined (*) [16])(param_2 + 4);
        if (iVar3 == 0) {
          (*pauVar12)[0] = 0;
        }
        else {
          (*pauVar12)[0] = *(undefined *)**(undefined8 **)(local_48[0] + 0xf0);
        }
        if ((*param_1 & 0xfffffffffffff) != 0) {
          uVar16 = 0xf000000000000;
          do {
            if ((int)uVar10 < 1) break;
            uVar2 = (short)((*param_1 & uVar16) >> ((byte)sVar11 & 0x3f)) + 0x30;
            if (0x39 < uVar2) {
              uVar2 = uVar2 + sVar8;
            }
            (*pauVar13)[0] = (char)uVar2;
            uVar16 = uVar16 >> 4;
            uVar10 = (ulonglong)((int)uVar10 - 1);
            pauVar13 = (undefined (*) [16])(*pauVar13 + 1);
            sVar11 = sVar11 + -4;
          } while (-1 < sVar11);
          if ((-1 < sVar11) &&
             (pauVar1 = pauVar13, 8 < (ushort)((*param_1 & uVar16) >> ((byte)sVar11 & 0x3f)))) {
            while (pauVar6 = (undefined (*) [16])(pauVar1[-1] + 0xf),
                  ((*pauVar6)[0] + 0xba & 0xdf) == 0) {
              (*pauVar6)[0] = 0x30;
              pauVar1 = pauVar6;
            }
            if (pauVar6 == pauVar12) {
              pauVar1[-1][0xe] = pauVar1[-1][0xe] + '\x01';
            }
            else {
              if ((*pauVar6)[0] == '9') {
                (*pauVar6)[0] = (char)sVar8 + ':';
              }
              else {
                (*pauVar6)[0] = (*pauVar6)[0] + '\x01';
              }
            }
          }
        }
        if (0 < (int)uVar10) {
          FUN_180003c80(pauVar13,0x30,uVar10);
          pauVar13 = (undefined (*) [16])(*pauVar13 + uVar10);
        }
        if ((*pauVar12)[0] == '\0') {
          pauVar13 = pauVar12;
        }
        (*pauVar13)[0] = (-(param_5 != 0) & 0xe0U) + 0x70;
        lVar7 = ((uint)(*param_1 >> 0x34) & 0x7ff) - uVar17;
        if (lVar7 < 0) {
          (*pauVar13)[1] = 0x2d;
          lVar7 = -lVar7;
        }
        else {
          (*pauVar13)[1] = 0x2b;
        }
        pcVar14 = *pauVar13 + 2;
        *pcVar14 = '0';
        pcVar5 = pcVar14;
        if (lVar7 < 1000) {
LAB_18000cc1f:
          if (99 < lVar7) goto LAB_18000cc25;
        }
        else {
          *pcVar14 = (char)(lVar7 / 1000) + '0';
          pcVar5 = *pauVar13 + 3;
          lVar7 = lVar7 % 1000;
          if (pcVar5 == pcVar14) goto LAB_18000cc1f;
LAB_18000cc25:
          lVar9 = SUB168(SEXT816(-0x5c28f5c28f5c28f5) * SEXT816(lVar7) >> 0x40,0) + lVar7;
          lVar9 = (lVar9 >> 6) - (lVar9 >> 0x3f);
          *pcVar5 = (char)lVar9 + '0';
          pcVar5 = pcVar5 + 1;
          lVar7 = lVar7 + lVar9 * -100;
        }
        if ((pcVar5 != pcVar14) || (9 < lVar7)) {
          *pcVar5 = (char)(lVar7 / 10) + '0';
          pcVar5 = pcVar5 + 1;
          lVar7 = lVar7 % 10;
        }
        *pcVar5 = (char)lVar7 + '0';
        pcVar5[1] = '\0';
      }
      iVar3 = 0;
      goto LAB_18000cc95;
    }
    piVar4 = _errno();
    iVar3 = 0x22;
  }
  *piVar4 = iVar3;
  FUN_1800038fc();
LAB_18000cc95:
  if (local_30 != '\0') {
    *(uint *)(local_38 + 200) = *(uint *)(local_38 + 200) & 0xfffffffd;
  }
  return iVar3;
}



ulonglong FUN_18000ccc8(undefined *param_1,undefined *param_2,int param_3,int param_4,int *param_5,
                       char param_6,localeinfo_struct *param_7)

{
  code *pcVar1;
  errno_t eVar2;
  uint *puVar3;
  size_t sVar4;
  ulonglong uVar5;
  undefined *puVar6;
  uint uVar7;
  undefined8 *_Str;
  char *_Dst;
  int iVar8;
  longlong local_38 [2];
  longlong local_28;
  char local_20;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_38,param_7);
  if ((param_1 == (undefined *)0x0) || (param_2 == (undefined *)0x0)) {
    puVar3 = (uint *)_errno();
    uVar7 = 0x16;
  }
  else {
    iVar8 = 0;
    if (0 < param_3) {
      iVar8 = param_3;
    }
    if ((undefined *)(longlong)(iVar8 + 9) < param_2) {
      if (param_6 != '\0') {
        _Str = (undefined8 *)(param_1 + (*param_5 == 0x2d));
        if (0 < param_3 != 0) {
          sVar4 = strlen((char *)_Str);
          FUN_180002f70((undefined8 *)((longlong)(int)(uint)(0 < param_3) + (longlong)_Str),_Str,
                        sVar4 + 1);
        }
      }
      puVar6 = param_1;
      if (*param_5 == 0x2d) {
        *param_1 = 0x2d;
        puVar6 = param_1 + 1;
      }
      if (0 < param_3) {
        *puVar6 = puVar6[1];
        puVar6 = puVar6 + 1;
        *puVar6 = *(undefined *)**(undefined8 **)(local_38[0] + 0xf0);
      }
      _Dst = puVar6 + (ulonglong)(param_6 == '\0') + (longlong)param_3;
      puVar6 = param_2 + (longlong)(param_1 + -(longlong)_Dst);
      if (param_2 == (undefined *)0xffffffffffffffff) {
        puVar6 = param_2;
      }
      eVar2 = strcpy_s(_Dst,(rsize_t)puVar6,"e+000");
      if (eVar2 != 0) {
        FUN_18000391c();
        pcVar1 = (code *)swi(3);
        uVar5 = (*pcVar1)();
        return uVar5;
      }
      if (param_4 != 0) {
        *_Dst = 'E';
      }
      if (**(char **)(param_5 + 4) != '0') {
        iVar8 = param_5[1] + -1;
        if (iVar8 < 0) {
          iVar8 = -iVar8;
          _Dst[1] = '-';
        }
        if (99 < iVar8) {
          _Dst[2] = _Dst[2] + (char)(iVar8 / 100);
          iVar8 = iVar8 % 100;
        }
        if (9 < iVar8) {
          _Dst[3] = _Dst[3] + (char)(iVar8 / 10);
          iVar8 = iVar8 % 10;
        }
        _Dst[4] = _Dst[4] + (char)iVar8;
      }
      if (((DAT_18001df98 & 1) != 0) && (_Dst[2] == '0')) {
        FUN_180002f70((undefined8 *)(_Dst + 2),(undefined8 *)(_Dst + 3),3);
      }
      uVar7 = 0;
      goto LAB_18000ce77;
    }
    puVar3 = (uint *)_errno();
    uVar7 = 0x22;
  }
  *puVar3 = uVar7;
  FUN_1800038fc();
LAB_18000ce77:
  if (local_20 != '\0') {
    *(uint *)(local_28 + 200) = *(uint *)(local_28 + 200) & 0xfffffffd;
  }
  return (ulonglong)uVar7;
}



// Library Function - Single Match
//  _cftoe_l
// 
// Library: Visual Studio 2012 Release

void _cftoe_l(undefined8 *param_1,undefined *param_2,undefined *param_3,int param_4,int param_5,
             localeinfo_struct *param_6)

{
  errno_t eVar1;
  int *piVar2;
  undefined *_SizeInBytes;
  _strflt local_68;
  char local_50 [24];
  ulonglong local_38;
  
  local_38 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff58;
  FUN_18000dba0(*param_1,(int *)&local_68,local_50,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == (undefined *)0x0)) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    FUN_1800038fc();
  }
  else {
    _SizeInBytes = (undefined *)0xffffffffffffffff;
    if (param_3 != (undefined *)0xffffffffffffffff) {
      _SizeInBytes = param_3 + (-(ulonglong)(0 < param_4) - (ulonglong)(local_68.sign == 0x2d));
    }
    eVar1 = _fptostr(param_2 + (ulonglong)(0 < param_4) + (ulonglong)(local_68.sign == 0x2d),
                     (size_t)_SizeInBytes,param_4 + 1,(STRFLT)&local_68);
    if (eVar1 == 0) {
      FUN_18000ccc8(param_2,param_3,param_4,param_5,(int *)&local_68,'\0',param_6);
    }
    else {
      *param_2 = 0;
    }
  }
  FUN_180002f40(local_38 ^ (ulonglong)&stack0xffffffffffffff58);
  return;
}



// Library Function - Single Match
//  _cftof2_l
// 
// Library: Visual Studio 2012 Release

undefined4
_cftof2_l(undefined8 *param_1,longlong param_2,int param_3,int *param_4,char param_5,
         localeinfo_struct *param_6)

{
  undefined (*_Str) [16];
  int iVar1;
  int *piVar2;
  size_t sVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 *_Str_00;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  iVar1 = param_4[1];
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,param_6);
  if ((param_1 == (undefined8 *)0x0) || (param_2 == 0)) {
    piVar2 = _errno();
    uVar6 = 0x16;
    *piVar2 = 0x16;
    FUN_1800038fc();
  }
  else {
    if ((param_5 != '\0') && (iVar1 + -1 == param_3)) {
      *(undefined2 *)((longlong)param_1 + (longlong)(iVar1 + -1) + (ulonglong)(*param_4 == 0x2d)) =
           0x30;
    }
    if (*param_4 == 0x2d) {
      *(undefined *)param_1 = 0x2d;
      param_1 = (undefined8 *)((longlong)param_1 + 1);
    }
    if (param_4[1] < 1) {
      sVar3 = strlen((char *)param_1);
      FUN_180002f70((undefined8 *)((longlong)param_1 + 1),param_1,sVar3 + 1);
      *(undefined *)param_1 = 0x30;
      _Str_00 = (undefined8 *)((longlong)param_1 + 1);
    }
    else {
      _Str_00 = (undefined8 *)((longlong)param_1 + (longlong)param_4[1]);
    }
    if (0 < param_3) {
      _Str = (undefined (*) [16])((longlong)_Str_00 + 1);
      sVar3 = strlen((char *)_Str_00);
      FUN_180002f70((undefined8 *)_Str,_Str_00,sVar3 + 1);
      *(undefined *)_Str_00 = *(undefined *)**(undefined8 **)(local_28[0] + 0xf0);
      iVar1 = param_4[1];
      if (iVar1 < 0) {
        iVar4 = -iVar1;
        iVar5 = iVar4;
        if ((param_5 == '\0') && (iVar5 = param_3, SBORROW4(param_3,iVar4) == param_3 + iVar1 < 0))
        {
          iVar5 = iVar4;
        }
        if (iVar5 != 0) {
          sVar3 = strlen((char *)_Str);
          FUN_180002f70((undefined8 *)(*_Str + iVar5),(undefined8 *)_Str,sVar3 + 1);
        }
        FUN_180003c80(_Str,0x30,(longlong)iVar5);
      }
    }
    uVar6 = 0;
  }
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return uVar6;
}



// Library Function - Single Match
//  _cftof_l
// 
// Library: Visual Studio 2012 Release

void _cftof_l(undefined8 *param_1,undefined8 *param_2,longlong param_3,int param_4,
             localeinfo_struct *param_5)

{
  errno_t eVar1;
  int *piVar2;
  size_t _SizeInBytes;
  _strflt local_68;
  char local_50 [24];
  ulonglong local_38;
  
  local_38 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff68;
  FUN_18000dba0(*param_1,(int *)&local_68,local_50,0x16);
  if ((param_2 == (undefined8 *)0x0) || (param_3 == 0)) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    FUN_1800038fc();
  }
  else {
    _SizeInBytes = 0xffffffffffffffff;
    if (param_3 != -1) {
      _SizeInBytes = param_3 - (ulonglong)(local_68.sign == 0x2d);
    }
    eVar1 = _fptostr((char *)((ulonglong)(local_68.sign == 0x2d) + (longlong)param_2),_SizeInBytes,
                     local_68.decpt + param_4,(STRFLT)&local_68);
    if (eVar1 == 0) {
      _cftof2_l(param_2,param_3,param_4,(int *)&local_68,'\0',param_5);
    }
    else {
      *(undefined *)param_2 = 0;
    }
  }
  FUN_180002f40(local_38 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



// Library Function - Single Match
//  _cftog_l
// 
// Library: Visual Studio 2012 Release

void _cftog_l(undefined8 *param_1,undefined8 *param_2,undefined *param_3,int param_4,int param_5,
             localeinfo_struct *param_6)

{
  char *_Buf;
  errno_t eVar1;
  int *piVar2;
  undefined *_SizeInBytes;
  char *pcVar3;
  int iVar4;
  _strflt local_68;
  char local_50 [24];
  ulonglong local_38;
  
  local_38 = DAT_1800170a0 ^ (ulonglong)&stack0xffffffffffffff58;
  FUN_18000dba0(*param_1,(int *)&local_68,local_50,0x16);
  if ((param_2 == (undefined8 *)0x0) || (param_3 == (undefined *)0x0)) {
    piVar2 = _errno();
    *piVar2 = 0x16;
    FUN_1800038fc();
  }
  else {
    iVar4 = local_68.decpt + -1;
    _SizeInBytes = (undefined *)0xffffffffffffffff;
    _Buf = (char *)((ulonglong)(local_68.sign == 0x2d) + (longlong)param_2);
    if (param_3 != (undefined *)0xffffffffffffffff) {
      _SizeInBytes = param_3 + -(ulonglong)(local_68.sign == 0x2d);
    }
    eVar1 = _fptostr(_Buf,(size_t)_SizeInBytes,param_4,(STRFLT)&local_68);
    if (eVar1 == 0) {
      local_68.decpt = local_68.decpt + -1;
      if ((local_68.decpt < -4) || (param_4 <= local_68.decpt)) {
        FUN_18000ccc8((undefined *)param_2,param_3,param_4,param_5,(int *)&local_68,'\x01',param_6);
      }
      else {
        if (iVar4 < local_68.decpt) {
          do {
            pcVar3 = _Buf;
            _Buf = pcVar3 + 1;
          } while (*pcVar3 != '\0');
          pcVar3[-1] = '\0';
        }
        _cftof2_l(param_2,(longlong)param_3,param_4,(int *)&local_68,'\x01',param_6);
      }
    }
    else {
      *(undefined *)param_2 = 0;
    }
  }
  FUN_180002f40(local_38 ^ (ulonglong)&stack0xffffffffffffff58);
  return;
}



// Library Function - Single Match
//  _cropzeros_l
// 
// Library: Visual Studio 2012 Release

void _cropzeros_l(char *_Buf,_locale_t _Locale)

{
  char cVar1;
  char *pcVar2;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  char *pcVar3;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Locale);
  cVar1 = *_Buf;
  if (cVar1 != '\0') {
    do {
      if (cVar1 == ***(char ***)(local_28[0] + 0xf0)) break;
      _Buf = _Buf + 1;
      cVar1 = *_Buf;
    } while (cVar1 != '\0');
  }
  if (*_Buf != '\0') {
    do {
      _Buf = _Buf + 1;
      pcVar2 = _Buf;
      if (*_Buf == '\0') break;
    } while ((*_Buf + 0xbbU & 0xdf) != 0);
    do {
      pcVar3 = pcVar2;
      pcVar2 = pcVar3 + -1;
    } while (*pcVar2 == '0');
    if (*pcVar2 == ***(char ***)(local_28[0] + 0xf0)) {
      pcVar2 = pcVar3 + -2;
    }
    do {
      cVar1 = *_Buf;
      pcVar2 = pcVar2 + 1;
      _Buf = _Buf + 1;
      *pcVar2 = cVar1;
    } while (cVar1 != '\0');
  }
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  _forcdecpt_l
// 
// Library: Visual Studio 2012 Release

void _forcdecpt_l(char *_Buf,_locale_t _Locale)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  longlong local_28 [2];
  longlong local_18;
  char local_10;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_28,(localeinfo_struct *)_Locale);
  uVar2 = FUN_18000d8a0((int)*_Buf);
  if (uVar2 != 0x65) {
    do {
      _Buf = (char *)((byte *)_Buf + 1);
      iVar3 = isdigit((uint)(byte)*_Buf);
    } while (iVar3 != 0);
  }
  uVar2 = FUN_18000d8a0((int)*_Buf);
  if (uVar2 == 0x78) {
    _Buf = (char *)((byte *)_Buf + 2);
  }
  bVar4 = *_Buf;
  *_Buf = ***(byte ***)(local_28[0] + 0xf0);
  do {
    _Buf = (char *)((byte *)_Buf + 1);
    bVar1 = *_Buf;
    *_Buf = bVar4;
    bVar4 = bVar1;
  } while (*_Buf != 0);
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return;
}



void FUN_18000d4ac(char *param_1,int param_2,undefined8 *param_3)

{
  undefined8 uVar1;
  int iVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  short sVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint local_28;
  
  *(undefined4 *)param_3 = 0;
  *(undefined4 *)((longlong)param_3 + 4) = 0;
  *(undefined4 *)(param_3 + 1) = 0;
  sVar6 = 0x404e;
  if (param_2 != 0) {
    uVar5 = 0;
    uVar9 = 0;
    uVar8 = 0;
    bVar4 = true;
    do {
      uVar1 = *param_3;
      iVar2 = *(int *)(param_3 + 1);
      uVar10 = uVar5 * 4;
      uVar7 = (uVar9 * 2 | uVar5 >> 0x1f) * 2 | uVar5 * 2 >> 0x1f;
      uVar9 = (uVar8 * 2 | uVar9 >> 0x1f) * 2 | uVar9 * 2 >> 0x1f;
      local_28 = (uint)uVar1;
      *(uint *)param_3 = uVar10;
      uVar5 = uVar10 + local_28;
      *(uint *)((longlong)param_3 + 4) = uVar7;
      *(uint *)(param_3 + 1) = uVar9;
      if ((uVar5 < uVar10) || (bVar3 = false, uVar5 < local_28)) {
        bVar3 = bVar4;
      }
      *(uint *)param_3 = uVar5;
      uVar8 = uVar7;
      if (bVar3) {
        uVar8 = uVar7 + 1;
        if ((uVar8 < uVar7) || (bVar3 = false, uVar8 == 0)) {
          bVar3 = bVar4;
        }
        *(uint *)((longlong)param_3 + 4) = uVar8;
        if (bVar3) {
          uVar9 = uVar9 + 1;
          *(uint *)(param_3 + 1) = uVar9;
        }
      }
      uVar10 = (uint)((ulonglong)uVar1 >> 0x20);
      uVar7 = uVar8 + uVar10;
      if ((uVar7 < uVar8) || (bVar3 = false, uVar7 < uVar10)) {
        bVar3 = bVar4;
      }
      *(uint *)((longlong)param_3 + 4) = uVar7;
      if (bVar3) {
        uVar9 = uVar9 + 1;
        *(uint *)(param_3 + 1) = uVar9;
      }
      uVar10 = uVar5 * 2;
      uVar8 = (uVar9 + iVar2) * 2 | uVar7 >> 0x1f;
      *(uint *)param_3 = uVar10;
      *(uint *)(param_3 + 1) = uVar8;
      uVar7 = uVar7 * 2 | uVar5 >> 0x1f;
      *(uint *)((longlong)param_3 + 4) = uVar7;
      uVar5 = uVar10 + (int)*param_1;
      if ((uVar5 < uVar10) || (bVar3 = false, uVar5 < (uint)(int)*param_1)) {
        bVar3 = bVar4;
      }
      *(uint *)param_3 = uVar5;
      uVar9 = uVar7;
      if (bVar3) {
        uVar9 = uVar7 + 1;
        if ((uVar9 < uVar7) || (bVar3 = false, uVar9 == 0)) {
          bVar3 = bVar4;
        }
        *(uint *)((longlong)param_3 + 4) = uVar9;
        if (bVar3) {
          uVar8 = uVar8 + 1;
          *(uint *)(param_3 + 1) = uVar8;
        }
      }
      param_1 = param_1 + 1;
      *(uint *)((longlong)param_3 + 4) = uVar9;
      *(uint *)(param_3 + 1) = uVar8;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  if (*(int *)(param_3 + 1) == 0) {
    uVar5 = *(uint *)((longlong)param_3 + 4);
    do {
      uVar9 = *(uint *)param_3;
      uVar10 = uVar5 >> 0x10;
      *(uint *)param_3 = uVar9 << 0x10;
      uVar8 = uVar9 >> 0x10 | uVar5 << 0x10;
      sVar6 = sVar6 + -0x10;
      uVar9 = uVar5 >> 0x10;
      uVar5 = uVar8;
    } while (uVar9 == 0);
    *(uint *)((longlong)param_3 + 4) = uVar8;
    *(uint *)(param_3 + 1) = uVar10;
  }
  uVar5 = *(uint *)(param_3 + 1);
  if ((uVar5 & 0x8000) == 0) {
    uVar9 = *(uint *)param_3;
    uVar8 = *(uint *)((longlong)param_3 + 4);
    do {
      uVar10 = uVar5 * 2;
      uVar5 = uVar8 >> 0x1f;
      uVar8 = uVar8 * 2 | uVar9 >> 0x1f;
      uVar5 = uVar10 | uVar5;
      sVar6 = sVar6 + -1;
      uVar9 = uVar9 * 2;
    } while ((uVar10 & 0x8000) == 0);
    *(uint *)param_3 = uVar9;
    *(uint *)((longlong)param_3 + 4) = uVar8;
    *(uint *)(param_3 + 1) = uVar5;
  }
  *(short *)((longlong)param_3 + 10) = sVar6;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  isdigit
// 
// Library: Visual Studio 2012 Release

int isdigit(int _C)

{
  uint uVar1;
  localeinfo_struct local_28;
  longlong local_18;
  char local_10;
  
  if (_DAT_18001df58 == 0) {
    uVar1 = *(ushort *)(PTR_DAT_180017f88 + (longlong)_C * 2) & 4;
  }
  else {
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(localeinfo_struct *)0x0);
    if ((local_28.locinfo)->mb_cur_max < 2) {
      uVar1 = (local_28.locinfo)->pctype[_C] & 4;
    }
    else {
      uVar1 = _isctype_l(_C,4,(_locale_t)&local_28);
    }
    if (local_10 != '\0') {
      *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
    }
  }
  return (int)uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_18000d8a0(uint param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  CHAR local_res8;
  CHAR local_res9;
  undefined local_resa;
  byte local_res18;
  undefined local_res19;
  localeinfo_struct local_28;
  longlong local_18;
  char local_10;
  
  if (_DAT_18001df58 == 0) {
    if (param_1 - 0x41 < 0x1a) {
      param_1 = param_1 + 0x20;
    }
    return param_1;
  }
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,(localeinfo_struct *)0x0);
  if (param_1 < 0x100) {
    if ((local_28.locinfo)->mb_cur_max < 2) {
      uVar1 = (local_28.locinfo)->pctype[(int)param_1] & 1;
    }
    else {
      uVar1 = _isctype_l(param_1,1,(_locale_t)&local_28);
    }
    if (uVar1 == 0) goto LAB_18000d7b7;
    uVar1 = (uint)(local_28.locinfo)->pclmap[(int)param_1];
    goto LAB_18000d87b;
  }
  if ((local_28.locinfo)->mb_cur_max < 2) {
LAB_18000d807:
    piVar3 = _errno();
    iVar2 = 1;
    *piVar3 = 0x2a;
    local_res9 = '\0';
    local_res8 = (CHAR)param_1;
  }
  else {
    iVar2 = _isleadbyte_l((int)param_1 >> 8 & 0xff,(_locale_t)&local_28);
    if (iVar2 == 0) goto LAB_18000d807;
    local_resa = 0;
    iVar2 = 2;
    local_res8 = (CHAR)(param_1 >> 8);
    local_res9 = (CHAR)param_1;
  }
  iVar2 = __crtLCMapStringA((_locale_t)&local_28,(local_28.locinfo)->locale_name[2],0x100,
                            &local_res8,iVar2,(LPSTR)&local_res18,3,(local_28.locinfo)->lc_codepage,
                            1);
  if (iVar2 == 0) {
LAB_18000d7b7:
    if (local_10 == '\0') {
      return param_1;
    }
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
    return param_1;
  }
  uVar1 = (uint)local_res18;
  if (iVar2 != 1) {
    uVar1 = (uint)CONCAT11(local_res18,local_res19);
  }
LAB_18000d87b:
  if (local_10 != '\0') {
    *(uint *)(local_18 + 200) = *(uint *)(local_18 + 200) & 0xfffffffd;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  strrchr
// 
// Library: Visual Studio 2012 Release

char * strrchr(char *_Str,int _Ch)

{
  ulonglong uVar1;
  undefined4 in_EAX;
  uint uVar2;
  undefined (*pauVar3) [16];
  uint uVar4;
  int iVar5;
  char *pcVar6;
  uint uVar7;
  char *pcVar8;
  bool bVar9;
  bool bVar10;
  char cVar11;
  char cVar12;
  char cVar13;
  char cVar14;
  undefined in_XMM1 [16];
  undefined auVar15 [16];
  
  pauVar3 = (undefined (*) [16])0x0;
  if (_Ch == 0) {
    auVar15 = in_XMM1 & (undefined  [16])0x0;
    pcVar6 = (char *)((ulonglong)_Str & 0xfffffffffffffff0);
    cVar11 = SUB161(auVar15 >> 0x40,0);
    cVar12 = SUB161(auVar15 >> 0x48,0);
    cVar13 = SUB161(auVar15 >> 0x50,0);
    cVar14 = SUB161(auVar15 >> 0x58,0);
    uVar2 = pmovmskb(in_EAX,CONCAT115(-(pcVar6[0xf] == '\0'),
                                      CONCAT114(-(pcVar6[0xe] == '\0'),
                                                CONCAT113(-(pcVar6[0xd] == '\0'),
                                                          CONCAT112(-(pcVar6[0xc] == '\0'),
                                                                    CONCAT111(-(pcVar6[0xb] ==
                                                                               cVar14),CONCAT110(-(
                                                  pcVar6[10] == cVar13),
                                                  CONCAT19(-(pcVar6[9] == cVar12),
                                                           CONCAT18(-(pcVar6[8] == cVar11),
                                                                    CONCAT17(-(pcVar6[7] == '\0'),
                                                                             CONCAT16(-(pcVar6[6] ==
                                                                                       '\0'),
                                                  CONCAT15(-(pcVar6[5] == '\0'),
                                                           CONCAT14(-(pcVar6[4] == '\0'),
                                                                    CONCAT13(-(pcVar6[3] == '\0'),
                                                                             CONCAT12(-(pcVar6[2] ==
                                                                                       '\0'),
                                                  CONCAT11(-(pcVar6[1] == '\0'),-(*pcVar6 == '\0')))
                                                  ))))))))))))));
    uVar2 = uVar2 & -1 << ((byte)_Str & 0xf);
    while (uVar2 == 0) {
      uVar2 = pmovmskb(0,CONCAT115(-(pcVar6[0x1f] == '\0'),
                                   CONCAT114(-(pcVar6[0x1e] == '\0'),
                                             CONCAT113(-(pcVar6[0x1d] == '\0'),
                                                       CONCAT112(-(pcVar6[0x1c] == '\0'),
                                                                 CONCAT111(-(pcVar6[0x1b] == cVar14)
                                                                           ,CONCAT110(-(pcVar6[0x1a]
                                                                                       == cVar13),
                                                                                      CONCAT19(-(
                                                  pcVar6[0x19] == cVar12),
                                                  CONCAT18(-(pcVar6[0x18] == cVar11),
                                                           CONCAT17(-(pcVar6[0x17] == '\0'),
                                                                    CONCAT16(-(pcVar6[0x16] == '\0')
                                                                             ,CONCAT15(-(pcVar6[0x15
                                                  ] == '\0'),
                                                  CONCAT14(-(pcVar6[0x14] == '\0'),
                                                           CONCAT13(-(pcVar6[0x13] == '\0'),
                                                                    CONCAT12(-(pcVar6[0x12] == '\0')
                                                                             ,CONCAT11(-(pcVar6[0x11
                                                  ] == '\0'),-(pcVar6[0x10] == '\0')))))))))))))))))
      ;
      pcVar6 = pcVar6 + 0x10;
    }
    uVar4 = 0;
    if (uVar2 != 0) {
      for (; (uVar2 >> uVar4 & 1) == 0; uVar4 = uVar4 + 1) {
      }
    }
    pauVar3 = (undefined (*) [16])(pcVar6 + uVar4);
  }
  else {
    if (_DAT_180017230 < 2) {
      uVar2 = (uint)_Str & 0xf;
      pcVar6 = (char *)((ulonglong)_Str & 0xfffffffffffffff0);
      uVar7 = -1 << (sbyte)uVar2;
      auVar15 = pshuflw(in_XMM1,ZEXT416((_Ch & 0xffU) << 8 | _Ch & 0xffU),0);
      uVar4 = pmovmskb(uVar2,CONCAT115(-(pcVar6[0xf] == '\0'),
                                       CONCAT114(-(pcVar6[0xe] == '\0'),
                                                 CONCAT113(-(pcVar6[0xd] == '\0'),
                                                           CONCAT112(-(pcVar6[0xc] == '\0'),
                                                                     CONCAT111(-(pcVar6[0xb] == '\0'
                                                                                ),CONCAT110(-(pcVar6
                                                  [10] == '\0'),
                                                  CONCAT19(-(pcVar6[9] == '\0'),
                                                           CONCAT18(-(pcVar6[8] == '\0'),
                                                                    CONCAT17(-(pcVar6[7] == '\0'),
                                                                             CONCAT16(-(pcVar6[6] ==
                                                                                       '\0'),
                                                  CONCAT15(-(pcVar6[5] == '\0'),
                                                           CONCAT14(-(pcVar6[4] == '\0'),
                                                                    CONCAT13(-(pcVar6[3] == '\0'),
                                                                             CONCAT12(-(pcVar6[2] ==
                                                                                       '\0'),
                                                  CONCAT11(-(pcVar6[1] == '\0'),-(*pcVar6 == '\0')))
                                                  ))))))))))))));
      cVar11 = SUB161(auVar15,0);
      cVar12 = SUB161(auVar15 >> 8,0);
      cVar13 = SUB161(auVar15 >> 0x10,0);
      cVar14 = SUB161(auVar15 >> 0x18,0);
      uVar2 = pmovmskb(_Ch,CONCAT115(-(cVar14 == pcVar6[0xf]),
                                     CONCAT114(-(cVar13 == pcVar6[0xe]),
                                               CONCAT113(-(cVar12 == pcVar6[0xd]),
                                                         CONCAT112(-(cVar11 == pcVar6[0xc]),
                                                                   CONCAT111(-(cVar14 == pcVar6[0xb]
                                                                              ),CONCAT110(-(cVar13 
                                                  == pcVar6[10]),
                                                  CONCAT19(-(cVar12 == pcVar6[9]),
                                                           CONCAT18(-(cVar11 == pcVar6[8]),
                                                                    CONCAT17(-(cVar14 == pcVar6[7]),
                                                                             CONCAT16(-(cVar13 ==
                                                                                       pcVar6[6]),
                                                                                      CONCAT15(-(
                                                  cVar12 == pcVar6[5]),
                                                  CONCAT14(-(cVar11 == pcVar6[4]),
                                                           CONCAT13(-(cVar14 == pcVar6[3]),
                                                                    CONCAT12(-(cVar13 == pcVar6[2]),
                                                                             CONCAT11(-(cVar12 ==
                                                                                       pcVar6[1]),
                                                                                      -(cVar11 ==
                                                                                       *pcVar6))))))
                                                  )))))))))));
      uVar2 = uVar2 & uVar7;
      uVar4 = uVar4 & uVar7;
      while (uVar4 == 0) {
        uVar4 = 0x1f;
        if (uVar2 != 0) {
          for (; uVar2 >> uVar4 == 0; uVar4 = uVar4 - 1) {
          }
        }
        if (uVar2 != 0) {
          pauVar3 = (undefined (*) [16])(pcVar6 + uVar4);
        }
        pcVar8 = pcVar6 + 0x10;
        uVar4 = pmovmskb((int)(undefined (*) [16])(pcVar6 + uVar4),
                         CONCAT115(-(pcVar6[0x1f] == '\0'),
                                   CONCAT114(-(pcVar6[0x1e] == '\0'),
                                             CONCAT113(-(pcVar6[0x1d] == '\0'),
                                                       CONCAT112(-(pcVar6[0x1c] == '\0'),
                                                                 CONCAT111(-(pcVar6[0x1b] == '\0'),
                                                                           CONCAT110(-(pcVar6[0x1a]
                                                                                      == '\0'),
                                                                                     CONCAT19(-(
                                                  pcVar6[0x19] == '\0'),
                                                  CONCAT18(-(pcVar6[0x18] == '\0'),
                                                           CONCAT17(-(pcVar6[0x17] == '\0'),
                                                                    CONCAT16(-(pcVar6[0x16] == '\0')
                                                                             ,CONCAT15(-(pcVar6[0x15
                                                  ] == '\0'),
                                                  CONCAT14(-(pcVar6[0x14] == '\0'),
                                                           CONCAT13(-(pcVar6[0x13] == '\0'),
                                                                    CONCAT12(-(pcVar6[0x12] == '\0')
                                                                             ,CONCAT11(-(pcVar6[0x11
                                                  ] == '\0'),-(*pcVar8 == '\0')))))))))))))))));
        uVar2 = pmovmskb(uVar2,CONCAT115(-(cVar14 == pcVar6[0x1f]),
                                         CONCAT114(-(cVar13 == pcVar6[0x1e]),
                                                   CONCAT113(-(cVar12 == pcVar6[0x1d]),
                                                             CONCAT112(-(cVar11 == pcVar6[0x1c]),
                                                                       CONCAT111(-(cVar14 ==
                                                                                  pcVar6[0x1b]),
                                                                                 CONCAT110(-(cVar13 
                                                  == pcVar6[0x1a]),
                                                  CONCAT19(-(cVar12 == pcVar6[0x19]),
                                                           CONCAT18(-(cVar11 == pcVar6[0x18]),
                                                                    CONCAT17(-(cVar14 ==
                                                                              pcVar6[0x17]),
                                                                             CONCAT16(-(cVar13 ==
                                                                                       pcVar6[0x16])
                                                                                      ,CONCAT15(-(
                                                  cVar12 == pcVar6[0x15]),
                                                  CONCAT14(-(cVar11 == pcVar6[0x14]),
                                                           CONCAT13(-(cVar14 == pcVar6[0x13]),
                                                                    CONCAT12(-(cVar13 ==
                                                                              pcVar6[0x12]),
                                                                             CONCAT11(-(cVar12 ==
                                                                                       pcVar6[0x11])
                                                                                      ,-(cVar11 ==
                                                                                        *pcVar8)))))
                                                  ))))))))))));
        pcVar6 = pcVar8;
      }
      uVar2 = uVar2 & (-uVar4 & uVar4) - 1;
      uVar4 = 0x1f;
      if (uVar2 != 0) {
        for (; uVar2 >> uVar4 == 0; uVar4 = uVar4 - 1) {
        }
      }
      if (uVar2 != 0) {
        pauVar3 = (undefined (*) [16])(pcVar6 + uVar4);
      }
    }
    else {
      uVar1 = (ulonglong)_Str & 0xf;
      while (bVar10 = uVar1 == 0, !bVar10) {
        if (*_Str == _Ch) {
          pauVar3 = (undefined (*) [16])_Str;
        }
        if (*_Str == '\0') {
          return (char *)pauVar3;
        }
        _Str = _Str + 1;
        uVar1 = (ulonglong)_Str & 0xf;
      }
      bVar9 = false;
      while( true ) {
        iVar5 = pcmpistri(ZEXT416(_Ch & 0xff),*(undefined (*) [16])_Str,0x40);
        if (bVar9) {
          pauVar3 = (undefined (*) [16])(_Str + iVar5);
          bVar10 = pauVar3 == (undefined (*) [16])0x0;
          pcmpistri(ZEXT416(_Ch & 0xff),*(undefined (*) [16])_Str,0x40);
        }
        if (bVar10) break;
        bVar9 = (undefined (*) [16])0xffffffffffffffef < _Str;
        _Str = (char *)((longlong)_Str + 0x10);
        bVar10 = (undefined (*) [16])_Str == (undefined (*) [16])0x0;
      }
    }
  }
  return (char *)pauVar3;
}



// Library Function - Single Match
//  _fptostr
// 
// Library: Visual Studio 2012 Release

errno_t _fptostr(char *_Buf,size_t _SizeInBytes,int _Digits,STRFLT _PtFlt)

{
  undefined8 *_Str;
  int iVar1;
  errno_t *peVar2;
  undefined8 *puVar3;
  size_t sVar4;
  char *pcVar5;
  char cVar6;
  errno_t eVar7;
  
  pcVar5 = _PtFlt->mantissa;
  if ((_Buf == (char *)0x0) || (_SizeInBytes == 0)) {
    peVar2 = _errno();
    eVar7 = 0x16;
  }
  else {
    *_Buf = '\0';
    iVar1 = 0;
    if (0 < _Digits) {
      iVar1 = _Digits;
    }
    if ((ulonglong)(longlong)(iVar1 + 1) < _SizeInBytes) {
      _Str = (undefined8 *)(_Buf + 1);
      *_Buf = '0';
      puVar3 = _Str;
      for (; 0 < _Digits; _Digits = _Digits + -1) {
        if (*pcVar5 == '\0') {
          cVar6 = '0';
        }
        else {
          cVar6 = *pcVar5;
          pcVar5 = pcVar5 + 1;
        }
        *(char *)puVar3 = cVar6;
        puVar3 = (undefined8 *)((longlong)puVar3 + 1);
      }
      *(undefined *)puVar3 = 0;
      if ((-1 < _Digits) && ('4' < *pcVar5)) {
        while (puVar3 = (undefined8 *)((longlong)puVar3 + -1), *(char *)puVar3 == '9') {
          *(undefined *)puVar3 = 0x30;
        }
        *(char *)puVar3 = *(char *)puVar3 + '\x01';
      }
      if (*_Buf == '1') {
        _PtFlt->decpt = _PtFlt->decpt + 1;
      }
      else {
        sVar4 = strlen((char *)_Str);
        FUN_180002f70((undefined8 *)_Buf,_Str,sVar4 + 1);
      }
      return 0;
    }
    peVar2 = _errno();
    eVar7 = 0x22;
  }
  *peVar2 = eVar7;
  FUN_1800038fc();
  return eVar7;
}



// Library Function - Single Match
//  __dtold
// 
// Library: Visual Studio 2012 Release

void __dtold(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  ushort uVar3;
  uint uVar4;
  ushort uVar5;
  
  uVar4 = param_2[1];
  uVar5 = *(ushort *)((longlong)param_2 + 6) & 0x8000;
  uVar1 = *param_2;
  uVar3 = *(ushort *)((longlong)param_2 + 6) >> 4 & 0x7ff;
  uVar2 = 0x80000000;
  if (uVar3 == 0) {
    if (((uVar4 & 0xfffff) == 0) && (uVar1 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      goto LAB_18000db92;
    }
    uVar3 = 0x3c01;
    uVar2 = 0;
  }
  else {
    if (uVar3 == 0x7ff) {
      uVar3 = 0x7fff;
    }
    else {
      uVar3 = uVar3 + 0x3c00;
    }
  }
  *param_1 = uVar1 << 0xb;
  uVar4 = uVar1 >> 0x15 | (uVar4 & 0xfffff) << 0xb | uVar2;
  param_1[1] = uVar4;
  if (uVar2 == 0) {
    do {
      uVar4 = *param_1 >> 0x1f | uVar4 * 2;
      *param_1 = *param_1 * 2;
      uVar3 = uVar3 - 1;
    } while (-1 < (int)uVar4);
    param_1[1] = uVar4;
  }
  uVar5 = uVar5 | uVar3;
LAB_18000db92:
  *(ushort *)(param_1 + 2) = uVar5;
  return;
}



void FUN_18000dba0(undefined8 param_1,int *param_2,char *param_3,rsize_t param_4)

{
  code *pcVar1;
  int iVar2;
  errno_t eVar3;
  undefined auStack168 [32];
  undefined8 local_88;
  undefined8 local_78;
  undefined2 local_70;
  undefined8 local_68;
  undefined2 local_60;
  short local_58;
  char local_56;
  char local_54 [28];
  ulonglong local_38;
  
  local_38 = DAT_1800170a0 ^ (ulonglong)auStack168;
  local_78 = param_1;
  __dtold((uint *)&local_68,(uint *)&local_78);
  local_78 = local_68;
  local_70 = local_60;
  iVar2 = FUN_18000dc58((int *)&local_78,0x11,0,&local_58);
  *param_2 = (int)local_56;
  param_2[1] = (int)local_58;
  param_2[2] = iVar2;
  eVar3 = strcpy_s(param_3,param_4,local_54);
  if (eVar3 == 0) {
    *(char **)(param_2 + 4) = param_3;
    FUN_180002f40(local_38 ^ (ulonglong)auStack168);
    return;
  }
  local_88 = 0;
  FUN_18000391c();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_18000dc58(int *param_1,int param_2,uint param_3,short *param_4)

{
  short *psVar1;
  code *pcVar2;
  undefined3 uVar3;
  bool bVar4;
  undefined uVar5;
  ushort uVar6;
  errno_t eVar7;
  short sVar8;
  ushort uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  uint *puVar13;
  ulonglong uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  undefined *puVar18;
  char cVar19;
  ushort uVar20;
  uint uVar21;
  uint uVar22;
  longlong lVar23;
  short *psVar24;
  short *psVar25;
  int iVar26;
  int iVar27;
  ushort *puVar28;
  undefined4 *puVar29;
  ulonglong *puVar30;
  undefined auStack248 [32];
  undefined8 local_d8;
  ushort local_c8;
  ushort local_c6;
  int local_c4;
  uint local_c0;
  undefined2 local_bc;
  undefined *local_b8;
  uint local_b0;
  int local_ac;
  int local_a8;
  short *local_a0;
  uint local_98;
  ulonglong *local_90;
  byte local_88;
  undefined uStack135;
  ushort uStack134;
  ushort auStack132 [6];
  ushort local_78 [4];
  ushort uStack112;
  undefined uStack110;
  byte bStack109;
  int local_68;
  int local_64;
  undefined4 local_60;
  ulonglong local_58;
  undefined4 local_50;
  ulonglong local_48;
  
  local_48 = DAT_1800170a0 ^ (ulonglong)auStack248;
  iVar27 = *param_1;
  uVar21 = param_1[1];
  local_c6 = *(ushort *)(param_1 + 2) & 0x8000;
  uVar20 = *(ushort *)(param_1 + 2) & 0x7fff;
  local_68 = -0x33333334;
  local_64 = -0x33333334;
  local_60 = 0x3ffbcccc;
  if (local_c6 == 0) {
    *(undefined *)(param_4 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_4 + 1) = 0x2d;
  }
  local_ac = param_2;
  local_a0 = param_4;
  local_98 = param_3;
  if (uVar20 == 0) {
    if ((uVar21 != 0) || (iVar27 != 0)) goto LAB_18000ddea;
    uVar5 = 0x20;
    if (local_c6 == 0x8000) {
      uVar5 = 0x2d;
    }
LAB_18000dd05:
    *param_4 = 0;
    *(undefined *)(param_4 + 1) = uVar5;
    *(undefined2 *)((longlong)param_4 + 3) = 0x3001;
  }
  else {
    if (uVar20 == 0x7fff) {
      *param_4 = 1;
      if (((uVar21 == 0x80000000) && (iVar27 == 0)) || ((uVar21 >> 0x1e & 1) != 0)) {
        if ((local_c6 == 0) || (uVar21 != 0xc0000000)) {
          if ((uVar21 != 0x80000000) || (iVar27 != 0)) goto LAB_18000ddc1;
          eVar7 = strcpy_s((char *)(param_4 + 2),0x16,"1#INF");
          if (eVar7 != 0) {
            local_d8 = 0;
            FUN_18000391c();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
        }
        else {
          if (iVar27 != 0) {
LAB_18000ddc1:
            eVar7 = strcpy_s((char *)(param_4 + 2),0x16,"1#QNAN");
            if (eVar7 != 0) {
              local_d8 = 0;
              FUN_18000391c();
              pcVar2 = (code *)swi(3);
              (*pcVar2)();
              return;
            }
            goto LAB_18000ddde;
          }
          eVar7 = strcpy_s((char *)(param_4 + 2),0x16,"1#IND");
          if (eVar7 != 0) {
            local_d8 = 0;
            FUN_18000391c();
            pcVar2 = (code *)swi(3);
            (*pcVar2)();
            return;
          }
        }
        *(undefined *)((longlong)param_4 + 3) = 5;
      }
      else {
        eVar7 = strcpy_s((char *)(param_4 + 2),0x16,"1#SNAN");
        if (eVar7 != 0) {
          local_d8 = 0;
          FUN_18000391c();
          pcVar2 = (code *)swi(3);
          (*pcVar2)();
          return;
        }
LAB_18000ddde:
        *(undefined *)((longlong)param_4 + 3) = 6;
      }
      goto LAB_18000e676;
    }
LAB_18000ddea:
    local_78[1] = (ushort)iVar27;
    local_78[2] = (ushort)((uint)iVar27 >> 0x10);
    uStack110 = (undefined)uVar20;
    bStack109 = (byte)(uVar20 >> 8);
    puVar18 = &DAT_180018330;
    local_78[3] = (ushort)uVar21;
    uStack112 = (ushort)(uVar21 >> 0x10);
    local_78[0] = 0;
    local_a8 = 5;
    iVar10 = ((uint)(uVar20 >> 8) + (uVar21 >> 0x18) * 2) * 0x4d +
             (uint)uVar20 * 0x4d10 + -0x134312f4;
    local_c0 = iVar10 >> 0x10;
    sVar8 = (short)((uint)iVar10 >> 0x10);
    uVar21 = SEXT24(sVar8);
    if (-uVar21 == 0) {
LAB_18000e1c4:
      uVar22 = CONCAT22(local_78[3],local_78[2]);
      uVar21 = iVar27 << 0x10;
    }
    else {
      uVar15 = -uVar21;
      if (0 < (int)uVar21) {
        puVar18 = (undefined *)0x180018490;
        uVar15 = uVar21;
      }
      if (uVar15 == 0) goto LAB_18000e1c4;
      uVar22 = CONCAT22(local_78[3],local_78[2]);
      uVar21 = iVar27 << 0x10;
      do {
        iVar27 = 0;
        puVar18 = puVar18 + 0x54;
        local_b0 = (int)uVar15 >> 3;
        if ((uVar15 & 7) != 0) {
          local_90 = (ulonglong *)(puVar18 + (longlong)(int)(uVar15 & 7) * 0xc);
          if (0x7fff < *(ushort *)local_90) {
            puVar30 = local_90 + 1;
            uVar14 = *local_90;
            local_90 = &local_58;
            local_50 = *(undefined4 *)puVar30;
            local_58._0_6_ = CONCAT42((int)(uVar14 >> 0x10) + -1,(short)uVar14);
            local_58 = uVar14 & 0xffff000000000000 | (ulonglong)(uint6)local_58;
          }
          local_c4 = 0;
          uVar9 = *(ushort *)((longlong)local_90 + 10) & 0x7fff;
          local_88 = 0;
          uStack135 = 0;
          uStack134 = 0;
          auStack132[0] = 0;
          auStack132[1] = 0;
          uVar6 = CONCAT11(bStack109,uStack110) & 0x7fff;
          auStack132[2] = 0;
          auStack132[3] = 0;
          local_c8 = (*(ushort *)((longlong)local_90 + 10) ^ CONCAT11(bStack109,uStack110)) & 0x8000
          ;
          uVar20 = uVar6 + uVar9;
          if (((uVar6 < 0x7fff) && (uVar9 < 0x7fff)) && (uVar20 < 0xbffe)) {
            if (0x3fbf < uVar20) {
              if (((uVar6 == 0) &&
                  (uVar20 = uVar20 + 1,
                  (CONCAT13(bStack109,CONCAT12(uStack110,uStack112)) & 0x7fffffff) == 0)) &&
                 ((uVar22 == 0 && (uVar21 == 0)))) {
                uStack110 = 0;
                bStack109 = 0;
                goto LAB_18000e1ad;
              }
              if (((uVar9 == 0) &&
                  (uVar20 = uVar20 + 1, (*(uint *)(local_90 + 1) & 0x7fffffff) == 0)) &&
                 ((*(int *)((longlong)local_90 + 4) == 0 && (*(int *)local_90 == 0))))
              goto LAB_18000df34;
              iVar10 = 5;
              puVar13 = (uint *)&local_88;
              do {
                if (0 < iVar10) {
                  puVar30 = local_90 + 1;
                  puVar28 = (ushort *)((longlong)local_78 + (longlong)(iVar27 * 2));
                  iVar26 = iVar10;
                  do {
                    uVar21 = *puVar13 + (uint)*puVar28 * (uint)*(ushort *)puVar30;
                    if ((uVar21 < *puVar13) ||
                       (bVar4 = false, uVar21 < (uint)*puVar28 * (uint)*(ushort *)puVar30)) {
                      bVar4 = true;
                    }
                    *puVar13 = uVar21;
                    if (bVar4) {
                      *(short *)(puVar13 + 1) = *(short *)(puVar13 + 1) + 1;
                    }
                    iVar26 = iVar26 + -1;
                    puVar28 = puVar28 + 1;
                    puVar30 = (ulonglong *)((longlong)puVar30 + -2);
                  } while (0 < iVar26);
                }
                iVar10 = iVar10 + -1;
                puVar13 = (uint *)((longlong)puVar13 + 2);
                iVar27 = iVar27 + 1;
              } while (0 < iVar10);
              uVar15 = CONCAT22(auStack132[3],auStack132[2]);
              uVar21 = CONCAT22(uStack134,CONCAT11(uStack135,local_88));
              uVar20 = uVar20 + 0xc002;
              uVar22 = uVar21;
              if ((short)uVar20 < 1) {
LAB_18000e066:
                uVar20 = uVar20 - 1;
                if (-1 < (short)uVar20) goto LAB_18000e0d3;
                uVar14 = (ulonglong)(ushort)-uVar20;
                local_bc = 0;
                iVar27 = local_c4;
                do {
                  uVar22 = uVar15;
                  if ((local_88 & 1) != 0) {
                    iVar27 = iVar27 + 1;
                  }
                  uVar16 = CONCAT22(auStack132[1],auStack132[0]);
                  uVar11 = uVar21 >> 1;
                  auStack132[1] = auStack132[1] >> 1 | (ushort)((uVar22 << 0x1f) >> 0x10);
                  uVar15 = uVar22 >> 1;
                  uVar21 = uVar11 | uVar16 << 0x1f;
                  auStack132[0] = (ushort)(uVar16 >> 1);
                  local_88 = (byte)uVar11;
                  uStack135 = (undefined)(uVar11 >> 8);
                  uStack134 = (ushort)(uVar21 >> 0x10);
                  uVar14 = uVar14 - 1;
                } while (uVar14 != 0);
                uVar20 = 0;
                auStack132[2] = (ushort)uVar15;
                auStack132[3] = (ushort)(uVar22 >> 0x11);
                if (iVar27 == 0) goto LAB_18000e0d3;
                uVar6 = (ushort)uVar11 | 1;
                local_88 = (byte)uVar6;
                uVar21 = uVar11 | 1;
              }
              else {
                do {
                  uVar21 = uVar22;
                  if ((uVar15 & 0x80000000) != 0) break;
                  uVar16 = uVar15 * 2;
                  uVar21 = uVar22 * 2;
                  iVar27 = CONCAT22(auStack132[1],auStack132[0]) * 2;
                  uVar20 = uVar20 - 1;
                  auStack132[0] = (ushort)iVar27 | (ushort)(uVar22 >> 0x1f);
                  uVar15 = uVar16 | auStack132[1] >> 0xf;
                  local_88 = (byte)uVar21;
                  uStack135 = (undefined)(uVar21 >> 8);
                  uStack134 = (ushort)(uVar21 >> 0x10);
                  auStack132[1] = (ushort)((uint)iVar27 >> 0x10);
                  auStack132[2] = (ushort)uVar15;
                  auStack132[3] = (ushort)(uVar16 >> 0x10);
                  uVar22 = uVar21;
                } while (0 < (short)uVar20);
                if ((short)uVar20 < 1) goto LAB_18000e066;
LAB_18000e0d3:
                uVar6 = CONCAT11(uStack135,local_88);
              }
              if ((0x8000 < uVar6) || ((uVar21 & 0x1ffff) == 0x18000)) {
                if (CONCAT22(auStack132[0],uStack134) == -1) {
                  uStack134 = 0;
                  auStack132[0] = 0;
                  if (CONCAT22(auStack132[2],auStack132[1]) == -1) {
                    auStack132[1] = 0;
                    auStack132[2] = 0;
                    if (auStack132[3] == 0xffff) {
                      auStack132[3] = 0x8000;
                      uVar20 = uVar20 + 1;
                    }
                    else {
                      auStack132[3] = auStack132[3] + 1;
                    }
                  }
                  else {
                    iVar27 = CONCAT22(auStack132[2],auStack132[1]) + 1;
                    auStack132[1] = (ushort)iVar27;
                    auStack132[2] = (ushort)((uint)iVar27 >> 0x10);
                  }
                  uVar15 = CONCAT22(auStack132[3],auStack132[2]);
                }
                else {
                  iVar27 = CONCAT22(auStack132[0],uStack134) + 1;
                  uStack134 = (ushort)iVar27;
                  auStack132[0] = (ushort)((uint)iVar27 >> 0x10);
                }
              }
              if (uVar20 < 0x7fff) {
                bStack109 = (byte)(uVar20 >> 8) | (byte)(local_c8 >> 8);
                local_78[3] = (ushort)uVar15;
                uStack112 = (ushort)(uVar15 >> 0x10);
                local_78[0] = uStack134;
                local_78[1] = auStack132[0];
                local_78[2] = auStack132[1];
                uVar22 = CONCAT22(local_78[3],auStack132[1]);
                uVar21 = CONCAT22(auStack132[0],uStack134);
                uStack110 = (undefined)uVar20;
                goto LAB_18000e1ad;
              }
              goto LAB_18000e18f;
            }
LAB_18000df34:
            local_78[2] = 0;
            local_78[3] = 0;
            uStack112 = 0;
            uStack110 = 0;
            bStack109 = 0;
          }
          else {
LAB_18000e18f:
            local_78[2] = 0;
            local_78[3] = 0;
            iVar27 = (-(uint)(local_c8 != 0) & 0x80000000) + 0x7fff8000;
            uStack112 = (ushort)iVar27;
            uStack110 = (undefined)((uint)iVar27 >> 0x10);
            bStack109 = (byte)((uint)iVar27 >> 0x18);
          }
          local_78[3] = 0;
          local_78[2] = 0;
          uVar22 = 0;
          local_78[0] = 0;
          local_78[1] = 0;
          uVar21 = uVar22;
        }
LAB_18000e1ad:
        uVar15 = local_b0;
        local_b8 = puVar18;
      } while (local_b0 != 0);
    }
    iVar27 = 0;
    uVar15 = CONCAT13(bStack109,CONCAT12(uStack110,uStack112));
    uVar20 = (ushort)(uVar15 >> 0x10);
    uVar16 = uVar22;
    if (0x3ffe < uVar20) {
      local_c0 = local_c0 & 0xffff0000 | (uint)(ushort)(sVar8 + 1);
      uVar16 = 0;
      local_c4 = 0;
      local_88 = 0;
      uStack135 = 0;
      uStack134 = 0;
      auStack132[0] = 0;
      auStack132[1] = 0;
      auStack132[2] = 0;
      auStack132[3] = 0;
      uVar9 = (local_60._2_2_ ^ uVar20) & 0x8000;
      uVar6 = (uVar20 & 0x7fff) + (local_60._2_2_ & 0x7fff);
      if ((((uVar20 & 0x7fff) < 0x7fff) && ((local_60._2_2_ & 0x7fff) < 0x7fff)) && (uVar6 < 0xbffe)
         ) {
        if (uVar6 < 0x3fc0) {
LAB_18000e248:
          uStack112 = 0;
          uStack110 = 0;
          bStack109 = 0;
          uVar21 = uVar16;
        }
        else {
          if ((((uVar15 & 0x7fff0000) == 0) &&
              (uVar6 = uVar6 + 1,
              (CONCAT13(bStack109,CONCAT12(uStack110,uStack112)) & 0x7fffffff) == 0)) &&
             ((uVar22 == 0 && (uVar21 == 0)))) {
            uStack110 = 0;
            bStack109 = 0;
            uVar16 = uVar22;
          }
          else {
            if ((((local_60 & 0x7fff0000) == 0) && (uVar6 = uVar6 + 1, (local_60 & 0x7fffffff) == 0)
                ) && ((local_64 == 0 && (local_68 == 0)))) goto LAB_18000e248;
            puVar13 = (uint *)&local_88;
            do {
              if (0 < local_a8) {
                puVar29 = &local_60;
                puVar28 = (ushort *)((longlong)local_78 + (longlong)(iVar27 * 2));
                iVar10 = local_a8;
                do {
                  bVar4 = false;
                  uVar21 = *puVar13 + (uint)*(ushort *)puVar29 * (uint)*puVar28;
                  if ((uVar21 < *puVar13) || (uVar21 < (uint)*(ushort *)puVar29 * (uint)*puVar28)) {
                    bVar4 = true;
                  }
                  *puVar13 = uVar21;
                  if (bVar4) {
                    *(short *)(puVar13 + 1) = *(short *)(puVar13 + 1) + 1;
                  }
                  iVar10 = iVar10 + -1;
                  puVar28 = puVar28 + 1;
                  puVar29 = (undefined4 *)((longlong)puVar29 + -2);
                } while (0 < iVar10);
              }
              local_a8 = local_a8 + -1;
              puVar13 = (uint *)((longlong)puVar13 + 2);
              iVar27 = iVar27 + 1;
            } while (0 < local_a8);
            uVar15 = CONCAT22(auStack132[3],auStack132[2]);
            uVar21 = CONCAT22(uStack134,CONCAT11(uStack135,local_88));
            uVar6 = uVar6 + 0xc002;
            uVar22 = uVar21;
            if ((short)uVar6 < 1) {
LAB_18000e36d:
              uVar6 = uVar6 - 1;
              if (-1 < (short)uVar6) goto LAB_18000e3d2;
              uVar14 = (ulonglong)(ushort)-uVar6;
              uVar6 = 0;
              iVar27 = local_c4;
              do {
                uVar22 = uVar15;
                if ((local_88 & 1) != 0) {
                  iVar27 = iVar27 + 1;
                }
                uVar16 = CONCAT22(auStack132[1],auStack132[0]);
                uVar11 = uVar21 >> 1;
                auStack132[1] = auStack132[1] >> 1 | (ushort)((uVar22 << 0x1f) >> 0x10);
                uVar15 = uVar22 >> 1;
                uVar21 = uVar11 | uVar16 << 0x1f;
                auStack132[0] = (ushort)(uVar16 >> 1);
                local_88 = (byte)uVar11;
                uStack135 = (undefined)(uVar11 >> 8);
                uStack134 = (ushort)(uVar21 >> 0x10);
                uVar14 = uVar14 - 1;
              } while (uVar14 != 0);
              auStack132[2] = (ushort)uVar15;
              auStack132[3] = (ushort)(uVar22 >> 0x11);
              if (iVar27 == 0) goto LAB_18000e3d2;
              uVar20 = (ushort)uVar11 | 1;
              local_88 = (byte)uVar20;
              uVar21 = uVar11 | 1;
            }
            else {
              do {
                uVar21 = uVar22;
                if ((uVar15 & 0x80000000) != 0) break;
                uVar16 = uVar15 * 2;
                uVar21 = uVar22 * 2;
                iVar27 = CONCAT22(auStack132[1],auStack132[0]) * 2;
                uVar6 = uVar6 - 1;
                auStack132[0] = (ushort)iVar27 | (ushort)(uVar22 >> 0x1f);
                uVar15 = uVar16 | auStack132[1] >> 0xf;
                local_88 = (byte)uVar21;
                uStack135 = (undefined)(uVar21 >> 8);
                uStack134 = (ushort)(uVar21 >> 0x10);
                auStack132[1] = (ushort)((uint)iVar27 >> 0x10);
                auStack132[2] = (ushort)uVar15;
                auStack132[3] = (ushort)(uVar16 >> 0x10);
                uVar22 = uVar21;
              } while (0 < (short)uVar6);
              if ((short)uVar6 < 1) goto LAB_18000e36d;
LAB_18000e3d2:
              uVar20 = CONCAT11(uStack135,local_88);
            }
            if ((0x8000 < uVar20) || ((uVar21 & 0x1ffff) == 0x18000)) {
              if (CONCAT22(auStack132[0],uStack134) == -1) {
                uStack134 = 0;
                auStack132[0] = 0;
                if (CONCAT22(auStack132[2],auStack132[1]) == -1) {
                  auStack132[1] = 0;
                  auStack132[2] = 0;
                  if (auStack132[3] == 0xffff) {
                    auStack132[3] = 0x8000;
                    uVar6 = uVar6 + 1;
                  }
                  else {
                    auStack132[3] = auStack132[3] + 1;
                  }
                }
                else {
                  iVar27 = CONCAT22(auStack132[2],auStack132[1]) + 1;
                  auStack132[1] = (ushort)iVar27;
                  auStack132[2] = (ushort)((uint)iVar27 >> 0x10);
                }
                uVar15 = CONCAT22(auStack132[3],auStack132[2]);
              }
              else {
                iVar27 = CONCAT22(auStack132[0],uStack134) + 1;
                uStack134 = (ushort)iVar27;
                auStack132[0] = (ushort)((uint)iVar27 >> 0x10);
              }
            }
            if (uVar6 < 0x7fff) {
              bStack109 = (byte)(uVar6 >> 8) | (byte)(uVar9 >> 8);
              local_78[3] = (ushort)uVar15;
              uStack112 = (ushort)(uVar15 >> 0x10);
              local_78[0] = uStack134;
              uStack110 = (undefined)uVar6;
              local_78[1] = auStack132[0];
              local_78[2] = auStack132[1];
              uVar16 = CONCAT22(local_78[3],auStack132[1]);
              uVar21 = CONCAT22(auStack132[0],uStack134);
            }
            else {
              iVar27 = (-(uint)(uVar9 != 0) & 0x80000000) + 0x7fff8000;
              uStack112 = (ushort)iVar27;
              uStack110 = (undefined)((uint)iVar27 >> 0x10);
              bStack109 = (byte)((uint)iVar27 >> 0x18);
              uVar16 = 0;
              uVar21 = 0;
            }
          }
        }
      }
      else {
        iVar27 = (-(uint)(uVar9 != 0) & 0x80000000) + 0x7fff8000;
        uStack112 = (ushort)iVar27;
        uStack110 = (undefined)((uint)iVar27 >> 0x10);
        bStack109 = (byte)((uint)iVar27 >> 0x18);
        uVar21 = uVar16;
      }
    }
    *param_4 = (short)local_c0;
    iVar27 = param_2;
    if (((param_3 & 1) != 0) && (iVar27 = param_2 + (short)local_c0, iVar27 < 1)) {
      uVar5 = 0x20;
      if (local_c6 == 0x8000) {
        uVar5 = 0x2d;
      }
      goto LAB_18000dd05;
    }
    uVar3 = CONCAT12(uStack110,uStack112);
    uStack110 = 0;
    uVar15 = (uint)uStack112;
    lVar23 = 8;
    if (0x15 < iVar27) {
      iVar27 = 0x15;
    }
    iVar10 = (CONCAT13(bStack109,uVar3) >> 0x10) - 0x3ffe;
    do {
      uVar22 = uVar16 * 2;
      uVar11 = uVar16 >> 0x1f;
      uVar16 = uVar22 | uVar21 >> 0x1f;
      uVar15 = uVar15 * 2 | uVar11;
      uVar21 = uVar21 * 2;
      lVar23 = lVar23 + -1;
    } while (lVar23 != 0);
    local_78[2] = (ushort)uVar16;
    local_78[3] = (ushort)(uVar22 >> 0x10);
    local_78[0] = (ushort)uVar21;
    local_78[1] = (ushort)(uVar21 >> 0x10);
    if ((iVar10 < 0) && (uVar22 = -iVar10 & 0xff, uVar22 != 0)) {
      do {
        uVar12 = uVar21 >> 1;
        uVar17 = uVar16 >> 1;
        uVar11 = uVar15 << 0x1f;
        uVar21 = uVar16 << 0x1f;
        uVar22 = uVar22 - 1;
        uVar15 = uVar15 >> 1;
        uVar16 = uVar17 | uVar11;
        uVar21 = uVar12 | uVar21;
      } while (0 < (int)uVar22);
      local_78[2] = (ushort)uVar17;
      local_78[3] = (ushort)(uVar16 >> 0x10);
      local_78[0] = (ushort)uVar12;
      local_78[1] = (ushort)(uVar21 >> 0x10);
    }
    iVar27 = iVar27 + 1;
    psVar1 = param_4 + 2;
    psVar24 = psVar1;
    if (0 < iVar27) {
      while( true ) {
        uVar11 = CONCAT22(local_78[1],local_78[0]);
        local_58 = CONCAT26(local_78[3],CONCAT24(local_78[2],uVar11));
        uVar12 = (uVar16 * 2 | uVar21 >> 0x1f) * 2 | uVar21 * 2 >> 0x1f;
        uVar22 = uVar11 + uVar21 * 4;
        uVar17 = (uVar15 * 2 | uVar16 >> 0x1f) * 2 | uVar16 * 2 >> 0x1f;
        if ((uVar22 < uVar21 * 4) || (uVar21 = uVar12, uVar22 < uVar11)) {
          uVar21 = uVar12 + 1;
          if ((uVar21 < uVar12) || (bVar4 = false, uVar21 == 0)) {
            bVar4 = true;
          }
          if (bVar4) {
            uVar17 = uVar17 + 1;
          }
        }
        uVar16 = (uint)(local_58 >> 0x20);
        uVar11 = uVar21 + uVar16;
        if ((uVar11 < uVar21) || (uVar11 < uVar16)) {
          uVar17 = uVar17 + 1;
        }
        uVar21 = uVar22 * 2;
        uVar16 = uVar11 * 2 | uVar22 >> 0x1f;
        uVar15 = (uVar17 + uVar15) * 2;
        iVar27 = iVar27 + -1;
        local_78[0] = (ushort)uVar21;
        local_78[1] = (ushort)(uVar21 >> 0x10);
        uStack112 = (ushort)uVar15 | (ushort)(uVar11 >> 0x1f);
        local_78[2] = (ushort)uVar16;
        local_78[3] = (ushort)(uVar11 * 2 >> 0x10);
        uStack110 = (undefined)(uVar15 >> 0x10);
        *(char *)psVar24 = (char)(uVar15 >> 0x18) + '0';
        psVar24 = (short *)((longlong)psVar24 + 1);
        if (iVar27 < 1) break;
        uVar15 = uVar15 & 0xffffff | uVar11 >> 0x1f;
      }
    }
    bStack109 = 0;
    psVar25 = psVar24 + -1;
    if ('4' < *(char *)((longlong)psVar24 + -1)) {
      for (; (psVar1 <= psVar25 && (*(char *)psVar25 == '9'));
          psVar25 = (short *)((longlong)psVar25 + -1)) {
        *(char *)psVar25 = '0';
      }
      if (psVar25 < psVar1) {
        psVar25 = (short *)((longlong)psVar25 + 1);
        *param_4 = *param_4 + 1;
      }
      *(char *)psVar25 = *(char *)psVar25 + '\x01';
LAB_18000e662:
      cVar19 = ((char)psVar25 - (char)param_4) + -3;
      *(char *)((longlong)param_4 + 3) = cVar19;
      *(undefined *)((longlong)cVar19 + 4 + (longlong)param_4) = 0;
      goto LAB_18000e676;
    }
    for (; (psVar1 <= psVar25 && (*(char *)psVar25 == '0'));
        psVar25 = (short *)((longlong)psVar25 + -1)) {
    }
    if (psVar1 <= psVar25) goto LAB_18000e662;
    *param_4 = 0;
    *(undefined *)((longlong)param_4 + 3) = 1;
    uVar5 = 0x20;
    if (local_c6 == 0x8000) {
      uVar5 = 0x2d;
    }
    *(undefined *)(param_4 + 1) = uVar5;
    *(char *)psVar1 = '0';
  }
  *(undefined *)((longlong)param_4 + 5) = 0;
LAB_18000e676:
  FUN_180002f40(local_48 ^ (ulonglong)auStack248);
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018000e730. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



void RtlUnwindEx(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,
                PVOID ReturnValue,PCONTEXT ContextRecord,PUNWIND_HISTORY_TABLE HistoryTable)

{
                    // WARNING: Could not recover jumptable at 0x00018000e736. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwindEx(TargetFrame,TargetIp,ExceptionRecord,ReturnValue,ContextRecord,HistoryTable);
  return;
}



void FUN_18000e740(undefined8 param_1,longlong param_2)

{
  if ((*(longlong *)(param_2 + 0x40) == 0) && (DAT_180017238 != -1)) {
    FUN_180005204();
  }
  return;
}



void FUN_18000e766(undefined8 *param_1,longlong param_2)

{
  undefined4 uVar1;
  
  *(undefined8 **)(param_2 + 0x40) = param_1;
  uVar1 = *(undefined4 *)*param_1;
  *(undefined4 *)(param_2 + 0x30) = uVar1;
  *(undefined8 **)(param_2 + 0x38) = param_1;
  *(undefined4 *)(param_2 + 0x28) = uVar1;
  if (*(int *)(param_2 + 0x78) == 1) {
    FUN_1800034d8(*(undefined8 *)(param_2 + 0x70),0,*(longlong *)(param_2 + 0x80));
  }
  FUN_180004e94(*(int *)(param_2 + 0x28),*(void **)(param_2 + 0x38));
  return;
}



void FUN_18000e7af(void)

{
  FUN_180008ad8(0xd);
  return;
}



void FUN_18000e7c8(void)

{
  FUN_180008ad8(0xc);
  return;
}



void FUN_18000e7e1(undefined8 param_1,longlong param_2)

{
  if (*(int *)(param_2 + 0x80) != 0) {
    FUN_180008ad8(8);
  }
  return;
}



void FUN_18000e805(void)

{
  FUN_180008ad8(0xb);
  return;
}



void FUN_18000e820(undefined8 param_1,longlong param_2)

{
  FUN_180009a58(*(uint *)(param_2 + 0x50));
  return;
}



void FUN_18000e837(void)

{
  FUN_180008ad8(0xc);
  return;
}



void FUN_18000e850(void)

{
  FUN_180008ad8(0xd);
  return;
}



void FUN_18000e869(void)

{
                    // WARNING: Could not recover jumptable at 0x00018000e87e. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection(DAT_1800180d0);
  return;
}



bool FUN_18000e890(int **param_1)

{
  return **param_1 == -0x3ffffffb;
}



void FUN_18000e8b0(void)

{
  FUN_18000559c();
  return;
}



void FUN_18000e8c4(undefined8 param_1,longlong param_2)

{
  if (*(int *)(param_2 + 0x60) != 0) {
    FUN_180008ad8(0);
  }
  return;
}



void FUN_18000e8e2(void)

{
  FUN_180008ad8(1);
  return;
}



void FUN_18000e8fb(undefined8 param_1,longlong param_2)

{
  FUN_180006c88(*(int *)(param_2 + 0x20),
                *(longlong *)(DAT_18001dfa0 + (longlong)*(int *)(param_2 + 0x20) * 8));
  return;
}



void FUN_18000e923(void)

{
  FUN_180008ad8(1);
  return;
}



void FUN_18000e93c(void)

{
  FUN_180008ad8(10);
  return;
}



void FUN_18000e955(undefined8 param_1,longlong param_2)

{
  _unlock_file(*(FILE **)(param_2 + 0x30));
  return;
}



void FUN_18000e96d(undefined8 param_1,longlong param_2)

{
  FUN_180009a58(*(uint *)(param_2 + 0x40));
  return;
}


