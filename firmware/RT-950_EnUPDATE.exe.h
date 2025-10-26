typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned long long    qword;
typedef unsigned int    uint;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

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

typedef unsigned short    wchar16;
typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
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
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

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
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
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

typedef struct IMAGE_COR20_HEADER IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;

typedef struct CLI_METADATA_DIRECTORY CLI_METADATA_DIRECTORY, *PCLI_METADATA_DIRECTORY;

typedef enum COR20_Flags {
    COMIMAGE_FLAGS_ILONLY=1,
    COMIMAGE_FLAGS_32BITREQUIRED=2,
    COMIMAGE_FLAGS_IL_LIBRARY=4,
    COMIMAGE_FLAGS_STRONGNAMESIGNED=8,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT=16,
    COMIMAGE_FLAGS_TRACKDEBUGDATA=65536
} COR20_Flags;

typedef struct IMAGE_DATA_DIRECTORY.conflict IMAGE_DATA_DIRECTORY.conflict, *PIMAGE_DATA_DIRECTORY.conflict;

struct CLI_METADATA_DIRECTORY {
    dword VirtualAddress;
    dword Size;
};

struct IMAGE_DATA_DIRECTORY.conflict {
    dword VirtualAddress;
    dword Size;
};

struct IMAGE_COR20_HEADER {
    dword cb; // Size of the structure
    word MajorRuntimeVersion; // Version of CLR Runtime
    word MinorRuntimeVersion;
    struct CLI_METADATA_DIRECTORY MetaData; // RVA and size of MetaData
    enum COR20_Flags Flags;
    dword EntryPointToken; // This is a metadata token if not a valid RVA
    struct IMAGE_DATA_DIRECTORY.conflict Resources;
    struct IMAGE_DATA_DIRECTORY.conflict StrongNameSignature;
    struct IMAGE_DATA_DIRECTORY.conflict CodeManagerTable; // Should be 0
    struct IMAGE_DATA_DIRECTORY.conflict VTableFixups;
    struct IMAGE_DATA_DIRECTORY.conflict ExportAddressTableJumps; // Should be 0
    struct IMAGE_DATA_DIRECTORY.conflict ManagedNativeHeader; // 0 unless this is a native image
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct CLI_METADATA_HEADER CLI_METADATA_HEADER, *PCLI_METADATA_HEADER;

typedef struct CLI_Stream_Header_#~ CLI_Stream_Header_#~, *PCLI_Stream_Header_#~;

typedef struct CLI_Stream_Header_#Strings CLI_Stream_Header_#Strings, *PCLI_Stream_Header_#Strings;

typedef struct CLI_Stream_Header_#US CLI_Stream_Header_#US, *PCLI_Stream_Header_#US;

typedef struct CLI_Stream_Header_#GUID CLI_Stream_Header_#GUID, *PCLI_Stream_Header_#GUID;

typedef struct CLI_Stream_Header_#Blob CLI_Stream_Header_#Blob, *PCLI_Stream_Header_#Blob;

struct CLI_Stream_Header_#Blob {
    dword offset;
    dword size;
    char name[8];
};

struct CLI_Stream_Header_#GUID {
    dword offset;
    dword size;
    char name[8];
};

struct CLI_Stream_Header_#~ {
    dword offset;
    dword size;
    char name[4];
};

struct CLI_Stream_Header_#US {
    dword offset;
    dword size;
    char name[4];
};

struct CLI_Stream_Header_#Strings {
    dword offset;
    dword size;
    char name[12];
};

struct CLI_METADATA_HEADER {
    dword Signature; // must be 0x424a5342
    word MajorVersion;
    word MinorVersion;
    dword Reserved; // should be 0
    dword VersionLength;
    char Version[12];
    word Flags; // should be 0
    word StreamsCount; // number of stream headers to follow
    struct CLI_Stream_Header_#~ #~;
    struct CLI_Stream_Header_#Strings #Strings;
    struct CLI_Stream_Header_#US #US;
    struct CLI_Stream_Header_#GUID #GUID;
    struct CLI_Stream_Header_#Blob #Blob;
};

typedef struct SzArray_17805 SzArray_17805, *PSzArray_17805;

typedef enum TypeCode {
    ELEMENT_TYPE_END=0,
    ELEMENT_TYPE_VOID=1,
    ELEMENT_TYPE_BOOLEAN=2,
    ELEMENT_TYPE_CHAR=3,
    ELEMENT_TYPE_I1=4,
    ELEMENT_TYPE_U1=5,
    ELEMENT_TYPE_I2=6,
    ELEMENT_TYPE_U2=7,
    ELEMENT_TYPE_I4=8,
    ELEMENT_TYPE_U4=9,
    ELEMENT_TYPE_I8=10,
    ELEMENT_TYPE_U8=11,
    ELEMENT_TYPE_R4=12,
    ELEMENT_TYPE_R8=13,
    ELEMENT_TYPE_STRING=14,
    ELEMENT_TYPE_PTR=15,
    ELEMENT_TYPE_BYREF=16,
    ELEMENT_TYPE_VALUETYPE=17,
    ELEMENT_TYPE_CLASS=18,
    ELEMENT_TYPE_VAR=19,
    ELEMENT_TYPE_ARRAY=20,
    ELEMENT_TYPE_GENERICINST=21,
    ELEMENT_TYPE_TYPEDBYREF=22,
    ELEMENT_TYPE_I=24,
    ELEMENT_TYPE_U=25,
    ELEMENT_TYPE_FNPTR=27,
    ELEMENT_TYPE_OBJECT=28,
    ELEMENT_TYPE_SZARRAY=29,
    ELEMENT_TYPE_MVAR=30,
    ELEMENT_TYPE_CMOD_REQD=31,
    ELEMENT_TYPE_CMOD_OPT=32,
    ELEMENT_TYPE_INTERNAL=33,
    ELEMENT_TYPE_MAX=34,
    ELEMENT_TYPE_MODIFIER=64,
    ELEMENT_TYPE_SENTINEL=65,
    ELEMENT_TYPE_PINNED=69
} TypeCode;

struct SzArray_17805 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17649 SzArray_17649, *PSzArray_17649;

struct SzArray_17649 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17800 SzArray_17800, *PSzArray_17800;

struct SzArray_17800 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17642 SzArray_17642, *PSzArray_17642;

struct SzArray_17642 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17831 SzArray_17831, *PSzArray_17831;

struct SzArray_17831 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17798 SzArray_17798, *PSzArray_17798;

struct SzArray_17798 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17995 SzArray_17995, *PSzArray_17995;

struct SzArray_17995 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_18008 SzArray_18008, *PSzArray_18008;

struct SzArray_18008 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct Class Class, *PClass;

struct Class {
    enum TypeCode Class; // Class
    byte Type; // TypeDefOrRefOrSpecEncoded
};

typedef struct Class.conflict Class.conflict, *PClass.conflict;

struct Class.conflict {
    enum TypeCode Class; // Class
    word Type; // TypeDefOrRefOrSpecEncoded
};

typedef struct SzArray_18001 SzArray_18001, *PSzArray_18001;

struct SzArray_18001 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct ValueType.conflict19 ValueType.conflict19, *PValueType.conflict19;

struct ValueType.conflict19 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x57
};

typedef struct SzArray_18357 SzArray_18357, *PSzArray_18357;

struct SzArray_18357 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct ValueType.conflict18 ValueType.conflict18, *PValueType.conflict18;

struct ValueType.conflict18 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x54
};

typedef struct ValueType.conflict ValueType.conflict, *PValueType.conflict;

struct ValueType.conflict {
    enum TypeCode ValueType; // ValueType
    byte TypeDefOrRefEncoded; // TypeRef: Row 0x4
};

typedef struct SzArray_17990 SzArray_17990, *PSzArray_17990;

struct SzArray_17990 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_18359 SzArray_18359, *PSzArray_18359;

struct SzArray_18359 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_18239 SzArray_18239, *PSzArray_18239;

struct SzArray_18239 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct ValueType.conflict15 ValueType.conflict15, *PValueType.conflict15;

struct ValueType.conflict15 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x4e
};

typedef struct ValueType.conflict14 ValueType.conflict14, *PValueType.conflict14;

struct ValueType.conflict14 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x4c
};

typedef struct ValueType.conflict17 ValueType.conflict17, *PValueType.conflict17;

struct ValueType.conflict17 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x51
};

typedef struct ValueType.conflict16 ValueType.conflict16, *PValueType.conflict16;

struct ValueType.conflict16 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x4f
};

typedef struct ValueType.conflict7 ValueType.conflict7, *PValueType.conflict7;

struct ValueType.conflict7 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x3e
};

typedef struct ValueType.conflict11 ValueType.conflict11, *PValueType.conflict11;

struct ValueType.conflict11 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x49
};

typedef struct ValueType.conflict8 ValueType.conflict8, *PValueType.conflict8;

struct ValueType.conflict8 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x40
};

typedef struct ValueType.conflict10 ValueType.conflict10, *PValueType.conflict10;

struct ValueType.conflict10 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x46
};

typedef struct ValueType.conflict5 ValueType.conflict5, *PValueType.conflict5;

struct ValueType.conflict5 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x39
};

typedef struct ValueType.conflict13 ValueType.conflict13, *PValueType.conflict13;

struct ValueType.conflict13 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x4b
};

typedef struct ValueType.conflict6 ValueType.conflict6, *PValueType.conflict6;

struct ValueType.conflict6 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x3d
};

typedef struct ValueType.conflict12 ValueType.conflict12, *PValueType.conflict12;

struct ValueType.conflict12 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x4a
};

typedef struct ValueType.conflict9 ValueType.conflict9, *PValueType.conflict9;

struct ValueType.conflict9 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x41
};

typedef struct ValueType.conflict3 ValueType.conflict3, *PValueType.conflict3;

struct ValueType.conflict3 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x32
};

typedef struct SzArray_17817 SzArray_17817, *PSzArray_17817;

struct SzArray_17817 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct ValueType ValueType, *PValueType;

struct ValueType {
    enum TypeCode ValueType; // ValueType
    byte TypeDefOrRefEncoded; // TypeDef: Row 0x2
};

typedef struct ValueType.conflict4 ValueType.conflict4, *PValueType.conflict4;

struct ValueType.conflict4 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x33
};

typedef struct ValueType.conflict1 ValueType.conflict1, *PValueType.conflict1;

struct ValueType.conflict1 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x23
};

typedef struct ValueType.conflict2 ValueType.conflict2, *PValueType.conflict2;

struct ValueType.conflict2 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x2a
};

typedef struct SzArray_17613 SzArray_17613, *PSzArray_17613;

struct SzArray_17613 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_18352 SzArray_18352, *PSzArray_18352;

struct SzArray_18352 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17697 SzArray_17697, *PSzArray_17697;

struct SzArray_17697 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_17661 SzArray_17661, *PSzArray_17661;

struct SzArray_17661 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct SzArray_18347 SzArray_18347, *PSzArray_18347;

struct SzArray_18347 {
    enum TypeCode TypeCode; // SzArray
    enum TypeCode Type; // type or void
};

typedef struct ValueType.conflict21 ValueType.conflict21, *PValueType.conflict21;

struct ValueType.conflict21 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x5c
};

typedef struct ValueType.conflict20 ValueType.conflict20, *PValueType.conflict20;

struct ValueType.conflict20 {
    enum TypeCode ValueType; // ValueType
    word TypeDefOrRefEncoded; // TypeRef: Row 0x59
};

typedef struct Blob_ConstantSig_675 Blob_ConstantSig_675, *PBlob_ConstantSig_675;

typedef struct ConstantSig_675 ConstantSig_675, *PConstantSig_675;

struct ConstantSig_675 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_675 {
    byte Size; // coded integer - blob size
    struct ConstantSig_675 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_660 Blob_Generic_660, *PBlob_Generic_660;

struct Blob_Generic_660 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_665 Blob_Generic_665, *PBlob_Generic_665;

struct Blob_Generic_665 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_422 Blob_Generic_422, *PBlob_Generic_422;

struct Blob_Generic_422 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_300 Blob_Generic_300, *PBlob_Generic_300;

struct Blob_Generic_300 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_783 Blob_Generic_783, *PBlob_Generic_783;

struct Blob_Generic_783 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_Generic_306 Blob_Generic_306, *PBlob_Generic_306;

struct Blob_Generic_306 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_547 Blob_Generic_547, *PBlob_Generic_547;

struct Blob_Generic_547 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_428 Blob_Generic_428, *PBlob_Generic_428;

struct Blob_Generic_428 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_680 Blob_ConstantSig_680, *PBlob_ConstantSig_680;

typedef struct ConstantSig_680 ConstantSig_680, *PConstantSig_680;

struct ConstantSig_680 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_680 {
    byte Size; // coded integer - blob size
    struct ConstantSig_680 ConstantSig; // Data stored in a constant
};

typedef struct Blob_LocalVarSig_75 Blob_LocalVarSig_75, *PBlob_LocalVarSig_75;

typedef struct LocalVarSig_75 LocalVarSig_75, *PLocalVarSig_75;

typedef struct Type_17590 Type_17590, *PType_17590;

typedef struct Type_17591 Type_17591, *PType_17591;

struct Type_17591 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct Type_17590 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct LocalVarSig_75 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17590 Type;
    struct Type_17591 Type;
};

struct Blob_LocalVarSig_75 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_75 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_ConstantSig_685 Blob_ConstantSig_685, *PBlob_ConstantSig_685;

typedef struct ConstantSig_685 ConstantSig_685, *PConstantSig_685;

struct ConstantSig_685 {
};

struct Blob_ConstantSig_685 {
    byte Size; // coded integer - blob size
    struct ConstantSig_685 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_689 Blob_ConstantSig_689, *PBlob_ConstantSig_689;

typedef struct ConstantSig_689 ConstantSig_689, *PConstantSig_689;

struct ConstantSig_689 {
};

struct Blob_ConstantSig_689 {
    byte Size; // coded integer - blob size
    struct ConstantSig_689 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_687 Blob_ConstantSig_687, *PBlob_ConstantSig_687;

typedef struct ConstantSig_687 ConstantSig_687, *PConstantSig_687;

struct ConstantSig_687 {
};

struct Blob_ConstantSig_687 {
    byte Size; // coded integer - blob size
    struct ConstantSig_687 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_650 Blob_Generic_650, *PBlob_Generic_650;

struct Blob_Generic_650 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_890 Blob_Generic_890, *PBlob_Generic_890;

struct Blob_Generic_890 {
    byte Size; // coded integer - blob size
    byte Generic[10]; // Undefined blob contents
};

typedef struct Blob_Generic_533 Blob_Generic_533, *PBlob_Generic_533;

struct Blob_Generic_533 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_774 Blob_Generic_774, *PBlob_Generic_774;

struct Blob_Generic_774 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_16 Blob_Generic_16, *PBlob_Generic_16;

struct Blob_Generic_16 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_10 Blob_Generic_10, *PBlob_Generic_10;

struct Blob_Generic_10 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_779 Blob_Generic_779, *PBlob_Generic_779;

struct Blob_Generic_779 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_1005 Blob_Generic_1005, *PBlob_Generic_1005;

struct Blob_Generic_1005 {
    byte Size; // coded integer - blob size
    byte Generic[23]; // Undefined blob contents
};

typedef struct Blob_Generic_415 Blob_Generic_415, *PBlob_Generic_415;

struct Blob_Generic_415 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_1248 Blob_Generic_1248, *PBlob_Generic_1248;

struct Blob_Generic_1248 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_655 Blob_Generic_655, *PBlob_Generic_655;

struct Blob_Generic_655 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_539 Blob_Generic_539, *PBlob_Generic_539;

struct Blob_Generic_539 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_333 Blob_LocalVarSig_333, *PBlob_LocalVarSig_333;

typedef struct LocalVarSig_333 LocalVarSig_333, *PLocalVarSig_333;

typedef struct Type_17848 Type_17848, *PType_17848;

struct Type_17848 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct LocalVarSig_333 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17848 Type;
};

struct Blob_LocalVarSig_333 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_333 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_ConstantSig_691 Blob_ConstantSig_691, *PBlob_ConstantSig_691;

typedef struct ConstantSig_691 ConstantSig_691, *PConstantSig_691;

struct ConstantSig_691 {
};

struct Blob_ConstantSig_691 {
    byte Size; // coded integer - blob size
    struct ConstantSig_691 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_695 Blob_ConstantSig_695, *PBlob_ConstantSig_695;

typedef struct ConstantSig_695 ConstantSig_695, *PConstantSig_695;

struct ConstantSig_695 {
};

struct Blob_ConstantSig_695 {
    byte Size; // coded integer - blob size
    struct ConstantSig_695 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_693 Blob_ConstantSig_693, *PBlob_ConstantSig_693;

typedef struct ConstantSig_693 ConstantSig_693, *PConstantSig_693;

struct ConstantSig_693 {
};

struct Blob_ConstantSig_693 {
    byte Size; // coded integer - blob size
    struct ConstantSig_693 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_655 Blob_ConstantSig_655, *PBlob_ConstantSig_655;

typedef struct ConstantSig_655 ConstantSig_655, *PConstantSig_655;

struct ConstantSig_655 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_655 {
    byte Size; // coded integer - blob size
    struct ConstantSig_655 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_401 Blob_Generic_401, *PBlob_Generic_401;

struct Blob_Generic_401 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_883 Blob_Generic_883, *PBlob_Generic_883;

struct Blob_Generic_883 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_640 Blob_Generic_640, *PBlob_Generic_640;

struct Blob_Generic_640 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_761 Blob_Generic_761, *PBlob_Generic_761;

struct Blob_Generic_761 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_645 Blob_Generic_645, *PBlob_Generic_645;

struct Blob_Generic_645 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_523 Blob_Generic_523, *PBlob_Generic_523;

struct Blob_Generic_523 {
    byte Size; // coded integer - blob size
    byte Generic[9]; // Undefined blob contents
};

typedef struct Blob_Generic_765 Blob_Generic_765, *PBlob_Generic_765;

struct Blob_Generic_765 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_408 Blob_Generic_408, *PBlob_Generic_408;

struct Blob_Generic_408 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_769 Blob_Generic_769, *PBlob_Generic_769;

struct Blob_Generic_769 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_306 Blob_LocalVarSig_306, *PBlob_LocalVarSig_306;

typedef struct LocalVarSig_306 LocalVarSig_306, *PLocalVarSig_306;

typedef struct Type_17821 Type_17821, *PType_17821;

struct Type_17821 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct LocalVarSig_306 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17821 Type;
};

struct Blob_LocalVarSig_306 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_306 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_LocalVarSig_547 Blob_LocalVarSig_547, *PBlob_LocalVarSig_547;

typedef struct LocalVarSig_547 LocalVarSig_547, *PLocalVarSig_547;

typedef struct Type_18062 Type_18062, *PType_18062;

struct Type_18062 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct LocalVarSig_547 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_18062 Type;
};

struct Blob_LocalVarSig_547 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_547 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_ConstantSig_660 Blob_ConstantSig_660, *PBlob_ConstantSig_660;

typedef struct ConstantSig_660 ConstantSig_660, *PConstantSig_660;

struct ConstantSig_660 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_660 {
    byte Size; // coded integer - blob size
    struct ConstantSig_660 ConstantSig; // Data stored in a constant
};

typedef struct Blob_MethodDefSig_157 Blob_MethodDefSig_157, *PBlob_MethodDefSig_157;

typedef struct MethodDefSig_157 MethodDefSig_157, *PMethodDefSig_157;

typedef struct Type_17672 Type_17672, *PType_17672;

struct Type_17672 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodDefSig_157 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_17672 RetType;
};

struct Blob_MethodDefSig_157 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_157 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_ConstantSig_665 Blob_ConstantSig_665, *PBlob_ConstantSig_665;

typedef struct ConstantSig_665 ConstantSig_665, *PConstantSig_665;

struct ConstantSig_665 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_665 {
    byte Size; // coded integer - blob size
    struct ConstantSig_665 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_753 Blob_Generic_753, *PBlob_Generic_753;

struct Blob_Generic_753 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_630 Blob_Generic_630, *PBlob_Generic_630;

struct Blob_Generic_630 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_872 Blob_Generic_872, *PBlob_Generic_872;

struct Blob_Generic_872 {
    byte Size; // coded integer - blob size
    byte Generic[10]; // Undefined blob contents
};

typedef struct Blob_Generic_757 Blob_Generic_757, *PBlob_Generic_757;

struct Blob_Generic_757 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_999 Blob_Generic_999, *PBlob_Generic_999;

struct Blob_Generic_999 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_635 Blob_Generic_635, *PBlob_Generic_635;

struct Blob_Generic_635 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_512 Blob_Generic_512, *PBlob_Generic_512;

struct Blob_Generic_512 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_517 Blob_Generic_517, *PBlob_Generic_517;

struct Blob_Generic_517 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_1029 Blob_Generic_1029, *PBlob_Generic_1029;

struct Blob_Generic_1029 {
    byte Size; // coded integer - blob size
    byte Generic[41]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_553 Blob_LocalVarSig_553, *PBlob_LocalVarSig_553;

typedef struct LocalVarSig_553 LocalVarSig_553, *PLocalVarSig_553;

typedef struct Type_18068 Type_18068, *PType_18068;

struct Type_18068 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct LocalVarSig_553 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_18068 Type;
};

struct Blob_LocalVarSig_553 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_553 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_ConstantSig_670 Blob_ConstantSig_670, *PBlob_ConstantSig_670;

typedef struct ConstantSig_670 ConstantSig_670, *PConstantSig_670;

struct ConstantSig_670 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_670 {
    byte Size; // coded integer - blob size
    struct ConstantSig_670 ConstantSig; // Data stored in a constant
};

typedef struct Blob_LocalVarSig_558 Blob_LocalVarSig_558, *PBlob_LocalVarSig_558;

typedef struct LocalVarSig_558 LocalVarSig_558, *PLocalVarSig_558;

typedef struct Type_18073 Type_18073, *PType_18073;

struct Type_18073 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct LocalVarSig_558 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_18073 Type;
};

struct Blob_LocalVarSig_558 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_558 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_MethodDefSig_144 Blob_MethodDefSig_144, *PBlob_MethodDefSig_144;

typedef struct MethodDefSig_144 MethodDefSig_144, *PMethodDefSig_144;

typedef struct Type_17659 Type_17659, *PType_17659;

typedef struct Type_17660 Type_17660, *PType_17660;

typedef struct Type_17662 Type_17662, *PType_17662;

typedef struct Type_17663 Type_17663, *PType_17663;

struct Type_17660 {
    struct SzArray_17661 ELEMENT_TYPE_SZARRAY;
};

struct Type_17662 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17663 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17659 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodDefSig_144 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_17659 RetType;
    struct Type_17660 Param0;
    struct Type_17662 Param1;
    struct Type_17663 Param2;
};

struct Blob_MethodDefSig_144 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_144 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_Generic_460 Blob_Generic_460, *PBlob_Generic_460;

struct Blob_Generic_460 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_467 Blob_Generic_467, *PBlob_Generic_467;

struct Blob_Generic_467 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_46 Blob_Generic_46, *PBlob_Generic_46;

struct Blob_Generic_46 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_294 Blob_MethodRefSig_294, *PBlob_MethodRefSig_294;

typedef struct MethodRefSig_294 MethodRefSig_294, *PMethodRefSig_294;

typedef struct Type_17809 Type_17809, *PType_17809;

struct Type_17809 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_294 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17809 RetType;
};

struct Blob_MethodRefSig_294 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_294 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_586 Blob_Generic_586, *PBlob_Generic_586;

struct Blob_Generic_586 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_226 Blob_Generic_226, *PBlob_Generic_226;

struct Blob_Generic_226 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_347 Blob_Generic_347, *PBlob_Generic_347;

struct Blob_Generic_347 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_1158 Blob_Generic_1158, *PBlob_Generic_1158;

struct Blob_Generic_1158 {
    byte Size; // coded integer - blob size
    byte Generic[89]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_484 Blob_LocalVarSig_484, *PBlob_LocalVarSig_484;

typedef struct LocalVarSig_484 LocalVarSig_484, *PLocalVarSig_484;

typedef struct Type_17999 Type_17999, *PType_17999;

typedef struct Type_18000 Type_18000, *PType_18000;

typedef struct Type_18002 Type_18002, *PType_18002;

typedef struct Type_18003 Type_18003, *PType_18003;

typedef struct Type_18004 Type_18004, *PType_18004;

typedef struct Type_18005 Type_18005, *PType_18005;

typedef struct Type_18006 Type_18006, *PType_18006;

typedef struct Type_18007 Type_18007, *PType_18007;

struct Type_18003 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18007 {
    struct SzArray_18008 ELEMENT_TYPE_SZARRAY;
};

struct Type_17999 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18002 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18006 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18005 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18004 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18000 {
    struct SzArray_18001 ELEMENT_TYPE_SZARRAY;
};

struct LocalVarSig_484 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17999 Type;
    struct Type_18000 Type;
    struct Type_18002 Type;
    struct Type_18003 Type;
    struct Type_18004 Type;
    struct Type_18005 Type;
    struct Type_18006 Type;
    struct Type_18007 Type;
};

struct Blob_LocalVarSig_484 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_484 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_Generic_693 Blob_Generic_693, *PBlob_Generic_693;

struct Blob_Generic_693 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_691 Blob_Generic_691, *PBlob_Generic_691;

struct Blob_Generic_691 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_58 Blob_Generic_58, *PBlob_Generic_58;

struct Blob_Generic_58 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_214 Blob_Generic_214, *PBlob_Generic_214;

struct Blob_Generic_214 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_577 Blob_Generic_577, *PBlob_Generic_577;

struct Blob_Generic_577 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_161 Blob_MethodRefSig_161, *PBlob_MethodRefSig_161;

typedef struct MethodRefSig_161 MethodRefSig_161, *PMethodRefSig_161;

typedef struct Type_17676 Type_17676, *PType_17676;

typedef struct Type_17677 Type_17677, *PType_17677;

typedef struct Type_17678 Type_17678, *PType_17678;

typedef struct Type_17679 Type_17679, *PType_17679;

typedef struct Type_17680 Type_17680, *PType_17680;

struct Type_17680 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17678 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17676 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17679 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17677 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_161 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17676 RetType;
    struct Type_17677 Param0;
    struct Type_17678 Param1;
    struct Type_17679 Param2;
    struct Type_17680 Param3;
};

struct Blob_MethodRefSig_161 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_161 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_455 Blob_Generic_455, *PBlob_Generic_455;

struct Blob_Generic_455 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_697 Blob_Generic_697, *PBlob_Generic_697;

struct Blob_Generic_697 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_333 Blob_Generic_333, *PBlob_Generic_333;

struct Blob_Generic_333 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_695 Blob_Generic_695, *PBlob_Generic_695;

struct Blob_Generic_695 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_53 Blob_Generic_53, *PBlob_Generic_53;

struct Blob_Generic_53 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_338 Blob_Generic_338, *PBlob_Generic_338;

struct Blob_Generic_338 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_699 Blob_Generic_699, *PBlob_Generic_699;

struct Blob_Generic_699 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_169 Blob_MethodRefSig_169, *PBlob_MethodRefSig_169;

typedef struct MethodRefSig_169 MethodRefSig_169, *PMethodRefSig_169;

typedef struct Type_17684 Type_17684, *PType_17684;

typedef struct Type_17685 Type_17685, *PType_17685;

typedef struct Type_17686 Type_17686, *PType_17686;

struct Type_17684 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17686 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17685 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_169 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17684 RetType;
    struct Type_17685 Param0;
    struct Type_17686 Param1;
};

struct Blob_MethodRefSig_169 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_169 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_219 Blob_Generic_219, *PBlob_Generic_219;

struct Blob_Generic_219 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_289 Blob_MethodRefSig_289, *PBlob_MethodRefSig_289;

typedef struct MethodRefSig_289 MethodRefSig_289, *PMethodRefSig_289;

typedef struct Type_17804 Type_17804, *PType_17804;

struct Type_17804 {
    struct SzArray_17805 ELEMENT_TYPE_SZARRAY;
};

struct MethodRefSig_289 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17804 RetType;
};

struct Blob_MethodRefSig_289 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_289 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_LocalVarSig_497 Blob_LocalVarSig_497, *PBlob_LocalVarSig_497;

typedef struct LocalVarSig_497 LocalVarSig_497, *PLocalVarSig_497;

typedef struct Type_18012 Type_18012, *PType_18012;

typedef struct Type_18013 Type_18013, *PType_18013;

typedef struct Type_18014 Type_18014, *PType_18014;

typedef struct Type_18015 Type_18015, *PType_18015;

typedef struct Type_18016 Type_18016, *PType_18016;

typedef struct Type_18017 Type_18017, *PType_18017;

typedef struct Type_18018 Type_18018, *PType_18018;

typedef struct Type_18019 Type_18019, *PType_18019;

struct Type_18014 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18013 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18019 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18016 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18018 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18012 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18015 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_18017 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct LocalVarSig_497 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_18012 Type;
    struct Type_18013 Type;
    struct Type_18014 Type;
    struct Type_18015 Type;
    struct Type_18016 Type;
    struct Type_18017 Type;
    struct Type_18018 Type;
    struct Type_18019 Type;
};

struct Blob_LocalVarSig_497 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_497 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_LocalVarSig_46 Blob_LocalVarSig_46, *PBlob_LocalVarSig_46;

typedef struct LocalVarSig_46 LocalVarSig_46, *PLocalVarSig_46;

typedef struct Type_17561 Type_17561, *PType_17561;

typedef struct Type_17563 Type_17563, *PType_17563;

struct Type_17561 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct Type_17563 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct LocalVarSig_46 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17561 Type;
    struct Type_17563 Type;
};

struct Blob_LocalVarSig_46 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_46 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_ConstantSig_699 Blob_ConstantSig_699, *PBlob_ConstantSig_699;

typedef struct ConstantSig_699 ConstantSig_699, *PConstantSig_699;

struct ConstantSig_699 {
};

struct Blob_ConstantSig_699 {
    byte Size; // coded integer - blob size
    struct ConstantSig_699 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_697 Blob_ConstantSig_697, *PBlob_ConstantSig_697;

typedef struct ConstantSig_697 ConstantSig_697, *PConstantSig_697;

struct ConstantSig_697 {
};

struct Blob_ConstantSig_697 {
    byte Size; // coded integer - blob size
    struct ConstantSig_697 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_320 Blob_Generic_320, *PBlob_Generic_320;

struct Blob_Generic_320 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_562 Blob_Generic_562, *PBlob_Generic_562;

struct Blob_Generic_562 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_680 Blob_Generic_680, *PBlob_Generic_680;

struct Blob_Generic_680 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_687 Blob_Generic_687, *PBlob_Generic_687;

struct Blob_Generic_687 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_685 Blob_Generic_685, *PBlob_Generic_685;

struct Blob_Generic_685 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_26 Blob_Generic_26, *PBlob_Generic_26;

struct Blob_Generic_26 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_442 Blob_Generic_442, *PBlob_Generic_442;

struct Blob_Generic_442 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_21 Blob_Generic_21, *PBlob_Generic_21;

struct Blob_Generic_21 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_448 Blob_Generic_448, *PBlob_Generic_448;

struct Blob_Generic_448 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_326 Blob_Generic_326, *PBlob_Generic_326;

struct Blob_Generic_326 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_568 Blob_Generic_568, *PBlob_Generic_568;

struct Blob_Generic_568 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_689 Blob_Generic_689, *PBlob_Generic_689;

struct Blob_Generic_689 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_209 Blob_Generic_209, *PBlob_Generic_209;

struct Blob_Generic_209 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_157 Blob_MethodRefSig_157, *PBlob_MethodRefSig_157;

typedef struct MethodRefSig_157 MethodRefSig_157, *PMethodRefSig_157;

struct MethodRefSig_157 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17672 RetType;
};

struct Blob_MethodRefSig_157 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_157 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_6 Blob_MethodRefSig_6, *PBlob_MethodRefSig_6;

typedef struct MethodRefSig_6 MethodRefSig_6, *PMethodRefSig_6;

typedef struct Type_17521 Type_17521, *PType_17521;

struct Type_17521 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_6 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17521 RetType;
};

struct Blob_MethodRefSig_6 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_6 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_275 Blob_MethodRefSig_275, *PBlob_MethodRefSig_275;

typedef struct MethodRefSig_275 MethodRefSig_275, *PMethodRefSig_275;

typedef struct Type_17790 Type_17790, *PType_17790;

typedef struct Type_17791 Type_17791, *PType_17791;

struct Type_17790 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17791 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_275 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17790 RetType;
    struct Type_17791 Param0;
};

struct Blob_MethodRefSig_275 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_275 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_152 Blob_MethodRefSig_152, *PBlob_MethodRefSig_152;

typedef struct MethodRefSig_152 MethodRefSig_152, *PMethodRefSig_152;

typedef struct Type_17667 Type_17667, *PType_17667;

typedef struct Type_17668 Type_17668, *PType_17668;

struct Type_17667 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17668 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_152 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17667 RetType;
    struct Type_17668 Param0;
};

struct Blob_MethodRefSig_152 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_152 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_394 Blob_MethodRefSig_394, *PBlob_MethodRefSig_394;

typedef struct MethodRefSig_394 MethodRefSig_394, *PMethodRefSig_394;

typedef struct Type_17909 Type_17909, *PType_17909;

typedef struct Type_17910 Type_17910, *PType_17910;

struct Type_17910 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_17909 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_394 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17909 RetType;
    struct Type_17910 Param0;
};

struct Blob_MethodRefSig_394 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_394 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_LocalVarSig_226 Blob_LocalVarSig_226, *PBlob_LocalVarSig_226;

typedef struct LocalVarSig_226 LocalVarSig_226, *PLocalVarSig_226;

typedef struct Type_17741 Type_17741, *PType_17741;

struct Type_17741 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct LocalVarSig_226 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17741 Type;
};

struct Blob_LocalVarSig_226 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_226 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_MethodRefSig_1 Blob_MethodRefSig_1, *PBlob_MethodRefSig_1;

typedef struct MethodRefSig_1 MethodRefSig_1, *PMethodRefSig_1;

typedef struct Type_17516 Type_17516, *PType_17516;

typedef struct Type_17517 Type_17517, *PType_17517;

struct Type_17517 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17516 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_1 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17516 RetType;
    struct Type_17517 Param0;
};

struct Blob_MethodRefSig_1 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_1 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_670 Blob_Generic_670, *PBlob_Generic_670;

struct Blob_Generic_670 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_791 Blob_Generic_791, *PBlob_Generic_791;

struct Blob_Generic_791 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_381 Blob_MethodRefSig_381, *PBlob_MethodRefSig_381;

typedef struct MethodRefSig_381 MethodRefSig_381, *PMethodRefSig_381;

typedef struct Type_17896 Type_17896, *PType_17896;

typedef struct Type_17897 Type_17897, *PType_17897;

typedef struct Type_17898 Type_17898, *PType_17898;

typedef struct Type_17899 Type_17899, *PType_17899;

typedef struct Type_17902 Type_17902, *PType_17902;

typedef struct Type_17905 Type_17905, *PType_17905;

struct Type_17905 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_17898 {
    enum TypeCode ELEMENT_TYPE_R4;
};

struct Type_17896 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17902 {
    struct ValueType.conflict16 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17899 {
    struct ValueType.conflict15 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17897 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_381 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17896 RetType;
    struct Type_17897 Param0;
    struct Type_17898 Param1;
    struct Type_17899 Param2;
    struct Type_17902 Param3;
    struct Type_17905 Param4;
};

struct Blob_MethodRefSig_381 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_381 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_675 Blob_Generic_675, *PBlob_Generic_675;

struct Blob_Generic_675 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_140 Blob_MethodRefSig_140, *PBlob_MethodRefSig_140;

typedef struct MethodRefSig_140 MethodRefSig_140, *PMethodRefSig_140;

typedef struct Type_17655 Type_17655, *PType_17655;

struct Type_17655 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_140 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17655 RetType;
};

struct Blob_MethodRefSig_140 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_140 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_261 Blob_MethodRefSig_261, *PBlob_MethodRefSig_261;

typedef struct MethodRefSig_261 MethodRefSig_261, *PMethodRefSig_261;

typedef struct Type_17776 Type_17776, *PType_17776;

typedef struct Type_17779 Type_17779, *PType_17779;

typedef struct Type_17780 Type_17780, *PType_17780;

typedef struct Type_17781 Type_17781, *PType_17781;

typedef struct Type_17784 Type_17784, *PType_17784;

struct Type_17779 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17776 {
    struct ValueType.conflict5 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17781 {
    struct ValueType.conflict8 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17784 {
    struct ValueType.conflict9 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17780 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_261 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17776 RetType;
    struct Type_17779 Param0;
    struct Type_17780 Param1;
    struct Type_17781 Param2;
    struct Type_17784 Param3;
};

struct Blob_MethodRefSig_261 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_261 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_311 Blob_Generic_311, *PBlob_Generic_311;

struct Blob_Generic_311 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_553 Blob_Generic_553, *PBlob_Generic_553;

struct Blob_Generic_553 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_558 Blob_Generic_558, *PBlob_Generic_558;

struct Blob_Generic_558 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_33 Blob_Generic_33, *PBlob_Generic_33;

struct Blob_Generic_33 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_435 Blob_Generic_435, *PBlob_Generic_435;

struct Blob_Generic_435 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_798 Blob_Generic_798, *PBlob_Generic_798;

struct Blob_Generic_798 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_474 Blob_LocalVarSig_474, *PBlob_LocalVarSig_474;

typedef struct LocalVarSig_474 LocalVarSig_474, *PLocalVarSig_474;

typedef struct Type_17989 Type_17989, *PType_17989;

typedef struct Type_17991 Type_17991, *PType_17991;

typedef struct Type_17992 Type_17992, *PType_17992;

typedef struct Type_17993 Type_17993, *PType_17993;

typedef struct Type_17994 Type_17994, *PType_17994;

struct Type_17994 {
    struct SzArray_17995 ELEMENT_TYPE_SZARRAY;
};

struct Type_17991 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17993 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17992 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17989 {
    struct SzArray_17990 ELEMENT_TYPE_SZARRAY;
};

struct LocalVarSig_474 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17989 Type;
    struct Type_17991 Type;
    struct Type_17992 Type;
    struct Type_17993 Type;
    struct Type_17994 Type;
};

struct Blob_LocalVarSig_474 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_474 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_Generic_39 Blob_Generic_39, *PBlob_Generic_39;

struct Blob_Generic_39 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_144 Blob_MethodRefSig_144, *PBlob_MethodRefSig_144;

typedef struct MethodRefSig_144 MethodRefSig_144, *PMethodRefSig_144;

struct MethodRefSig_144 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17659 RetType;
    struct Type_17660 Param0;
    struct Type_17662 Param1;
    struct Type_17663 Param2;
};

struct Blob_MethodRefSig_144 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_144 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_ConstantSig_595 Blob_ConstantSig_595, *PBlob_ConstantSig_595;

typedef struct ConstantSig_595 ConstantSig_595, *PConstantSig_595;

struct ConstantSig_595 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_595 {
    byte Size; // coded integer - blob size
    struct ConstantSig_595 ConstantSig; // Data stored in a constant
};

typedef struct Blob_FieldSig_769 Blob_FieldSig_769, *PBlob_FieldSig_769;

typedef struct FieldSig_769 FieldSig_769, *PFieldSig_769;

typedef struct Type_18283 Type_18283, *PType_18283;

struct Type_18283 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct FieldSig_769 {
    byte FIELD; // Magic (0x06)
    struct Type_18283 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_769 {
    byte Size; // coded integer - blob size
    struct FieldSig_769 FieldSig; // Type information for Field
};

typedef struct CustomAttrib_930 CustomAttrib_930, *PCustomAttrib_930;

struct CustomAttrib_930 {
    word PROLOG; // Magic (0x0001)
    dword FixedArg_0; // Elem (ELEMENT_TYPE_I4)
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct Blob_FieldSig_765 Blob_FieldSig_765, *PBlob_FieldSig_765;

typedef struct FieldSig_765 FieldSig_765, *PFieldSig_765;

typedef struct Type_18279 Type_18279, *PType_18279;

struct Type_18279 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_765 {
    byte FIELD; // Magic (0x06)
    struct Type_18279 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_765 {
    byte Size; // coded integer - blob size
    struct FieldSig_765 FieldSig; // Type information for Field
};

typedef struct CustomAttrib_939 CustomAttrib_939, *PCustomAttrib_939;

struct CustomAttrib_939 {
    word PROLOG; // Magic (0x0001)
    word NumNamed; // Number of NamedArgs to follow
    byte FieldOrProp; // PROPERTY
    byte FieldOrPropType; // ELEMENT_TYPE_BOOLEAN
    byte PackedLen;
    char FieldOrPropName[23];
};

typedef struct Blob_Generic_701 Blob_Generic_701, *PBlob_Generic_701;

struct Blob_Generic_701 {
    byte Size; // coded integer - blob size
    byte Generic[1]; // Undefined blob contents
};

typedef struct Blob_Generic_822 Blob_Generic_822, *PBlob_Generic_822;

struct Blob_Generic_822 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_MethodDefSig_21 Blob_MethodDefSig_21, *PBlob_MethodDefSig_21;

typedef struct MethodDefSig_21 MethodDefSig_21, *PMethodDefSig_21;

typedef struct Type_17536 Type_17536, *PType_17536;

typedef struct Type_17537 Type_17537, *PType_17537;

struct Type_17536 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17537 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct MethodDefSig_21 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_17536 RetType;
    struct Type_17537 Param0;
};

struct Blob_MethodDefSig_21 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_21 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_Generic_706 Blob_Generic_706, *PBlob_Generic_706;

struct Blob_Generic_706 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_826 Blob_Generic_826, *PBlob_Generic_826;

struct Blob_Generic_826 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_703 Blob_Generic_703, *PBlob_Generic_703;

struct Blob_Generic_703 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_FieldSig_761 Blob_FieldSig_761, *PBlob_FieldSig_761;

typedef struct FieldSig_761 FieldSig_761, *PFieldSig_761;

typedef struct Type_18275 Type_18275, *PType_18275;

struct Type_18275 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_761 {
    byte FIELD; // Magic (0x06)
    struct Type_18275 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_761 {
    byte Size; // coded integer - blob size
    struct FieldSig_761 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_779 Blob_FieldSig_779, *PBlob_FieldSig_779;

typedef struct FieldSig_779 FieldSig_779, *PFieldSig_779;

typedef struct Type_18293 Type_18293, *PType_18293;

struct Type_18293 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_779 {
    byte FIELD; // Magic (0x06)
    struct Type_18293 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_779 {
    byte Size; // coded integer - blob size
    struct FieldSig_779 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_930 Blob_Generic_930, *PBlob_Generic_930;

struct Blob_Generic_930 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_815 Blob_Generic_815, *PBlob_Generic_815;

struct Blob_Generic_815 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_939 Blob_Generic_939, *PBlob_Generic_939;

struct Blob_Generic_939 {
    byte Size; // coded integer - blob size
    byte Generic[30]; // Undefined blob contents
};

typedef struct Blob_FieldSig_774 Blob_FieldSig_774, *PBlob_FieldSig_774;

typedef struct FieldSig_774 FieldSig_774, *PFieldSig_774;

typedef struct Type_18288 Type_18288, *PType_18288;

struct Type_18288 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct FieldSig_774 {
    byte FIELD; // Magic (0x06)
    struct Type_18288 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_774 {
    byte Size; // coded integer - blob size
    struct FieldSig_774 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_749 Blob_FieldSig_749, *PBlob_FieldSig_749;

typedef struct FieldSig_749 FieldSig_749, *PFieldSig_749;

typedef struct Type_18263 Type_18263, *PType_18263;

struct Type_18263 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_749 {
    byte FIELD; // Magic (0x06)
    struct Type_18263 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_749 {
    byte Size; // coded integer - blob size
    struct FieldSig_749 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_745 Blob_FieldSig_745, *PBlob_FieldSig_745;

typedef struct FieldSig_745 FieldSig_745, *PFieldSig_745;

typedef struct Type_18259 Type_18259, *PType_18259;

struct Type_18259 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_745 {
    byte FIELD; // Magic (0x06)
    struct Type_18259 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_745 {
    byte Size; // coded integer - blob size
    struct FieldSig_745 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_921 Blob_Generic_921, *PBlob_Generic_921;

struct Blob_Generic_921 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_926 Blob_Generic_926, *PBlob_Generic_926;

struct Blob_Generic_926 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_802 Blob_Generic_802, *PBlob_Generic_802;

struct Blob_Generic_802 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_808 Blob_Generic_808, *PBlob_Generic_808;

struct Blob_Generic_808 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_FieldSig_741 Blob_FieldSig_741, *PBlob_FieldSig_741;

typedef struct FieldSig_741 FieldSig_741, *PFieldSig_741;

typedef struct Type_18255 Type_18255, *PType_18255;

struct Type_18255 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_741 {
    byte FIELD; // Magic (0x06)
    struct Type_18255 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_741 {
    byte Size; // coded integer - blob size
    struct FieldSig_741 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_757 Blob_FieldSig_757, *PBlob_FieldSig_757;

typedef struct FieldSig_757 FieldSig_757, *PFieldSig_757;

typedef struct Type_18271 Type_18271, *PType_18271;

struct Type_18271 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_757 {
    byte FIELD; // Magic (0x06)
    struct Type_18271 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_757 {
    byte Size; // coded integer - blob size
    struct FieldSig_757 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_915 Blob_Generic_915, *PBlob_Generic_915;

struct Blob_Generic_915 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_MethodDefSig_16 Blob_MethodDefSig_16, *PBlob_MethodDefSig_16;

typedef struct MethodDefSig_16 MethodDefSig_16, *PMethodDefSig_16;

typedef struct Type_17531 Type_17531, *PType_17531;

typedef struct Type_17532 Type_17532, *PType_17532;

struct Type_17532 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17531 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodDefSig_16 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_17531 RetType;
    struct Type_17532 Param0;
};

struct Blob_MethodDefSig_16 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_16 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_FieldSig_753 Blob_FieldSig_753, *PBlob_FieldSig_753;

typedef struct FieldSig_753 FieldSig_753, *PFieldSig_753;

typedef struct Type_18267 Type_18267, *PType_18267;

struct Type_18267 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_753 {
    byte FIELD; // Magic (0x06)
    struct Type_18267 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_753 {
    byte Size; // coded integer - blob size
    struct FieldSig_753 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_728 Blob_FieldSig_728, *PBlob_FieldSig_728;

typedef struct FieldSig_728 FieldSig_728, *PFieldSig_728;

typedef struct Type_18242 Type_18242, *PType_18242;

struct Type_18242 {
    enum TypeCode ELEMENT_TYPE_I8;
};

struct FieldSig_728 {
    byte FIELD; // Magic (0x06)
    struct Type_18242 ELEMENT_TYPE_I8;
};

struct Blob_FieldSig_728 {
    byte Size; // coded integer - blob size
    struct FieldSig_728 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_724 Blob_FieldSig_724, *PBlob_FieldSig_724;

typedef struct FieldSig_724 FieldSig_724, *PFieldSig_724;

typedef struct Type_18238 Type_18238, *PType_18238;

struct Type_18238 {
    struct SzArray_18239 ELEMENT_TYPE_SZARRAY;
};

struct FieldSig_724 {
    byte FIELD; // Magic (0x06)
    struct Type_18238 ELEMENT_TYPE_SZARRAY;
};

struct Blob_FieldSig_724 {
    byte Size; // coded integer - blob size
    struct FieldSig_724 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_721 Blob_FieldSig_721, *PBlob_FieldSig_721;

typedef struct FieldSig_721 FieldSig_721, *PFieldSig_721;

typedef struct Type_18235 Type_18235, *PType_18235;

struct Type_18235 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct FieldSig_721 {
    byte FIELD; // Magic (0x06)
    struct Type_18235 ELEMENT_TYPE_BOOLEAN;
};

struct Blob_FieldSig_721 {
    byte Size; // coded integer - blob size
    struct FieldSig_721 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_620 Blob_Generic_620, *PBlob_Generic_620;

struct Blob_Generic_620 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_741 Blob_Generic_741, *PBlob_Generic_741;

struct Blob_Generic_741 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_860 Blob_Generic_860, *PBlob_Generic_860;

struct Blob_Generic_860 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_625 Blob_Generic_625, *PBlob_Generic_625;

struct Blob_Generic_625 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_867 Blob_Generic_867, *PBlob_Generic_867;

struct Blob_Generic_867 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_745 Blob_Generic_745, *PBlob_Generic_745;

struct Blob_Generic_745 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_508 Blob_Generic_508, *PBlob_Generic_508;

struct Blob_Generic_508 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_749 Blob_Generic_749, *PBlob_Generic_749;

struct Blob_Generic_749 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_523 Blob_LocalVarSig_523, *PBlob_LocalVarSig_523;

typedef struct LocalVarSig_523 LocalVarSig_523, *PLocalVarSig_523;

typedef struct Type_18038 Type_18038, *PType_18038;

typedef struct Type_18039 Type_18039, *PType_18039;

typedef struct Type_18042 Type_18042, *PType_18042;

struct Type_18042 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_18038 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18039 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct LocalVarSig_523 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_18038 Type;
    struct Type_18039 Type;
    struct Type_18042 Type;
};

struct Blob_LocalVarSig_523 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_523 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_FieldSig_737 Blob_FieldSig_737, *PBlob_FieldSig_737;

typedef struct FieldSig_737 FieldSig_737, *PFieldSig_737;

typedef struct Type_18251 Type_18251, *PType_18251;

struct Type_18251 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_737 {
    byte FIELD; // Magic (0x06)
    struct Type_18251 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_737 {
    byte Size; // coded integer - blob size
    struct FieldSig_737 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_734 Blob_FieldSig_734, *PBlob_FieldSig_734;

typedef struct FieldSig_734 FieldSig_734, *PFieldSig_734;

typedef struct Type_18248 Type_18248, *PType_18248;

struct Type_18248 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct FieldSig_734 {
    byte FIELD; // Magic (0x06)
    struct Type_18248 ELEMENT_TYPE_STRING;
};

struct Blob_FieldSig_734 {
    byte Size; // coded integer - blob size
    struct FieldSig_734 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_610 Blob_Generic_610, *PBlob_Generic_610;

struct Blob_Generic_610 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_731 Blob_Generic_731, *PBlob_Generic_731;

struct Blob_Generic_731 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_Generic_970 Blob_Generic_970, *PBlob_Generic_970;

struct Blob_Generic_970 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_Generic_734 Blob_Generic_734, *PBlob_Generic_734;

struct Blob_Generic_734 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_Generic_854 Blob_Generic_854, *PBlob_Generic_854;

struct Blob_Generic_854 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_737 Blob_Generic_737, *PBlob_Generic_737;

struct Blob_Generic_737 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_979 Blob_Generic_979, *PBlob_Generic_979;

struct Blob_Generic_979 {
    byte Size; // coded integer - blob size
    byte Generic[19]; // Undefined blob contents
};

typedef struct Blob_Generic_615 Blob_Generic_615, *PBlob_Generic_615;

struct Blob_Generic_615 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_FieldSig_731 Blob_FieldSig_731, *PBlob_FieldSig_731;

typedef struct FieldSig_731 FieldSig_731, *PFieldSig_731;

typedef struct Type_18245 Type_18245, *PType_18245;

struct Type_18245 {
    enum TypeCode ELEMENT_TYPE_R8;
};

struct FieldSig_731 {
    byte FIELD; // Magic (0x06)
    struct Type_18245 ELEMENT_TYPE_R8;
};

struct Blob_FieldSig_731 {
    byte Size; // coded integer - blob size
    struct FieldSig_731 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_706 Blob_FieldSig_706, *PBlob_FieldSig_706;

typedef struct FieldSig_706 FieldSig_706, *PFieldSig_706;

typedef struct Type_18220 Type_18220, *PType_18220;

struct Type_18220 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct FieldSig_706 {
    byte FIELD; // Magic (0x06)
    struct Type_18220 ELEMENT_TYPE_VALUETYPE;
};

struct Blob_FieldSig_706 {
    byte Size; // coded integer - blob size
    struct FieldSig_706 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_703 Blob_FieldSig_703, *PBlob_FieldSig_703;

typedef struct FieldSig_703 FieldSig_703, *PFieldSig_703;

typedef struct Type_18217 Type_18217, *PType_18217;

struct Type_18217 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct FieldSig_703 {
    byte FIELD; // Magic (0x06)
    struct Type_18217 ELEMENT_TYPE_I4;
};

struct Blob_FieldSig_703 {
    byte Size; // coded integer - blob size
    struct FieldSig_703 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_841 Blob_Generic_841, *PBlob_Generic_841;

struct Blob_Generic_841 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_724 Blob_Generic_724, *PBlob_Generic_724;

struct Blob_Generic_724 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_600 Blob_Generic_600, *PBlob_Generic_600;

struct Blob_Generic_600 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_721 Blob_Generic_721, *PBlob_Generic_721;

struct Blob_Generic_721 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_Generic_728 Blob_Generic_728, *PBlob_Generic_728;

struct Blob_Generic_728 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_Generic_848 Blob_Generic_848, *PBlob_Generic_848;

struct Blob_Generic_848 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_605 Blob_Generic_605, *PBlob_Generic_605;

struct Blob_Generic_605 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_97 Blob_LocalVarSig_97, *PBlob_LocalVarSig_97;

typedef struct LocalVarSig_97 LocalVarSig_97, *PLocalVarSig_97;

typedef struct Type_17612 Type_17612, *PType_17612;

typedef struct Type_17614 Type_17614, *PType_17614;

typedef struct Type_17615 Type_17615, *PType_17615;

typedef struct Type_17616 Type_17616, *PType_17616;

typedef struct Type_17617 Type_17617, *PType_17617;

typedef struct Type_17619 Type_17619, *PType_17619;

typedef struct Type_17621 Type_17621, *PType_17621;

typedef struct Type_17622 Type_17622, *PType_17622;

typedef struct Type_17623 Type_17623, *PType_17623;

typedef struct Type_17624 Type_17624, *PType_17624;

typedef struct Type_17625 Type_17625, *PType_17625;

typedef struct Type_17626 Type_17626, *PType_17626;

typedef struct Type_17627 Type_17627, *PType_17627;

typedef struct Type_17629 Type_17629, *PType_17629;

typedef struct Type_17631 Type_17631, *PType_17631;

struct Type_17619 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17629 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17617 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17616 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17627 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17623 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17624 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17614 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17615 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17631 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17622 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17612 {
    struct SzArray_17613 ELEMENT_TYPE_SZARRAY;
};

struct Type_17626 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17621 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17625 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct LocalVarSig_97 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17612 Type;
    struct Type_17614 Type;
    struct Type_17615 Type;
    struct Type_17616 Type;
    struct Type_17617 Type;
    struct Type_17619 Type;
    struct Type_17621 Type;
    struct Type_17622 Type;
    struct Type_17623 Type;
    struct Type_17624 Type;
    struct Type_17625 Type;
    struct Type_17626 Type;
    struct Type_17627 Type;
    struct Type_17629 Type;
    struct Type_17631 Type;
};

struct Blob_LocalVarSig_97 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_97 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_FieldSig_714 Blob_FieldSig_714, *PBlob_FieldSig_714;

typedef struct FieldSig_714 FieldSig_714, *PFieldSig_714;

typedef struct Type_18228 Type_18228, *PType_18228;

struct Type_18228 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_714 {
    byte FIELD; // Magic (0x06)
    struct Type_18228 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_714 {
    byte Size; // coded integer - blob size
    struct FieldSig_714 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_710 Blob_FieldSig_710, *PBlob_FieldSig_710;

typedef struct FieldSig_710 FieldSig_710, *PFieldSig_710;

typedef struct Type_18224 Type_18224, *PType_18224;

struct Type_18224 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct FieldSig_710 {
    byte FIELD; // Magic (0x06)
    struct Type_18224 ELEMENT_TYPE_CLASS;
};

struct Blob_FieldSig_710 {
    byte Size; // coded integer - blob size
    struct FieldSig_710 FieldSig; // Type information for Field
};

typedef struct Blob_FieldSig_718 Blob_FieldSig_718, *PBlob_FieldSig_718;

typedef struct FieldSig_718 FieldSig_718, *PFieldSig_718;

typedef struct Type_18232 Type_18232, *PType_18232;

struct Type_18232 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct FieldSig_718 {
    byte FIELD; // Magic (0x06)
    struct Type_18232 ELEMENT_TYPE_U1;
};

struct Blob_FieldSig_718 {
    byte Size; // coded integer - blob size
    struct FieldSig_718 FieldSig; // Type information for Field
};

typedef struct Blob_Generic_710 Blob_Generic_710, *PBlob_Generic_710;

struct Blob_Generic_710 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_831 Blob_Generic_831, *PBlob_Generic_831;

struct Blob_Generic_831 {
    byte Size; // coded integer - blob size
    byte Generic[9]; // Undefined blob contents
};

typedef struct Blob_Generic_714 Blob_Generic_714, *PBlob_Generic_714;

struct Blob_Generic_714 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_718 Blob_Generic_718, *PBlob_Generic_718;

struct Blob_Generic_718 {
    byte Size; // coded integer - blob size
    byte Generic[2]; // Undefined blob contents
};

typedef struct Blob_MethodDefSig_860 Blob_MethodDefSig_860, *PBlob_MethodDefSig_860;

typedef struct MethodDefSig_860 MethodDefSig_860, *PMethodDefSig_860;

typedef struct Type_18375 Type_18375, *PType_18375;

typedef struct Type_18376 Type_18376, *PType_18376;

struct Type_18376 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_18375 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodDefSig_860 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18375 RetType;
    struct Type_18376 Param0;
};

struct Blob_MethodDefSig_860 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_860 MethodDefSig; // Type info for method return and params
};

typedef struct CustomAttrib_1071 CustomAttrib_1071, *PCustomAttrib_1071;

struct CustomAttrib_1071 {
    word PROLOG; // Magic (0x0001)
    byte PackedLen;
    char FixedArg_0[7];
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct Blob_MethodRefSig_71 Blob_MethodRefSig_71, *PBlob_MethodRefSig_71;

typedef struct MethodRefSig_71 MethodRefSig_71, *PMethodRefSig_71;

typedef struct Type_17586 Type_17586, *PType_17586;

struct Type_17586 {
    enum TypeCode ELEMENT_TYPE_I8;
};

struct MethodRefSig_71 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17586 RetType;
};

struct Blob_MethodRefSig_71 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_71 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_867 Blob_MethodDefSig_867, *PBlob_MethodDefSig_867;

typedef struct MethodDefSig_867 MethodDefSig_867, *PMethodDefSig_867;

typedef struct Type_18382 Type_18382, *PType_18382;

struct Type_18382 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_867 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18382 RetType;
};

struct Blob_MethodDefSig_867 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_867 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodDefSig_508 Blob_MethodDefSig_508, *PBlob_MethodDefSig_508;

typedef struct MethodDefSig_508 MethodDefSig_508, *PMethodDefSig_508;

typedef struct Type_18023 Type_18023, *PType_18023;

struct Type_18023 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodDefSig_508 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18023 RetType;
};

struct Blob_MethodDefSig_508 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_508 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodRefSig_533 Blob_MethodRefSig_533, *PBlob_MethodRefSig_533;

typedef struct MethodRefSig_533 MethodRefSig_533, *PMethodRefSig_533;

typedef struct Type_18048 Type_18048, *PType_18048;

struct Type_18048 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_533 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18048 RetType;
};

struct Blob_MethodRefSig_533 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_533 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_539 Blob_MethodRefSig_539, *PBlob_MethodRefSig_539;

typedef struct MethodRefSig_539 MethodRefSig_539, *PMethodRefSig_539;

typedef struct Type_18054 Type_18054, *PType_18054;

typedef struct Type_18055 Type_18055, *PType_18055;

typedef struct Type_18056 Type_18056, *PType_18056;

struct Type_18054 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18055 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_18056 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_539 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18054 RetType;
    struct Type_18055 Param0;
    struct Type_18056 Param1;
};

struct Blob_MethodRefSig_539 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_539 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_415 Blob_MethodRefSig_415, *PBlob_MethodRefSig_415;

typedef struct MethodRefSig_415 MethodRefSig_415, *PMethodRefSig_415;

typedef struct Type_17930 Type_17930, *PType_17930;

typedef struct Type_17931 Type_17931, *PType_17931;

struct Type_17931 {
    struct ValueType.conflict18 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17930 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_415 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17930 RetType;
    struct Type_17931 Param0;
};

struct Blob_MethodRefSig_415 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_415 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_6 Blob_MethodDefSig_6, *PBlob_MethodDefSig_6;

typedef struct MethodDefSig_6 MethodDefSig_6, *PMethodDefSig_6;

struct MethodDefSig_6 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_17521 RetType;
};

struct Blob_MethodDefSig_6 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_6 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodRefSig_64 Blob_MethodRefSig_64, *PBlob_MethodRefSig_64;

typedef struct MethodRefSig_64 MethodRefSig_64, *PMethodRefSig_64;

typedef struct Type_17579 Type_17579, *PType_17579;

typedef struct Type_17580 Type_17580, *PType_17580;

struct Type_17580 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_17579 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_64 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17579 RetType;
    struct Type_17580 Param0;
};

struct Blob_MethodRefSig_64 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_64 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_854 Blob_MethodDefSig_854, *PBlob_MethodDefSig_854;

typedef struct MethodDefSig_854 MethodDefSig_854, *PMethodDefSig_854;

typedef struct Type_18369 Type_18369, *PType_18369;

struct Type_18369 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_854 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18369 RetType;
};

struct Blob_MethodDefSig_854 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_854 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodRefSig_401 Blob_MethodRefSig_401, *PBlob_MethodRefSig_401;

typedef struct MethodRefSig_401 MethodRefSig_401, *PMethodRefSig_401;

typedef struct Type_17916 Type_17916, *PType_17916;

typedef struct Type_17917 Type_17917, *PType_17917;

struct Type_17916 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17917 {
    struct ValueType.conflict17 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_401 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17916 RetType;
    struct Type_17917 Param0;
};

struct Blob_MethodRefSig_401 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_401 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_408 Blob_MethodRefSig_408, *PBlob_MethodRefSig_408;

typedef struct MethodRefSig_408 MethodRefSig_408, *PMethodRefSig_408;

typedef struct Type_17923 Type_17923, *PType_17923;

typedef struct Type_17924 Type_17924, *PType_17924;

struct Type_17924 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_17923 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_408 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17923 RetType;
    struct Type_17924 Param0;
};

struct Blob_MethodRefSig_408 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_408 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_CustomAttrib_600 Blob_CustomAttrib_600, *PBlob_CustomAttrib_600;

typedef struct CustomAttrib_600 CustomAttrib_600, *PCustomAttrib_600;

struct CustomAttrib_600 {
    word PROLOG; // Magic (0x0001)
    word NumNamed; // Number of NamedArgs to follow
};

struct Blob_CustomAttrib_600 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_600 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_58 Blob_MethodRefSig_58, *PBlob_MethodRefSig_58;

typedef struct MethodRefSig_58 MethodRefSig_58, *PMethodRefSig_58;

typedef struct Type_17573 Type_17573, *PType_17573;

typedef struct Type_17574 Type_17574, *PType_17574;

typedef struct Type_17575 Type_17575, *PType_17575;

struct Type_17574 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct Type_17573 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17575 {
    enum TypeCode ELEMENT_TYPE_I;
};

struct MethodRefSig_58 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17573 RetType;
    struct Type_17574 Param0;
    struct Type_17575 Param1;
};

struct Blob_MethodRefSig_58 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_58 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_53 Blob_MethodRefSig_53, *PBlob_MethodRefSig_53;

typedef struct MethodRefSig_53 MethodRefSig_53, *PMethodRefSig_53;

typedef struct Type_17568 Type_17568, *PType_17568;

typedef struct Type_17569 Type_17569, *PType_17569;

struct Type_17569 {
    enum TypeCode ELEMENT_TYPE_R8;
};

struct Type_17568 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_53 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17568 RetType;
    struct Type_17569 Param0;
};

struct Blob_MethodRefSig_53 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_53 MethodRefSig; // Type info for imported method return and params
};

typedef struct CustomAttrib_1093 CustomAttrib_1093, *PCustomAttrib_1093;

struct CustomAttrib_1093 {
    word PROLOG; // Magic (0x0001)
    byte PackedLen;
    char FixedArg_0[51];
    byte PackedLen;
    char FixedArg_1[7];
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct CustomAttrib_999 CustomAttrib_999, *PCustomAttrib_999;

struct CustomAttrib_999 {
    word PROLOG; // Magic (0x0001)
    byte FixedArg_0; // Elem (ELEMENT_TYPE_BOOLEAN)
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct Blob_MethodDefSig_841 Blob_MethodDefSig_841, *PBlob_MethodDefSig_841;

typedef struct MethodDefSig_841 MethodDefSig_841, *PMethodDefSig_841;

typedef struct Type_18356 Type_18356, *PType_18356;

typedef struct Type_18358 Type_18358, *PType_18358;

struct Type_18358 {
    struct SzArray_18359 ELEMENT_TYPE_SZARRAY;
};

struct Type_18356 {
    struct SzArray_18357 ELEMENT_TYPE_SZARRAY;
};

struct MethodDefSig_841 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18356 RetType;
    struct Type_18358 Param0;
};

struct Blob_MethodDefSig_841 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_841 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodDefSig_848 Blob_MethodDefSig_848, *PBlob_MethodDefSig_848;

typedef struct MethodDefSig_848 MethodDefSig_848, *PMethodDefSig_848;

typedef struct Type_18363 Type_18363, *PType_18363;

struct Type_18363 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_848 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18363 RetType;
};

struct Blob_MethodDefSig_848 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_848 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_CustomAttrib_939 Blob_CustomAttrib_939, *PBlob_CustomAttrib_939;

struct Blob_CustomAttrib_939 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_939 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_517 Blob_MethodRefSig_517, *PBlob_MethodRefSig_517;

typedef struct MethodRefSig_517 MethodRefSig_517, *PMethodRefSig_517;

typedef struct Type_18032 Type_18032, *PType_18032;

typedef struct Type_18033 Type_18033, *PType_18033;

struct Type_18032 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18033 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_517 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18032 RetType;
    struct Type_18033 Param0;
};

struct Blob_MethodRefSig_517 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_517 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_CustomAttrib_930 Blob_CustomAttrib_930, *PBlob_CustomAttrib_930;

struct Blob_CustomAttrib_930 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_930 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_512 Blob_MethodRefSig_512, *PBlob_MethodRefSig_512;

typedef struct MethodRefSig_512 MethodRefSig_512, *PMethodRefSig_512;

typedef struct Type_18027 Type_18027, *PType_18027;

typedef struct Type_18028 Type_18028, *PType_18028;

struct Type_18027 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18028 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct MethodRefSig_512 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18027 RetType;
    struct Type_18028 Param0;
};

struct Blob_MethodRefSig_512 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_512 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_CustomAttrib_1029 Blob_CustomAttrib_1029, *PBlob_CustomAttrib_1029;

typedef struct CustomAttrib_1029 CustomAttrib_1029, *PCustomAttrib_1029;

struct CustomAttrib_1029 {
    word PROLOG; // Magic (0x0001)
    byte PackedLen;
    char FixedArg_0[36];
    word NumNamed; // Number of NamedArgs to follow
};

struct Blob_CustomAttrib_1029 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_1029 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodDefSig_831 Blob_MethodDefSig_831, *PBlob_MethodDefSig_831;

typedef struct MethodDefSig_831 MethodDefSig_831, *PMethodDefSig_831;

typedef struct Type_18346 Type_18346, *PType_18346;

typedef struct Type_18348 Type_18348, *PType_18348;

typedef struct Type_18349 Type_18349, *PType_18349;

typedef struct Type_18350 Type_18350, *PType_18350;

typedef struct Type_18351 Type_18351, *PType_18351;

struct Type_18351 {
    struct SzArray_18352 ELEMENT_TYPE_SZARRAY;
};

struct Type_18349 {
    enum TypeCode ELEMENT_TYPE_U2;
};

struct Type_18350 {
    enum TypeCode ELEMENT_TYPE_U2;
};

struct Type_18348 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_18346 {
    struct SzArray_18347 ELEMENT_TYPE_SZARRAY;
};

struct MethodDefSig_831 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18346 RetType;
    struct Type_18348 Param0;
    struct Type_18349 Param1;
    struct Type_18350 Param2;
    struct Type_18351 Param3;
};

struct Blob_MethodDefSig_831 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_831 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_PropertySig_926 Blob_PropertySig_926, *PBlob_PropertySig_926;

typedef struct PropertySig_926 PropertySig_926, *PPropertySig_926;

typedef struct Type_18441 Type_18441, *PType_18441;

struct Type_18441 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct PropertySig_926 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18441 RetType; // Return type
};

struct Blob_PropertySig_926 {
    byte Size; // coded integer - blob size
    struct PropertySig_926 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_Generic_6 Blob_Generic_6, *PBlob_Generic_6;

struct Blob_Generic_6 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_508 Blob_MethodRefSig_508, *PBlob_MethodRefSig_508;

typedef struct MethodRefSig_508 MethodRefSig_508, *PMethodRefSig_508;

struct MethodRefSig_508 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18023 RetType;
};

struct Blob_MethodRefSig_508 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_508 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_PropertySig_921 Blob_PropertySig_921, *PBlob_PropertySig_921;

typedef struct PropertySig_921 PropertySig_921, *PPropertySig_921;

typedef struct Type_18436 Type_18436, *PType_18436;

struct Type_18436 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct PropertySig_921 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18436 RetType; // Return type
};

struct Blob_PropertySig_921 {
    byte Size; // coded integer - blob size
    struct PropertySig_921 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_MethodRefSig_39 Blob_MethodRefSig_39, *PBlob_MethodRefSig_39;

typedef struct MethodRefSig_39 MethodRefSig_39, *PMethodRefSig_39;

typedef struct Type_17554 Type_17554, *PType_17554;

typedef struct Type_17555 Type_17555, *PType_17555;

struct Type_17555 {
    struct ValueType.conflict2 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17554 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_39 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17554 RetType;
    struct Type_17555 Param0;
};

struct Blob_MethodRefSig_39 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_39 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_1 Blob_Generic_1, *PBlob_Generic_1;

struct Blob_Generic_1 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_33 Blob_MethodRefSig_33, *PBlob_MethodRefSig_33;

typedef struct MethodRefSig_33 MethodRefSig_33, *PMethodRefSig_33;

typedef struct Type_17548 Type_17548, *PType_17548;

typedef struct Type_17549 Type_17549, *PType_17549;

typedef struct Type_17550 Type_17550, *PType_17550;

struct Type_17550 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17549 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17548 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_33 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17548 RetType;
    struct Type_17549 Param0;
    struct Type_17550 Param1;
};

struct Blob_MethodRefSig_33 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_33 MethodRefSig; // Type info for imported method return and params
};

typedef struct CustomAttrib_979 CustomAttrib_979, *PCustomAttrib_979;

struct CustomAttrib_979 {
    word PROLOG; // Magic (0x0001)
    byte PackedLen;
    char FixedArg_0[14];
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct Blob_MethodDefSig_822 Blob_MethodDefSig_822, *PBlob_MethodDefSig_822;

typedef struct MethodDefSig_822 MethodDefSig_822, *PMethodDefSig_822;

typedef struct Type_18337 Type_18337, *PType_18337;

struct Type_18337 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct MethodDefSig_822 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18337 RetType;
};

struct Blob_MethodDefSig_822 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_822 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_MethodDefSig_826 Blob_MethodDefSig_826, *PBlob_MethodDefSig_826;

typedef struct MethodDefSig_826 MethodDefSig_826, *PMethodDefSig_826;

typedef struct Type_18341 Type_18341, *PType_18341;

typedef struct Type_18342 Type_18342, *PType_18342;

struct Type_18341 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18342 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct MethodDefSig_826 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18341 RetType;
    struct Type_18342 Param0;
};

struct Blob_MethodDefSig_826 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_826 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_PropertySig_915 Blob_PropertySig_915, *PBlob_PropertySig_915;

typedef struct PropertySig_915 PropertySig_915, *PPropertySig_915;

typedef struct Type_18430 Type_18430, *PType_18430;

struct Type_18430 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct PropertySig_915 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18430 RetType; // Return type
};

struct Blob_PropertySig_915 {
    byte Size; // coded integer - blob size
    struct PropertySig_915 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_Generic_901 Blob_Generic_901, *PBlob_Generic_901;

struct Blob_Generic_901 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_905 Blob_Generic_905, *PBlob_Generic_905;

struct Blob_Generic_905 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_909 Blob_Generic_909, *PBlob_Generic_909;

struct Blob_Generic_909 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_26 Blob_MethodRefSig_26, *PBlob_MethodRefSig_26;

typedef struct MethodRefSig_26 MethodRefSig_26, *PMethodRefSig_26;

typedef struct Type_17541 Type_17541, *PType_17541;

typedef struct Type_17542 Type_17542, *PType_17542;

struct Type_17541 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17542 {
    struct ValueType.conflict1 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_26 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17541 RetType;
    struct Type_17542 Param0;
};

struct Blob_MethodRefSig_26 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_26 MethodRefSig; // Type info for imported method return and params
};

typedef struct CustomAttrib_970 CustomAttrib_970, *PCustomAttrib_970;

struct CustomAttrib_970 {
    word PROLOG; // Magic (0x0001)
    dword FixedArg_0; // Elem (ELEMENT_TYPE_VALUETYPE)
    word NumNamed; // Number of NamedArgs to follow
};

typedef struct Blob_CustomAttrib_999 Blob_CustomAttrib_999, *PBlob_CustomAttrib_999;

struct Blob_CustomAttrib_999 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_999 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_21 Blob_MethodRefSig_21, *PBlob_MethodRefSig_21;

typedef struct MethodRefSig_21 MethodRefSig_21, *PMethodRefSig_21;

struct MethodRefSig_21 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17536 RetType;
    struct Type_17537 Param0;
};

struct Blob_MethodRefSig_21 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_21 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_815 Blob_MethodDefSig_815, *PBlob_MethodDefSig_815;

typedef struct MethodDefSig_815 MethodDefSig_815, *PMethodDefSig_815;

typedef struct Type_18330 Type_18330, *PType_18330;

typedef struct Type_18331 Type_18331, *PType_18331;

typedef struct Type_18332 Type_18332, *PType_18332;

struct Type_18330 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18332 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct Type_18331 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct MethodDefSig_815 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18330 RetType;
    struct Type_18331 Param0;
    struct Type_18332 Param1;
};

struct Blob_MethodDefSig_815 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_815 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_CustomAttrib_1248 Blob_CustomAttrib_1248, *PBlob_CustomAttrib_1248;

typedef struct CustomAttrib_1248 CustomAttrib_1248, *PCustomAttrib_1248;

struct CustomAttrib_1248 {
    word PROLOG; // Magic (0x0001)
    dword FixedArg_0; // Elem (ELEMENT_TYPE_VALUETYPE)
    word NumNamed; // Number of NamedArgs to follow
};

struct Blob_CustomAttrib_1248 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_1248 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_PropertySig_905 Blob_PropertySig_905, *PBlob_PropertySig_905;

typedef struct PropertySig_905 PropertySig_905, *PPropertySig_905;

typedef struct Type_18420 Type_18420, *PType_18420;

struct Type_18420 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct PropertySig_905 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18420 RetType; // Return type
};

struct Blob_PropertySig_905 {
    byte Size; // coded integer - blob size
    struct PropertySig_905 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_PropertySig_909 Blob_PropertySig_909, *PBlob_PropertySig_909;

typedef struct PropertySig_909 PropertySig_909, *PPropertySig_909;

typedef struct Type_18424 Type_18424, *PType_18424;

struct Type_18424 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct PropertySig_909 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18424 RetType; // Return type
};

struct Blob_PropertySig_909 {
    byte Size; // coded integer - blob size
    struct PropertySig_909 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_MethodRefSig_16 Blob_MethodRefSig_16, *PBlob_MethodRefSig_16;

typedef struct MethodRefSig_16 MethodRefSig_16, *PMethodRefSig_16;

struct MethodRefSig_16 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17531 RetType;
    struct Type_17532 Param0;
};

struct Blob_MethodRefSig_16 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_16 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_PropertySig_901 Blob_PropertySig_901, *PBlob_PropertySig_901;

typedef struct PropertySig_901 PropertySig_901, *PPropertySig_901;

typedef struct Type_18416 Type_18416, *PType_18416;

struct Type_18416 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct PropertySig_901 {
    byte PROPERTY; // Magic (0x08) optionalled OR'd with HASTHIS (0x20)
    byte Count; // Number of params to follow RetType
    struct Type_18416 RetType; // Return type
};

struct Blob_PropertySig_901 {
    byte Size; // coded integer - blob size
    struct PropertySig_901 PropertySig; // Contains signature for properties. Gives params for getters/setters.
};

typedef struct Blob_MethodRefSig_10 Blob_MethodRefSig_10, *PBlob_MethodRefSig_10;

typedef struct MethodRefSig_10 MethodRefSig_10, *PMethodRefSig_10;

typedef struct Type_17525 Type_17525, *PType_17525;

typedef struct Type_17526 Type_17526, *PType_17526;

struct Type_17526 {
    struct ValueType.conflict ELEMENT_TYPE_VALUETYPE;
};

struct Type_17525 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_10 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17525 RetType;
    struct Type_17526 Param0;
};

struct Blob_MethodRefSig_10 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_10 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_802 Blob_MethodDefSig_802, *PBlob_MethodDefSig_802;

typedef struct MethodDefSig_802 MethodDefSig_802, *PMethodDefSig_802;

typedef struct Type_18317 Type_18317, *PType_18317;

typedef struct Type_18318 Type_18318, *PType_18318;

struct Type_18317 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18318 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_802 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18317 RetType;
    struct Type_18318 Param0;
};

struct Blob_MethodDefSig_802 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_802 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_CustomAttrib_979 Blob_CustomAttrib_979, *PBlob_CustomAttrib_979;

struct Blob_CustomAttrib_979 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_979 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodDefSig_808 Blob_MethodDefSig_808, *PBlob_MethodDefSig_808;

typedef struct MethodDefSig_808 MethodDefSig_808, *PMethodDefSig_808;

typedef struct Type_18323 Type_18323, *PType_18323;

typedef struct Type_18324 Type_18324, *PType_18324;

typedef struct Type_18325 Type_18325, *PType_18325;

struct Type_18323 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18325 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct Type_18324 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct MethodDefSig_808 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18323 RetType;
    struct Type_18324 Param0;
    struct Type_18325 Param1;
};

struct Blob_MethodDefSig_808 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_808 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_CustomAttrib_970 Blob_CustomAttrib_970, *PBlob_CustomAttrib_970;

struct Blob_CustomAttrib_970 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_970 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_Generic_140 Blob_Generic_140, *PBlob_Generic_140;

struct Blob_Generic_140 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_261 Blob_Generic_261, *PBlob_Generic_261;

struct Blob_Generic_261 {
    byte Size; // coded integer - blob size
    byte Generic[13]; // Undefined blob contents
};

typedef struct Blob_Generic_381 Blob_Generic_381, *PBlob_Generic_381;

struct Blob_Generic_381 {
    byte Size; // coded integer - blob size
    byte Generic[12]; // Undefined blob contents
};

typedef struct Blob_Generic_1071 Blob_Generic_1071, *PBlob_Generic_1071;

struct Blob_Generic_1071 {
    byte Size; // coded integer - blob size
    byte Generic[12]; // Undefined blob contents
};

typedef struct Blob_Generic_144 Blob_Generic_144, *PBlob_Generic_144;

struct Blob_Generic_144 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_Generic_81 Blob_Generic_81, *PBlob_Generic_81;

struct Blob_Generic_81 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_Generic_89 Blob_Generic_89, *PBlob_Generic_89;

struct Blob_Generic_89 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_LocalVarSig_282 Blob_LocalVarSig_282, *PBlob_LocalVarSig_282;

typedef struct LocalVarSig_282 LocalVarSig_282, *PLocalVarSig_282;

typedef struct Type_17797 Type_17797, *PType_17797;

typedef struct Type_17799 Type_17799, *PType_17799;

struct Type_17799 {
    struct SzArray_17800 ELEMENT_TYPE_SZARRAY;
};

struct Type_17797 {
    struct SzArray_17798 ELEMENT_TYPE_SZARRAY;
};

struct LocalVarSig_282 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17797 Type;
    struct Type_17799 Type;
};

struct Blob_LocalVarSig_282 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_282 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_MethodRefSig_132 Blob_MethodRefSig_132, *PBlob_MethodRefSig_132;

typedef struct MethodRefSig_132 MethodRefSig_132, *PMethodRefSig_132;

typedef struct Type_17647 Type_17647, *PType_17647;

typedef struct Type_17648 Type_17648, *PType_17648;

typedef struct Type_17650 Type_17650, *PType_17650;

typedef struct Type_17651 Type_17651, *PType_17651;

struct Type_17648 {
    struct SzArray_17649 ELEMENT_TYPE_SZARRAY;
};

struct Type_17651 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17647 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17650 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_132 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17647 RetType;
    struct Type_17648 Param0;
    struct Type_17650 Param1;
    struct Type_17651 Param2;
};

struct Blob_MethodRefSig_132 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_132 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_374 Blob_MethodRefSig_374, *PBlob_MethodRefSig_374;

typedef struct MethodRefSig_374 MethodRefSig_374, *PMethodRefSig_374;

typedef struct Type_17889 Type_17889, *PType_17889;

typedef struct Type_17890 Type_17890, *PType_17890;

struct Type_17890 {
    struct ValueType.conflict14 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17889 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_374 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17889 RetType;
    struct Type_17890 Param0;
};

struct Blob_MethodRefSig_374 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_374 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_254 Blob_MethodRefSig_254, *PBlob_MethodRefSig_254;

typedef struct MethodRefSig_254 MethodRefSig_254, *PMethodRefSig_254;

typedef struct Type_17769 Type_17769, *PType_17769;

typedef struct Type_17770 Type_17770, *PType_17770;

struct Type_17770 {
    struct ValueType.conflict7 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17769 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_254 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17769 RetType;
    struct Type_17770 Param0;
};

struct Blob_MethodRefSig_254 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_254 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_ConstantSig_600 Blob_ConstantSig_600, *PBlob_ConstantSig_600;

typedef struct ConstantSig_600 ConstantSig_600, *PConstantSig_600;

struct ConstantSig_600 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_600 {
    byte Size; // coded integer - blob size
    struct ConstantSig_600 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_254 Blob_Generic_254, *PBlob_Generic_254;

struct Blob_Generic_254 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_605 Blob_ConstantSig_605, *PBlob_ConstantSig_605;

typedef struct ConstantSig_605 ConstantSig_605, *PConstantSig_605;

struct ConstantSig_605 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_605 {
    byte Size; // coded integer - blob size
    struct ConstantSig_605 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_132 Blob_Generic_132, *PBlob_Generic_132;

struct Blob_Generic_132 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_Generic_374 Blob_Generic_374, *PBlob_Generic_374;

struct Blob_Generic_374 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_1084 Blob_Generic_1084, *PBlob_Generic_1084;

struct Blob_Generic_1084 {
    byte Size; // coded integer - blob size
    byte Generic[8]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_360 Blob_MethodRefSig_360, *PBlob_MethodRefSig_360;

typedef struct MethodRefSig_360 MethodRefSig_360, *PMethodRefSig_360;

typedef struct Type_17875 Type_17875, *PType_17875;

typedef struct Type_17876 Type_17876, *PType_17876;

struct Type_17876 {
    struct ValueType.conflict12 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17875 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_360 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17875 RetType;
    struct Type_17876 Param0;
};

struct Blob_MethodRefSig_360 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_360 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_497 Blob_Generic_497, *PBlob_Generic_497;

struct Blob_Generic_497 {
    byte Size; // coded integer - blob size
    byte Generic[10]; // Undefined blob contents
};

typedef struct Blob_Generic_97 Blob_Generic_97, *PBlob_Generic_97;

struct Blob_Generic_97 {
    byte Size; // coded integer - blob size
    byte Generic[22]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_367 Blob_MethodRefSig_367, *PBlob_MethodRefSig_367;

typedef struct MethodRefSig_367 MethodRefSig_367, *PMethodRefSig_367;

typedef struct Type_17882 Type_17882, *PType_17882;

typedef struct Type_17883 Type_17883, *PType_17883;

struct Type_17882 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17883 {
    struct ValueType.conflict13 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_367 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17882 RetType;
    struct Type_17883 Param0;
};

struct Blob_MethodRefSig_367 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_367 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_126 Blob_MethodRefSig_126, *PBlob_MethodRefSig_126;

typedef struct MethodRefSig_126 MethodRefSig_126, *PMethodRefSig_126;

typedef struct Type_17641 Type_17641, *PType_17641;

typedef struct Type_17643 Type_17643, *PType_17643;

struct Type_17643 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17641 {
    struct SzArray_17642 ELEMENT_TYPE_SZARRAY;
};

struct MethodRefSig_126 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17641 RetType;
    struct Type_17643 Param0;
};

struct Blob_MethodRefSig_126 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_126 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_247 Blob_MethodRefSig_247, *PBlob_MethodRefSig_247;

typedef struct MethodRefSig_247 MethodRefSig_247, *PMethodRefSig_247;

typedef struct Type_17762 Type_17762, *PType_17762;

typedef struct Type_17763 Type_17763, *PType_17763;

struct Type_17763 {
    struct ValueType.conflict6 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17762 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_247 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17762 RetType;
    struct Type_17763 Param0;
};

struct Blob_MethodRefSig_247 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_247 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_LocalVarSig_175 Blob_LocalVarSig_175, *PBlob_LocalVarSig_175;

typedef struct LocalVarSig_175 LocalVarSig_175, *PLocalVarSig_175;

typedef struct Type_17690 Type_17690, *PType_17690;

typedef struct Type_17691 Type_17691, *PType_17691;

typedef struct Type_17693 Type_17693, *PType_17693;

typedef struct Type_17695 Type_17695, *PType_17695;

typedef struct Type_17696 Type_17696, *PType_17696;

typedef struct Type_17698 Type_17698, *PType_17698;

typedef struct Type_17699 Type_17699, *PType_17699;

typedef struct Type_17700 Type_17700, *PType_17700;

typedef struct Type_17701 Type_17701, *PType_17701;

typedef struct Type_17702 Type_17702, *PType_17702;

typedef struct Type_17703 Type_17703, *PType_17703;

typedef struct Type_17704 Type_17704, *PType_17704;

typedef struct Type_17705 Type_17705, *PType_17705;

typedef struct Type_17706 Type_17706, *PType_17706;

typedef struct Type_17707 Type_17707, *PType_17707;

typedef struct Type_17708 Type_17708, *PType_17708;

typedef struct Type_17709 Type_17709, *PType_17709;

typedef struct Type_17710 Type_17710, *PType_17710;

typedef struct Type_17711 Type_17711, *PType_17711;

typedef struct Type_17712 Type_17712, *PType_17712;

typedef struct Type_17713 Type_17713, *PType_17713;

typedef struct Type_17714 Type_17714, *PType_17714;

typedef struct Type_17715 Type_17715, *PType_17715;

typedef struct Type_17716 Type_17716, *PType_17716;

typedef struct Type_17717 Type_17717, *PType_17717;

typedef struct Type_17718 Type_17718, *PType_17718;

typedef struct Type_17719 Type_17719, *PType_17719;

typedef struct Type_17720 Type_17720, *PType_17720;

struct Type_17707 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17706 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17705 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17704 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17709 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17708 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17720 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17703 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17702 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17701 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17700 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17718 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17717 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_17716 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_17715 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17719 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17711 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17713 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_17696 {
    struct SzArray_17697 ELEMENT_TYPE_SZARRAY;
};

struct Type_17710 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17693 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17690 {
    enum TypeCode ELEMENT_TYPE_U2;
};

struct Type_17712 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17698 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17695 {
    enum TypeCode ELEMENT_TYPE_I8;
};

struct Type_17691 {
    struct ValueType ELEMENT_TYPE_VALUETYPE;
};

struct Type_17714 {
    enum TypeCode ELEMENT_TYPE_U1;
};

struct Type_17699 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct LocalVarSig_175 {
    byte LOCAL_SIG; // Magic (0x07)
    byte Count; // Number of types to follow
    struct Type_17690 Type;
    struct Type_17691 Type;
    struct Type_17693 Type;
    struct Type_17695 Type;
    struct Type_17696 Type;
    struct Type_17698 Type;
    struct Type_17699 Type;
    struct Type_17700 Type;
    struct Type_17701 Type;
    struct Type_17702 Type;
    struct Type_17703 Type;
    struct Type_17704 Type;
    struct Type_17705 Type;
    struct Type_17706 Type;
    struct Type_17707 Type;
    struct Type_17708 Type;
    struct Type_17709 Type;
    struct Type_17710 Type;
    struct Type_17711 Type;
    struct Type_17712 Type;
    struct Type_17713 Type;
    struct Type_17714 Type;
    struct Type_17715 Type;
    struct Type_17716 Type;
    struct Type_17717 Type;
    struct Type_17718 Type;
    struct Type_17719 Type;
    struct Type_17720 Type;
};

struct Blob_LocalVarSig_175 {
    byte Size; // coded integer - blob size
    struct LocalVarSig_175 LocalVarSig; // Contains signature for function locals
};

typedef struct Blob_MethodRefSig_242 Blob_MethodRefSig_242, *PBlob_MethodRefSig_242;

typedef struct MethodRefSig_242 MethodRefSig_242, *PMethodRefSig_242;

typedef struct Type_17757 Type_17757, *PType_17757;

typedef struct Type_17758 Type_17758, *PType_17758;

struct Type_17758 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17757 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_242 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17757 RetType;
    struct Type_17758 Param0;
};

struct Blob_MethodRefSig_242 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_242 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_120 Blob_MethodRefSig_120, *PBlob_MethodRefSig_120;

typedef struct MethodRefSig_120 MethodRefSig_120, *PMethodRefSig_120;

typedef struct Type_17635 Type_17635, *PType_17635;

struct Type_17635 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_120 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17635 RetType;
};

struct Blob_MethodRefSig_120 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_120 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_360 Blob_Generic_360, *PBlob_Generic_360;

struct Blob_Generic_360 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_1093 Blob_Generic_1093, *PBlob_Generic_1093;

struct Blob_Generic_1093 {
    byte Size; // coded integer - blob size
    byte Generic[64]; // Undefined blob contents
};

typedef struct Blob_Generic_242 Blob_Generic_242, *PBlob_Generic_242;

struct Blob_Generic_242 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_484 Blob_Generic_484, *PBlob_Generic_484;

struct Blob_Generic_484 {
    byte Size; // coded integer - blob size
    byte Generic[12]; // Undefined blob contents
};

typedef struct Blob_Generic_120 Blob_Generic_120, *PBlob_Generic_120;

struct Blob_Generic_120 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_126 Blob_Generic_126, *PBlob_Generic_126;

struct Blob_Generic_126 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_247 Blob_Generic_247, *PBlob_Generic_247;

struct Blob_Generic_247 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_367 Blob_Generic_367, *PBlob_Generic_367;

struct Blob_Generic_367 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_Generic_64 Blob_Generic_64, *PBlob_Generic_64;

struct Blob_Generic_64 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_236 Blob_MethodRefSig_236, *PBlob_MethodRefSig_236;

typedef struct MethodRefSig_236 MethodRefSig_236, *PMethodRefSig_236;

typedef struct Type_17751 Type_17751, *PType_17751;

struct Type_17751 {
    struct ValueType.conflict5 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_236 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17751 RetType;
};

struct Blob_MethodRefSig_236 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_236 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_354 Blob_MethodRefSig_354, *PBlob_MethodRefSig_354;

typedef struct MethodRefSig_354 MethodRefSig_354, *PMethodRefSig_354;

typedef struct Type_17869 Type_17869, *PType_17869;

typedef struct Type_17870 Type_17870, *PType_17870;

typedef struct Type_17871 Type_17871, *PType_17871;

struct Type_17869 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17871 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct Type_17870 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_354 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17869 RetType;
    struct Type_17870 Param0;
    struct Type_17871 Param1;
};

struct Blob_MethodRefSig_354 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_354 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_230 Blob_MethodRefSig_230, *PBlob_MethodRefSig_230;

typedef struct MethodRefSig_230 MethodRefSig_230, *PMethodRefSig_230;

typedef struct Type_17745 Type_17745, *PType_17745;

typedef struct Type_17746 Type_17746, *PType_17746;

typedef struct Type_17747 Type_17747, *PType_17747;

struct Type_17745 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_17747 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17746 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_230 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17745 RetType;
    struct Type_17746 Param0;
    struct Type_17747 Param1;
};

struct Blob_MethodRefSig_230 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_230 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_71 Blob_Generic_71, *PBlob_Generic_71;

struct Blob_Generic_71 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_Generic_474 Blob_Generic_474, *PBlob_Generic_474;

struct Blob_Generic_474 {
    byte Size; // coded integer - blob size
    byte Generic[9]; // Undefined blob contents
};

typedef struct Blob_Generic_595 Blob_Generic_595, *PBlob_Generic_595;

struct Blob_Generic_595 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_MethodDefSig_798 Blob_MethodDefSig_798, *PBlob_MethodDefSig_798;

typedef struct MethodDefSig_798 MethodDefSig_798, *PMethodDefSig_798;

typedef struct Type_18313 Type_18313, *PType_18313;

struct Type_18313 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct MethodDefSig_798 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18313 RetType;
};

struct Blob_MethodDefSig_798 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_798 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_Generic_230 Blob_Generic_230, *PBlob_Generic_230;

struct Blob_Generic_230 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_701 Blob_ConstantSig_701, *PBlob_ConstantSig_701;

typedef struct ConstantSig_701 ConstantSig_701, *PConstantSig_701;

struct ConstantSig_701 {
};

struct Blob_ConstantSig_701 {
    byte Size; // coded integer - blob size
    struct ConstantSig_701 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_236 Blob_Generic_236, *PBlob_Generic_236;

struct Blob_Generic_236 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_354 Blob_Generic_354, *PBlob_Generic_354;

struct Blob_Generic_354 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_75 Blob_Generic_75, *PBlob_Generic_75;

struct Blob_Generic_75 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_467 Blob_MethodRefSig_467, *PBlob_MethodRefSig_467;

typedef struct MethodRefSig_467 MethodRefSig_467, *PMethodRefSig_467;

typedef struct Type_17982 Type_17982, *PType_17982;

typedef struct Type_17983 Type_17983, *PType_17983;

struct Type_17983 {
    struct ValueType.conflict21 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17982 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_467 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17982 RetType;
    struct Type_17983 Param0;
};

struct Blob_MethodRefSig_467 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_467 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_460 Blob_MethodRefSig_460, *PBlob_MethodRefSig_460;

typedef struct MethodRefSig_460 MethodRefSig_460, *PMethodRefSig_460;

typedef struct Type_17975 Type_17975, *PType_17975;

typedef struct Type_17976 Type_17976, *PType_17976;

struct Type_17975 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17976 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_460 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17975 RetType;
    struct Type_17976 Param0;
};

struct Blob_MethodRefSig_460 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_460 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_347 Blob_MethodRefSig_347, *PBlob_MethodRefSig_347;

typedef struct MethodRefSig_347 MethodRefSig_347, *PMethodRefSig_347;

typedef struct Type_17862 Type_17862, *PType_17862;

typedef struct Type_17863 Type_17863, *PType_17863;

struct Type_17863 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_17862 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_347 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17862 RetType;
    struct Type_17863 Param0;
};

struct Blob_MethodRefSig_347 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_347 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_783 Blob_MethodDefSig_783, *PBlob_MethodDefSig_783;

typedef struct MethodDefSig_783 MethodDefSig_783, *PMethodDefSig_783;

typedef struct Type_18298 Type_18298, *PType_18298;

typedef struct Type_18299 Type_18299, *PType_18299;

typedef struct Type_18301 Type_18301, *PType_18301;

typedef struct Type_18302 Type_18302, *PType_18302;

struct Type_18301 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_18302 {
    enum TypeCode ELEMENT_TYPE_BOOLEAN;
};

struct Type_18298 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18299 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_783 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18298 RetType;
    struct Type_18299 Param0;
    struct Type_18301 Param1;
    struct Type_18302 Param2;
};

struct Blob_MethodDefSig_783 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_783 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_ConstantSig_635 Blob_ConstantSig_635, *PBlob_ConstantSig_635;

typedef struct ConstantSig_635 ConstantSig_635, *PConstantSig_635;

struct ConstantSig_635 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_635 {
    byte Size; // coded integer - blob size
    struct ConstantSig_635 ConstantSig; // Data stored in a constant
};

typedef struct Blob_MethodRefSig_455 Blob_MethodRefSig_455, *PBlob_MethodRefSig_455;

typedef struct MethodRefSig_455 MethodRefSig_455, *PMethodRefSig_455;

typedef struct Type_17970 Type_17970, *PType_17970;

typedef struct Type_17971 Type_17971, *PType_17971;

struct Type_17970 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct Type_17971 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_455 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17970 RetType;
    struct Type_17971 Param0;
};

struct Blob_MethodRefSig_455 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_455 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_214 Blob_MethodRefSig_214, *PBlob_MethodRefSig_214;

typedef struct MethodRefSig_214 MethodRefSig_214, *PMethodRefSig_214;

typedef struct Type_17729 Type_17729, *PType_17729;

typedef struct Type_17730 Type_17730, *PType_17730;

struct Type_17729 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17730 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_214 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17729 RetType;
    struct Type_17730 Param0;
};

struct Blob_MethodRefSig_214 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_214 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_219 Blob_MethodRefSig_219, *PBlob_MethodRefSig_219;

typedef struct MethodRefSig_219 MethodRefSig_219, *PMethodRefSig_219;

typedef struct Type_17734 Type_17734, *PType_17734;

typedef struct Type_17735 Type_17735, *PType_17735;

typedef struct Type_17736 Type_17736, *PType_17736;

typedef struct Type_17737 Type_17737, *PType_17737;

struct Type_17734 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17736 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17735 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17737 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct MethodRefSig_219 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17734 RetType;
    struct Type_17735 Param0;
    struct Type_17736 Param1;
    struct Type_17737 Param2;
};

struct Blob_MethodRefSig_219 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_219 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_338 Blob_MethodRefSig_338, *PBlob_MethodRefSig_338;

typedef struct MethodRefSig_338 MethodRefSig_338, *PMethodRefSig_338;

typedef struct Type_17853 Type_17853, *PType_17853;

typedef struct Type_17856 Type_17856, *PType_17856;

struct Type_17856 {
    struct ValueType.conflict11 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17853 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_338 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17853 RetType;
    struct Type_17856 Param0;
};

struct Blob_MethodRefSig_338 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_338 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodDefSig_791 Blob_MethodDefSig_791, *PBlob_MethodDefSig_791;

typedef struct MethodDefSig_791 MethodDefSig_791, *PMethodDefSig_791;

typedef struct Type_18306 Type_18306, *PType_18306;

typedef struct Type_18307 Type_18307, *PType_18307;

typedef struct Type_18309 Type_18309, *PType_18309;

struct Type_18306 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_18309 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_18307 {
    struct Class ELEMENT_TYPE_CLASS;
};

struct MethodDefSig_791 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte Count; // Number of parameter types to follow RetType
    struct Type_18306 RetType;
    struct Type_18307 Param0;
    struct Type_18309 Param1;
};

struct Blob_MethodDefSig_791 {
    byte Size; // coded integer - blob size
    struct MethodDefSig_791 MethodDefSig; // Type info for method return and params
};

typedef struct Blob_ConstantSig_640 Blob_ConstantSig_640, *PBlob_ConstantSig_640;

typedef struct ConstantSig_640 ConstantSig_640, *PConstantSig_640;

struct ConstantSig_640 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_640 {
    byte Size; // coded integer - blob size
    struct ConstantSig_640 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_294 Blob_Generic_294, *PBlob_Generic_294;

struct Blob_Generic_294 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_645 Blob_ConstantSig_645, *PBlob_ConstantSig_645;

typedef struct ConstantSig_645 ConstantSig_645, *PConstantSig_645;

struct ConstantSig_645 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_645 {
    byte Size; // coded integer - blob size
    struct ConstantSig_645 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_175 Blob_Generic_175, *PBlob_Generic_175;

struct Blob_Generic_175 {
    byte Size; // coded integer - blob size
    byte Generic[33]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_442 Blob_MethodRefSig_442, *PBlob_MethodRefSig_442;

typedef struct MethodRefSig_442 MethodRefSig_442, *PMethodRefSig_442;

typedef struct Type_17957 Type_17957, *PType_17957;

struct Type_17957 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_442 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17957 RetType;
};

struct Blob_MethodRefSig_442 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_442 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_CustomAttrib_1093 Blob_CustomAttrib_1093, *PBlob_CustomAttrib_1093;

struct Blob_CustomAttrib_1093 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_1093 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_320 Blob_MethodRefSig_320, *PBlob_MethodRefSig_320;

typedef struct MethodRefSig_320 MethodRefSig_320, *PMethodRefSig_320;

typedef struct Type_17835 Type_17835, *PType_17835;

struct Type_17835 {
    struct ValueType.conflict10 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_320 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17835 RetType;
};

struct Blob_MethodRefSig_320 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_320 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_562 Blob_MethodRefSig_562, *PBlob_MethodRefSig_562;

typedef struct MethodRefSig_562 MethodRefSig_562, *PMethodRefSig_562;

typedef struct Type_18077 Type_18077, *PType_18077;

typedef struct Type_18078 Type_18078, *PType_18078;

typedef struct Type_18079 Type_18079, *PType_18079;

struct Type_18079 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct Type_18078 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_18077 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_562 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18077 RetType;
    struct Type_18078 Param0;
    struct Type_18079 Param1;
};

struct Blob_MethodRefSig_562 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_562 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_209 Blob_MethodRefSig_209, *PBlob_MethodRefSig_209;

typedef struct MethodRefSig_209 MethodRefSig_209, *PMethodRefSig_209;

typedef struct Type_17724 Type_17724, *PType_17724;

typedef struct Type_17725 Type_17725, *PType_17725;

struct Type_17725 {
    enum TypeCode ELEMENT_TYPE_CHAR;
};

struct Type_17724 {
    enum TypeCode ELEMENT_TYPE_I4;
};

struct MethodRefSig_209 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17724 RetType;
    struct Type_17725 Param0;
};

struct Blob_MethodRefSig_209 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_209 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_448 Blob_MethodRefSig_448, *PBlob_MethodRefSig_448;

typedef struct MethodRefSig_448 MethodRefSig_448, *PMethodRefSig_448;

typedef struct Type_17963 Type_17963, *PType_17963;

typedef struct Type_17964 Type_17964, *PType_17964;

struct Type_17963 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17964 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_448 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17963 RetType;
    struct Type_17964 Param0;
};

struct Blob_MethodRefSig_448 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_448 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_ConstantSig_650 Blob_ConstantSig_650, *PBlob_ConstantSig_650;

typedef struct ConstantSig_650 ConstantSig_650, *PConstantSig_650;

struct ConstantSig_650 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_650 {
    byte Size; // coded integer - blob size
    struct ConstantSig_650 ConstantSig; // Data stored in a constant
};

typedef struct Blob_MethodRefSig_326 Blob_MethodRefSig_326, *PBlob_MethodRefSig_326;

typedef struct MethodRefSig_326 MethodRefSig_326, *PMethodRefSig_326;

typedef struct Type_17841 Type_17841, *PType_17841;

typedef struct Type_17842 Type_17842, *PType_17842;

struct Type_17842 {
    struct ValueType.conflict10 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17841 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_326 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17841 RetType;
    struct Type_17842 Param0;
};

struct Blob_MethodRefSig_326 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_326 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_568 Blob_MethodRefSig_568, *PBlob_MethodRefSig_568;

typedef struct MethodRefSig_568 MethodRefSig_568, *PMethodRefSig_568;

typedef struct Type_18083 Type_18083, *PType_18083;

typedef struct Type_18086 Type_18086, *PType_18086;

struct Type_18083 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_18086 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct MethodRefSig_568 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_18083 RetType;
    struct Type_18086 Param0;
};

struct Blob_MethodRefSig_568 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_568 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_161 Blob_Generic_161, *PBlob_Generic_161;

struct Blob_Generic_161 {
    byte Size; // coded integer - blob size
    byte Generic[7]; // Undefined blob contents
};

typedef struct Blob_Generic_282 Blob_Generic_282, *PBlob_Generic_282;

struct Blob_Generic_282 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_610 Blob_ConstantSig_610, *PBlob_ConstantSig_610;

typedef struct ConstantSig_610 ConstantSig_610, *PConstantSig_610;

struct ConstantSig_610 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_610 {
    byte Size; // coded integer - blob size
    struct ConstantSig_610 ConstantSig; // Data stored in a constant
};

typedef struct Blob_ConstantSig_615 Blob_ConstantSig_615, *PBlob_ConstantSig_615;

typedef struct ConstantSig_615 ConstantSig_615, *PConstantSig_615;

struct ConstantSig_615 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_615 {
    byte Size; // coded integer - blob size
    struct ConstantSig_615 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_169 Blob_Generic_169, *PBlob_Generic_169;

struct Blob_Generic_169 {
    byte Size; // coded integer - blob size
    byte Generic[5]; // Undefined blob contents
};

typedef struct Blob_Generic_289 Blob_Generic_289, *PBlob_Generic_289;

struct Blob_Generic_289 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_311 Blob_MethodRefSig_311, *PBlob_MethodRefSig_311;

typedef struct MethodRefSig_311 MethodRefSig_311, *PMethodRefSig_311;

typedef struct Type_17826 Type_17826, *PType_17826;

typedef struct Type_17827 Type_17827, *PType_17827;

typedef struct Type_17830 Type_17830, *PType_17830;

struct Type_17827 {
    struct Class.conflict ELEMENT_TYPE_CLASS;
};

struct Type_17826 {
    enum TypeCode ELEMENT_TYPE_OBJECT;
};

struct Type_17830 {
    struct SzArray_17831 ELEMENT_TYPE_SZARRAY;
};

struct MethodRefSig_311 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17826 RetType;
    struct Type_17827 Param0;
    struct Type_17830 Param1;
};

struct Blob_MethodRefSig_311 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_311 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_435 Blob_MethodRefSig_435, *PBlob_MethodRefSig_435;

typedef struct MethodRefSig_435 MethodRefSig_435, *PMethodRefSig_435;

typedef struct Type_17950 Type_17950, *PType_17950;

typedef struct Type_17951 Type_17951, *PType_17951;

struct Type_17950 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17951 {
    struct ValueType.conflict20 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_435 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17950 RetType;
    struct Type_17951 Param0;
};

struct Blob_MethodRefSig_435 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_435 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_89 Blob_MethodRefSig_89, *PBlob_MethodRefSig_89;

typedef struct MethodRefSig_89 MethodRefSig_89, *PMethodRefSig_89;

typedef struct Type_17604 Type_17604, *PType_17604;

typedef struct Type_17605 Type_17605, *PType_17605;

typedef struct Type_17606 Type_17606, *PType_17606;

struct Type_17606 {
    struct ValueType.conflict4 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17605 {
    enum TypeCode ELEMENT_TYPE_I8;
};

struct Type_17604 {
    enum TypeCode ELEMENT_TYPE_I8;
};

struct MethodRefSig_89 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17604 RetType;
    struct Type_17605 Param0;
    struct Type_17606 Param1;
};

struct Blob_MethodRefSig_89 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_89 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_ConstantSig_620 Blob_ConstantSig_620, *PBlob_ConstantSig_620;

typedef struct ConstantSig_620 ConstantSig_620, *PConstantSig_620;

struct ConstantSig_620 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_620 {
    byte Size; // coded integer - blob size
    struct ConstantSig_620 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_275 Blob_Generic_275, *PBlob_Generic_275;

struct Blob_Generic_275 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_ConstantSig_625 Blob_ConstantSig_625, *PBlob_ConstantSig_625;

typedef struct ConstantSig_625 ConstantSig_625, *PConstantSig_625;

struct ConstantSig_625 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_625 {
    byte Size; // coded integer - blob size
    struct ConstantSig_625 ConstantSig; // Data stored in a constant
};

typedef struct Blob_Generic_152 Blob_Generic_152, *PBlob_Generic_152;

struct Blob_Generic_152 {
    byte Size; // coded integer - blob size
    byte Generic[4]; // Undefined blob contents
};

typedef struct Blob_Generic_394 Blob_Generic_394, *PBlob_Generic_394;

struct Blob_Generic_394 {
    byte Size; // coded integer - blob size
    byte Generic[6]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_81 Blob_MethodRefSig_81, *PBlob_MethodRefSig_81;

typedef struct MethodRefSig_81 MethodRefSig_81, *PMethodRefSig_81;

typedef struct Type_17596 Type_17596, *PType_17596;

typedef struct Type_17597 Type_17597, *PType_17597;

typedef struct Type_17598 Type_17598, *PType_17598;

struct Type_17597 {
    enum TypeCode ELEMENT_TYPE_STRING;
};

struct Type_17596 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17598 {
    struct ValueType.conflict3 ELEMENT_TYPE_VALUETYPE;
};

struct MethodRefSig_81 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17596 RetType;
    struct Type_17597 Param0;
    struct Type_17598 Param1;
};

struct Blob_MethodRefSig_81 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_81 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_Generic_157 Blob_Generic_157, *PBlob_Generic_157;

struct Blob_Generic_157 {
    byte Size; // coded integer - blob size
    byte Generic[3]; // Undefined blob contents
};

typedef struct Blob_MethodRefSig_422 Blob_MethodRefSig_422, *PBlob_MethodRefSig_422;

typedef struct MethodRefSig_422 MethodRefSig_422, *PMethodRefSig_422;

typedef struct Type_17937 Type_17937, *PType_17937;

typedef struct Type_17938 Type_17938, *PType_17938;

typedef struct Type_17939 Type_17939, *PType_17939;

struct Type_17938 {
    enum TypeCode ELEMENT_TYPE_R4;
};

struct Type_17937 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct Type_17939 {
    enum TypeCode ELEMENT_TYPE_R4;
};

struct MethodRefSig_422 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17937 RetType;
    struct Type_17938 Param0;
    struct Type_17939 Param1;
};

struct Blob_MethodRefSig_422 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_422 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_MethodRefSig_300 Blob_MethodRefSig_300, *PBlob_MethodRefSig_300;

typedef struct MethodRefSig_300 MethodRefSig_300, *PMethodRefSig_300;

typedef struct Type_17815 Type_17815, *PType_17815;

typedef struct Type_17816 Type_17816, *PType_17816;

struct Type_17816 {
    struct SzArray_17817 ELEMENT_TYPE_SZARRAY;
};

struct Type_17815 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_300 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17815 RetType;
    struct Type_17816 Param0;
};

struct Blob_MethodRefSig_300 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_300 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_CustomAttrib_1071 Blob_CustomAttrib_1071, *PBlob_CustomAttrib_1071;

struct Blob_CustomAttrib_1071 {
    byte Size; // coded integer - blob size
    struct CustomAttrib_1071 CustomAttrib; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct Blob_MethodRefSig_428 Blob_MethodRefSig_428, *PBlob_MethodRefSig_428;

typedef struct MethodRefSig_428 MethodRefSig_428, *PMethodRefSig_428;

typedef struct Type_17943 Type_17943, *PType_17943;

typedef struct Type_17944 Type_17944, *PType_17944;

struct Type_17944 {
    struct ValueType.conflict19 ELEMENT_TYPE_VALUETYPE;
};

struct Type_17943 {
    enum TypeCode ELEMENT_TYPE_VOID;
};

struct MethodRefSig_428 {
    byte Flags; // ORed VARARG/GENERIC/HASTHIS/EXPLICITTHIS
    byte ParamCount; // Number of parameter types to follow RetType
    struct Type_17943 RetType;
    struct Type_17944 Param0;
};

struct Blob_MethodRefSig_428 {
    byte Size; // coded integer - blob size
    struct MethodRefSig_428 MethodRefSig; // Type info for imported method return and params
};

typedef struct Blob_ConstantSig_630 Blob_ConstantSig_630, *PBlob_ConstantSig_630;

typedef struct ConstantSig_630 ConstantSig_630, *PConstantSig_630;

struct ConstantSig_630 {
    dword ELEMENT_TYPE_I4;
};

struct Blob_ConstantSig_630 {
    byte Size; // coded integer - blob size
    struct ConstantSig_630 ConstantSig; // Data stored in a constant
};

typedef struct ParamRow ParamRow, *PParamRow;

typedef enum ParamAttributes {
    In=1,
    Out=2,
    Optional=16,
    HasDefault=4096,
    HasFieldMarshal=8192,
    Unused=53216
} ParamAttributes;

struct ParamRow {
    enum ParamAttributes Flags; // bitmask of type ParamAttributes
    word Sequence; // constant
    word Name; // index into String heap
};

typedef struct ManifestResource Row ManifestResource Row, *PManifestResource Row;

typedef enum ManifestResourceAttributes {
    Public=1,
    Private=2
} ManifestResourceAttributes;

struct ManifestResource Row {
    dword Offset;
    enum ManifestResourceAttributes Flags; // Bitmask of type ManifestResourceAttributes
    word Name; // index into String heap
    word Implementation; // Implementation coded index
};

typedef struct MethodDef Row MethodDef Row, *PMethodDef Row;

typedef enum MethodImplAttributes {
    CodeType_IL=0,
    CodeType_Native=1,
    CodeType_OPTIL=2,
    CodeType_Runtime=3,
    Unmanaged=4,
    NoInlining=8,
    ForwardRef=16,
    Synchronized=32,
    NoOptimization=64,
    PreserveSig=128,
    InternalCall=4096,
    MaxMethodImplVal=65535
} MethodImplAttributes;

typedef enum MethodAttributes {
    MAccess_CompilerControlled=0,
    MAccess_Private=1,
    MAccess_FamANDAssem=2,
    MAccess_Assem=3,
    MAccess_Family=4,
    MAccess_FamORAssem=5,
    MAccess_Public=6,
    UnmanagedExport=8,
    Static=16,
    Final=32,
    Virtual=64,
    HideBySig=128,
    VtableLayout_NewSlot=256,
    Strict=512,
    Abstract=1024,
    SpecialName=2048,
    RTSpecialName=4096,
    PInvokeImpl=8192,
    HasSecurity=16384,
    RequireSecObject=32768
} MethodAttributes;

struct MethodDef Row {
    dword RVA;
    enum MethodImplAttributes ImplFlags; // Bitmask of type MethodImplAttributes
    enum MethodAttributes Flags; // Bitmask of type MethodAttribute
    word Name; // index into String heap
    word Signature; // index into Blob heap
    word ParamList; // index into Param table
};

typedef struct MemberRef Row MemberRef Row, *PMemberRef Row;

struct MemberRef Row {
    word Class; // index-MemberRefParent coded
    word Name; // index into String heap
    word Signature; // index into Blob heap
};

typedef struct TypeRef Row TypeRef Row, *PTypeRef Row;

struct TypeRef Row {
    word ResolutionScope;
    word TypeName;
    word TypeNamespace;
};

typedef struct AssemblyRef Row AssemblyRef Row, *PAssemblyRef Row;

typedef enum AssemblyFlags {
    PublicKey=1,
    Retargetable=256,
    DisableJITcompileOptimizer=16384,
    EnableJITcompileTracking=32768
} AssemblyFlags;

struct AssemblyRef Row {
    word MajorVersion;
    word MinorVersion;
    word BuildNumber;
    word RevisionNumber;
    enum AssemblyFlags Flags; // Bitmask of type AssemblyFlags
    word PublicKeyOrToken; // Public Key or token identifying the author of the assembly.
    word Name; // index into String heap
    word Culture; // index into String heap
    word HashValue; // index into Blob heap
};

typedef struct Property Row Property Row, *PProperty Row;

typedef enum PropertyAttributes {
    SpecialName=512,
    RTSpecialName=1024,
    HasDefault=4096,
    Unused=59903
} PropertyAttributes;

struct Property Row {
    enum PropertyAttributes Flags; // Bitmask of type PropertyAttributes
    word Name;
    word Type; // Blob index to the signature, not a TypeDef/TypeRef
};

typedef struct Field Row Field Row, *PField Row;

typedef enum FieldAttributes {
    Access_CompilerControlled=0,
    Access_Private=1,
    Access_FamANDAssem=2,
    Access_Assembly=3,
    Access_Family=4,
    Access_FamORAssem=5,
    Access_Public=6,
    Static=16,
    InitOnly=32,
    Literal=64,
    NotSerialized=128,
    HasFieldRVA=256,
    SpecialName=512,
    RTSpecialName=1024,
    HasFieldMarshal=4096,
    PInvokeImpl=8192,
    HasDefault=32768
} FieldAttributes;

struct Field Row {
    enum FieldAttributes Flags; // see CorFieldAttr
    word Name; // index into String heap
    word Signature; // index into Blob heap
};

typedef struct Constant Row Constant Row, *PConstant Row;

struct Constant Row {
    enum TypeCode Type; // if Class, indicates nullref
    byte Reserved; // should be 0
    word Parent; // index - coded HasConstant
    word Value; // index into Blob heap
};

typedef struct PropertyMap Row PropertyMap Row, *PPropertyMap Row;

struct PropertyMap Row {
    word Parent;
    word options; // Index into Property table. Points to contiguous run of Properties until next ref from PropertyMap or end of table.
};

typedef struct NestedClass Row NestedClass Row, *PNestedClass Row;

struct NestedClass Row {
    word NestedClass; // TypeDef index
    word EnclosingClass; // TypeDef index
};

typedef struct CustomAttribute Row CustomAttribute Row, *PCustomAttribute Row;

struct CustomAttribute Row {
    word Parent;
    word Type;
    word Value;
};

typedef struct MethodSemantics Row MethodSemantics Row, *PMethodSemantics Row;

typedef enum MethodSemanticsAttributes {
    Setter=1,
    Getter=2,
    Other=4,
    AddOn=8,
    RemoveOn=16,
    Fire=32
} MethodSemanticsAttributes;

struct MethodSemantics Row {
    enum MethodSemanticsAttributes Semantics; // Bitmask of type MethodSemanticsAttributes
    word Method; // index into MethodDef table
    word Association; // HasSemantics coded index into Event or Property
};

typedef struct TypeDef Row TypeDef Row, *PTypeDef Row;

typedef enum TypeAttributes {
    Visibility_NotPublic=0,
    Visibility_Public=1,
    Visibility_NestedPublic=2,
    Visibility_NestedPrivate=3,
    Visibility_NestedFamily=4,
    Visibility_NestedAssembly=5,
    Visibility_NestedFamANDAssem=6,
    Visibility_NestedFamORAssem=7,
    SequentialLayout=8,
    ExplicitLayout=16,
    Interface=32,
    Abstract=128,
    Sealed=256,
    SpecialName=1024,
    RTSpecialName=2048,
    Import=4096,
    Serializable=8192,
    UnicodeClass=65536,
    AutoClass=131072,
    CustomFormatClass=196608,
    HasSecurity=262144,
    BeforeFieldInit=1048576,
    IsTypeForwarder=2097152,
    CustomStringFormatMask=12582912
} TypeAttributes;

struct TypeDef Row {
    enum TypeAttributes Flags; // see CorTypeAttr
    word TypeName; // index into String heap
    word TypeNamespace; // index into String heap
    word Extends; // index: coded TypeDefOrRef
    word FieldList; // index into Field table
    word MethodList; // index into MethodDef table
};

typedef struct StandAloneSig Row StandAloneSig Row, *PStandAloneSig Row;

struct StandAloneSig Row {
    word Signature;
};

typedef struct Assembly Table Assembly Table, *PAssembly Table;

typedef enum AssemblyHash {
    None=0,
    Reserved (MD5)=32771,
    SHA1=32772
} AssemblyHash;

struct Assembly Table {
    enum AssemblyHash HashAlg; // Type of hash present
    word MajorVersion;
    word MinorVersion;
    word BuildNumber;
    word RevisionNumber;
    enum AssemblyFlags Flags; // Bitmask of type AssemblyFlags
    word PublicKey; // index into Blob heap
    word Name; // index into String heap
    word Culture; // index into String heap
};

typedef struct Module Row Module Row, *PModule Row;

struct Module Row {
    word Generation; // reserved, shall be 0
    word Name; // index into String heap
    word MvId; // used to distinguish between versions of same module
    word EncId; // reserved, shall be 0
    word EncBaseId; // reserved, shall be 0
};

typedef struct #US #US, *P#US;

struct #US {
    byte Reserved; // Always 0
    byte Next string size;
    wchar16 [1][14];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [1f][14];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [3d][6];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [4b][1];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [4f][14];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [6d][20];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [97][13];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [b3][5];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [bf][22];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [ed][34];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [133][24];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [165][27];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [19d][22];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [1cb][1];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [1cf][22];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [1fd][25];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [231][15];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [251][19];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [279][15];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [299][16];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [2bb][11];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [2d5][27];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [30d][5];
    byte Extra byte; // 0x01 if string contains non-ASCII
    word Next string size;
    wchar16 [319][179];
    byte Extra byte; // 0x01 if string contains non-ASCII
    word Next string size;
    wchar16 [482][91];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [53b][12];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [555][10];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [56b][2];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [571][11];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [589][3];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [591][9];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [5a5][11];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [5bd][13];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [5d9][10];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [5ef][13];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [60b][12];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [625][8];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [637][8];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [649][10];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [65f][8];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [671][17];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [695][35];
    byte Extra byte; // 0x01 if string contains non-ASCII
    byte Next string size;
    wchar16 [6dd][7];
    byte Extra byte; // 0x01 if string contains non-ASCII
};

typedef struct #GUID #GUID, *P#GUID;

struct #GUID {
    GUID [0];
};

typedef struct #Strings #Strings, *P#Strings;

struct #Strings {
    char [0][1];
    char [1][17];
    char [12][12];
    char [1e][17];
    char [2f][11];
    char [3a][22];
    char [50][9];
    char [59][6];
    char [5f][17];
    char [70][11];
    char [7b][22];
    char [91][9];
    char [9a][17];
    char [ab][11];
    char [b6][22];
    char [cc][11];
    char [d7][22];
    char [ed][9];
    char [f6][12];
    char [102][15];
    char [111][20];
    char [125][14];
    char [133][19];
    char [146][14];
    char [154][11];
    char [15f][6];
    char [165][6];
    char [16b][10];
    char [175][10];
    char [17f][3];
    char [182][15];
    char [191][25];
    char [1aa][14];
    char [1b8][8];
    char [1c0][17];
    char [1d1][5];
    char [1d6][9];
    char [1df][16];
    char [1ef][7];
    char [1f6][9];
    char [1ff][14];
    char [20d][12];
    char [219][4];
    char [21d][8];
    char [225][5];
    char [22a][12];
    char [236][22];
    char [24c][12];
    char [258][18];
    char [26a][13];
    char [277][25];
    char [290][29];
    char [2ad][24];
    char [2c5][8];
    char [2cd][4];
    char [2d1][12];
    char [2dd][12];
    char [2e9][12];
    char [2f5][12];
    char [301][7];
    char [308][11];
    char [313][16];
    char [323][18];
    char [335][9];
    char [33e][21];
    char [353][15];
    char [362][13];
    char [36f][8];
    char [377][10];
    char [381][16];
    char [391][8];
    char [399][9];
    char [3a2][10];
    char [3ac][12];
    char [3b8][14];
    char [3c6][14];
    char [3d4][12];
    char [3e0][18];
    char [3f2][18];
    char [404][17];
    char [415][11];
    char [420][12];
    char [42c][18];
    char [43e][10];
    char [448][14];
    char [456][9];
    char [45f][13];
    char [46c][13];
    char [479][17];
    char [48a][14];
    char [498][23];
    char [4af][12];
    char [4bb][12];
    char [4c7][16];
    char [4d7][11];
    char [4e2][24];
    char [4fa][12];
    char [506][6];
    char [50c][8];
    char [514][13];
    char [521][14];
    char [52f][18];
    char [541][23];
    char [558][21];
    char [56d][21];
    char [582][17];
    char [593][6];
    char [599][6];
    char [59f][19];
    char [5b2][27];
    char [5cd][14];
    char [5db][23];
    char [5f2][29];
    char [60f][20];
    char [623][27];
    char [63e][25];
    char [657][20];
    char [66b][23];
    char [682][29];
    char [69f][27];
    char [6ba][27];
    char [6d5][29];
    char [6f2][31];
    char [711][29];
    char [72e][32];
    char [74e][25];
    char [767][27];
    char [782][25];
    char [79b][30];
    char [7b9][12];
    char [7c5][6];
    char [7cb][5];
    char [7d0][7];
    char [7d7][18];
    char [7e9][9];
    char [7f2][15];
    char [801][12];
    char [80d][17];
    char [81e][12];
    char [82a][8];
    char [832][9];
    char [83b][8];
    char [843][9];
    char [84c][10];
    char [856][14];
    char [864][12];
    char [870][17];
    char [881][15];
    char [890][15];
    char [89f][15];
    char [8ae][13];
    char [8bb][11];
    char [8c6][9];
    char [8cf][13];
    char [8dc][4];
    char [8e0][11];
    char [8eb][9];
    char [8f4][12];
    char [900][12];
    char [90c][11];
    char [917][14];
    char [925][9];
    char [92e][18];
    char [940][10];
    char [94a][18];
    char [95c][21];
    char [971][17];
    char [982][5];
    char [987][13];
    char [994][22];
    char [9aa][17];
    char [9bb][12];
    char [9c7][11];
    char [9d2][8];
    char [9da][9];
    char [9e3][9];
    char [9ec][7];
    char [9f3][5];
    char [9f8][5];
    char [9fd][12];
    char [a09][8];
    char [a11][8];
    char [a19][10];
    char [a23][5];
    char [a28][14];
    char [a36][9];
    char [a3f][11];
    char [a4a][11];
    char [a55][9];
    char [a5e][15];
    char [a6d][12];
    char [a79][13];
    char [a86][14];
    char [a94][21];
    char [aa9][21];
    char [abe][18];
    char [ad0][18];
    char [ae2][17];
    char [af3][18];
    char [b05][18];
    char [b17][7];
    char [b1e][4];
    char [b22][9];
    char [b2b][12];
    char [b37][6];
    char [b3d][5];
    char [b42][6];
    char [b48][5];
    char [b4d][15];
    char [b5c][7];
    char [b63][7];
    char [b6a][20];
    char [b7e][25];
    char [b97][20];
    char [bab][24];
    char [bc3][10];
    char [bcd][11];
    char [bd8][9];
    char [be1][14];
    char [bef][11];
    char [bfa][11];
    char [c05][11];
    char [c10][12];
    char [c1c][14];
    char [c2a][14];
    char [c38][28];
    char [c54][9];
    char [c5d][6];
    char [c63][7];
    char [c6a][19];
    char [c7d][31];
    char [c9c][32];
    char [cbc][17];
    char [ccd][34];
    char [cef][46];
    char [d1d][15];
    char [d2c][21];
    char [d41][26];
    char [d5b][19];
    char [d6e][13];
    char [d7b][9];
    char [d84][9];
    char [d8d][8];
    char [d95][16];
    char [da5][16];
    char [db5][17];
    char [dc6][13];
    char [dd3][10];
    char [ddd][21];
    char [df2][24];
    char [e0a][18];
    char [e1c][14];
    char [e2a][13];
    char [e37][13];
    char [e44][13];
    char [e51][13];
    char [e5e][11];
    char [e69][16];
    char [e79][7];
    char [e80][4];
    char [e84][10];
    char [e8e][7];
    char [e95][14];
    char [ea3][7];
    char [eaa][13];
    char [eb7][12];
    char [ec3][34];
    char [ee5][13];
    char [ef2][13];
    char [eff][7];
    char [f06][11];
    char [f11][7];
    char [f18][17];
    char [f29][20];
    char [f3d][6];
    char [f43][9];
    char [f4c][6];
    char [f52][12];
    char [f5e][11];
    char [f69][11];
    char [f74][6];
    char [f7a][14];
    char [f88][13];
    char [f95][14];
    char [fa3][12];
    char [faf][9];
    char [fb8][9];
    char [fc1][15];
    char [fd0][5];
    char [fd5][9];
    char [fde][9];
    char [fe7][13];
    char [ff4][11];
    char [fff][16];
    char [100f][9];
    char [1018][8];
    char [1020][11];
    char [102b][11];
    char [1036][13];
    char [1043][13];
    char [1050][21];
    char [1065][10];
    char [106f][9];
    char [1078][14];
    char [1086][11];
    char [1091][1];
    char [1092][1];
    char [1093][1];
};

typedef struct #~ #~, *P#~;

struct #~ {
    dword Reserved; // Always 0
    byte MajorVersion;
    byte MinorVersion;
    byte HeapSizes; // Bit vector for heap sizes
    byte Reserved; // Always 1
    qword Valid; // Bit vector of present tables
    qword Sorted; // Bit vector of sorted tables
    dword Rows[17]; // # of rows for each corresponding present table
    struct Module Row Module; // CLI Metadata Table: Module
    struct TypeRef Row TypeRef[94]; // CLI Metadata Table: TypeRef
    struct TypeDef Row TypeDef[10]; // CLI Metadata Table: TypeDef
    struct Field Row Field[71]; // CLI Metadata Table: Field
    struct MethodDef Row MethodDef[46]; // CLI Metadata Table: MethodDef
    struct ParamRow Param[48]; // CLI Metadata Table: Param
    struct MemberRef Row MemberRef[135]; // CLI Metadata Table: MemberRef
    struct Constant Row Constant[27]; // CLI Metadata Table: Constant
    struct CustomAttribute Row CustomAttribute[36]; // CLI Metadata Table: CustomAttribute
    struct StandAloneSig Row StandAloneSig[15]; // CLI Metadata Table: StandAloneSig
    struct PropertyMap Row PropertyMap[3]; // CLI Metadata Table: PropertyMap
    struct Property Row Property[7]; // CLI Metadata Table: Property
    struct MethodSemantics Row MethodSemantics[12]; // CLI Metadata Table: MethodSemantics
    struct Assembly Table Assembly; // CLI Metadata Table: Assembly
    struct AssemblyRef Row AssemblyRef[4]; // CLI Metadata Table: AssemblyRef
    struct ManifestResource Row ManifestResource[2]; // CLI Metadata Table: ManifestResource
    struct NestedClass Row NestedClass[2]; // CLI Metadata Table: NestedClass
};

typedef struct #Blob #Blob, *P#Blob;

struct #Blob {
    byte Reserved; // Always 0
    struct Blob_MethodRefSig_1 MethodRefSig_1; // Type info for imported method return and params
    struct Blob_MethodRefSig_6 MethodRefSig_6; // Type info for imported method return and params
    struct Blob_MethodRefSig_10 MethodRefSig_10; // Type info for imported method return and params
    struct Blob_MethodRefSig_16 MethodRefSig_16; // Type info for imported method return and params
    struct Blob_MethodRefSig_21 MethodRefSig_21; // Type info for imported method return and params
    struct Blob_MethodRefSig_26 MethodRefSig_26; // Type info for imported method return and params
    struct Blob_MethodRefSig_33 MethodRefSig_33; // Type info for imported method return and params
    struct Blob_MethodRefSig_39 MethodRefSig_39; // Type info for imported method return and params
    struct Blob_LocalVarSig_46 LocalVarSig_46; // Contains signature for function locals
    struct Blob_MethodRefSig_53 MethodRefSig_53; // Type info for imported method return and params
    struct Blob_MethodRefSig_58 MethodRefSig_58; // Type info for imported method return and params
    struct Blob_MethodRefSig_64 MethodRefSig_64; // Type info for imported method return and params
    struct Blob_MethodRefSig_71 MethodRefSig_71; // Type info for imported method return and params
    struct Blob_LocalVarSig_75 LocalVarSig_75; // Contains signature for function locals
    struct Blob_MethodRefSig_81 MethodRefSig_81; // Type info for imported method return and params
    struct Blob_MethodRefSig_89 MethodRefSig_89; // Type info for imported method return and params
    struct Blob_LocalVarSig_97 LocalVarSig_97; // Contains signature for function locals
    struct Blob_MethodRefSig_120 MethodRefSig_120; // Type info for imported method return and params
    struct Blob_MethodRefSig_126 MethodRefSig_126; // Type info for imported method return and params
    struct Blob_MethodRefSig_132 MethodRefSig_132; // Type info for imported method return and params
    struct Blob_MethodRefSig_140 MethodRefSig_140; // Type info for imported method return and params
    struct Blob_MethodRefSig_144 MethodRefSig_144; // Type info for imported method return and params
    struct Blob_MethodRefSig_152 MethodRefSig_152; // Type info for imported method return and params
    struct Blob_MethodRefSig_157 MethodRefSig_157; // Type info for imported method return and params
    struct Blob_MethodRefSig_161 MethodRefSig_161; // Type info for imported method return and params
    struct Blob_MethodRefSig_169 MethodRefSig_169; // Type info for imported method return and params
    struct Blob_LocalVarSig_175 LocalVarSig_175; // Contains signature for function locals
    struct Blob_MethodRefSig_209 MethodRefSig_209; // Type info for imported method return and params
    struct Blob_MethodRefSig_214 MethodRefSig_214; // Type info for imported method return and params
    struct Blob_MethodRefSig_219 MethodRefSig_219; // Type info for imported method return and params
    struct Blob_LocalVarSig_226 LocalVarSig_226; // Contains signature for function locals
    struct Blob_MethodRefSig_230 MethodRefSig_230; // Type info for imported method return and params
    struct Blob_MethodRefSig_236 MethodRefSig_236; // Type info for imported method return and params
    struct Blob_MethodRefSig_242 MethodRefSig_242; // Type info for imported method return and params
    struct Blob_MethodRefSig_247 MethodRefSig_247; // Type info for imported method return and params
    struct Blob_MethodRefSig_254 MethodRefSig_254; // Type info for imported method return and params
    struct Blob_MethodRefSig_261 MethodRefSig_261; // Type info for imported method return and params
    struct Blob_MethodRefSig_275 MethodRefSig_275; // Type info for imported method return and params
    struct Blob_LocalVarSig_282 LocalVarSig_282; // Contains signature for function locals
    struct Blob_MethodRefSig_289 MethodRefSig_289; // Type info for imported method return and params
    struct Blob_MethodRefSig_294 MethodRefSig_294; // Type info for imported method return and params
    struct Blob_MethodRefSig_300 MethodRefSig_300; // Type info for imported method return and params
    struct Blob_LocalVarSig_306 LocalVarSig_306; // Contains signature for function locals
    struct Blob_MethodRefSig_311 MethodRefSig_311; // Type info for imported method return and params
    struct Blob_MethodRefSig_320 MethodRefSig_320; // Type info for imported method return and params
    struct Blob_MethodRefSig_326 MethodRefSig_326; // Type info for imported method return and params
    struct Blob_LocalVarSig_333 LocalVarSig_333; // Contains signature for function locals
    struct Blob_MethodRefSig_338 MethodRefSig_338; // Type info for imported method return and params
    struct Blob_MethodRefSig_347 MethodRefSig_347; // Type info for imported method return and params
    struct Blob_MethodRefSig_354 MethodRefSig_354; // Type info for imported method return and params
    struct Blob_MethodRefSig_360 MethodRefSig_360; // Type info for imported method return and params
    struct Blob_MethodRefSig_367 MethodRefSig_367; // Type info for imported method return and params
    struct Blob_MethodRefSig_374 MethodRefSig_374; // Type info for imported method return and params
    struct Blob_MethodRefSig_381 MethodRefSig_381; // Type info for imported method return and params
    struct Blob_MethodRefSig_394 MethodRefSig_394; // Type info for imported method return and params
    struct Blob_MethodRefSig_401 MethodRefSig_401; // Type info for imported method return and params
    struct Blob_MethodRefSig_408 MethodRefSig_408; // Type info for imported method return and params
    struct Blob_MethodRefSig_415 MethodRefSig_415; // Type info for imported method return and params
    struct Blob_MethodRefSig_422 MethodRefSig_422; // Type info for imported method return and params
    struct Blob_MethodRefSig_428 MethodRefSig_428; // Type info for imported method return and params
    struct Blob_MethodRefSig_435 MethodRefSig_435; // Type info for imported method return and params
    struct Blob_MethodRefSig_442 MethodRefSig_442; // Type info for imported method return and params
    struct Blob_MethodRefSig_448 MethodRefSig_448; // Type info for imported method return and params
    struct Blob_MethodRefSig_455 MethodRefSig_455; // Type info for imported method return and params
    struct Blob_MethodRefSig_460 MethodRefSig_460; // Type info for imported method return and params
    struct Blob_MethodRefSig_467 MethodRefSig_467; // Type info for imported method return and params
    struct Blob_LocalVarSig_474 LocalVarSig_474; // Contains signature for function locals
    struct Blob_LocalVarSig_484 LocalVarSig_484; // Contains signature for function locals
    struct Blob_LocalVarSig_497 LocalVarSig_497; // Contains signature for function locals
    struct Blob_MethodRefSig_508 MethodRefSig_508; // Type info for imported method return and params
    struct Blob_MethodRefSig_512 MethodRefSig_512; // Type info for imported method return and params
    struct Blob_MethodRefSig_517 MethodRefSig_517; // Type info for imported method return and params
    struct Blob_LocalVarSig_523 LocalVarSig_523; // Contains signature for function locals
    struct Blob_MethodRefSig_533 MethodRefSig_533; // Type info for imported method return and params
    struct Blob_MethodRefSig_539 MethodRefSig_539; // Type info for imported method return and params
    struct Blob_LocalVarSig_547 LocalVarSig_547; // Contains signature for function locals
    struct Blob_LocalVarSig_553 LocalVarSig_553; // Contains signature for function locals
    struct Blob_LocalVarSig_558 LocalVarSig_558; // Contains signature for function locals
    struct Blob_MethodRefSig_562 MethodRefSig_562; // Type info for imported method return and params
    struct Blob_MethodRefSig_568 MethodRefSig_568; // Type info for imported method return and params
    struct Blob_Generic_577 [241];
    struct Blob_Generic_586 [24a];
    struct Blob_ConstantSig_595 ConstantSig_595; // Data stored in a constant
    struct Blob_CustomAttrib_600 CustomAttrib_600; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_ConstantSig_605 ConstantSig_605; // Data stored in a constant
    struct Blob_ConstantSig_610 ConstantSig_610; // Data stored in a constant
    struct Blob_ConstantSig_615 ConstantSig_615; // Data stored in a constant
    struct Blob_ConstantSig_620 ConstantSig_620; // Data stored in a constant
    struct Blob_ConstantSig_625 ConstantSig_625; // Data stored in a constant
    struct Blob_ConstantSig_630 ConstantSig_630; // Data stored in a constant
    struct Blob_ConstantSig_635 ConstantSig_635; // Data stored in a constant
    struct Blob_ConstantSig_640 ConstantSig_640; // Data stored in a constant
    struct Blob_ConstantSig_645 ConstantSig_645; // Data stored in a constant
    struct Blob_ConstantSig_650 ConstantSig_650; // Data stored in a constant
    struct Blob_ConstantSig_655 ConstantSig_655; // Data stored in a constant
    struct Blob_ConstantSig_660 ConstantSig_660; // Data stored in a constant
    struct Blob_ConstantSig_665 ConstantSig_665; // Data stored in a constant
    struct Blob_ConstantSig_670 ConstantSig_670; // Data stored in a constant
    struct Blob_ConstantSig_675 ConstantSig_675; // Data stored in a constant
    struct Blob_ConstantSig_680 ConstantSig_680; // Data stored in a constant
    struct Blob_ConstantSig_685 ConstantSig_685; // Data stored in a constant
    struct Blob_ConstantSig_687 ConstantSig_687; // Data stored in a constant
    struct Blob_ConstantSig_689 ConstantSig_689; // Data stored in a constant
    struct Blob_ConstantSig_691 ConstantSig_691; // Data stored in a constant
    struct Blob_ConstantSig_693 ConstantSig_693; // Data stored in a constant
    struct Blob_ConstantSig_695 ConstantSig_695; // Data stored in a constant
    struct Blob_ConstantSig_697 ConstantSig_697; // Data stored in a constant
    struct Blob_ConstantSig_699 ConstantSig_699; // Data stored in a constant
    struct Blob_ConstantSig_701 ConstantSig_701; // Data stored in a constant
    struct Blob_FieldSig_703 FieldSig_703; // Type information for Field
    struct Blob_FieldSig_706 FieldSig_706; // Type information for Field
    struct Blob_FieldSig_710 FieldSig_710; // Type information for Field
    struct Blob_FieldSig_714 FieldSig_714; // Type information for Field
    struct Blob_FieldSig_718 FieldSig_718; // Type information for Field
    struct Blob_FieldSig_721 FieldSig_721; // Type information for Field
    struct Blob_FieldSig_724 FieldSig_724; // Type information for Field
    struct Blob_FieldSig_728 FieldSig_728; // Type information for Field
    struct Blob_FieldSig_731 FieldSig_731; // Type information for Field
    struct Blob_FieldSig_734 FieldSig_734; // Type information for Field
    struct Blob_FieldSig_737 FieldSig_737; // Type information for Field
    struct Blob_FieldSig_741 FieldSig_741; // Type information for Field
    struct Blob_FieldSig_745 FieldSig_745; // Type information for Field
    struct Blob_FieldSig_749 FieldSig_749; // Type information for Field
    struct Blob_FieldSig_753 FieldSig_753; // Type information for Field
    struct Blob_FieldSig_757 FieldSig_757; // Type information for Field
    struct Blob_FieldSig_761 FieldSig_761; // Type information for Field
    struct Blob_FieldSig_765 FieldSig_765; // Type information for Field
    struct Blob_FieldSig_769 FieldSig_769; // Type information for Field
    struct Blob_FieldSig_774 FieldSig_774; // Type information for Field
    struct Blob_FieldSig_779 FieldSig_779; // Type information for Field
    struct Blob_MethodDefSig_783 MethodDefSig_783; // Type info for method return and params
    struct Blob_MethodDefSig_791 MethodDefSig_791; // Type info for method return and params
    struct Blob_MethodDefSig_798 MethodDefSig_798; // Type info for method return and params
    struct Blob_MethodDefSig_802 MethodDefSig_802; // Type info for method return and params
    struct Blob_MethodDefSig_808 MethodDefSig_808; // Type info for method return and params
    struct Blob_MethodDefSig_815 MethodDefSig_815; // Type info for method return and params
    struct Blob_MethodDefSig_822 MethodDefSig_822; // Type info for method return and params
    struct Blob_MethodDefSig_826 MethodDefSig_826; // Type info for method return and params
    struct Blob_MethodDefSig_831 MethodDefSig_831; // Type info for method return and params
    struct Blob_MethodDefSig_841 MethodDefSig_841; // Type info for method return and params
    struct Blob_MethodDefSig_848 MethodDefSig_848; // Type info for method return and params
    struct Blob_MethodDefSig_854 MethodDefSig_854; // Type info for method return and params
    struct Blob_MethodDefSig_860 MethodDefSig_860; // Type info for method return and params
    struct Blob_MethodDefSig_867 MethodDefSig_867; // Type info for method return and params
    struct Blob_Generic_872 [368];
    struct Blob_Generic_883 [373];
    struct Blob_Generic_890 [37a];
    struct Blob_PropertySig_901 PropertySig_901; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_PropertySig_905 PropertySig_905; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_PropertySig_909 PropertySig_909; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_PropertySig_915 PropertySig_915; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_PropertySig_921 PropertySig_921; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_PropertySig_926 PropertySig_926; // Contains signature for properties. Gives params for getters/setters.
    struct Blob_CustomAttrib_930 CustomAttrib_930; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_CustomAttrib_939 CustomAttrib_939; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_CustomAttrib_970 CustomAttrib_970; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_CustomAttrib_979 CustomAttrib_979; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_CustomAttrib_999 CustomAttrib_999; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_Generic_1005 [3ed];
    struct Blob_CustomAttrib_1029 CustomAttrib_1029; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_CustomAttrib_1071 CustomAttrib_1071; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_Generic_1084 [43c];
    struct Blob_CustomAttrib_1093 CustomAttrib_1093; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
    struct Blob_Generic_1158 [486];
    struct Blob_CustomAttrib_1248 CustomAttrib_1248; // A CustomAttrib blob stores values of fixed or named parameters supplied when instantiating a custom attribute
};

typedef struct MethodDefHdr_Fat MethodDefHdr_Fat, *PMethodDefHdr_Fat;

struct MethodDefHdr_Fat {
    word Size+Flags; // L.S. Bits 0:3 Size of hdr in bytes, Bits 4:15 Flags
    word MaxStack; // Maximum number of items on the operand stack
    dword CodeSize; // Size of actual method body in bytes
    dword LocalVarSigTok; // Signature for the local variables of the method. 0 means no locals. References standalone signature in Metadata tables, which references #Blob heap.
};

typedef struct MethodDefHdr_Tiny MethodDefHdr_Tiny, *PMethodDefHdr_Tiny;

struct MethodDefHdr_Tiny {
    byte Size+Flags; // L.S. Bits 0:1 Flags, Bits 2:7 Size of method in Bytes
};

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

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[114];
};




int * .ctor(uint * sPHelper, undefined4 filePath);
int * BootLoading(uint * sPHelper, byte * filePath);
int * HandShake_0(uint * param_1, byte * param_2, undefined2 param_3);
int * BootLoading(int s, byte * param_2);
void ErrorCntClr(int * param_1, byte * param_2, undefined4 param_3, undefined4 param_4);
void BaseTimer_Elapsed(int * sender, byte * e, undefined4 param_3, undefined4 param_4);
void .ctor(int * param_1, int param_2, undefined4 param_3, undefined4 param_4);
void btnOpenFile_Click(int * sender, char * e, undefined4 param_3, undefined4 param_4);
void btnDownload_Click(int * sender, byte * e, undefined4 param_3, undefined4 param_4);
void btn_AutoUpdate_Click(int * sender, byte * e);
void FlashBtnDownState(int * param_1, byte * param_2);
void PrintMessage(int * msg, byte * param_2);
void cbBComPort_Click(undefined4 sender, int e);
void TaskBooting(int * param_1, byte * param_2);
void TaskPrintMsg(undefined4 param_1, byte * param_2);
void FormMain_Load(undefined4 sender, char * e);
void Dispose(uint * param_1, byte * param_2);
void InitializeComponent(uint * param_1, byte * param_2, uint param_3);
byte get_Command(char * param_1, byte * param_2);
void set_Command(char * param_1, byte * param_2, int param_3);
byte get_CommandArgs(char * param_1, byte * param_2);
void set_CommandArgs(char * param_1, byte * param_2);
bool get_Verify(char * param_1, byte * param_2, char * param_3);
void set_Verify(char * param_1, int * param_2, char * param_3, undefined4 param_4, int param_5);
byte * Packing(int param_1, int * param_2);
byte * AnalysePackage(int package, byte * param_2);
undefined4 CrcValidation(uint dat, undefined4 offset, uint * count, uint * param_4, undefined1 * param_5, undefined4 param_6, byte * param_7, byte * param_8, undefined4 param_9, byte * param_10, undefined4 param_11, byte param_12, undefined4 param_13, uint param_14);
undefined4 .ctor(undefined4 param_1, byte * param_2);
undefined4 Main(int param_1, byte * param_2);
undefined4 .ctor(undefined4 param_1, byte * param_2);
undefined4 get_ResourceManager(char * param_1, int param_2);
undefined4 get_Culture(int param_1, byte * param_2);
undefined4 set_Culture(int value, byte * param_2);
undefined4 get_Default(int param_1, byte * param_2);
undefined4 get_dirpath(int param_1, byte * param_2);
undefined4 set_dirpath(int value, byte * param_2);
undefined4 .ctor(undefined4 param_1, byte * param_2);
undefined4 .cctor(int param_1, char * param_2);
void entry(void);

