
/*--------------------------------------------------------------------*/
/*--- Reading of syms & debug info from PDB-format files.         ---*/
/*---                                                   readpdb.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.
   Spring 2008:
      derived from readelf.c and valgrind-20031012-wine/vg_symtab2.c
      derived from wine-1.0/tools/winedump/pdb.c and msc.c

   Copyright (C) 2000-2017 Julian Seward
      jseward@acm.org
   Copyright 2006 Eric Pouech (winedump/pdb.c and msc.c)
      GNU Lesser General Public License version 2.1 or later applies.
   Copyright (C) 2008 BitWagon Software LLC

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.

   The GNU General Public License is contained in the file COPYING.
*/

#if defined(VGO_linux) || defined(VGO_darwin) || defined(VGO_solaris) || defined(VGO_freebsd)

#include "pub_core_basics.h"
#include "pub_core_debuginfo.h"
#include "pub_core_vki.h"          // VKI_PAGE_SIZE
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"     // VG_(open), read, lseek, close
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"     // VG_(getpid), system
#include "pub_core_options.h"      // VG_(clo_verbosity)
#include "pub_core_oset.h"
#include "pub_core_xarray.h"       // keeps priv_storage.h happy
#include "pub_core_redir.h"

#include "priv_misc.h"             /* dinfo_zalloc/free/strdup */
#include "priv_image.h"
#include "priv_d3basics.h"
#include "priv_storage.h"
#include "priv_readpdb.h"          // self
#include "priv_readelf.h"          /* open/find_debug_file/_ad_hoc */
#include "priv_readdwarf.h"        /* 'cos ELF contains DWARF */
#include "priv_readdwarf3.h"


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- Biasing                                              ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

/* There are just two simple ways of biasing in use here.

   The CodeView debug info entries contain virtual addresses
   relative to segment (here it is one PE section), which in
   turn specifies its start as a VA relative to "image base".

   The second type of debug info (FPOs) contain VAs relative
   directly to the image base, without the segment indirection.

   The original/preferred image base is set in the PE header,
   but it can change as long as the file contains relocation
   data. So everything is biased using the current image base,
   which is the base AVMA passed by Wine.

   The difference between the original image base and current
   image base, which is what Wine sends here in the last
   argument of VG_(di_notify_pdb_debuginfo), is not used.
*/

/* This module leaks space; enable m_main's calling of
   VG_(di_discard_ALL_debuginfo)() at shutdown and run with
   --profile-heap=yes to see.  The main culprit appears to be
   di.readpe.pdr.1.  I haven't bothered to chase it further. */


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- PE/PDB definitions                                   ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

typedef  ULong  ULONGLONG;
typedef  UInt   DWORD;
typedef  UShort WORD;
typedef  UChar  BYTE;


/* the following DOS and WINDOWS structures, defines and PE/PDB
 * parsing code are copied or derived from the WINE
 * project - http://www.winehq.com/
 */

/*
 * File formats definitions
 */
#define   OFFSET_OF(__c,__f)   ((int)(((char*)&(((__c*)0)->__f))-((char*)0)))
#define   WIN32_PATH_MAX 256

#pragma pack(2)
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      /* 00: MZ Header signature */
    WORD  e_cblp;       /* 02: Bytes on last page of file */
    WORD  e_cp;         /* 04: Pages in file */
    WORD  e_crlc;       /* 06: Relocations */
    WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
    WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
    WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
    WORD  e_ss;         /* 0e: Initial (relative) SS value */
    WORD  e_sp;         /* 10: Initial SP value */
    WORD  e_csum;       /* 12: Checksum */
    WORD  e_ip;         /* 14: Initial IP value */
    WORD  e_cs;         /* 16: Initial (relative) CS value */
    WORD  e_lfarlc;     /* 18: File address of relocation table */
    WORD  e_ovno;       /* 1a: Overlay number */
    WORD  e_res[4];     /* 1c: Reserved words */
    WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
    WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
    WORD  e_res2[10];   /* 28: Reserved words */
    DWORD e_lfanew;     /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

#define IMAGE_DOS_SIGNATURE    0x5A4D     /* MZ   */
#define IMAGE_OS2_SIGNATURE    0x454E     /* NE   */
#define IMAGE_OS2_SIGNATURE_LE 0x454C     /* LE   */
#define IMAGE_OS2_SIGNATURE_LX 0x584C     /* LX */
#define IMAGE_VXD_SIGNATURE    0x454C     /* LE   */
#define IMAGE_NT_SIGNATURE     0x00004550 /* PE00 */

/* Subsystem Values */

#define IMAGE_SUBSYSTEM_UNKNOWN     0
#define IMAGE_SUBSYSTEM_NATIVE      1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2  /* Windows GUI subsystem */
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3  /* Windows character subsystem*/
#define IMAGE_SUBSYSTEM_OS2_CUI     5
#define IMAGE_SUBSYSTEM_POSIX_CUI   7

typedef struct _IMAGE_SYMBOL {
    union {
        BYTE    ShortName[8];
        struct {
            DWORD   Short;
            DWORD   Long;
        } Name;
        DWORD   LongName[2];
    } N;
    DWORD   Value;
    WORD    SectionNumber;
    WORD    Type;
    BYTE    StorageClass;
    BYTE    NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef IMAGE_SYMBOL *PIMAGE_SYMBOL;

#define IMAGE_SIZEOF_SYMBOL 18

#define IMAGE_SYM_UNDEFINED           (SHORT)0
#define IMAGE_SYM_ABSOLUTE            (SHORT)-1
#define IMAGE_SYM_DEBUG               (SHORT)-2

#define IMAGE_SYM_TYPE_NULL                 0x0000
#define IMAGE_SYM_TYPE_VOID                 0x0001
#define IMAGE_SYM_TYPE_CHAR                 0x0002
#define IMAGE_SYM_TYPE_SHORT                0x0003
#define IMAGE_SYM_TYPE_INT                  0x0004
#define IMAGE_SYM_TYPE_LONG                 0x0005
#define IMAGE_SYM_TYPE_FLOAT                0x0006
#define IMAGE_SYM_TYPE_DOUBLE               0x0007
#define IMAGE_SYM_TYPE_STRUCT               0x0008
#define IMAGE_SYM_TYPE_UNION                0x0009
#define IMAGE_SYM_TYPE_ENUM                 0x000A
#define IMAGE_SYM_TYPE_MOE                  0x000B
#define IMAGE_SYM_TYPE_BYTE                 0x000C
#define IMAGE_SYM_TYPE_WORD                 0x000D
#define IMAGE_SYM_TYPE_UINT                 0x000E
#define IMAGE_SYM_TYPE_DWORD                0x000F
#define IMAGE_SYM_TYPE_PCODE                0x8000

#define IMAGE_SYM_DTYPE_NULL                0
#define IMAGE_SYM_DTYPE_POINTER             1
#define IMAGE_SYM_DTYPE_FUNCTION            2
#define IMAGE_SYM_DTYPE_ARRAY               3

#define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1
#define IMAGE_SYM_CLASS_NULL                0x0000
#define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
#define IMAGE_SYM_CLASS_EXTERNAL            0x0002
#define IMAGE_SYM_CLASS_STATIC              0x0003
#define IMAGE_SYM_CLASS_REGISTER            0x0004
#define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
#define IMAGE_SYM_CLASS_LABEL               0x0006
#define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
#define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
#define IMAGE_SYM_CLASS_ARGUMENT            0x0009
#define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
#define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
#define IMAGE_SYM_CLASS_UNION_TAG           0x000C
#define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
#define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
#define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
#define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
#define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
#define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

#define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044
#define IMAGE_SYM_CLASS_BLOCK               0x0064
#define IMAGE_SYM_CLASS_FUNCTION            0x0065
#define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
#define IMAGE_SYM_CLASS_FILE                0x0067
#define IMAGE_SYM_CLASS_SECTION             0x0068
#define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

#define N_BTMASK                            0x000F
#define N_TMASK                             0x0030
#define N_TMASK1                            0x00C0
#define N_TMASK2                            0x00F0
#define N_BTSHFT                            4
#define N_TSHIFT                            2

#define BTYPE(x) ((x) & N_BTMASK)

#ifndef ISPTR
#define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
#endif

#ifndef ISFCN
#define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
#endif

#ifndef ISARY
#define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
#endif

#ifndef ISTAG
#define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
#endif

#ifndef INCREF
#define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
#endif
#ifndef DECREF
#define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
#endif

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; /* 0x20b */
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER {

  /* Standard fields */

  WORD  Magic; /* 0x10b or 0x107 */ /* 0x00 */
  BYTE  MajorLinkerVersion;
  BYTE  MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;    /* 0x10 */
  DWORD BaseOfCode;
  DWORD BaseOfData;

  /* NT additional fields */

  DWORD ImageBase;
  DWORD SectionAlignment;   /* 0x20 */
  DWORD FileAlignment;
  WORD  MajorOperatingSystemVersion;
  WORD  MinorOperatingSystemVersion;
  WORD  MajorImageVersion;
  WORD  MinorImageVersion;
  WORD  MajorSubsystemVersion;    /* 0x30 */
  WORD  MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;     /* 0x40 */
  WORD  Subsystem;
  WORD  DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;    /* 0x50 */
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */
  /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

/* Possible Magic values */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

typedef struct _IMAGE_NT_HEADERS64 {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
  DWORD Signature; /* "PE"\0\0 */ /* 0x00 */
  IMAGE_FILE_HEADER FileHeader;   /* 0x04 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader; /* 0x18 */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#if (VEX_HOST_WORDSIZE == 8)
typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#endif

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define	IMAGE_SIZEOF_SECTION_HEADER 40

#define IMAGE_FIRST_SECTION(ntheader) \
  ((PIMAGE_SECTION_HEADER)((BYTE *)&((PIMAGE_NT_HEADERS)(ntheader))->OptionalHeader + \
                           ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))

/* These defines are for the Characteristics bitfield. */
/* #define IMAGE_SCN_TYPE_REG			0x00000000 - Reserved */
/* #define IMAGE_SCN_TYPE_DSECT			0x00000001 - Reserved */
/* #define IMAGE_SCN_TYPE_NOLOAD		0x00000002 - Reserved */
/* #define IMAGE_SCN_TYPE_GROUP			0x00000004 - Reserved */
/* #define IMAGE_SCN_TYPE_NO_PAD		0x00000008 - Reserved */
/* #define IMAGE_SCN_TYPE_COPY			0x00000010 - Reserved */

#define IMAGE_SCN_CNT_CODE			          0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA		0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA	0x00000080

#define	IMAGE_SCN_LNK_OTHER			0x00000100
#define	IMAGE_SCN_LNK_INFO			0x00000200
/* #define	IMAGE_SCN_TYPE_OVER		0x00000400 - Reserved */
#define	IMAGE_SCN_LNK_REMOVE			0x00000800
#define	IMAGE_SCN_LNK_COMDAT			0x00001000

/* 						0x00002000 - Reserved */
/* #define IMAGE_SCN_MEM_PROTECTED 		0x00004000 - Obsolete */
#define	IMAGE_SCN_MEM_FARDATA			  0x00008000

/* #define IMAGE_SCN_MEM_SYSHEAP		0x00010000 - Obsolete */
#define	IMAGE_SCN_MEM_PURGEABLE			0x00020000
#define	IMAGE_SCN_MEM_16BIT			    0x00020000
#define	IMAGE_SCN_MEM_LOCKED			  0x00040000
#define	IMAGE_SCN_MEM_PRELOAD			  0x00080000

#define	IMAGE_SCN_ALIGN_1BYTES			0x00100000
#define	IMAGE_SCN_ALIGN_2BYTES			0x00200000
#define	IMAGE_SCN_ALIGN_4BYTES			0x00300000
#define	IMAGE_SCN_ALIGN_8BYTES			0x00400000
#define	IMAGE_SCN_ALIGN_16BYTES			0x00500000  /* Default */
#define IMAGE_SCN_ALIGN_32BYTES			0x00600000
#define IMAGE_SCN_ALIGN_64BYTES			0x00700000
/* 						0x00800000 - Unused */

#define IMAGE_SCN_LNK_NRELOC_OVFL		0x01000000

#define IMAGE_SCN_MEM_DISCARDABLE		0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED		0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED			0x08000000
#define IMAGE_SCN_MEM_SHARED			  0x10000000
#define IMAGE_SCN_MEM_EXECUTE			  0x20000000
#define IMAGE_SCN_MEM_READ			    0x40000000
#define IMAGE_SCN_MEM_WRITE			    0x80000000

#pragma pack()

typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD  MajorVersion;
  WORD  MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

typedef struct _GUID  /* 16 bytes */
{
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[ 8 ];
} GUID;

/*========================================================================
 * Process PDB file.
 */

#pragma pack(1)
typedef struct _PDB_FILE
{
    DWORD size;
    DWORD unknown;

} PDB_FILE, *PPDB_FILE;

// A .pdb file begins with a variable-length one-line text string
// that ends in "\r\n\032".  This is followed by a 4-byte "signature"
// ("DS\0\0" for newer files, "JG\0\0" for older files), then
// aligned up to a 4-byte boundary, then the struct below:
struct PDB_JG_HEADER
{
    //char ident[40];  // "Microsoft C/C++ program database 2.00\r\n\032"
    //DWORD  signature;  // "JG\0\0"
    DWORD    blocksize;  // 0x400 typical; also 0x800, 0x1000
    WORD     freelist;
    WORD     total_alloc;
    PDB_FILE toc;
    WORD     toc_block[ 1 ];
};

struct PDB_DS_HEADER
{
    //char   signature[32];  // "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0"
    DWORD block_size;
    DWORD unknown1;
    DWORD num_pages;
    DWORD toc_size;
    DWORD unknown2;
    DWORD toc_page;
};

struct PDB_JG_TOC
{
    DWORD    nFiles;
    PDB_FILE file[ 1 ];

};

struct PDB_DS_TOC
{
    DWORD num_files;
    DWORD file_size[1];
};

struct PDB_JG_ROOT
{
    DWORD version;
    DWORD TimeDateStamp;
    DWORD age;
    DWORD cbNames;
    char  names[ 1 ];
};

struct PDB_DS_ROOT
{
    DWORD version;
    DWORD TimeDateStamp;
    DWORD age;
    GUID  guid;
    DWORD cbNames;
    char  names[1];
};

typedef struct _PDB_TYPES_OLD
{
    DWORD version;
    WORD  first_index;
    WORD  last_index;
    DWORD type_size;
    WORD  file;
    WORD  pad;

} PDB_TYPES_OLD, *PPDB_TYPES_OLD;

typedef struct _PDB_TYPES
{
    DWORD version;
    DWORD type_offset;
    DWORD first_index;
    DWORD last_index;
    DWORD type_size;
    WORD  file;
    WORD  pad;
    DWORD hash_size;
    DWORD hash_base;
    DWORD hash_offset;
    DWORD hash_len;
    DWORD search_offset;
    DWORD search_len;
    DWORD unknown_offset;
    DWORD unknown_len;

} PDB_TYPES, *PPDB_TYPES;

typedef struct _PDB_SYMBOL_RANGE
{
    WORD  segment;
    WORD  pad1;
    DWORD offset;
    DWORD size;
    DWORD characteristics;
    WORD  index;
    WORD  pad2;

} PDB_SYMBOL_RANGE, *PPDB_SYMBOL_RANGE;

typedef struct _PDB_SYMBOL_RANGE_EX
{
    WORD  segment;
    WORD  pad1;
    DWORD offset;
    DWORD size;
    DWORD characteristics;
    WORD  index;
    WORD  pad2;
    DWORD timestamp;
    DWORD unknown;

} PDB_SYMBOL_RANGE_EX, *PPDB_SYMBOL_RANGE_EX;

typedef struct _PDB_SYMBOL_FILE
{
    DWORD unknown1;
    PDB_SYMBOL_RANGE range;
    WORD  flag;
    WORD  file;
    DWORD symbol_size;
    DWORD lineno_size;
    DWORD unknown2;
    DWORD nSrcFiles;
    DWORD attribute;
    char filename[ 1 ];

} PDB_SYMBOL_FILE, *PPDB_SYMBOL_FILE;

typedef struct _PDB_SYMBOL_FILE_EX
{
    DWORD unknown1;
    PDB_SYMBOL_RANGE_EX range;
    WORD  flag;
    WORD  file;
    DWORD symbol_size;
    DWORD lineno_size;
    DWORD unknown2;
    DWORD nSrcFiles;
    DWORD attribute;
    DWORD reserved[ 2 ];
    char filename[ 1 ];

} PDB_SYMBOL_FILE_EX, *PPDB_SYMBOL_FILE_EX;

typedef struct _PDB_SYMBOL_SOURCE
{
    WORD nModules;
    WORD nSrcFiles;
    WORD table[ 1 ];

} PDB_SYMBOL_SOURCE, *PPDB_SYMBOL_SOURCE;

typedef struct _PDB_SYMBOL_IMPORT
{
    DWORD unknown1;
    DWORD unknown2;
    DWORD TimeDateStamp;
    DWORD nRequests;
    char filename[ 1 ];

} PDB_SYMBOL_IMPORT, *PPDB_SYMBOL_IMPORT;

typedef struct _PDB_SYMBOLS_OLD
{
    WORD  hash1_file;
    WORD  hash2_file;
    WORD  gsym_file;
    WORD  pad;
    DWORD module_size;
    DWORD offset_size;
    DWORD hash_size;
    DWORD srcmodule_size;

} PDB_SYMBOLS_OLD, *PPDB_SYMBOLS_OLD;

typedef struct _PDB_SYMBOLS
{
    DWORD signature;
    DWORD version;
    DWORD unknown;
    DWORD hash1_file;
    DWORD hash2_file;
    DWORD gsym_file;
    DWORD module_size;
    DWORD offset_size;
    DWORD hash_size;
    DWORD srcmodule_size;
    DWORD pdbimport_size;
    DWORD resvd[ 5 ];

} PDB_SYMBOLS, *PPDB_SYMBOLS;
#pragma pack()

/*========================================================================
 * Process CodeView symbol information.
 */

/* from wine-1.0/include/wine/mscvpdb.h */

struct p_string  /* "Pascal string": prefixed by byte containing length */
{
    BYTE namelen;
    char name[1];
};
/* The other kind of "char name[1]" is a "C++ string" terminated by '\0'.
 * "Name mangling" to encode type information often exceeds 255 bytes.
 * Instead of using a 2-byte explicit length, they save one byte of space
 * but incur a strlen().  This is justified by other code that wants
 * a "C string" [terminated by '\0'] anyway.
 */

union codeview_symbol
{
    struct
    {
        short int	        len;
        short int	        id;
    } generic;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        symtype;
        struct p_string         p_name;
    } data_v1;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        symtype;
	unsigned int	        offset;
	unsigned short	        segment;
        struct p_string         p_name;
    } data_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];  /* terminated by '\0' */
    } data_v3;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        thunk_len;
	unsigned char	        thtype;
        struct p_string         p_name;
    } thunk_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            offset;
        unsigned short          segment;
        unsigned short          thunk_len;
        unsigned char           thtype;
        char                    name[1];  /* terminated by '\0' */
    } thunk_v3;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned short	        proctype;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v1;

    struct
    {
	short int	        len;
	short int	        id;
	unsigned int	        pparent;
	unsigned int	        pend;
	unsigned int	        next;
	unsigned int	        proc_len;
	unsigned int	        debug_start;
	unsigned int	        debug_end;
	unsigned int	        proctype;
	unsigned int	        offset;
	unsigned short	        segment;
	unsigned char	        flags;
        struct p_string         p_name;
    } proc_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            pparent;
        unsigned int            pend;
        unsigned int            next;
        unsigned int            proc_len;
        unsigned int            debug_start;
        unsigned int            debug_end;
        unsigned int            proctype;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        char                    name[1];  /* terminated by '\0' */
    } proc_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } public_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            symtype;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];  /* terminated by '\0' */
    } public_v3;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_BPREL_V1 */
	unsigned int	        offset;	        /* Stack offset relative to BP */
	unsigned short	        symtype;
        struct p_string         p_name;
    } stack_v1;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_BPREL_V2 */
	unsigned int	        offset;	        /* Stack offset relative to EBP */
	unsigned int	        symtype;
        struct p_string         p_name;
    } stack_v2;

    struct
    {
        short int               len;            /* Total length of this entry */
        short int               id;             /* Always S_BPREL_V3 */
        int                     offset;         /* Stack offset relative to BP */
        unsigned int            symtype;
        char                    name[1];  /* terminated by '\0' */
    } stack_v3;

    struct
    {
        short int               len;            /* Total length of this entry */
        short int               id;             /* Always S_BPREL_V3 */
        int                     offset;         /* Stack offset relative to BP */
        unsigned int            symtype;
        unsigned short          unknown;
        char                    name[1];  /* terminated by '\0' */
    } stack_xxxx_v3;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER */
        unsigned short          type;
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v1;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER_V2 */
        unsigned int            type;           /* check whether type & reg are correct */
        unsigned short          reg;
        struct p_string         p_name;
        /* don't handle register tracking */
    } register_v2;

    struct
    {
	short int	        len;	        /* Total length of this entry */
	short int	        id;		/* Always S_REGISTER_V3 */
        unsigned int            type;           /* check whether type & reg are correct */
        unsigned short          reg;
        char                    name[1];  /* terminated by '\0' */
        /* don't handle register tracking */
    } register_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        struct p_string         p_name;
    } block_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            parent;
        unsigned int            end;
        unsigned int            length;
        unsigned int            offset;
        unsigned short          segment;
        char                    name[1];  /* terminated by '\0' */
    } block_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        struct p_string         p_name;
    } label_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
        unsigned char           flags;
        char                    name[1];  /* terminated by '\0' */
    } label_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned short          type;
        unsigned short          cvalue;         /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } constant_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        unsigned short          cvalue;         /* numeric leaf */
#if 0
        struct p_string         p_name;
#endif
    } constant_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        unsigned short          cvalue;
#if 0
        char                    name[1];  /* terminated by '\0' */
#endif
    } constant_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned short          type;
        struct p_string         p_name;
    } udt_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned                type;
        struct p_string         p_name;
    } udt_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            type;
        char                    name[1];  /* terminated by '\0' */
    } udt_v3;

    struct
    {
        short int               len;
        short int               id;
        char                    signature[4];
        struct p_string         p_name;
    } objname_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            unknown;
        struct p_string         p_name;
    } compiland_v1;

    struct
    {
        short int               len;
        short int               id;
        unsigned                unknown1[4];
        unsigned short          unknown2;
        struct p_string         p_name;
    } compiland_v2;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            unknown;
        char                    name[1];  /* terminated by '\0' */
    } compiland_v3;

    struct
    {
        short int               len;
        short int               id;
        unsigned int            offset;
        unsigned short          segment;
    } ssearch_v1;
};

#define S_COMPILAND_V1  0x0001
#define S_REGISTER_V1   0x0002
#define S_CONSTANT_V1   0x0003
#define S_UDT_V1        0x0004
#define S_SSEARCH_V1    0x0005
#define S_END_V1        0x0006
#define S_SKIP_V1       0x0007
#define S_CVRESERVE_V1  0x0008
#define S_OBJNAME_V1    0x0009
#define S_ENDARG_V1     0x000a
#define S_COBOLUDT_V1   0x000b
#define S_MANYREG_V1    0x000c
#define S_RETURN_V1     0x000d
#define S_ENTRYTHIS_V1  0x000e

#define S_BPREL_V1      0x0200
#define S_LDATA_V1      0x0201
#define S_GDATA_V1      0x0202
#define S_PUB_V1        0x0203
#define S_LPROC_V1      0x0204
#define S_GPROC_V1      0x0205
#define S_THUNK_V1      0x0206
#define S_BLOCK_V1      0x0207
#define S_WITH_V1       0x0208
#define S_LABEL_V1      0x0209
#define S_CEXMODEL_V1   0x020a
#define S_VFTPATH_V1    0x020b
#define S_REGREL_V1     0x020c
#define S_LTHREAD_V1    0x020d
#define S_GTHREAD_V1    0x020e

#define S_PROCREF_V1    0x0400
#define S_DATAREF_V1    0x0401
#define S_ALIGN_V1      0x0402
#define S_LPROCREF_V1   0x0403

#define S_REGISTER_V2   0x1001 /* Variants with new 32-bit type indices */
#define S_CONSTANT_V2   0x1002
#define S_UDT_V2        0x1003
#define S_COBOLUDT_V2   0x1004
#define S_MANYREG_V2    0x1005
#define S_BPREL_V2      0x1006
#define S_LDATA_V2      0x1007
#define S_GDATA_V2      0x1008
#define S_PUB_V2        0x1009
#define S_LPROC_V2      0x100a
#define S_GPROC_V2      0x100b
#define S_VFTTABLE_V2   0x100c
#define S_REGREL_V2     0x100d
#define S_LTHREAD_V2    0x100e
#define S_GTHREAD_V2    0x100f
#if 0
#define S_XXXXXXXXX_32  0x1012  /* seems linked to a function, content unknown */
#endif
#define S_COMPILAND_V2  0x1013

#define S_COMPILAND_V3  0x1101
#define S_THUNK_V3      0x1102
#define S_BLOCK_V3      0x1103
#define S_LABEL_V3      0x1105
#define S_REGISTER_V3   0x1106
#define S_CONSTANT_V3   0x1107
#define S_UDT_V3        0x1108
#define S_BPREL_V3      0x110B
#define S_LDATA_V3      0x110C
#define S_GDATA_V3      0x110D
#define S_PUB_V3        0x110E
#define S_LPROC_V3      0x110F
#define S_GPROC_V3      0x1110
#define S_BPREL_XXXX_V3 0x1111  /* not really understood, but looks like bprel... */
#define S_MSTOOL_V3     0x1116  /* compiler command line options and build information */
#define S_PUB_FUNC1_V3  0x1125  /* didn't get the difference between the two */
#define S_PUB_FUNC2_V3  0x1127


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- pdb-reading: bits and pieces                         ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

struct pdb_reader
{
   void* (*read_file)(const struct pdb_reader*, unsigned, unsigned *);
   // JRS 2009-Apr-8: .uu_n_pdbimage is never used.
   UChar* pdbimage;      // image address
   SizeT  uu_n_pdbimage; // size
   union {
      struct {
         struct PDB_JG_HEADER* header;
         struct PDB_JG_TOC* toc;
         struct PDB_JG_ROOT* root;
      } jg;
      struct {
         struct PDB_DS_HEADER* header;
         struct PDB_DS_TOC* toc;
         struct PDB_DS_ROOT* root;
      } ds;
   } u;
};


static void* pdb_ds_read( const struct pdb_reader* pdb,
                          const unsigned* block_list,
                          unsigned  size )
{
   unsigned  blocksize, nBlocks;
   UChar* buffer;
   UInt i;

   if (!size) return NULL;
   if (size > 512 * 1024 * 1024) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: pdb_ds_read: implausible size "
                "(%u); skipping -- possible invalid .pdb file?\n", size);
      return NULL;
   }

   blocksize = pdb->u.ds.header->block_size;
   nBlocks   = (size + blocksize - 1) / blocksize;
   buffer    = ML_(dinfo_zalloc)("di.readpe.pdr.1", nBlocks * blocksize);
   for (i = 0; i < nBlocks; i++)
      VG_(memcpy)( buffer + i * blocksize,
                   pdb->pdbimage + block_list[i] * blocksize,
                   blocksize );
   return buffer;
}


static void* pdb_jg_read( const struct pdb_reader* pdb,
                          const unsigned short* block_list,
                          int size )
{
   unsigned  blocksize, nBlocks;
   UChar* buffer;
   UInt i;
   //VG_(printf)("pdb_read %p %p %d\n", pdb, block_list, size);
   if ( !size ) return NULL;

   blocksize = pdb->u.jg.header->blocksize;
   nBlocks = (size + blocksize-1) / blocksize;
   buffer = ML_(dinfo_zalloc)("di.readpe.pjr.1", nBlocks * blocksize);
   for ( i = 0; i < nBlocks; i++ )
      VG_(memcpy)( buffer + i*blocksize,
                   pdb->pdbimage + block_list[i]*blocksize, blocksize );
   return buffer;
}


static void* find_pdb_header( void* pdbimage,
                              unsigned* signature )
{
   static const HChar pdbtxt[]= "Microsoft C/C++";
   HChar* txteof = VG_(strchr)(pdbimage, '\032');
   if (! txteof) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: \\032 header character not found. "
                " possible invalid/unsupported pdb file format?\n");
      return NULL;
   }
   if (0!=VG_(strncmp)(pdbimage, pdbtxt, -1+ sizeof(pdbtxt))) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: %s header string not found. "
                " possible invalid/unsupported pdb file format?\n",
                pdbtxt);;
      return NULL;
   }

   *signature = *(unsigned*)(1+ txteof);
   HChar *img_addr = pdbimage;    // so we can do address arithmetic
   return ((~3& (3+ (4+ 1+ (txteof - img_addr)))) + img_addr);
}


static void* pdb_ds_read_file( const struct pdb_reader* reader,
                               unsigned  file_number,
                               unsigned* plength )
{
   unsigned i, *block_list;
   if (!reader->u.ds.toc || file_number >= reader->u.ds.toc->num_files)
      return NULL;
   if (reader->u.ds.toc->file_size[file_number] == 0
       || reader->u.ds.toc->file_size[file_number] == 0xFFFFFFFF)
      return NULL;

   block_list
      = reader->u.ds.toc->file_size + reader->u.ds.toc->num_files;
   for (i = 0; i < file_number; i++)
      block_list += (reader->u.ds.toc->file_size[i] 
                     + reader->u.ds.header->block_size - 1)
                    /
                    reader->u.ds.header->block_size;
   if (plength)
      *plength = reader->u.ds.toc->file_size[file_number];
   return pdb_ds_read( reader, block_list,
                       reader->u.ds.toc->file_size[file_number]);
}


static void* pdb_jg_read_file( const struct pdb_reader* pdb,
                               unsigned fileNr,
                               unsigned *plength )
{
   //VG_(printf)("pdb_read_file %p %d\n", pdb, fileNr);
   unsigned blocksize = pdb->u.jg.header->blocksize;
   struct PDB_JG_TOC* toc = pdb->u.jg.toc;
   unsigned i;
   unsigned short* block_list;

   if ( !toc || fileNr >= toc->nFiles )
       return NULL;

   block_list
      = (unsigned short *) &toc->file[ toc->nFiles ];
   for ( i = 0; i < fileNr; i++ )
      block_list += (toc->file[i].size + blocksize-1) / blocksize;

   if (plength)
      *plength = toc->file[fileNr].size;
   return pdb_jg_read( pdb, block_list, toc->file[fileNr].size );
}


static void pdb_ds_init( struct pdb_reader * reader,
                         UChar* pdbimage,
                         SizeT  n_pdbimage )
{
   reader->read_file     = pdb_ds_read_file;
   reader->pdbimage      = pdbimage;
   reader->uu_n_pdbimage = n_pdbimage;
   reader->u.ds.toc
      = pdb_ds_read(
           reader,
           (unsigned*)(reader->u.ds.header->block_size 
                       * reader->u.ds.header->toc_page 
                       + reader->pdbimage),
           reader->u.ds.header->toc_size
        );
}


static void pdb_jg_init( struct pdb_reader* reader,
                         void* pdbimage,
                         unsigned n_pdbimage )
{
   reader->read_file     = pdb_jg_read_file;
   reader->pdbimage      = pdbimage;
   reader->uu_n_pdbimage = n_pdbimage;
   reader->u.jg.toc = pdb_jg_read(reader,
                                  reader->u.jg.header->toc_block,
                                  reader->u.jg.header->toc.size);
}


static 
void pdb_check_root_version_and_timestamp( const HChar* pdbname,
                                           ULong  pdbmtime,
                                           UInt  version,
                                           UInt TimeDateStamp )
{
   switch ( version ) {
      case 19950623:      /* VC 4.0 */
      case 19950814:
      case 19960307:      /* VC 5.0 */
      case 19970604:      /* VC 6.0 */
      case 20000404:      /* VC 7.0  FIXME?? */
         break;
      default:
         if (VG_(clo_verbosity) > 1)
            VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                      "Unknown .pdb root block version %u\n", version );
   }
   if ( TimeDateStamp != pdbmtime ) {
      if (VG_(clo_verbosity) > 1)
         VG_(umsg)("LOAD_PDB_DEBUGINFO: Wrong time stamp of .PDB file "
                   "%s (0x%08x, 0x%08llx)\n",
                   pdbname, TimeDateStamp, pdbmtime );
   }
}


static DWORD pdb_get_file_size( const struct pdb_reader* reader, unsigned idx )
{
   if (reader->read_file == pdb_jg_read_file)
      return reader->u.jg.toc->file[idx].size;
   else
      return reader->u.ds.toc->file_size[idx];
}


static void pdb_convert_types_header( PDB_TYPES *types, char* image )
{
   VG_(memset)( types, 0, sizeof(PDB_TYPES) );
   if ( !image )
      return;
   if ( *(DWORD *)image < 19960000 ) {  /* FIXME: correct version? */
      /* Old version of the types record header */
      PDB_TYPES_OLD *old = (PDB_TYPES_OLD *)image;
      types->version     = old->version;
      types->type_offset = sizeof(PDB_TYPES_OLD);
      types->type_size   = old->type_size;
      types->first_index = old->first_index;
      types->last_index  = old->last_index;
      types->file        = old->file;
   } else {
      /* New version of the types record header */
      *types = *(PDB_TYPES *)image;
   }
}


static void pdb_convert_symbols_header( PDB_SYMBOLS *symbols,
                                        int *header_size, char* image )
{
   VG_(memset)( symbols, 0, sizeof(PDB_SYMBOLS) );
   if ( !image )
      return;
   if ( *(DWORD *)image != 0xffffffff ) {
      /* Old version of the symbols record header */
      PDB_SYMBOLS_OLD *old     = (PDB_SYMBOLS_OLD *)image;
      symbols->version         = 0;
      symbols->module_size     = old->module_size;
      symbols->offset_size     = old->offset_size;
      symbols->hash_size       = old->hash_size;
      symbols->srcmodule_size  = old->srcmodule_size;
      symbols->pdbimport_size  = 0;
      symbols->hash1_file      = old->hash1_file;
      symbols->hash2_file      = old->hash2_file;
      symbols->gsym_file       = old->gsym_file;
      *header_size = sizeof(PDB_SYMBOLS_OLD);
   } else {
      /* New version of the symbols record header */
      *symbols = *(PDB_SYMBOLS *)image;
      *header_size = sizeof(PDB_SYMBOLS);
   }
}


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- Main stuff: reading of symbol addresses              ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

static ULong DEBUG_SnarfCodeView(
                DebugInfo* di,
                PtrdiffT bias,
                const IMAGE_SECTION_HEADER* sectp,
                const void* root, /* FIXME: better name */
                Int offset,
                Int size
             )
{
   Int    i, length;
   DiSym  vsym;
   const  HChar* nmstr;
   HChar  symname[4096 /*WIN32_PATH_MAX*/];  // FIXME: really ?

   Bool  debug = di->trace_symtab;
   ULong n_syms_read = 0;

   if (debug)
      VG_(umsg)("BEGIN SnarfCodeView addr=%p offset=%d length=%d\n", 
                root, offset, size );

   VG_(memset)(&vsym, 0, sizeof(vsym));  /* avoid holes */
   /*
    * Loop over the different types of records and whenever we
    * find something we are interested in, record it and move on.
    */
   for ( i = offset; i < size; i += length )
   {
      const union codeview_symbol *sym =
         (const union codeview_symbol *)((const char *)root + i);

      length = sym->generic.len + 2;

      //VG_(printf)("id=%x  len=%d\n", sym->generic.id, length);
      switch ( sym->generic.id ) {

      default:
         if (0) {
            const UInt *isym = (const UInt *)sym;
            VG_(printf)("unknown id 0x%x len=0x%x at %p\n",
                        (UInt)sym->generic.id, (UInt)sym->generic.len, sym);
            VG_(printf)("  %8x  %8x  %8x  %8x\n", 
                        isym[1], isym[2], isym[3], isym[4]);
            VG_(printf)("  %8x  %8x  %8x  %8x\n",
                        isym[5], isym[6], isym[7], isym[8]);
         }
         break;
      /*
       * Global and local data symbols.  We don't associate these
       * with any given source file.
       */
      case S_GDATA_V1:
      case S_LDATA_V1:
      case S_PUB_V1:
         VG_(memcpy)(symname, sym->data_v1.p_name.name,
                              sym->data_v1.p_name.namelen);
         symname[sym->data_v1.p_name.namelen] = '\0';

         if (debug)
            VG_(umsg)("  Data %s\n", symname );

         if (0 /*VG_(needs).data_syms*/) {
            nmstr = ML_(addStr)(di, symname, sym->data_v1.p_name.namelen);
            vsym.avmas.main = bias + sectp[sym->data_v1.segment-1].VirtualAddress
                                 + sym->data_v1.offset;
            SET_TOCPTR_AVMA(vsym.avmas, 0);
            vsym.pri_name  = nmstr;
            vsym.sec_names = NULL;
            vsym.size      = sym->data_v1.p_name.namelen;
                             // FIXME: .namelen is sizeof(.data) including .name[]
            vsym.isText    = (sym->generic.id == S_PUB_V1);
            vsym.isIFunc   = False;
            vsym.isGlobal  = True;
            ML_(addSym)( di, &vsym );
            n_syms_read++;
         }
         break;
      case S_GDATA_V2:
      case S_LDATA_V2:
      case S_PUB_V2: {
         Int const k = sym->data_v2.p_name.namelen;
         VG_(memcpy)(symname, sym->data_v2.p_name.name, k);
         symname[k] = '\0';

         if (debug)
            VG_(umsg)("  S_GDATA_V2/S_LDATA_V2/S_PUB_V2 %s\n", symname );

         if (sym->generic.id==S_PUB_V2 /*VG_(needs).data_syms*/) {
            nmstr = ML_(addStr)(di, symname, k);
            vsym.avmas.main = bias + sectp[sym->data_v2.segment-1].VirtualAddress
                                  + sym->data_v2.offset;
            SET_TOCPTR_AVMA(vsym.avmas, 0);
            vsym.pri_name  = nmstr;
            vsym.sec_names = NULL;
            vsym.size      = 4000;
                             // FIXME: data_v2.len is sizeof(.data),
                             // not size of function!
            vsym.isText    = !!(IMAGE_SCN_CNT_CODE 
                                & sectp[sym->data_v2.segment-1].Characteristics);
            vsym.isIFunc   = False;
            vsym.isGlobal  = True;
            ML_(addSym)( di, &vsym );
            n_syms_read++;
         }
         break;
      }
      case S_PUB_V3:
      /* not completely sure of those two anyway */
      case S_PUB_FUNC1_V3:
      case S_PUB_FUNC2_V3: {
         Int k = sym->public_v3.len - (-1+ sizeof(sym->public_v3));
         if ((-1+ sizeof(symname)) < k)
            k = -1+ sizeof(symname);
         VG_(memcpy)(symname, sym->public_v3.name, k);
         symname[k] = '\0';

         if (debug)
            VG_(umsg)("  S_PUB_FUNC1_V3/S_PUB_FUNC2_V3/S_PUB_V3 %s\n",
                      symname );

         if (1  /*sym->generic.id==S_PUB_FUNC1_V3 
                  || sym->generic.id==S_PUB_FUNC2_V3*/) {
            nmstr = ML_(addStr)(di, symname, k);
            vsym.avmas.main = bias + sectp[sym->public_v3.segment-1].VirtualAddress
                                  + sym->public_v3.offset;
            SET_TOCPTR_AVMA(vsym.avmas, 0);
            vsym.pri_name  = nmstr;
            vsym.sec_names = NULL;
            vsym.size      = 4000;
                             // FIXME: public_v3.len is not length of the
                             // .text of the function
            vsym.isText    = !!(IMAGE_SCN_CNT_CODE
                                & sectp[sym->data_v2.segment-1].Characteristics);
            vsym.isIFunc   = False;
            vsym.isGlobal  = True;
            ML_(addSym)( di, &vsym );
            n_syms_read++;
         }
         break;
      }

      /*
       * Sort of like a global function, but it just points
       * to a thunk, which is a stupid name for what amounts to
       * a PLT slot in the normal jargon that everyone else uses.
       */
      case S_THUNK_V3:
      case S_THUNK_V1:
         /* valgrind ignores PLTs */ /* JRS: it does? */
         break;

      /*
       * Global and static functions.
       */
      case S_GPROC_V1:
      case S_LPROC_V1:
         VG_(memcpy)(symname, sym->proc_v1.p_name.name,
                              sym->proc_v1.p_name.namelen);
         symname[sym->proc_v1.p_name.namelen] = '\0';
         nmstr = ML_(addStr)(di, symname, sym->proc_v1.p_name.namelen);
         vsym.avmas.main = bias + sectp[sym->proc_v1.segment-1].VirtualAddress
                               + sym->proc_v1.offset;
         SET_TOCPTR_AVMA(vsym.avmas, 0);
         vsym.pri_name  = nmstr;
         vsym.sec_names = NULL;
         vsym.size      = sym->proc_v1.proc_len;
         vsym.isText    = True;
         vsym.isIFunc   = False;
         vsym.isGlobal  = sym->generic.id == S_GPROC_V1;
         if (debug)
            VG_(umsg)("  Adding function %s addr=%#lx length=%u\n",
                      symname, vsym.avmas.main, vsym.size );
         ML_(addSym)( di, &vsym );
         n_syms_read++;
         break;

      case S_GPROC_V2:
      case S_LPROC_V2:
         VG_(memcpy)(symname, sym->proc_v2.p_name.name,
                              sym->proc_v2.p_name.namelen);
         symname[sym->proc_v2.p_name.namelen] = '\0';
         nmstr = ML_(addStr)(di, symname, sym->proc_v2.p_name.namelen);
         vsym.avmas.main = bias + sectp[sym->proc_v2.segment-1].VirtualAddress
                               + sym->proc_v2.offset;
         SET_TOCPTR_AVMA(vsym.avmas, 0);
         vsym.pri_name  = nmstr;
         vsym.sec_names = NULL;
         vsym.size      = sym->proc_v2.proc_len;
         vsym.isText    = True;
         vsym.isIFunc   = False;
         vsym.isGlobal  = sym->generic.id == S_GPROC_V2;
         if (debug)
            VG_(umsg)("  Adding function %s addr=%#lx length=%u\n",
                      symname, vsym.avmas.main, vsym.size );
         ML_(addSym)( di, &vsym );
         n_syms_read++;
         break;
      case S_LPROC_V3:
      case S_GPROC_V3: {
         if (debug)
            VG_(umsg)("  S_LPROC_V3/S_GPROC_V3 %s\n", sym->proc_v3.name );

         if (1) {
            nmstr = ML_(addStr)(di, sym->proc_v3.name,
                                    VG_(strlen)(sym->proc_v3.name));
            vsym.avmas.main = bias + sectp[sym->proc_v3.segment-1].VirtualAddress
                                  + sym->proc_v3.offset;
            SET_TOCPTR_AVMA(vsym.avmas, 0);
            vsym.pri_name  = nmstr;
            vsym.sec_names = NULL;
            vsym.size      = sym->proc_v3.proc_len;
            vsym.isText    = 1;
            vsym.isIFunc   = False;
            vsym.isGlobal  = sym->generic.id == S_GPROC_V3;
            ML_(addSym)( di, &vsym );
            n_syms_read++;
         }
         break;
      }
      /* JRS: how is flow supposed to arrive at commented out code below? */
      //if (nest_block)
      //{
      //   printf(">>> prev func '%s' still has nest_block %u count\n",
      //          curr_func, nest_block);
      //   nest_block = 0;
      //}
      //curr_func = strdup(sym->proc_v3.name);
      /* EPP  unsigned int    pparent; */
      /* EPP  unsigned int    pend; */
      /* EPP  unsigned int    next; */
      /* EPP  unsigned int    debug_start; */
      /* EPP  unsigned int    debug_end; */
      /* EPP  unsigned char   flags; */
      // break;


      /*
       * Function parameters and stack variables.
       */
      case S_BPREL_XXXX_V3:
      case S_BPREL_V3:
      case S_BPREL_V2:
      case S_BPREL_V1:
         /* ignored */
         break;

      case S_LABEL_V3:  // FIXME
      case S_LABEL_V1:
         break;

      case S_SSEARCH_V1:
      case S_ALIGN_V1:
      case S_MSTOOL_V3:
      case S_UDT_V3:
      case S_UDT_V2:
      case S_UDT_V1:
      case S_CONSTANT_V3:
      case S_CONSTANT_V1:
      case S_OBJNAME_V1:
      case S_END_V1:
      case S_COMPILAND_V3:
      case S_COMPILAND_V2:
      case S_COMPILAND_V1:
      case S_BLOCK_V3:
      case S_BLOCK_V1:
      case S_REGISTER_V3:
      case S_REGISTER_V2:
      case S_REGISTER_V1:
         /* ignored */
         break;

      /*
       * These are special, in that they are always followed by an
       * additional length-prefixed string which is *not* included
       * into the symbol length count.  We need to skip it.
       */
      case S_PROCREF_V1:
      case S_DATAREF_V1:
      case S_LPROCREF_V1: {
         const unsigned char *name = (const unsigned char *)sym + length;
         length += (*name + 1 + 3) & ~3;
         break;
      }
      } /* switch ( sym->generic.id ) */

   } /* for ( i = offset; i < size; i += length ) */

   if (debug)
      VG_(umsg)("END SnarfCodeView addr=%p offset=%d length=%d\n", 
                root, offset, size );
   return n_syms_read;
}


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- Main stuff: reading of line number tables            ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

union any_size
{
          char const *c;
         short const *s;
           int const *i;
  unsigned int const *ui;
};

struct startend
{
  unsigned int          start;
  unsigned int          end;
};

static ULong DEBUG_SnarfLinetab(
          DebugInfo* di,
          PtrdiffT bias,
          const IMAGE_SECTION_HEADER* sectp,
          const void* linetab,
          Int size
       )
{
   //VG_(printf)("DEBUG_SnarfLinetab %p %p %p %d\n", di, sectp, linetab, size);
   Int                file_segcount;
   HChar              filename[WIN32_PATH_MAX];
   const UInt         * filetab;
   const UChar        * fn;
   Int                i;
   Int                k;
   const UInt         * lt_ptr;
   Int                nfile;
   Int                nseg;
   union any_size     pnt;
   union any_size     pnt2;
   const struct startend * start;
   Int                this_seg;

   Bool  debug = di->trace_symtab;
   ULong n_lines_read = 0;

   if (debug) {
      VG_(umsg)("BEGIN SnarfLineTab linetab=%p size=%d\n", linetab, size);
   }

   /*
    * Now get the important bits.
    */
   pnt.c = linetab;
   nfile = *pnt.s++;
   nseg  = *pnt.s++;

   filetab = pnt.ui;

   /*
    * Now count up the number of segments in the file.
    */
   nseg = 0;
   for (i = 0; i < nfile; i++) {
      pnt2.c = (const HChar *)linetab + filetab[i];
      nseg += *pnt2.s;
   }

   this_seg = 0;
   for (i = 0; i < nfile; i++) {
      const HChar *fnmstr;
      const HChar *dirstr;
      UInt  fnmdirstr_ix;

      /*
       * Get the pointer into the segment information.
       */
      pnt2.c = (const HChar *)linetab + filetab[i];
      file_segcount = *pnt2.s;

      pnt2.ui++;
      lt_ptr = pnt2.ui;
      start = (const struct startend *) (lt_ptr + file_segcount);

      /*
       * Now snarf the filename for all of the segments for this file.
       */
      fn = (const UChar*) (start + file_segcount);
      /* fn now points at a Pascal-style string, that is, the first
         byte is the length, and the remaining up to 255 (presumably)
         are the contents. */
      vg_assert(WIN32_PATH_MAX >= 256);
      VG_(memset)(filename, 0, sizeof(filename));
      VG_(memcpy)(filename, fn + 1, *fn);
      vg_assert(filename[ sizeof(filename)-1 ] == 0);
      filename[(Int)*fn] = 0;
      fnmstr = VG_(strrchr)(filename, '\\');
      if (fnmstr == NULL)
         fnmstr = filename;
      else 
         ++fnmstr;
      k = VG_(strlen)(fnmstr);
      dirstr = ML_(addStr)(di, filename, *fn - k);
      fnmstr = ML_(addStr)(di, fnmstr, k);
      fnmdirstr_ix = ML_(addFnDn) (di, fnmstr, dirstr);

      for (k = 0; k < file_segcount; k++, this_seg++) {
         Int linecount;
         Int segno;

         pnt2.c = (const HChar *)linetab + lt_ptr[k];

         segno = *pnt2.s++;
         linecount = *pnt2.s++;

         if ( linecount > 0 ) {
            UInt j;

            if (debug)
               VG_(umsg)(
                  "  Adding %d lines for file %s segment %d addr=%#x end=%#x\n",
                  linecount, filename, segno, start[k].start, start[k].end );

            for ( j = 0; j < linecount; j++ ) {
               Addr startaddr = bias + sectp[segno-1].VirtualAddress
                                     + pnt2.ui[j];
               Addr endaddr   = bias + sectp[segno-1].VirtualAddress
                                     + ((j < (linecount - 1))
                                           ? pnt2.ui[j+1] 
                                           : start[k].end);
               if (debug)
                  VG_(umsg)(
                     "  Adding line %d addr=%#lx end=%#lx\n", 
                     ((const unsigned short *)(pnt2.ui + linecount))[j],
                     startaddr, endaddr );
               ML_(addLineInfo)(
                   di,
                   fnmdirstr_ix,
                   startaddr, endaddr,
                   ((const unsigned short *)(pnt2.ui + linecount))[j], j );
               n_lines_read++;
            }
         }
      }
   }

   if (debug)
      VG_(umsg)("END SnarfLineTab linetab=%p size=%d\n", 
                linetab, size );

    return n_lines_read;
}



/* there's a new line tab structure from MS Studio 2005 and after
 * it's made of:
 * DWORD        000000f4
 * DWORD        lineblk_offset (counting bytes after this field)
 * an array of codeview_linetab2_file structures
 * an array (starting at <lineblk_offset>) of codeview_linetab2_block structures
 */

typedef struct codeview_linetab2_file
{
    DWORD       offset;         /* offset in string table for filename */
    WORD        unk;            /* always 0x0110... type of following
                                   information ??? */
    BYTE        md5[16];        /* MD5 signature of file (signature on
                                   file's content or name ???) */
    WORD        pad0;           /* always 0 */
} codeview_linetab2_file;

typedef struct codeview_linetab2_block
{
    DWORD       header;         /* 0x000000f2 */
    DWORD       size_of_block;  /* next block is at # bytes after this field */
    DWORD       start;          /* start address of function with line numbers */
    DWORD       seg;            /* segment of function with line numbers */
    DWORD       size;           /* size of function with line numbers */
    DWORD       file_offset;    /* offset for accessing corresponding
                                   codeview_linetab2_file */
    DWORD       nlines;         /* number of lines in this block */
    DWORD       size_lines;     /* number of bytes following for line
                                   number information */
    struct {
        DWORD   offset;         /* offset (from <seg>:<start>) for line number */
        DWORD   lineno;         /* the line number (OR:ed with
                                   0x80000000 why ???) */
    } l[1];                     /* actually array of <nlines> */
} codeview_linetab2_block;

static ULong codeview_dump_linetab2(
                DebugInfo* di,
                Addr bias,
                const IMAGE_SECTION_HEADER* sectp,
                const HChar* linetab,
                DWORD size,
                const HChar* strimage,
                DWORD strsize,
                const HChar* pfx
             )
{
   DWORD       offset;
   unsigned    i;
   const codeview_linetab2_block* lbh;
   const codeview_linetab2_file* fd;

   Bool  debug = di->trace_symtab;
   ULong n_line2s_read = 0;

   if (*(const DWORD*)linetab != 0x000000f4)
      return 0;
   offset = *((const DWORD*)linetab + 1);
   lbh = (const codeview_linetab2_block*)(linetab + 8 + offset);

   while ((const HChar*)lbh < linetab + size) {

      UInt filedirname_ix;
      Addr svma_s, svma_e;
      if (lbh->header != 0x000000f2) {
         /* FIXME: should also check that whole lbh fits in linetab + size */
         if (debug)
            VG_(printf)("%sblock end %x\n", pfx, lbh->header);
         break;
      }
      if (debug)
         VG_(printf)("%sblock from %04x:%08x-%08x (size %u) (%u lines)\n",
                     pfx, lbh->seg, lbh->start, lbh->start + lbh->size - 1,
                     lbh->size, lbh->nlines);
      fd = (const codeview_linetab2_file*)(linetab + 8 + lbh->file_offset);
      if (debug)
         VG_(printf)(
            "%s  md5=%02x%02x%02x%02x%02x%02x%02x%02x"
                    "%02x%02x%02x%02x%02x%02x%02x%02x\n",
             pfx, fd->md5[ 0], fd->md5[ 1], fd->md5[ 2], fd->md5[ 3],
                  fd->md5[ 4], fd->md5[ 5], fd->md5[ 6], fd->md5[ 7],
                  fd->md5[ 8], fd->md5[ 9], fd->md5[10], fd->md5[11],
                  fd->md5[12], fd->md5[13], fd->md5[14], fd->md5[15] );
      /* FIXME: should check that string is within strimage + strsize */
      const HChar* filename = NULL; // in ML_(addStr) space
      const HChar* dirname  = NULL; // in ML_(addStr) space
      if (strimage) {
         const HChar* strI = strimage + fd->offset;
         /* Copy |strI| into mutable storage, temporarily, so we can put a zero
            byte in place of the last pathname separator. */
         HChar* strM  = ML_(dinfo_strdup)("di.readpe.cdl2.1", strI);
         HChar* fname = VG_(strrchr)(strM, '\\');
         if (fname == NULL) {
            filename = ML_(addStr)(di, strM, -1);
            dirname  = NULL;
         } else {
            *fname++ = '\0';
            filename = ML_(addStr)(di, fname, -1);
            dirname  = ML_(addStr)(di, strM, -1);
         }
         ML_(dinfo_free)(strM);
      } else {
         filename = ML_(addStr)(di, "???", -1);
         dirname  = NULL;
      }

      if (debug)
         VG_(printf)("%s  file=%s\n", pfx, filename);

      filedirname_ix = ML_(addFnDn) (di, filename, dirname);

      for (i = 0; i < lbh->nlines; i++) {
         if (debug)
            VG_(printf)("%s  offset=%08x line=%u\n",
                        pfx, lbh->l[i].offset, lbh->l[i].lineno ^ 0x80000000);
      }

      if (lbh->nlines > 1) {
         for (i = 0; i < lbh->nlines-1; i++) {
            svma_s = sectp[lbh->seg - 1].VirtualAddress + lbh->start
                     + lbh->l[i].offset;
            svma_e = sectp[lbh->seg - 1].VirtualAddress + lbh->start
                     + lbh->l[i+1].offset-1;
            if (debug)
               VG_(printf)("%s  line %u: %08lx to %08lx\n",
                           pfx, lbh->l[i].lineno ^ 0x80000000, svma_s, svma_e);
            ML_(addLineInfo)( di, 
                              filedirname_ix,
                              bias + svma_s,
                              bias + svma_e + 1,
                              lbh->l[i].lineno ^ 0x80000000, 0 );
            n_line2s_read++;
         }
         svma_s = sectp[lbh->seg - 1].VirtualAddress + lbh->start
                  + lbh->l[ lbh->nlines-1].offset;
         svma_e = sectp[lbh->seg - 1].VirtualAddress + lbh->start
                  + lbh->size - 1;
         if (debug)
            VG_(printf)("%s  line %u: %08lx to %08lx\n",
                        pfx, lbh->l[ lbh->nlines-1  ].lineno ^ 0x80000000,
                        svma_s, svma_e);
          ML_(addLineInfo)( di, 
                            filedirname_ix,
                            bias + svma_s,
                            bias + svma_e + 1,
                            lbh->l[lbh->nlines-1].lineno ^ 0x80000000, 0 );
          n_line2s_read++;
       }

       lbh = (const codeview_linetab2_block*)
                ((const char*)lbh + 8 + lbh->size_of_block);
    }
    return n_line2s_read;
}


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- Main stuff: pdb_dump                                 ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

static Int cmp_FPO_DATA_for_canonicalisation ( const void* f1V,
                                               const void* f2V )
{
   /* Cause FPO data to be sorted first in ascending order of range
      starts, and for entries with the same range start, with the
      shorter range (length) first. */
   const FPO_DATA* f1 = f1V;
   const FPO_DATA* f2 = f2V;
   if (f1->ulOffStart < f2->ulOffStart) return -1;
   if (f1->ulOffStart > f2->ulOffStart) return  1;
   if (f1->cbProcSize < f2->cbProcSize) return -1;
   if (f1->cbProcSize > f2->cbProcSize) return  1;
   return 0; /* identical in both start and length */
}

static unsigned get_stream_by_name(const struct pdb_reader* pdb, const char* name)
{
    const DWORD* pdw;
    const DWORD* ok_bits;
    DWORD        cbstr, count;
    DWORD        string_idx, stream_idx;
    unsigned     i;
    const char*  str;

    if (pdb->read_file == pdb_jg_read_file)
    {
        str = pdb->u.jg.root->names;
        cbstr = pdb->u.jg.root->cbNames;
    }
    else
    {
        str = pdb->u.ds.root->names;
        cbstr = pdb->u.ds.root->cbNames;
    }

    pdw = (const DWORD*)(str + cbstr);
    pdw++; /* number of ok entries */
    count = *pdw++;

    /* bitfield: first dword is len (in dword), then data */
    ok_bits = pdw;
    pdw += *ok_bits++ + 1;
    if (*pdw++ != 0)
    {
        if (VG_(clo_verbosity) > 1)
           VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                     "get_stream_by_name: unexpected value\n");
        return -1;
    }

    for (i = 0; i < count; i++)
    {
        if (ok_bits[i / 32] & (1 << (i % 32)))
        {
            string_idx = *pdw++;
            stream_idx = *pdw++;
            if (!VG_(strcmp)(name, &str[string_idx])) return stream_idx;
        }
    }
    return -1;
}
 

static void *read_string_table(const struct pdb_reader* pdb)
{
    unsigned    stream_idx;
    void*       ret;

    stream_idx = get_stream_by_name(pdb, "/names");
    if (stream_idx == -1) return NULL;
    ret = pdb->read_file(pdb, stream_idx,0);
    if (ret && *(const DWORD*)ret == 0xeffeeffe) {
       return ret;
    }
    if (VG_(clo_verbosity) > 1)
       VG_(umsg)("LOAD_PDB_DEBUGINFO: read_string_table: "
                 "wrong header 0x%08x, expecting 0xeffeeffe\n",
                 *(const DWORD*)ret);
    ML_(dinfo_free)( ret );
    return NULL;
}

/* JRS fixme: compare with version in current Wine sources */
static void pdb_dump( const struct pdb_reader* pdb,
                      DebugInfo* di,
                      Addr       pe_avma,
                      PtrdiffT   pe_bias,
                      const IMAGE_SECTION_HEADER* sectp_avma )
{
   Int header_size;

   PDB_TYPES types;
   PDB_SYMBOLS symbols;
   unsigned len_modimage;
   char *modimage;
   const char *file; 

   Bool debug = di->trace_symtab;

   ULong n_fpos_read = 0, n_syms_read = 0,
         n_lines_read = 0, n_line2s_read = 0;

   // FIXME: symbols for bare indices 1,2,3,5 in .pdb file

   char* types_image   = pdb->read_file( pdb, 2, 0 );
   char* symbols_image = pdb->read_file( pdb, 3, 0 );

   /* establish filesimage and filessize.  These are only needed for
      reading linetab2 tables, as far as I can deduce from the Wine
      sources. */
   DWORD filessize  = 0;
   char* filesimage = read_string_table(pdb);
   if (filesimage) {
      filessize = *(const DWORD*)(filesimage + 8);
   } else {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: pdb_dump: string table not found\n");
   }

   /* Since we just use the FPO data without reformatting, at least
      do a basic sanity check on the struct layout. */
   vg_assert(sizeof(FPO_DATA) == 16);
   if (di->text_present) { 
      /* only load FPO if there's text present (otherwise it's
         meaningless?) */
      unsigned sz = 0;
      di->fpo = pdb->read_file( pdb, 5, &sz );

      // FIXME: seems like the size can be a non-integral number
      // of FPO_DATAs.  Force-align it (moronically).  Perhaps this
      // signifies that we're not looking at a valid FPO table ..
      // who knows.  Needs investigation.
      while (sz > 0 && (sz % sizeof(FPO_DATA)) != 0)
         sz--;

      di->fpo_size = sz;
      if (0) VG_(printf)("FPO: got fpo_size %lu\n", (UWord)sz);
      vg_assert(0 == (di->fpo_size % sizeof(FPO_DATA)));
      di->fpo_base_avma = pe_avma;
   } else {
      vg_assert(di->fpo == NULL);
      vg_assert(di->fpo_size == 0);
   }

   // BEGIN clean up FPO data
   if (di->fpo && di->fpo_size > 0) {
      Word i, j;
      Bool anyChanges;
      Int itersAvail = 10;

      vg_assert(sizeof(di->fpo[0]) == 16);
      di->fpo_size /= sizeof(di->fpo[0]);

      // BEGIN FPO-data tidying-up loop
      do {

         vg_assert(itersAvail >= 0); /* safety check -- don't loop forever */
         itersAvail--;

         anyChanges = False;

         /* First get them in ascending order of start point */
         VG_(ssort)( di->fpo, (SizeT)di->fpo_size, (SizeT)sizeof(FPO_DATA),
                              cmp_FPO_DATA_for_canonicalisation );
         /* Get rid of any zero length entries */
         j = 0;
         for (i = 0; i < di->fpo_size; i++) {
            if (di->fpo[i].cbProcSize == 0) {
               anyChanges = True;
               continue;
            }
            di->fpo[j++] = di->fpo[i];
         }
         vg_assert(j >= 0 && j <= di->fpo_size);
         di->fpo_size = j;

         /* Get rid of any dups */
         if (di->fpo_size > 1) {
            j = 1;
            for (i = 1; i < di->fpo_size; i++) {
               Bool dup
                  = di->fpo[j-1].ulOffStart == di->fpo[i].ulOffStart
                    && di->fpo[j-1].cbProcSize == di->fpo[i].cbProcSize;
               if (dup) {
                 anyChanges = True;
                 continue;
               }
               di->fpo[j++] = di->fpo[i];
            }
            vg_assert(j >= 0 && j <= di->fpo_size);
            di->fpo_size = j;
         }

         /* Truncate any overlapping ranges */
         for (i = 1; i < di->fpo_size; i++) {
            vg_assert(di->fpo[i-1].ulOffStart <= di->fpo[i].ulOffStart);
            if (di->fpo[i-1].ulOffStart + di->fpo[i-1].cbProcSize 
                > di->fpo[i].ulOffStart) {
               anyChanges = True;
               di->fpo[i-1].cbProcSize
                  = di->fpo[i].ulOffStart - di->fpo[i-1].ulOffStart;
            }
         }

      } while (anyChanges);
      // END FPO-data tidying-up loop

      /* Should now be in ascending order, non overlapping, no zero ranges.
         Check this, get the min and max avmas, and bias the entries. */
      for (i = 0; i < di->fpo_size; i++) {
         vg_assert(di->fpo[i].cbProcSize > 0);

         if (i > 0) {
            vg_assert(di->fpo[i-1].ulOffStart < di->fpo[i].ulOffStart);
            vg_assert(di->fpo[i-1].ulOffStart + di->fpo[i-1].cbProcSize
                      <= di->fpo[i].ulOffStart);
         }
      }

      /* Now bias the table.  This can't be done in the same pass as
         the sanity check, hence a second loop. */
      for (i = 0; i < di->fpo_size; i++) {
         di->fpo[i].ulOffStart += pe_avma;
         // make sure the biasing didn't royally screw up, by wrapping
         // the range around the end of the address space
         vg_assert(0xFFFFFFFF - di->fpo[i].ulOffStart /* "remaining space" */
                   >= di->fpo[i].cbProcSize);
      }

      /* Dump any entries which point outside the text segment and
         compute the min/max avma "hint" addresses. */
      Addr min_avma = ~(Addr)0;
      Addr max_avma = (Addr)0;
      vg_assert(di->text_present);
      j = 0;
      for (i = 0; i < di->fpo_size; i++) {
         if ((Addr)(di->fpo[i].ulOffStart) >= di->text_avma
             && (Addr)(di->fpo[i].ulOffStart + di->fpo[i].cbProcSize)
                <= di->text_avma + di->text_size) {
            /* Update min/max limits as we go along. */
            if (di->fpo[i].ulOffStart < min_avma)
               min_avma = di->fpo[i].ulOffStart;
            if (di->fpo[i].ulOffStart + di->fpo[i].cbProcSize - 1 > max_avma)
               max_avma = di->fpo[i].ulOffStart + di->fpo[i].cbProcSize - 1;
            /* Keep */
            di->fpo[j++] = di->fpo[i];
            if (0)
            VG_(printf)("FPO: keep text=[0x%lx,0x%lx) 0x%lx 0x%lx\n",
                        di->text_avma, di->text_avma + di->text_size,
                        (Addr)di->fpo[i].ulOffStart,
                        (Addr)di->fpo[i].ulOffStart 
                        + (Addr)di->fpo[i].cbProcSize - 1);
         } else {
            if (0)
            VG_(printf)("FPO: SKIP text=[0x%lx,0x%lx) 0x%lx 0x%lx\n",
                        di->text_avma, di->text_avma + di->text_size,
                        (Addr)di->fpo[i].ulOffStart,
                        (Addr)di->fpo[i].ulOffStart 
                        + (Addr)di->fpo[i].cbProcSize - 1);
            /* out of range; ignore */
         }
      }
      vg_assert(j >= 0 && j <= di->fpo_size);
      di->fpo_size = j;

      /* And record min/max */
      /* biasing shouldn't cause wraparound (?!) */
      if (di->fpo_size > 0) {
         vg_assert(min_avma <= max_avma); /* should always hold */
         di->fpo_minavma = min_avma;
         di->fpo_maxavma = max_avma;
      } else {
         di->fpo_minavma = 0;
         di->fpo_maxavma = 0;
      }

      if (0) {
         VG_(printf)("FPO: min/max avma %#lx %#lx\n",
                     di->fpo_minavma, di->fpo_maxavma);
      }

      n_fpos_read += (ULong)di->fpo_size;
   }
   // END clean up FPO data

   pdb_convert_types_header( &types, types_image );
   switch ( types.version ) {
      case 19950410:      /* VC 4.0 */
      case 19951122:
      case 19961031:      /* VC 5.0 / 6.0 */
      case 20040203:      /* VC 7.0  FIXME??  */
         break;
      default:
         if (VG_(clo_verbosity) > 1)
            VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                      "Unknown .pdb type info version %u\n", types.version );
   }

   header_size = 0;
   pdb_convert_symbols_header( &symbols, &header_size, symbols_image );
   switch ( symbols.version ) {
      case 0:            /* VC 4.0 */
      case 19960307:     /* VC 5.0 */
      case 19970606:     /* VC 6.0 */
      case 19990903:     /* VC 7.0  FIXME?? */
         break;
      default:
         if (VG_(clo_verbosity) > 1)
            VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                      "Unknown .pdb symbol info version %u\n",
                      symbols.version );
   }

   /*
    * Read global symbol table
    */
   modimage = pdb->read_file( pdb, symbols.gsym_file, &len_modimage );
   if (modimage) {
      if (debug)
         VG_(umsg)("\n");
      if (VG_(clo_verbosity) > 1)
         VG_(umsg)("LOAD_PDB_DEBUGINFO: Reading global symbols\n" );
      DEBUG_SnarfCodeView( di, pe_avma, sectp_avma, modimage, 0, len_modimage );
      ML_(dinfo_free)( modimage );
   }

   /*
    * Read per-module symbol / linenumber tables
    */
   file = symbols_image + header_size;
   while ( file - symbols_image < header_size + symbols.module_size ) {
      int file_nr, /* file_index, */ symbol_size, lineno_size;
      const char *file_name;

      if ( symbols.version < 19970000 ) {
         const PDB_SYMBOL_FILE *sym_file = (const PDB_SYMBOL_FILE *) file;
         file_nr     = sym_file->file;
         file_name   = sym_file->filename;
         /* file_index  = sym_file->range.index; */ /* UNUSED */
         symbol_size = sym_file->symbol_size;
         lineno_size = sym_file->lineno_size;
      } else {
         const PDB_SYMBOL_FILE_EX *sym_file = (const PDB_SYMBOL_FILE_EX *) file;
         file_nr     = sym_file->file;
         file_name   = sym_file->filename;
         /* file_index  = sym_file->range.index; */ /* UNUSED */
         symbol_size = sym_file->symbol_size;
         lineno_size = sym_file->lineno_size;
      }

      modimage = pdb->read_file( pdb, file_nr, 0 );
      if (modimage) {
         Int total_size;
         if (0) VG_(printf)("lineno_size %d symbol_size %d\n",
                            lineno_size, symbol_size );

         total_size = pdb_get_file_size(pdb, file_nr);

         if (symbol_size) {
            if (debug)
               VG_(umsg)("\n");
            if (VG_(clo_verbosity) > 1)
               VG_(umsg)("LOAD_PDB_DEBUGINFO: Reading symbols for %s\n",
                                        file_name );
            n_syms_read 
               += DEBUG_SnarfCodeView( di, pe_avma, sectp_avma, modimage,
                                           sizeof(DWORD),
                                           symbol_size );
         }

         if (lineno_size) {
            if (debug)
               VG_(umsg)("\n");
            if (VG_(clo_verbosity) > 1)
               VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                         "Reading lines for %s\n", file_name );
            n_lines_read
               += DEBUG_SnarfLinetab( di, pe_avma, sectp_avma,
                                          modimage + symbol_size, lineno_size );
         }

         /* anyway, lineno_size doesn't see to really be the size of
          * the line number information, and it's not clear yet when
          * to call for linetab2...
          */
         if (0) VG_(printf)("Reading lines for %s\n", file_name );
         n_line2s_read
            += codeview_dump_linetab2(
                  di, pe_avma, sectp_avma,
                      (HChar*)modimage + symbol_size + lineno_size,
                      total_size - (symbol_size + lineno_size),
                  /* if filesimage is NULL, pass that directly onwards
                     to codeview_dump_linetab2, so it knows not to
                     poke around in there. */
                  filesimage ? filesimage + 12 : NULL,
                  filessize, "        "
               );

         ML_(dinfo_free)( modimage );
      }

      file_name += VG_(strlen)(file_name) + 1;
      file = (const char *)( 
                (unsigned long)(file_name
                                + VG_(strlen)(file_name) + 1 + 3) & ~3 );
   }

   /*
    * Cleanup
    */
   if ( symbols_image ) ML_(dinfo_free)( symbols_image );
   if ( types_image ) ML_(dinfo_free)( types_image );
   if ( pdb->u.jg.toc ) ML_(dinfo_free)( pdb->u.jg.toc );

   if (VG_(clo_verbosity) > 1) {
      VG_(dmsg)("LOAD_PDB_DEBUGINFO:"
                "    # symbols read = %llu\n", n_syms_read );
      VG_(dmsg)("LOAD_PDB_DEBUGINFO:"
                "    # lines   read = %llu\n", n_lines_read );
      VG_(dmsg)("LOAD_PDB_DEBUGINFO:"
                "    # line2s  read = %llu\n", n_line2s_read );
      VG_(dmsg)("LOAD_PDB_DEBUGINFO:"
                "    # fpos    read = %llu\n", n_fpos_read );
   }
}


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- TOP LEVEL for PDB reading                            ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

/* Read line, symbol and unwind information from a PDB file.
*/
Bool ML_(read_pdb_debug_info)(
        DebugInfo* di,
        Addr       obj_avma,
        PtrdiffT   obj_bias,
        void*      pdbimage,
        SizeT      n_pdbimage,
        const HChar* pdbname,
        ULong      pdbmtime
     )
{
   Char*    pe_seg_avma;
   Int      i;
   Addr     mapped_avma, mapped_end_avma;
   unsigned signature;
   void*    hdr;
   struct pdb_reader     reader;
   IMAGE_DOS_HEADER*     dos_avma;
   IMAGE_NT_HEADERS*     ntheaders_avma;
   IMAGE_SECTION_HEADER* sectp_avma;
   IMAGE_SECTION_HEADER* pe_sechdr_avma;

   if (VG_(clo_verbosity) > 1)
       VG_(umsg)("LOAD_PDB_DEBUGINFO: Processing PDB file %s\n", pdbname );

   dos_avma = (IMAGE_DOS_HEADER *)obj_avma;
   if (dos_avma->e_magic != IMAGE_DOS_SIGNATURE) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: IMAGE_DOS_SIGNATURE not found. "
                " possible invalid/unsupported pdb file format?\n");
       return False;
   }

   ntheaders_avma
      = (IMAGE_NT_HEADERS *)((Char*)dos_avma + dos_avma->e_lfanew);
   if (ntheaders_avma->Signature != IMAGE_NT_SIGNATURE) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: IMAGE_NT_SIGNATURE not found. "
                " possible invalid/unsupported pdb file format?\n");
      return False;
   }

   sectp_avma
      = (IMAGE_SECTION_HEADER *)(
           (Char*)ntheaders_avma
           + OFFSET_OF(IMAGE_NT_HEADERS, OptionalHeader)
           + ntheaders_avma->FileHeader.SizeOfOptionalHeader
        );

   /* JRS: this seems like something of a hack. */
   di->soname = ML_(dinfo_strdup)("di.readpdb.rpdi.1", pdbname);

   /* someone (ie WINE) is loading a Windows PE format object.  we
      need to use its details to determine which area of memory is
      executable... */
   pe_seg_avma
      = (Char*)ntheaders_avma
        + OFFSET_OF(IMAGE_NT_HEADERS, OptionalHeader)
        + ntheaders_avma->FileHeader.SizeOfOptionalHeader;

   /* Iterate over PE headers and fill our section mapping table. */
   for ( i = 0;
         i < ntheaders_avma->FileHeader.NumberOfSections;
         i++, pe_seg_avma += sizeof(IMAGE_SECTION_HEADER) ) {
      pe_sechdr_avma = (IMAGE_SECTION_HEADER *)pe_seg_avma;

      if (VG_(clo_verbosity) > 1) {
         /* Copy name, it can be 8 chars and not NUL-terminated */
         char name[9];
         VG_(memcpy)(name, pe_sechdr_avma->Name, 8);
         name[8] = '\0';
         VG_(umsg)("LOAD_PDB_DEBUGINFO:"
                   "   Scanning PE section %ps at avma %#lx svma %#x\n",
                   name, obj_avma + pe_sechdr_avma->VirtualAddress,
                   pe_sechdr_avma->VirtualAddress);
      }

      if (pe_sechdr_avma->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
         continue;

      mapped_avma     = (Addr)obj_avma + pe_sechdr_avma->VirtualAddress;
      mapped_end_avma = mapped_avma + pe_sechdr_avma->Misc.VirtualSize;

      DebugInfoMapping map;
      map.avma = mapped_avma;
      map.size = pe_sechdr_avma->Misc.VirtualSize;
      map.foff = pe_sechdr_avma->PointerToRawData;
      map.ro   = False;

      if (pe_sechdr_avma->Characteristics & IMAGE_SCN_CNT_CODE) {
         /* Ignore uninitialised code sections - if you have
            incremental linking enabled in Visual Studio then you will
            get a uninitialised code section called .textbss before
            the real text section and valgrind will compute the wrong
            avma value and hence the wrong bias. */
         if (!(pe_sechdr_avma->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
            map.rx   = True;
            map.rw   = False;
            VG_(addToXA)(di->fsm.maps, &map);
            di->fsm.have_rx_map = True;

            di->text_present = True;
            if (di->text_avma == 0) {
               di->text_svma = pe_sechdr_avma->VirtualAddress;
               di->text_avma = mapped_avma;
               di->text_size = pe_sechdr_avma->Misc.VirtualSize;
            } else {
               di->text_size = mapped_end_avma - di->text_avma;
            }
         }
      }
      else if (pe_sechdr_avma->Characteristics 
               & IMAGE_SCN_CNT_INITIALIZED_DATA) {
         map.rx   = False;
         map.rw   = True;
         VG_(addToXA)(di->fsm.maps, &map);
         di->fsm.rw_map_count = 1;

         di->data_present = True;
         if (di->data_avma == 0) {
            di->data_avma = mapped_avma;
            di->data_size = pe_sechdr_avma->Misc.VirtualSize;
         } else {
            di->data_size = mapped_end_avma - di->data_avma;
         }
      }
      else if (pe_sechdr_avma->Characteristics
               & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
         di->bss_present = True;
         if (di->bss_avma == 0) {
            di->bss_avma = mapped_avma;
            di->bss_size = pe_sechdr_avma->Misc.VirtualSize;
         } else {
            di->bss_size = mapped_end_avma - di->bss_avma;
         }
      }
   }

   if (di->fsm.have_rx_map && di->fsm.rw_map_count && !di->have_dinfo) {
      vg_assert(di->fsm.filename);
      TRACE_SYMTAB("\n");
      TRACE_SYMTAB("------ start PE OBJECT with PDB INFO "
                   "---------------------\n");
      TRACE_SYMTAB("------ name = %s\n", di->fsm.filename);
      TRACE_SYMTAB("\n");
   }

   di->text_bias = obj_bias;

   if (VG_(clo_verbosity) > 1) {
      for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
         const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
         if (map->rx)
            VG_(dmsg)("LOAD_PDB_DEBUGINFO: "
                      "rx_map: avma %#lx size %7lu foff %lld\n",
                      map->avma, map->size, (Long)map->foff);
      }
      for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
         const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
         if (map->rw)
            VG_(dmsg)("LOAD_PDB_DEBUGINFO: "
                      "rw_map: avma %#lx size %7lu foff %lld\n",
                      map->avma, map->size, (Long)map->foff);
      }

      VG_(dmsg)("LOAD_PDB_DEBUGINFO: "
                "  text: avma %#lx svma %#lx size %7lu bias %#lx\n",
                di->text_avma, di->text_svma,
                di->text_size, (UWord)di->text_bias);
   }

   /*
    * Read in TOC and well-known files
    */
   signature = 0;
   hdr = find_pdb_header( pdbimage, &signature );
   if (0==hdr) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: find_pdb_header found no hdr. "
                " possible invalid/unsupported pdb file format?\n");
      return False; /* JRS: significance? no pdb header? */
   }

   VG_(memset)(&reader, 0, sizeof(reader));
   reader.u.jg.header = hdr;

   if (0==VG_(strncmp)((char const *)&signature, "DS\0\0", 4)) {
      struct PDB_DS_ROOT* root;
      pdb_ds_init( &reader, pdbimage, n_pdbimage );
      root = reader.read_file( &reader, 1, 0 );
      reader.u.ds.root = root;
      if (root) {
         pdb_check_root_version_and_timestamp(
            pdbname, pdbmtime, root->version, root->TimeDateStamp );
      }
      pdb_dump( &reader, di, obj_avma, obj_bias, sectp_avma );
      if (root) {
         ML_(dinfo_free)( root );
      }
   }
   else
   if (0==VG_(strncmp)((char const *)&signature, "JG\0\0", 4)) {
      struct PDB_JG_ROOT* root;
      pdb_jg_init( &reader, pdbimage, n_pdbimage );
      root = reader.read_file( &reader, 1, 0 );
      reader.u.jg.root = root;	
      if (root) {
         pdb_check_root_version_and_timestamp(
            pdbname, pdbmtime, root->version, root->TimeDateStamp);
      }
      pdb_dump( &reader, di, obj_avma, obj_bias, sectp_avma );
      if (root) {
         ML_(dinfo_free)( root );
      }
   }

   if (1) {
      TRACE_SYMTAB("\n------ Canonicalising the "
                   "acquired info ------\n");
      /* prepare read data for use */
      ML_(canonicaliseTables)( di );
      /* notify m_redir about it */
      TRACE_SYMTAB("\n------ Notifying m_redir ------\n");
      VG_(redir_notify_new_DebugInfo)( di );
      /* Note that we succeeded */
      di->have_dinfo = True;
   } else {
      TRACE_SYMTAB("\n------ PE with PDB reading failed ------\n");
      /* Something went wrong (eg. bad ELF file).  Should we delete
         this DebugInfo?  No - it contains info on the rw/rx
         mappings, at least. */
   }

   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("------ name = %s\n", di->fsm.filename);
   TRACE_SYMTAB("------ end PE OBJECT with PDB INFO "
                "--------------------\n");
   TRACE_SYMTAB("\n");

   return True;
}


/* Examine a PE file to see if it states the path of an associated PDB
   file; if so return that.  Caller must deallocate with
   ML_(dinfo_free).
*/

HChar* ML_(find_name_of_pdb_file)( const HChar* pename )
{
   /* This is a giant kludge, of the kind "you did WTF?!?", but it
      works. */
   Bool   do_cleanup = False;
   HChar  tmpnameroot[50];     // large enough
   HChar  tmpname[VG_(mkstemp_fullname_bufsz)(sizeof tmpnameroot - 1)];
   Int    fd, r;
   HChar* res = NULL;

   if (!pename)
      goto out;

   fd = -1;
   VG_(memset)(tmpnameroot, 0, sizeof(tmpnameroot));
   VG_(sprintf)(tmpnameroot, "petmp%d", VG_(getpid)());
   VG_(memset)(tmpname, 0, sizeof(tmpname));
   fd = VG_(mkstemp)( tmpnameroot, tmpname );
   if (fd == -1) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: "
                "Find PDB file: Can't create temporary file %s\n", tmpname);
      goto out;
   }
   do_cleanup = True;

   /* Make up the command to run, essentially:
      sh -c "strings (pename) | egrep '\.pdb$|\.PDB$' > (tmpname)"
   */
   const HChar* sh      = "/bin/sh";
   const HChar* strings = "strings";
   const HChar* egrep   = "grep -E";

   /* (sh) -c "(strings) (pename) | (egrep) 'pdb' > (tmpname) */
   Int cmdlen = VG_(strlen)(strings) + VG_(strlen)(pename)
                + VG_(strlen)(egrep) + VG_(strlen)(tmpname)
                + 100/*misc*/;
   HChar* cmd = ML_(dinfo_zalloc)("di.readpe.fnopf.cmd", cmdlen);
   VG_(sprintf)(cmd, "%s -c \"%s '%s' | %s '\\.pdb$|\\.PDB$' >> %s\"",
                     sh, strings, pename, egrep, tmpname);
   vg_assert(cmd[cmdlen-1] == 0);
   if (0) VG_(printf)("QQQQQQQQ: %s\n", cmd);

   r = VG_(system)( cmd );
   if (r) {
      VG_(dmsg)("LOAD_PDB_DEBUGINFO: "
                "Find PDB file: Command failed:\n   %s\n", cmd);
      goto out;
   }

   /* Find out how big the file is, and get it aboard. */
   struct vg_stat stat_buf;
   VG_(memset)(&stat_buf, 0, sizeof(stat_buf));

   SysRes sr = VG_(stat)(tmpname, &stat_buf);
   if (sr_isError(sr)) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: Find PDB file: can't stat %s\n", tmpname);
      goto out;
   }

   Int szB = (Int)stat_buf.size;
   if (szB == 0) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: Find PDB file: %s is empty\n", tmpname);
      goto out;
   }
   /* 6 == strlen("X.pdb\n") */
   if (szB < 6 || szB > 1024/*let's say*/) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: Find PDB file: %s has implausible size %d\n",
                tmpname, szB);
      goto out;
   }

   HChar* pdbname = ML_(dinfo_zalloc)("di.readpe.fnopf.pdbname", szB + 1);
   pdbname[szB] = 0;

   Int nread = VG_(read)(fd, pdbname, szB);
   if (nread != szB) {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: Find PDB file: read of %s failed\n", tmpname);
      goto out;
   }
   vg_assert(pdbname[szB] == 0);

   /* Check we've got something remotely sane -- must have one dot and
      one \n in it, and the \n must be at the end */
   Bool saw_dot = False;
   Int  saw_n_crs = 0;
   Int  i;
   for (i = 0; pdbname[i]; i++) {
      if (pdbname[i] == '.')  saw_dot = True;
      if (pdbname[i] == '\n') saw_n_crs++;
   }
   if (!saw_dot || saw_n_crs != 1 || pdbname[szB-1] != '\n') {
      VG_(umsg)("LOAD_PDB_DEBUGINFO: Find PDB file: can't make sense of: %s\n", pdbname);
      goto out;
   }
   /* Change the \n to a terminating zero, so we have a "normal" string */
   pdbname[szB-1] = 0;

   if (0) VG_(printf)("QQQQQQQQ: got %s\n", pdbname);

   res = pdbname;
   goto out;

  out:
   if (do_cleanup) {
      VG_(close)(fd);
      VG_(unlink)( tmpname );
   }
   return res;
}


static
Bool is_pe_object_file( const void* image, SizeT n_image, Bool rel_ok )
{
   const IMAGE_DOS_HEADER* dos_avma;
   const IMAGE_NT_HEADERS* ntheaders_avma;

   dos_avma = (const IMAGE_DOS_HEADER *)image;
   if (dos_avma->e_magic != IMAGE_DOS_SIGNATURE)
       return False;

   ntheaders_avma
      = (const IMAGE_NT_HEADERS *)(((const Char*)image) + dos_avma->e_lfanew);
   if (ntheaders_avma->Signature != IMAGE_NT_SIGNATURE)
      return False;

   return True;
}


static
Bool is_pe_object_file_by_DiImage( DiImage* img, Bool rel_ok )
{
   char buf[1024];

   if (!ML_(img_valid)(img, 0, sizeof(buf)))
      return False;

   ML_(img_get)(buf, img, 0, sizeof(buf));
   return is_pe_object_file( buf, sizeof(buf), rel_ok );
}


static
int shdr_name_strcmp( DiImage *img, IMAGE_SECTION_HEADER *shdr,
                      DiOffT strtab_off, const char *name )
{
   if (*shdr->Name != '/') return VG_(strcmp)((char *)shdr->Name, name);
   Long n = VG_(strtoll10)((const char*)shdr->Name + 1, NULL);
   return ML_(img_strcmp_c)(img, strtab_off + n, name);
}


static
Int cmp_IMAGE_SYMBOL_by_section_value( const void* v1, const void* v2 )
{
   const IMAGE_SYMBOL* s1 = v1, *s2 = v2;
   if (s1->SectionNumber != s2->SectionNumber)
      return s1->SectionNumber - s2->SectionNumber;
   if (s1->Value != s2->Value)
      return s1->Value - s2->Value;
   return 0;
}


Bool ML_(read_pe_debug_info) ( struct _DebugInfo* di, Addr obj_avma,
                               PtrdiffT obj_bias )
{
   /* TOPLEVEL */
   Bool     res, ok;
   Word     i, n;

   /* Image for the main PE file we're working with. */
   DiImage* mimg = NULL;

   /* Ditto for any PE debuginfo file that we might happen to load. */
   DiImage* dimg = NULL;

   /* Ditto for alternate PE debuginfo file that we might happen to load. */
   DiImage* aimg = NULL;

   /* Program header table image addr, # entries, entry size */
   DiOffT   phdr_mioff    = 0;
   UWord    phdr_mnent    = 0;
   UWord    phdr_ment_szB = 0;

   /* Section header image addr, # entries, entry size.  Also the
      associated string table. */
   DiOffT   shdr_mioff        = 0;
   UWord    shdr_mnent        = 0;
   UWord    shdr_ment_szB     = 0;

   DiOffT   strtab_mioff = 0;

   vg_assert(di);
   vg_assert(di->have_dinfo == False);
   vg_assert(di->fsm.filename);
   vg_assert(!di->symtab);
   vg_assert(!di->loctab);
   vg_assert(!di->inltab);
   vg_assert(!di->cfsi_base);
   vg_assert(!di->cfsi_m_ix);
   vg_assert(!di->cfsi_rd);
   vg_assert(!di->cfsi_exprs);
   vg_assert(!di->strpool);
   vg_assert(!di->fndnpool);
   vg_assert(!di->soname);

   res = False;

   /* Connect to the primary object image, so that we can read symbols
      and line number info out of it.  It will be disconnected
      immediately thereafter; it is only connected transiently. */
   mimg = ML_(img_from_local_file)(di->fsm.filename);
   if (mimg == NULL) {
      VG_(message)(Vg_UserMsg, "warning: connection to image %s failed\n",
                               di->fsm.filename );
      VG_(message)(Vg_UserMsg, "         no symbols or debug info loaded\n" );
      return False;
   }

   /* Ok, the object image is available.  Now verify that it is a
      valid PE. */
   ok = is_pe_object_file_by_DiImage(mimg, False);
   if (!ok)
      goto out;

   if (VG_(clo_verbosity) > 1 || VG_(clo_trace_redir))
      VG_(message)(Vg_DebugMsg, "Reading syms from %s\n",
                                di->fsm.filename );

   /* Find where the program and section header tables are, and give
      up if either is missing or outside the image (bogus). */
   IMAGE_DOS_HEADER dos_hdr;
   ok = ML_(img_valid)(mimg, 0, sizeof(dos_hdr));
   vg_assert(ok); // ML_(is_pe_object_file) should ensure this
   ML_(img_get)(&dos_hdr, mimg, 0, sizeof(dos_hdr));

   IMAGE_NT_HEADERS nt_hdr;
   ok = ML_(img_valid)(mimg, dos_hdr.e_lfanew, sizeof(nt_hdr));
   vg_assert(ok); // ML_(is_pe_object_file) should ensure this
   ML_(img_get)(&nt_hdr, mimg, dos_hdr.e_lfanew, sizeof(nt_hdr));

   phdr_mioff    = dos_hdr.e_lfanew;
   phdr_mnent    = 1;
   phdr_ment_szB = OFFSET_OF(IMAGE_NT_HEADERS, OptionalHeader)
                   + nt_hdr.FileHeader.SizeOfOptionalHeader;

   shdr_mioff    = phdr_mioff + phdr_ment_szB;
   shdr_mnent    = nt_hdr.FileHeader.NumberOfSections;
   shdr_ment_szB = sizeof(IMAGE_SECTION_HEADER);

   if (nt_hdr.FileHeader.PointerToSymbolTable
       && nt_hdr.FileHeader.NumberOfSymbols)
   {
      strtab_mioff = nt_hdr.FileHeader.PointerToSymbolTable
                     + nt_hdr.FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL);
   }

   TRACE_SYMTAB("------ Basic facts about the object ------\n");
   TRACE_SYMTAB("object:  n_oimage %llu\n",
                (ULong)ML_(img_size)(mimg));
   TRACE_SYMTAB("phdr:    ioff %llu nent %lu ent_szB %lu\n",
               phdr_mioff, phdr_mnent, phdr_ment_szB);
   TRACE_SYMTAB("shdr:    ioff %llu nent %lu ent_szB %lu\n",
               shdr_mioff, shdr_mnent, shdr_ment_szB);
   for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
      const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
      if (map->rx)
         TRACE_SYMTAB("rx_map:  avma %#lx   size %lu  foff %ld\n",
                      map->avma, map->size, map->foff);
   }
   for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
      const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
      if (map->rw)
         TRACE_SYMTAB("rw_map:  avma %#lx   size %lu  foff %ld\n",
                      map->avma, map->size, map->foff);
   }

   if (phdr_mnent == 0
       || !ML_(img_valid)(mimg, phdr_mioff, phdr_mnent * phdr_ment_szB)) {
      ML_(symerr)(di, True, "Missing or invalid PE Program Header Table");
      goto out;
   }

   if (shdr_mnent == 0
       || !ML_(img_valid)(mimg, shdr_mioff, shdr_mnent * shdr_ment_szB)) {
      ML_(symerr)(di, True, "Missing or invalid PE Section Header Table");
      goto out;
   }

   TRACE_SYMTAB("shdr:    string table at %llu\n", strtab_mioff);

   /* TOPLEVEL */
   /* Look through the program header table, and:
      - find (or fake up) the .soname for this object.
   */
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("------ Examining the program headers ------\n");
   vg_assert(di->soname == NULL);

   {
      /* TOPLEVEL */
      DWORD prev_svma = 0;

      for (i = 0; i < shdr_mnent; i++) {
         IMAGE_SECTION_HEADER a_shdr;
         ML_(img_get)(&a_shdr, mimg, shdr_mioff + i * shdr_ment_szB, sizeof(a_shdr));

         if (a_shdr.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) continue;

         TRACE_SYMTAB("PT_LOAD[%ld]: p_vaddr %#lx (prev %#lx)\n",
                      i, (UWord)a_shdr.VirtualAddress, (UWord)prev_svma);
         TRACE_SYMTAB("PT_LOAD[%ld]:   p_offset %lu, p_filesz %lu,"
                      " perms %c%c%c\n",
                      i, (UWord)a_shdr.PointerToRawData, (UWord)a_shdr.SizeOfRawData,
                      a_shdr.Characteristics & IMAGE_SCN_MEM_READ ? 'r' : '-',
                      a_shdr.Characteristics & IMAGE_SCN_MEM_WRITE ? 'w' : '-',
                      a_shdr.Characteristics & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-');
         if (a_shdr.VirtualAddress < prev_svma) {
            ML_(symerr)(di, True, "PE Sections are not in ascending order");
            goto out;
         }
         prev_svma = a_shdr.VirtualAddress;

         DebugInfoMapping map;
         map.avma = (Addr)obj_avma + a_shdr.VirtualAddress;
         map.size = a_shdr.Misc.VirtualSize;
         map.foff = a_shdr.PointerToRawData;
         map.ro   = False;
         map.rx   = False;
         map.rw   = False;

         if (a_shdr.Misc.VirtualSize == 0) continue;

         DWORD rx_mask = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
         DWORD rw_mask = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
         DWORD mask = rx_mask | rw_mask;
         if ((a_shdr.Characteristics & mask) == rw_mask) {
            map.rw   = True;
            VG_(addToXA)(di->fsm.maps, &map);
            di->fsm.rw_map_count += 1;
            TRACE_SYMTAB("PT_LOAD[%ld]:   acquired as rw\n", i);
         }
         else if ((a_shdr.Characteristics & mask) == rx_mask) {
            map.rx   = True;
            VG_(addToXA)(di->fsm.maps, &map);
            di->fsm.have_rx_map = True;
            TRACE_SYMTAB("PT_LOAD[%ld]:   acquired as rx\n", i);
         }
         else if ((a_shdr.Characteristics & mask) == IMAGE_SCN_MEM_READ) {
            map.ro   = True;
            VG_(addToXA)(di->fsm.maps, &map);
            TRACE_SYMTAB("PT_LOAD[%ld]:   acquired as ro\n", i);
         } else {
            VG_(addToXA)(di->fsm.maps, &map);
            TRACE_SYMTAB("PT_LOAD[%ld]:   acquired\n", i);
         }
      } /* for (i = 0; i < phdr_Mnent; i++) ... */

      for (i = 0; i < shdr_mnent; i++) {
         IMAGE_SECTION_HEADER a_shdr;
         ML_(img_get)(&a_shdr, mimg, shdr_mioff + i * shdr_ment_szB, sizeof(a_shdr));

         /* Try to get the soname.  If there isn't one, use "NONE".
            The seginfo needs to have some kind of soname in order to
            facilitate writing redirect functions, since all redirect
            specifications require a soname (pattern). */
         if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".edata")
             && di->soname == NULL) {
            IMAGE_EXPORT_DIRECTORY a_edir;
            ML_(img_get)(&a_edir, mimg, a_shdr.PointerToRawData, sizeof(a_edir));

            if (a_edir.Name >= a_shdr.VirtualAddress
                && a_edir.Name + sizeof(DWORD)
                   <= a_shdr.VirtualAddress + a_shdr.Misc.VirtualSize) {
               di->soname = ML_(img_strdup)(mimg, "di.redi.1",
                                            a_shdr.PointerToRawData
                                            + a_edir.Name - a_shdr.VirtualAddress);
               TRACE_SYMTAB("Found soname = %s\n", di->soname);
            }
         }
      } /* for (i = 0; i < phdr_Mnent; i++) ... */
      /* TOPLEVEL */

   } /* examine the program headers (local scope) */

   /* TOPLEVEL */

   if (!di->fsm.have_rx_map) goto out;

   di->fsm.rw_map_count = di->fsm.rw_map_count ? di->fsm.rw_map_count : 1;

   /* If, after looking at all the program headers, we still didn't
      find a soname, add a fake one. */
   if (di->soname == NULL) {
      TRACE_SYMTAB("No soname found; using (fake) \"NONE\"\n");
      di->soname = ML_(dinfo_strdup)("di.redi.2", "NONE");
   }

   /* Now read the section table. */
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("------ Examining the section headers ------\n");
   for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
      const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
      if (map->rx)
         TRACE_SYMTAB("rx: at %#lx are mapped foffsets %ld .. %lu\n",
                      map->avma, map->foff, map->foff + map->size - 1 );
   }
   for (i = 0; i < VG_(sizeXA)(di->fsm.maps); i++) {
      const DebugInfoMapping* map = VG_(indexXA)(di->fsm.maps, i);
      if (map->rw)
         TRACE_SYMTAB("rw: at %#lx are mapped foffsets %ld .. %lu\n",
                      map->avma, map->foff, map->foff + map->size - 1 );
   }

   /* TOPLEVEL */
   /* Iterate over section headers */
   for (i = 0; i < shdr_mnent; i++) {
      IMAGE_SECTION_HEADER a_shdr;
      ML_(img_get)(&a_shdr, mimg, shdr_mioff + i * shdr_ment_szB, sizeof(a_shdr));

      HChar* name = (HChar*)a_shdr.Name;
      Addr   svma = obj_avma + a_shdr.VirtualAddress;
      OffT   foff = a_shdr.PointerToRawData;
      UWord  size = a_shdr.Misc.VirtualSize;

      TRACE_SYMTAB(" [sec %2ld]  foff %6ld .. %6lu  "
                   "  svma %p  name \"%s\"\n",
                   i, foff, (size == 0) ? foff : foff+size-1, (void *) svma, name);

      /* Ignore zero sized sections. */
      if (size == 0) {
         TRACE_SYMTAB("zero sized section \"%s\", ignoring\n", name);
         continue;
      }

#     define BAD(_secname)                                 \
         do { ML_(symerr)(di, True,                        \
                          "Can't make sense of " _secname  \
                          " section mapping");             \
              /* make sure we don't assert if we find */   \
              /* ourselves back in this routine later, */  \
              /* with the same di */                       \
              di->soname = NULL;                           \
              goto out;                                    \
         } while (0)

      /* Find avma-s for: .text .data .rodata .bss and .eh_frame */

      /* Accept .text where mapped as rx (code), even if zero-sized */
      if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".text")) {
         if (!di->text_present) {
            di->text_present = True;
            di->text_svma = svma;
            di->text_avma = svma;
            di->text_size = size;
            di->text_bias = 0;
            di->text_debug_svma = svma;
            di->text_debug_bias = 0;
            TRACE_SYMTAB("acquiring .text svma = %#lx .. %#lx\n",
                         di->text_svma,
                         di->text_svma + di->text_size - 1);
            TRACE_SYMTAB("acquiring .text avma = %#lx .. %#lx\n",
                         di->text_avma,
                         di->text_avma + di->text_size - 1);
            TRACE_SYMTAB("acquiring .text bias = %#lx debug %#lx\n",
                         (UWord)di->text_bias, (UWord)di->text_debug_bias);
         } else {
            BAD(".text");
         }
      }

      /* Accept .data where mapped as rw (data), even if zero-sized */
      if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".data")) {
         if (!di->data_present) {
            di->data_present = True;
            di->data_svma = svma;
            di->data_avma = svma;
            di->data_size = size;
            di->data_bias = 0;
            di->data_debug_svma = svma;
            di->data_debug_bias = 0;
            TRACE_SYMTAB("acquiring .data svma = %#lx .. %#lx\n",
                         di->data_svma,
                         di->data_svma + di->data_size - 1);
            TRACE_SYMTAB("acquiring .data avma = %#lx .. %#lx\n",
                         di->data_avma,
                         di->data_avma + di->data_size - 1);
            TRACE_SYMTAB("acquiring .data bias = %#lx\n", (UWord)di->data_bias);
         } else {
            BAD(".data");
         }
      }

      /* Accept .rodata where mapped as rx or rw (data), even if zero-sized */
      if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".rodata")) {
         if (!di->rodata_present) {
            di->rodata_svma = svma;
            di->rodata_avma = svma;
            di->rodata_size = size;
            di->rodata_debug_svma = svma;
            di->rodata_bias = 0;
            di->rodata_debug_bias = 0;
            di->rodata_present = True;
            TRACE_SYMTAB("acquiring .rodata svma = %#lx .. %#lx\n",
                         di->rodata_svma,
                         di->rodata_svma + di->rodata_size - 1);
            TRACE_SYMTAB("acquiring .rodata avma = %#lx .. %#lx\n",
                         di->rodata_avma,
                         di->rodata_avma + di->rodata_size - 1);
            TRACE_SYMTAB("acquiring .rodata bias = %#lx\n",
                         (UWord)di->rodata_bias);
         } else {
            BAD(".rodata");
         }
      }

      /* Accept .bss where mapped as rw (data), even if zero-sized */
      if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".bss")) {
         if (!di->bss_present) {
            di->bss_present = True;
            di->bss_svma = svma;
            di->bss_avma = svma;
            di->bss_size = size;
            di->bss_bias = 0;
            di->bss_debug_svma = svma;
            di->bss_debug_bias = 0;
            TRACE_SYMTAB("acquiring .bss svma = %#lx .. %#lx\n",
                         di->bss_svma,
                         di->bss_svma + di->bss_size - 1);
            TRACE_SYMTAB("acquiring .bss avma = %#lx .. %#lx\n",
                         di->bss_avma,
                         di->bss_avma + di->bss_size - 1);
            TRACE_SYMTAB("acquiring .bss bias = %#lx\n",
                         (UWord)di->bss_bias);
         } else {
            BAD(".bss");
         }
      }

      /* Accept .eh_frame where mapped as rx (code).  This seems to be
         the common case.  However, if that doesn't pan out, try for
         rw (data) instead.  We can handle up to N_EHFRAME_SECTS per
         PE object. */
      if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, ".eh_frame")) {
         if (di->n_ehframe < N_EHFRAME_SECTS) {
            di->ehframe_avma[di->n_ehframe] = svma;
            di->ehframe_size[di->n_ehframe] = size;
            TRACE_SYMTAB("acquiring .eh_frame avma = %#lx\n",
                         di->ehframe_avma[di->n_ehframe]);
            di->n_ehframe++;
         } else {
            BAD(".eh_frame");
         }
      }

#     undef BAD

   } /* iterate over the section headers */

   /* TOPLEVEL */
   if (0) VG_(printf)("YYYY text_: avma %#lx  size %lu  bias %#lx\n",
                      di->text_avma, di->text_size, (UWord)di->text_bias);

   if (VG_(clo_verbosity) > 2 || VG_(clo_trace_redir))
      VG_(message)(Vg_DebugMsg, "   svma %#010lx, avma %#010lx\n",
                                di->text_avma - di->text_bias,
                                di->text_avma );

   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("------ Finding image addresses "
                "for debug-info sections ------\n");

   /* TOPLEVEL */
   /* Find interesting sections, read the symbol table(s), read any
      debug information.  Each section is located either in the main,
      debug or alt-debug files, but only in one.  For each section,
      |section_escn| records which of |mimg|, |dimg| or |aimg| we
      found it in, along with the section's image offset and its size.
      The triples (section_img, section_ioff, section_szB) are
      consistent, in that they are always either (NULL,
      DiOffT_INVALID, 0), or refer to the same image, and are all
      assigned together. */
   {
      /* TOPLEVEL */
      DiSlice debuglink_escn      = DiSlice_INVALID; // .gnu_debuglink
      DiSlice debug_line_escn     = DiSlice_INVALID; // .debug_line   (dwarf2)
      DiSlice debug_info_escn     = DiSlice_INVALID; // .debug_info   (dwarf2)
      DiSlice debug_types_escn    = DiSlice_INVALID; // .debug_types  (dwarf4)
      DiSlice debug_abbv_escn     = DiSlice_INVALID; // .debug_abbrev (dwarf2)
      DiSlice debug_str_escn      = DiSlice_INVALID; // .debug_str    (dwarf2)
      DiSlice debug_line_str_escn = DiSlice_INVALID; // .debug_line_str(dwarf5)
      DiSlice debug_ranges_escn   = DiSlice_INVALID; // .debug_ranges (dwarf2)
      DiSlice debug_rnglists_escn = DiSlice_INVALID; // .debug_rnglists(dwarf5)
      DiSlice debug_loclists_escn = DiSlice_INVALID; // .debug_loclists(dwarf5)
      DiSlice debug_addr_escn     = DiSlice_INVALID; // .debug_addr   (dwarf5)
      DiSlice debug_str_offsets_escn = DiSlice_INVALID; // .debug_str_offsets (dwarf5)
      DiSlice debug_loc_escn      = DiSlice_INVALID; // .debug_loc    (dwarf2)
      DiSlice debug_frame_escn    = DiSlice_INVALID; // .debug_frame  (dwarf2)
      DiSlice debug_line_alt_escn = DiSlice_INVALID; // .debug_line   (alt)
      DiSlice debug_info_alt_escn = DiSlice_INVALID; // .debug_info   (alt)
      DiSlice debug_abbv_alt_escn = DiSlice_INVALID; // .debug_abbrev (alt)
      DiSlice debug_str_alt_escn  = DiSlice_INVALID; // .debug_str    (alt)
      DiSlice dwarf1d_escn        = DiSlice_INVALID; // .debug        (dwarf1)
      DiSlice dwarf1l_escn        = DiSlice_INVALID; // .line         (dwarf1)
      DiSlice ehframe_escn[N_EHFRAME_SECTS];         // .eh_frame (dwarf2)

      for (i = 0; i < N_EHFRAME_SECTS; i++)
         ehframe_escn[i] = DiSlice_INVALID;

      /* Find all interesting sections */

      UInt ehframe_mix = 0;

      /* What FIND does: it finds the section called _SEC_NAME.  The
         size of it is assigned to _SEC_SIZE.  The address of the
         section in the transiently loaded oimage is assigned to
         _SEC_IMG.  If the section is found, _POST_FX is executed
         after _SEC_NAME and _SEC_SIZE have been assigned to.

         Even for sections which are marked loadable, the client's
         ld.so may not have loaded them yet, so there is no guarantee
         that we can safely prod around in any such area).  Because
         the entire object file is transiently mapped aboard for
         inspection, it's always safe to inspect that area. */

      /* TOPLEVEL */
      /* Iterate over section headers (again) */
      for (i = 0; i < shdr_mnent; i++) {

#        define FINDX(_sec_name, _sec_escn, _post_fx) \
         do { \
            IMAGE_SECTION_HEADER a_shdr; \
            ML_(img_get)(&a_shdr, mimg, \
                         shdr_mioff + i * shdr_ment_szB, \
                         sizeof(a_shdr)); \
            if (0 == shdr_name_strcmp(mimg, &a_shdr, strtab_mioff, _sec_name)) { \
               _sec_escn.img  = mimg; \
               _sec_escn.ioff = (DiOffT)a_shdr.PointerToRawData; \
               _sec_escn.szB  = a_shdr.Misc.VirtualSize; \
               vg_assert(_sec_escn.img  != NULL); \
               vg_assert(_sec_escn.ioff != DiOffT_INVALID); \
               TRACE_SYMTAB( "%-18s:  ioff %llu .. %llu\n", \
                             _sec_name, (ULong)a_shdr.PointerToRawData, \
                             ((ULong)a_shdr.PointerToRawData) + a_shdr.Misc.VirtualSize - 1); \
               /* SHT_NOBITS sections have zero size in the file. */ \
               if (a_shdr.PointerToRawData + \
                      a_shdr.Misc.VirtualSize > ML_(img_real_size)(mimg)) { \
                  ML_(symerr)(di, True, \
                              "   section beyond image end?!"); \
                  goto out; \
               } \
               _post_fx; \
            } \
         } while (0);

         /* Version with no post-effects */
#        define FIND(_sec_name, _sec_escn) \
            FINDX(_sec_name, _sec_escn, /**/)

         /*      NAME                  ElfSec */
         FIND(   ".gnu_debuglink",     debuglink_escn)

         FIND(   ".debug_line",        debug_line_escn)
         if (!ML_(sli_is_valid)(debug_line_escn))
            FIND(".zdebug_line",       debug_line_escn)

         FIND(   ".debug_info",        debug_info_escn)
         if (!ML_(sli_is_valid)(debug_info_escn))
            FIND(".zdebug_info",       debug_info_escn)

         FIND(   ".debug_types",       debug_types_escn)
         if (!ML_(sli_is_valid)(debug_types_escn))
            FIND(".zdebug_types",      debug_types_escn)

         FIND(   ".debug_abbrev",      debug_abbv_escn)
         if (!ML_(sli_is_valid)(debug_abbv_escn))
            FIND(".zdebug_abbrev",     debug_abbv_escn)

         FIND(   ".debug_str",         debug_str_escn)
         if (!ML_(sli_is_valid)(debug_str_escn))
            FIND(".zdebug_str",        debug_str_escn)

         FIND(   ".debug_line_str",    debug_line_str_escn)
         if (!ML_(sli_is_valid)(debug_line_str_escn))
            FIND(".zdebug_line_str",   debug_line_str_escn)

         FIND(   ".debug_ranges",      debug_ranges_escn)
         if (!ML_(sli_is_valid)(debug_ranges_escn))
            FIND(".zdebug_ranges",     debug_ranges_escn)

         FIND(   ".debug_rnglists",    debug_rnglists_escn)
         if (!ML_(sli_is_valid)(debug_rnglists_escn))
            FIND(".zdebug_rnglists",   debug_rnglists_escn)

         FIND(   ".debug_loclists",    debug_loclists_escn)
         if (!ML_(sli_is_valid)(debug_loclists_escn))
            FIND(".zdebug_loclists",   debug_loclists_escn)

         FIND(   ".debug_loc",         debug_loc_escn)
         if (!ML_(sli_is_valid)(debug_loc_escn))
            FIND(".zdebug_loc",    debug_loc_escn)

         FIND(   ".debug_frame",       debug_frame_escn)
         if (!ML_(sli_is_valid)(debug_frame_escn))
            FIND(".zdebug_frame",      debug_frame_escn)

         FIND(   ".debug_addr",        debug_addr_escn)
         if (!ML_(sli_is_valid)(debug_addr_escn))
            FIND(".zdebug_addr",       debug_addr_escn)

         FIND(   ".debug_str_offsets", debug_str_offsets_escn)
         if (!ML_(sli_is_valid)(debug_str_offsets_escn))
            FIND(".zdebug_str_offsets", debug_str_offsets_escn)

         FIND(   ".debug",             dwarf1d_escn)
         FIND(   ".line",              dwarf1l_escn)

         FINDX(  ".eh_frame",          ehframe_escn[ehframe_mix],
               do { ehframe_mix++; vg_assert(ehframe_mix <= N_EHFRAME_SECTS);
               } while (0)
         )
         /* Comment_on_EH_FRAME_MULTIPLE_INSTANCES: w.r.t. .eh_frame
            multi-instance kludgery, how are we assured that the order
            in which we fill in ehframe_escn[] is consistent with the
            order in which we previously filled in di->ehframe_avma[]
            and di->ehframe_size[] ?  By the fact that in both cases,
            these arrays were filled in by iterating over the section
            headers top-to-bottom.  So both loops (this one and the
            previous one) encounter the .eh_frame entries in the same
            order and so fill in these arrays in a consistent order.
         */

#        undef FINDX
#        undef FIND
      } /* Iterate over section headers (again) */

      /* TOPLEVEL */
      /* Now, see if we can find a debuginfo object, and if so connect
         |dimg| to it. */
      vg_assert(dimg == NULL && aimg == NULL);

      /* Look for a debug image that matches either the build-id or
         the debuglink-CRC32 in the main image.  If the main image
         doesn't contain either of those then this won't even bother
         to try looking.  This looks in all known places, including
         the --extra-debuginfo-path if specified and on the
         --debuginfo-server if specified. */
      if (debuglink_escn.img != NULL) {
         UInt crc_offset
            = VG_ROUNDUP(ML_(img_strlen)(debuglink_escn.img,
                                         debuglink_escn.ioff)+1, 4);
         vg_assert(crc_offset + sizeof(UInt) <= debuglink_escn.szB);

         /* Extract the CRC from the debuglink section */
         UInt crc = ML_(img_get_UInt)(debuglink_escn.img,
                                      debuglink_escn.ioff + crc_offset);

         /* See if we can find a matching debug file */
         HChar* debuglink_str_m
            = ML_(img_strdup)(debuglink_escn.img,
                              "di.redi_dlk.1", debuglink_escn.ioff);
         dimg = ML_(find_debug_file)( di, di->fsm.filename, NULL,
                                      debuglink_str_m, crc, False );
         if (debuglink_str_m)
            ML_(dinfo_free)(debuglink_str_m);
      } else {
         /* See if we can find a matching debug file */
         dimg = ML_(find_debug_file)( di, di->fsm.filename, NULL,
                                      NULL, 0, False );
      }

      /* As a last-ditch measure, try looking for in the
         --extra-debuginfo-path and/or on the --debuginfo-server, but
         only in the case where --allow-mismatched-debuginfo=yes.
         This is dangerous in that (1) it gives no assurance that the
         debuginfo object matches the main one, and hence (2) we will
         very likely get an assertion in the code below, if indeed
         there is a mismatch.  Hence it is disabled by default
         (--allow-mismatched-debuginfo=no).  Nevertheless it's
         sometimes a useful way of getting out of a tight spot.

         Note that we're ignoring the name in the .gnu_debuglink
         section here, and just looking for a file of the same name
         either the extra-path or on the server. */
      if (dimg == NULL && VG_(clo_allow_mismatched_debuginfo)) {
         dimg = ML_(find_debug_file_ad_hoc)( di, di->fsm.filename );
      }

      /* TOPLEVEL */
      /* If we were successful in finding a debug image, pull various
         SVMA/bias/size and image addresses out of it. */
      if (dimg != NULL && is_pe_object_file_by_DiImage(dimg, False)) {

         /* Pull out and validate program header and section header info */
         IMAGE_DOS_HEADER dos_hdr_dimg;
         ML_(img_get)(&dos_hdr_dimg, dimg, 0, sizeof(dos_hdr_dimg));

         IMAGE_NT_HEADERS nt_hdr_dimg;
         ML_(img_get)(&nt_hdr_dimg, dimg, dos_hdr_dimg.e_lfanew, sizeof(nt_hdr_dimg));

         DiOffT   phdr_dioff        = dos_hdr_dimg.e_lfanew;
         UWord    phdr_dnent        = 1;
         UWord    phdr_dent_szB     = OFFSET_OF(IMAGE_NT_HEADERS, OptionalHeader)
                                      + nt_hdr_dimg.FileHeader.SizeOfOptionalHeader;

         DiOffT   shdr_dioff        = phdr_dioff + phdr_dent_szB;
         UWord    shdr_dnent        = nt_hdr_dimg.FileHeader.NumberOfSections;
         UWord    shdr_dent_szB     = sizeof(IMAGE_SECTION_HEADER);

         DiOffT   strtab_dioff = 0;
         if (nt_hdr_dimg.FileHeader.PointerToSymbolTable
             && nt_hdr_dimg.FileHeader.NumberOfSymbols)
         {
             strtab_dioff = nt_hdr_dimg.FileHeader.PointerToSymbolTable
                            + nt_hdr_dimg.FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL);
         }

         PtrdiffT obj_dsmva;
         if (nt_hdr_dimg.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            obj_dsmva = ((IMAGE_OPTIONAL_HEADER64 *)&nt_hdr_dimg.OptionalHeader)->ImageBase;
         else
            obj_dsmva = ((IMAGE_OPTIONAL_HEADER32 *)&nt_hdr_dimg.OptionalHeader)->ImageBase;

         Bool need_dwarf2, need_dwarf1;

         if (phdr_dnent == 0
             || !ML_(img_valid)(dimg, phdr_dioff,
                                phdr_dnent * phdr_dent_szB)) {
            ML_(symerr)(di, True,
                        "Missing or invalid PE Program Header Table"
                        " (debuginfo file)");
            goto out;
         }

         if (shdr_dnent == 0
             || !ML_(img_valid)(dimg, shdr_dioff,
                                shdr_dnent * shdr_dent_szB)) {
            ML_(symerr)(di, True,
                        "Missing or invalid PE Section Header Table"
                        " (debuginfo file)");
            goto out;
         }

         need_dwarf2 = (debug_info_escn.img == NULL);
         need_dwarf1 = (dwarf1d_escn.img == NULL);

         /* Find all interesting sections in the debug image */
         for (i = 0; i < shdr_dnent; i++) {

            /* Find debug svma and bias information for sections
               we found in the main file. */

#           define FIND(_sec, _seg) \
            do { \
               IMAGE_SECTION_HEADER a_shdr; \
               ML_(img_get)(&a_shdr, dimg, shdr_dioff + i * shdr_dent_szB,  \
                              sizeof(a_shdr)); \
               if (di->_sec##_present \
                   && 0 == shdr_name_strcmp(dimg, &a_shdr, strtab_dioff, "." #_sec)) { \
                  vg_assert(di->_sec##_size == a_shdr.Misc.VirtualSize); \
                  /* Assume we have a correct value for the main */ \
                  /* object's bias.  Use that to derive the debuginfo */ \
                  /* object's bias, by adding the difference in SVMAs */ \
                  /* for the corresponding sections in the two files. */ \
                  /* That should take care of all prelinking effects. */ \
                  di->_sec##_debug_svma = obj_dsmva + a_shdr.VirtualAddress; \
                  di->_sec##_debug_bias \
                     = di->_sec##_bias + \
                       di->_sec##_svma - di->_sec##_debug_svma; \
                  TRACE_SYMTAB("acquiring ." #_sec \
                               " debug svma = %#lx .. %#lx\n",       \
                               di->_sec##_debug_svma, \
                               di->_sec##_debug_svma + di->_sec##_size - 1); \
                  TRACE_SYMTAB("acquiring ." #_sec " debug bias = %#lx\n", \
                               (UWord)di->_sec##_debug_bias);           \
               } \
            } while (0);

            /* SECTION   SEGMENT */
            FIND(text,   rx)
            FIND(data,   rw)
            FIND(sdata,  rw)
            FIND(rodata, rw)
            FIND(bss,    rw)
            FIND(sbss,   rw)

#           undef FIND

            /* Same deal as previous FIND, except only do it for those
               sections which we didn't find in the main file. */

#           define FIND(_condition, _sec_name, _sec_escn) \
            do { \
               IMAGE_SECTION_HEADER a_shdr; \
               ML_(img_get)(&a_shdr, dimg, shdr_dioff + i * shdr_dent_szB,  \
                              sizeof(a_shdr)); \
               if (_condition \
                   && 0 == shdr_name_strcmp(dimg, &a_shdr, strtab_dioff, _sec_name)) { \
                  if (_sec_escn.img != NULL) { \
                     ML_(symerr)(di, True, \
                                 "   debuginfo section duplicates a" \
                                 " section in the main ELF file"); \
                     goto out; \
                  } \
                  _sec_escn.img  = dimg; \
                  _sec_escn.ioff = (DiOffT)a_shdr.PointerToRawData;  \
                  _sec_escn.szB  = a_shdr.Misc.VirtualSize; \
                  vg_assert(_sec_escn.img  != NULL); \
                  vg_assert(_sec_escn.ioff != DiOffT_INVALID); \
                  TRACE_SYMTAB( "%-18s: dioff %llu .. %llu\n", \
                                _sec_name, \
                                (ULong)a_shdr.PointerToRawData, \
                                ((ULong)a_shdr.PointerToRawData) + a_shdr.Misc.VirtualSize - 1); \
                  if (a_shdr.PointerToRawData \
                      + a_shdr.Misc.VirtualSize > ML_(img_real_size)(_sec_escn.img)) { \
                     ML_(symerr)(di, True, \
                                 "   section beyond image end?!"); \
                     goto out; \
                  } \
               } \
            } while (0);

            /* NEEDED?               NAME                 ElfSec */
            FIND(   need_dwarf2,     ".debug_line",       debug_line_escn)
            if (!ML_(sli_is_valid)(debug_line_escn))
               FIND(need_dwarf2,     ".zdebug_line",      debug_line_escn)

            FIND(   need_dwarf2,     ".debug_info",       debug_info_escn)
            if (!ML_(sli_is_valid)(debug_info_escn))
               FIND(need_dwarf2,     ".zdebug_info",      debug_info_escn)

            FIND(   need_dwarf2,     ".debug_types",      debug_types_escn)
            if (!ML_(sli_is_valid)(debug_types_escn))
               FIND(need_dwarf2,     ".zdebug_types",     debug_types_escn)

            FIND(   need_dwarf2,     ".debug_abbrev",     debug_abbv_escn)
            if (!ML_(sli_is_valid)(debug_abbv_escn))
               FIND(need_dwarf2,     ".zdebug_abbrev",    debug_abbv_escn)

            FIND(   need_dwarf2,     ".debug_str",        debug_str_escn)
            if (!ML_(sli_is_valid)(debug_str_escn))
               FIND(need_dwarf2,     ".zdebug_str",       debug_str_escn)

            FIND(   need_dwarf2,     ".debug_line_str",   debug_line_str_escn)
            if (!ML_(sli_is_valid)(debug_line_str_escn))
               FIND(need_dwarf2,     ".zdebug_line_str",  debug_line_str_escn)

            FIND(   need_dwarf2,     ".debug_ranges",     debug_ranges_escn)
            if (!ML_(sli_is_valid)(debug_ranges_escn))
               FIND(need_dwarf2,     ".zdebug_ranges",    debug_ranges_escn)

            FIND(   need_dwarf2,     ".debug_rnglists",   debug_rnglists_escn)
            if (!ML_(sli_is_valid)(debug_rnglists_escn))
               FIND(need_dwarf2,     ".zdebug_rnglists",  debug_rnglists_escn)

            FIND(   need_dwarf2,     ".debug_loclists",   debug_loclists_escn)
            if (!ML_(sli_is_valid)(debug_loclists_escn))
               FIND(need_dwarf2,     ".zdebug_loclists",  debug_loclists_escn)

            FIND(   need_dwarf2,     ".debug_loc",        debug_loc_escn)
            if (!ML_(sli_is_valid)(debug_loc_escn))
               FIND(need_dwarf2,     ".zdebug_loc",       debug_loc_escn)

            FIND(   need_dwarf2,     ".debug_frame",      debug_frame_escn)
            if (!ML_(sli_is_valid)(debug_frame_escn))
               FIND(need_dwarf2,     ".zdebug_frame",     debug_frame_escn)

            FIND(   need_dwarf2,     ".debug_addr",       debug_addr_escn)
            if (!ML_(sli_is_valid)(debug_addr_escn))
               FIND(need_dwarf2,     ".zdebug_addr",      debug_addr_escn)

            FIND(   need_dwarf2,     ".debug_str_offsets", debug_str_offsets_escn)
            if (!ML_(sli_is_valid)(debug_str_offsets_escn))
               FIND(need_dwarf2,     ".zdebug_str_offsets", debug_str_offsets_escn)

            FIND(   need_dwarf1,     ".debug",            dwarf1d_escn)
            FIND(   need_dwarf1,     ".line",             dwarf1l_escn)

#           undef FIND
         } /* Find all interesting sections */
      } /* do we have a debug image? */

      /* TOPLEVEL */
      /* Read symbols */
      if (!nt_hdr.FileHeader.PointerToSymbolTable)
         ML_(symerr)(di, False, "   object doesn't have a symbol table");
      else
         TRACE_SYMTAB( "\n--- Reading (PE, standard) (%u entries) ---\n",
                       nt_hdr.FileHeader.NumberOfSymbols );

      XArray *symbols = VG_(newXA)(ML_(dinfo_zalloc), "di.rpedi.1",
                                   ML_(dinfo_free), sizeof(IMAGE_SYMBOL));

      for (i = 0; i < nt_hdr.FileHeader.NumberOfSymbols; i++) {
         IMAGE_SYMBOL sym;
         ML_(img_get)(&sym, mimg, nt_hdr.FileHeader.PointerToSymbolTable
                                  + i * sizeof(IMAGE_SYMBOL), sizeof(sym));

         if (sym.SectionNumber && sym.SectionNumber <= nt_hdr.FileHeader.NumberOfSections
             && (ISFCN(sym.Type) || sym.StorageClass == IMAGE_SYM_CLASS_EXTERNAL
                 || sym.StorageClass == IMAGE_SYM_CLASS_LABEL))
            VG_(addToXA)(symbols, &sym);

         i += sym.NumberOfAuxSymbols;
      }

      VG_(setCmpFnXA)(symbols, cmp_IMAGE_SYMBOL_by_section_value);
      VG_(sortXA)(symbols);

      for (i = 0, n = VG_(sizeXA)(symbols); i < n; i++) {
         const IMAGE_SYMBOL* sym = VG_(indexXA)(symbols, i);
         const IMAGE_SYMBOL* nsym = i + 1 < n ? VG_(indexXA)(symbols, i + 1) : NULL;

         IMAGE_SECTION_HEADER a_shdr;
         ML_(img_get)(&a_shdr, mimg,
                      shdr_mioff + (sym->SectionNumber - 1) * shdr_ment_szB,
                      sizeof(a_shdr));

         SymAVMAs sym_avmas_really;
         Int    sym_size = 0;
         Bool   is_text = False, is_ifunc = ISFCN(sym->Type);
         Bool   is_global = sym->StorageClass == IMAGE_SYM_CLASS_LABEL ? False : True;
         sym_avmas_really.main = obj_avma + a_shdr.VirtualAddress + sym->Value;
         SET_TOCPTR_AVMA(sym_avmas_really, 0);
         SET_LOCAL_EP_AVMA(sym_avmas_really, 0);

         if (!VG_(strcmp)((char *)a_shdr.Name, ".text"))
         {
            sym_size = di->text_size - sym->Value;
            is_text = True;
         }
         if (!VG_(strcmp)((char *)a_shdr.Name, ".data"))
            sym_size = di->data_size - sym->Value;
         if (!VG_(strcmp)((char *)a_shdr.Name, ".rodata"))
            sym_size = di->rodata_size - sym->Value;
         if (!VG_(strcmp)((char *)a_shdr.Name, ".bss"))
            sym_size = di->bss_size - sym->Value;

         if (nsym && nsym->SectionNumber == sym->SectionNumber)
            sym_size = nsym->Value - sym->Value;

         DiSym  disym;
         VG_(memset)(&disym, 0, sizeof(disym));
         HChar* cstr;

         if (sym->N.Name.Short)
         {
            char buffer[9];
            VG_(memcpy)(buffer, sym->N.ShortName, 8);
            buffer[8] = 0;
            cstr = ML_(dinfo_strdup)("di.res__n.1", buffer);
         }
         else
            cstr = ML_(img_strdup)(mimg, "di.res__n.1",
                                   strtab_mioff + sym->N.Name.Long);

         disym.avmas  = sym_avmas_really;
         disym.pri_name  = ML_(addStr) ( di, cstr, -1 );
         disym.sec_names = NULL;
         disym.size      = sym_size;
         disym.isText    = is_text;
         disym.isIFunc   = is_ifunc;
         disym.isGlobal  = is_global;
         if (cstr) { ML_(dinfo_free)(cstr); cstr = NULL; }
         vg_assert(disym.pri_name);
         vg_assert(GET_TOCPTR_AVMA(disym.avmas) == 0);
         /* has no role except on ppc64be-linux */
         ML_(addSym) ( di, &disym );

         if (TRACE_SYMTAB_ENABLED) {
            TRACE_SYMTAB("    rec(%c) [%4ld]:          "
                         "  val %#010lx, sz %4d  %s\n",
                         is_text ? 't' : 'd',
                         i,
                         disym.avmas.main,
                         (Int)disym.size,
                         disym.pri_name
            );
            if (GET_LOCAL_EP_AVMA(disym.avmas) != 0) {
                     TRACE_SYMTAB("               local entry point %#010lx\n",
                                  GET_LOCAL_EP_AVMA(disym.avmas));
            }
         }
      }

      VG_(deleteXA)(symbols);

      /* TOPLEVEL */
      /* Read .eh_frame and .debug_frame (call-frame-info) if any.  Do
         the .eh_frame section(s) first. */
      vg_assert(di->n_ehframe >= 0 && di->n_ehframe <= N_EHFRAME_SECTS);
      for (i = 0; i < di->n_ehframe; i++) {
         /* see Comment_on_EH_FRAME_MULTIPLE_INSTANCES above for why
            this next assertion should hold. */
         vg_assert(ML_(sli_is_valid)(ehframe_escn[i]));
         vg_assert(ehframe_escn[i].szB == di->ehframe_size[i]);
         ML_(read_callframe_info_dwarf3)( di,
                                          ehframe_escn[i],
                                          di->ehframe_avma[i],
                                          True/*is_ehframe*/ );
      }
      if (ML_(sli_is_valid)(debug_frame_escn)) {
         ML_(read_callframe_info_dwarf3)( di,
                                          debug_frame_escn,
                                          0/*assume zero avma*/,
                                          False/*!is_ehframe*/ );
      }

      /* TOPLEVEL */
      /* jrs 2006-01-01: icc-8.1 has been observed to generate
         binaries without debug_str sections.  Don't preclude
         debuginfo reading for that reason, but, in
         read_unitinfo_dwarf2, do check that debugstr is non-NULL
         before using it. */
      if (ML_(sli_is_valid)(debug_info_escn)
          && ML_(sli_is_valid)(debug_abbv_escn)
          && ML_(sli_is_valid)(debug_line_escn)) {
         /* The old reader: line numbers and unwind info only */
         ML_(read_debuginfo_dwarf3) ( di,
                                      debug_info_escn,
                                      debug_types_escn,
                                      debug_abbv_escn,
                                      debug_line_escn,
                                      debug_str_escn,
                                      debug_str_alt_escn,
                                      debug_line_str_escn );
         /* The new reader: read the DIEs in .debug_info to acquire
            information on variable types and locations or inline info.
            But only if the tool asks for it, or the user requests it on
            the command line. */
         if (VG_(clo_read_var_info) /* the user or tool asked for it */
             || VG_(clo_read_inline_info)) {
            ML_(new_dwarf3_reader)(
               di, debug_info_escn,     debug_types_escn,
                   debug_abbv_escn,     debug_line_escn,
                   debug_str_escn,      debug_ranges_escn,
                   debug_rnglists_escn, debug_loclists_escn,
                   debug_loc_escn,      debug_info_alt_escn,
                   debug_abbv_alt_escn, debug_line_alt_escn,
                   debug_str_alt_escn,  debug_line_str_escn,
                   debug_addr_escn,     debug_str_offsets_escn
            );
         }
      }

   } /* "Find interesting sections, read the symbol table(s), read any debug
        information" (a local scope) */

   /* TOPLEVEL */
   res = True;

  out:
   {
      /* Last, but not least, detach from the image(s). */
      if (mimg) ML_(img_done)(mimg);
      if (dimg) ML_(img_done)(dimg);
      if (aimg) ML_(img_done)(aimg);

      return res;
   } /* out: */

   /* NOTREACHED */
}

#endif // defined(VGO_linux) || defined(VGO_darwin) || defined(VGO_solaris) || defined(VGO_freebsd)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
