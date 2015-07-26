/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-2008 Hex-Rays

 *      Type Information.
 *      Designed by Iouri Kharon <yjh@styx.cabel.net>
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _TYPEINF_HPP
#define _TYPEINF_HPP
#include <idp.hpp>
#include <name.hpp>
#pragma pack(push, 4)
//
// This file describes the type information records in IDA
// The recommended way of using type info is to use the tinfo_t class
// (search for #tinfo in this file)
//
// The type information is internally kept as an array of bytes terminated by 0.
//
// Items in brackets [] are optional and sometimes are omitted.
// type_t... means a sequence type_t bytes which defines a type.

// NOTE: to work with the types of instructions or data in the database,
// use get/set_tinfo2() and similar functions.

typedef uchar type_t;
typedef uchar p_string;   // pascal-like string: dt length, characters
typedef uchar p_list;     // several p_strings
struct til_t;             // type information library
class lexer_t;            // lexical analyzer
class argloc_t;           // argument location
class tinfo_t;            // type info object
struct func_type_data_t;

//------------------------------------------------------------------------
#define RESERVED_BYTE 0xFF  // multifunctional purpose
//------------------------------------------------------------------------
const type_t TYPE_BASE_MASK  = 0x0F;  // the low 4 bits define the basic type
const type_t TYPE_FLAGS_MASK = 0x30;  // type flags (they have different
                                      // meaning for each basic type)
const type_t TYPE_MODIF_MASK = 0xC0;  // modifiers
                                      // for BT_ARRAY see ATT3 below
                                      // BT_VOID can have them ONLY in 'void *'

const type_t TYPE_FULL_MASK = (TYPE_BASE_MASK | TYPE_FLAGS_MASK);

//----------------------------------------
// BASIC TYPES: unknown & void
const type_t  BT_UNK         = 0x00;    // unknown
const type_t  BT_VOID        = 0x01;    // void
// ATT1: BT_UNK and BT_VOID with non-zero type flags can be used in function
// (and struct) declarations to describe the function arguments or structure
// fields if only their size is known. They may be used in ida to describe
// the user input. For struct used also as 'single-field-alignment-suffix'
// [__declspec(align(x))] with TYPE_MODIF_MASK == TYPE_FULL_MASK.
const type_t    BTMT_SIZE0   = 0x00;    // BT_VOID - normal void; BT_UNK - don't use
const type_t    BTMT_SIZE12  = 0x10;    // size = 1  byte  if BT_VOID; 2 if BT_UNK
const type_t    BTMT_SIZE48  = 0x20;    // size = 4  bytes if BT_VOID; 8 if BT_UNK
const type_t    BTMT_SIZE128 = 0x30;    // size = 16 bytes if BT_VOID; unknown if BT_UNK
                                        // (IN struct alignment - see below)

// convenience definitions of unknown types:
const type_t BT_UNK_BYTE  = (BT_VOID | BTMT_SIZE12);   // 1 byte
const type_t BT_UNK_WORD  = (BT_UNK  | BTMT_SIZE12);   // 2 bytes
const type_t BT_UNK_DWORD = (BT_VOID | BTMT_SIZE48);   // 4 bytes
const type_t BT_UNK_QWORD = (BT_UNK  | BTMT_SIZE48);   // 8 bytes
const type_t BT_UNK_OWORD = (BT_VOID | BTMT_SIZE128);  // 16 bytes
const type_t BT_UNKNOWN   = (BT_UNK  | BTMT_SIZE128);  // unknown size - for parameters

//----------------------------------------
// BASIC TYPES: integers
const type_t  BT_INT8        = 0x02;    // __int8
const type_t  BT_INT16       = 0x03;    // __int16
const type_t  BT_INT32       = 0x04;    // __int32
const type_t  BT_INT64       = 0x05;    // __int64
const type_t  BT_INT128      = 0x06;    // __int128 (for alpha & future use)
const type_t  BT_INT         = 0x07;    // natural int. (size provided by idp module)
const type_t    BTMT_UNKSIGN = 0x00;    // unknown signness
const type_t    BTMT_SIGNED  = 0x10;    // signed
const type_t    BTMT_USIGNED = 0x20;    // unsigned
const type_t    BTMT_UNSIGNED = BTMT_USIGNED;
const type_t    BTMT_CHAR    = 0x30;    // BT_INT8:          char
                                        // BT_INT:           segment register
                                        // others BT_INT(x): don't use

// convenience definition:
const type_t BT_SEGREG    = (BT_INT | BTMT_CHAR);      // segment register

//----------------------------------------
// BASIC TYPE: bool
const type_t  BT_BOOL        = 0x08;    // bool
const type_t    BTMT_DEFBOOL = 0x00;    // size is model specific or unknown(?)
const type_t    BTMT_BOOL1   = 0x10;    // size 1byte
const type_t    BTMT_BOOL2   = 0x20;    // size 2bytes
const type_t    BTMT_BOOL4   = 0x30;    // size 4bytes

//----------------------------------------
// BASIC TYPE: float
const type_t  BT_FLOAT       = 0x09;    // float
const type_t    BTMT_FLOAT   = 0x00;    // float (4 bytes)
const type_t    BTMT_DOUBLE  = 0x10;    // double (8 bytes)
const type_t    BTMT_LNGDBL  = 0x20;    // long double (compiler specific)
const type_t    BTMT_SPECFLT = 0x30;    // if ph.use_tbyte() : ph.tbyte_size bytes
                                        // otherwise 2 bytes


const type_t _BT_LAST_BASIC  = BT_FLOAT; // the last basic type
                                        // all basic types may be followed by
                                        // [tah-typeattrs]

//----------------------------------------
// DERIVED TYPE: pointer
const type_t  BT_PTR         = 0x0A;    // *
                                        // has the following format:
                                        // [db sizeof(ptr)]; [tah-typeattrs]; type_t...
// ATT2: pointers to undeclared yet BT_COMPLEX types are prohibited.
const type_t    BTMT_DEFPTR  = 0x00;    // default for model
const type_t    BTMT_NEAR    = 0x10;    // near
const type_t    BTMT_FAR     = 0x20;    // far
const type_t    BTMT_CLOSURE = 0x30;    // if ptr to BT_FUNC - __closure
                                        // in this case next byte MUST be
                                        // RESERVED_BYTE, and after it - BT_FUNC
                                        // else the next byte contains sizeof(ptr)
                                        // allowed values are 1-ph.max_ptr_size.
                                        // if value is bigger than ph.max_ptr_size,
                                        // based_ptr_name_and_size() is called
                                        // (see below) to find out the typeinfo

//----------------------------------------
// DERIVED TYPE: array
const type_t  BT_ARRAY       = 0x0B;    // []
// ATT3: for BT_ARRAY the BTMT_... flags must be equivalent to BTMT_... of elements
const type_t    BTMT_NONBASED= 0x10;    // if set
                                        //    array base==0
                                        //    format: dt num_elem; [tah-typeattrs]; type_t...
                                        //    if num_elem==0 then the array size is unknown
                                        // else
                                        //    format: da num_elem, base; [tah-typeattrs]; type_t...
const type_t    BTMT_ARRESERV= 0x20;    // reserved bit


//----------------------------------------
// DERIVED TYPE: function
const type_t  BT_FUNC        = 0x0C;    // ()
                                        // format:
        //  optional: CM_CC_SPOILED | num_of_spoiled_regs
        //            if num_of_spoiled_reg == 15:
        //              next byte is function attribute byte (see BFA_...)
        //            else:
        //              num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)
        //  cm_t... calling convention and memory model
        //  [tah-typeattrs];
        //  type_t... return type;
        //  [serialized argloc_t of returned value (if CM_CC_SPECIAL{PE} && !return void);
        //  if !CM_CC_VOIDARG:
        //    dt N (N=number of parameters)
        //    if ( N == 0 )
        //      if CM_CC_ELLIPSIS or CM_CC_SPECIALE
        //        func(...)
        //      else
        //        parameters are unknown
        //    else
        //      N records:
        //        type_t... (i.e. type of each parameter)
        //        [serialized argloc_t (if CM_CC_SPECIAL{PE})] (i.e. place of each parameter)
        //        [FAH_BYTE + de(funcarg_t::flags)]

// Ellipsis is not taken into account in the number of parameters
// ATT4: the return type can not be BT_ARRAY or BT_FUNC

const type_t    BTMT_DEFCALL  = 0x00;   // call method - default for model or unknown
const type_t    BTMT_NEARCALL = 0x10;   // function returns by retn
const type_t    BTMT_FARCALL  = 0x20;   // function returns by retf
const type_t    BTMT_INTCALL  = 0x30;   // function returns by iret
                                        // in this case cc MUST be 'unknown'

//----------------------------------------
// DERIVED TYPE: complex types
const type_t  BT_COMPLEX     = 0x0D;    // struct/union/enum/typedef
                                        // format:
                                        //   [dt N (N=field count) if !BTMT_TYPEDEF]
                                        //   if N == 0:
                                        //     p_string name (unnamed types have names "anon_...")
                                        //     [sdacl-typeattrs];
                                        //   else, for struct & union:
                                        //     if N == 0x7FFE   // Support for high (i.e., > 4095) members count
                                        //       N = get_de()
                                        //     ALPOW = N & 0x7
                                        //     MCNT = N >> 3
                                        //     if MCNT == 0
                                        //       empty struct
                                        //     if ALPOW == 0
                                        //       ALIGN = get_default_align()
                                        //     else
                                        //       ALIGN = (1 << (ALPOW - 1))
                                        //     [sdacl-typeattrs];
                                        //   else, for enums:
                                        //     if N == 0x7FFE   // Support for high enum entries count.
                                        //       N = get_de()
                                        //     [tah-typeattrs];
                                        //
const type_t    BTMT_STRUCT  = 0x00;    //     struct:
                                        //       MCNT records: type_t; [sdacl-typeattrs];
const type_t    BTMT_UNION   = 0x10;    //     union:
                                        //       MCNT records: type_t...
const type_t    BTMT_ENUM    = 0x20;    //     enum:
                                        //       next byte bte_t (see below)
                                        //       N records: de delta(s)
                                        //                  OR
                                        //                  blocks (see below)
const type_t    BTMT_TYPEDEF = 0x30;    // named reference
                                        //   always p_string name

const type_t BT_BITFIELD     = 0x0E;    //bitfield (only in struct)
                                        //['bitmasked' enum see below]
                                        // next byte is dt
                                        //  ((size in bits << 1) | (unsigned ? 1 : 0))
const type_t BTMT_BFLDI8    = 0x00;     // __int8
const type_t BTMT_BFLDI16   = 0x10;     // __int16
const type_t BTMT_BFLDI32   = 0x20;     // __int32
const type_t BTMT_BFLDI64   = 0x30;     // __int64


const type_t BT_RESERVED     = 0x0F;        //RESERVED


//------------------------------------------------------------------------
// TYPE MODIFIERS:
// "const volatile" types are forbidden

const type_t  BTM_CONST      = 0x40;    // const
const type_t  BTM_VOLATILE   = 0x80;    // volatile

//------------------------------------------------------------------------
// special enum definitions
typedef uchar bte_t;

const bte_t   BTE_SIZE_MASK = 0x07;   // storage size
                                        // if == 0 get_default_enum_size()
                                        // else 1 << (n -1) = 1,2,4...64
const bte_t   BTE_RESERVED    = 0x08; // must be 0, in order to distinsuish
                                      // from a tah-byte
const bte_t   BTE_BITFIELD    = 0x10; // 'subarrays'. In this case ANY record
                                      // has the following format:
                                      //   'de' mask (has name)
                                      //   'dt' cnt
                                      //   cnt records of 'de' values
                                      //      (cnt CAN be 0)
                                      // ATT: delta for ALL subsegment is ONE
const bte_t   BTE_OUT_MASK  = 0x60;   // output style mask
const bte_t   BTE_HEX         = 0x00; // hex
const bte_t   BTE_CHAR        = 0x20; // char or hex
const bte_t   BTE_SDEC        = 0x40; // signed decimal
const bte_t   BTE_UDEC        = 0x60; // unsigned decimal
const bte_t   BTE_ALWAYS    = 0x80;   // this bit MUST be present

//------------------------------------------------------------------------
// convenience shortcuts
const type_t BTF_BYTE    = BT_UNK_BYTE;
const type_t BTF_UNK     = BT_UNKNOWN;
const type_t BTF_VOID    = BT_VOID | BTMT_SIZE0;

const type_t BTF_INT8    = BT_INT8 | BTMT_SIGNED;
const type_t BTF_CHAR    = BT_INT8 | BTMT_CHAR;
const type_t BTF_UCHAR   = BT_INT8 | BTMT_USIGNED;
const type_t BTF_UINT8   = BT_INT8 | BTMT_USIGNED;

const type_t BTF_INT16   = BT_INT16 | BTMT_SIGNED;
const type_t BTF_UINT16  = BT_INT16 | BTMT_USIGNED;

const type_t BTF_INT32   = BT_INT32 | BTMT_SIGNED;
const type_t BTF_UINT32  = BT_INT32 | BTMT_USIGNED;

const type_t BTF_INT64   = BT_INT64 | BTMT_SIGNED;
const type_t BTF_UINT64  = BT_INT64 | BTMT_USIGNED;

const type_t BTF_INT128   = BT_INT128 | BTMT_SIGNED;
const type_t BTF_UINT128  = BT_INT128 | BTMT_USIGNED;

const type_t BTF_INT     = BT_INT | BTMT_UNKSIGN;
const type_t BTF_UINT    = BT_INT | BTMT_USIGNED;
const type_t BTF_SINT    = BT_INT | BTMT_SIGNED;

const type_t BTF_BOOL    = BT_BOOL;

const type_t BTF_FLOAT   = BT_FLOAT | BTMT_FLOAT;
const type_t BTF_DOUBLE  = BT_FLOAT | BTMT_DOUBLE;
const type_t BTF_LDOUBLE = BT_FLOAT | BTMT_LNGDBL;
const type_t BTF_TBYTE   = BT_FLOAT | BTMT_SPECFLT;

const type_t BTF_STRUCT  = BT_COMPLEX | BTMT_STRUCT;
const type_t BTF_UNION   = BT_COMPLEX | BTMT_UNION;
const type_t BTF_ENUM    = BT_COMPLEX | BTMT_ENUM;
const type_t BTF_TYPEDEF = BT_COMPLEX | BTMT_TYPEDEF;


//------------------------------------------------------------------------
// convenience functions:

inline bool is_type_const(type_t t)   { return (t & BTM_CONST) != 0; }
inline bool is_type_volatile(type_t t){ return (t & BTM_VOLATILE) != 0; }

inline type_t get_base_type(type_t t) { return (t & TYPE_BASE_MASK); }
inline type_t get_type_flags(type_t t){ return (t & TYPE_FLAGS_MASK); }
inline type_t get_full_type(type_t t) { return (t & TYPE_FULL_MASK); }

// is the type_t the last byte of type declaration?
// (there are no additional bytes after a basic type)
inline bool is_typeid_last(type_t t)  { return(get_base_type(t) <= _BT_LAST_BASIC); }

inline bool is_type_partial(type_t t) { return(get_base_type(t) <= BT_VOID) && get_type_flags(t) != 0; }
inline bool is_type_void(type_t t)    { return(get_full_type(t) == BTF_VOID); }
inline bool is_type_unknown(type_t t) { return(get_full_type(t) == BT_UNKNOWN); }

inline bool is_type_ptr(type_t t)     { return(get_base_type(t) == BT_PTR); }
inline bool is_type_complex(type_t t) { return(get_base_type(t) == BT_COMPLEX); }
inline bool is_type_func(type_t t)    { return(get_base_type(t) == BT_FUNC); }
inline bool is_type_array(type_t t)   { return(get_base_type(t) == BT_ARRAY); }

inline bool is_type_typedef(type_t t) { return(get_full_type(t) == BTF_TYPEDEF); }
// struct/union/enum
inline bool is_type_sue(type_t t)     { return is_type_complex(t) && !is_type_typedef(t); }
inline bool is_type_struct(type_t t)  { return(get_full_type(t) == BTF_STRUCT); }
inline bool is_type_union(type_t t)   { return(get_full_type(t) == BTF_UNION); }
inline bool is_type_struni(type_t t)  { return(is_type_struct(t) || is_type_union(t)); }
inline bool is_type_enum(type_t t)    { return(get_full_type(t) == BTF_ENUM); }

inline bool is_type_bitfld(type_t t)  { return(get_base_type(t) == BT_BITFIELD); }

inline bool is_type_int(type_t bt) { bt = get_base_type(bt); return bt >= BT_INT8 && bt <= BT_INT; }

inline bool is_type_int128(type_t t)
{
  return get_full_type(t) == (BT_INT128|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT128|BTMT_SIGNED);
}

inline bool is_type_int64(type_t t)
{
  return get_full_type(t) == (BT_INT64|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT64|BTMT_SIGNED);
}

inline bool is_type_int32(type_t t)
{
  return get_full_type(t) == (BT_INT32|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT32|BTMT_SIGNED);
}

inline bool is_type_int16(type_t t)
{
  return get_full_type(t) == (BT_INT16|BTMT_UNKSIGN)
      || get_full_type(t) == (BT_INT16|BTMT_SIGNED);
}

inline bool is_type_char(type_t t) // chars are signed by default(?)
{
  return get_full_type(t) == (BT_INT8|BTMT_CHAR)
      || get_full_type(t) == (BT_INT8|BTMT_SIGNED);
}

/// Is a pointer, array, or function type?
inline bool is_type_paf(type_t t)
{
  t = get_base_type(t);
  return t >= BT_PTR && t <= BT_FUNC;
}

// Is a pointer or array type?
inline bool is_type_ptr_or_array(type_t t) { t = get_base_type(t); return t == BT_PTR || t == BT_ARRAY; }
// Is a floating point type?
inline bool is_type_floating(type_t t){return get_base_type(t) == BT_FLOAT; } // any floating type
// Is an integral type (char/short/int/long/bool)?
inline bool is_type_integral(type_t t) { return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_BOOL; }
// Is an extended integral type? (integral or enum)
inline bool is_type_ext_integral(type_t t) { return is_type_integral(t) || is_type_enum(t); }
// Is an arithmetic type? (floating or integral)
inline bool is_type_arithmetic(type_t t) { return get_full_type(t) > BT_VOID && get_base_type(t) <= BT_FLOAT; }
// Is an extended arithmetic type? (arithmetic or enum)
inline bool is_type_ext_arithmetic(type_t t) { return is_type_arithmetic(t) || is_type_enum(t); }

inline bool is_type_uint(type_t t)   { return get_full_type(t) == BTF_UINT; }
inline bool is_type_uchar(type_t t)  { return get_full_type(t) == BTF_UCHAR; }
inline bool is_type_uint16(type_t t) { return get_full_type(t) == BTF_UINT16; }
inline bool is_type_uint32(type_t t) { return get_full_type(t) == BTF_UINT32; }
inline bool is_type_uint64(type_t t) { return get_full_type(t) == BTF_UINT64; }
inline bool is_type_uint128(type_t t){ return get_full_type(t) == BTF_UINT128; }
inline bool is_type_ldouble(type_t t){ return get_full_type(t) == BTF_LDOUBLE; }
inline bool is_type_double(type_t t) { return get_full_type(t) == BTF_DOUBLE; }
inline bool is_type_float(type_t t)  { return get_full_type(t) == BTF_FLOAT; }
inline bool is_type_bool(type_t t)   { return get_base_type(t) == BT_BOOL; }

// The type attributes start with the type attribute header byte (TAH)
#define MAX_DECL_ALIGN  0x000F
#define TAH_HASATTRS    0x0010  // has extended attributes

// type attributes for udts
#define TAUDT_UNALIGNED 0x0040  // struct: unaligned struct
#define TAUDT_MSSTRUCT  0x0020  // struct: gcc msstruct attribute
#define TAUDT_CPPOBJ    0x0080  // struct: a c++ object, not simple pod type

// type attributes for udt fields
#define TAFLD_BASECLASS 0x0020  // field: do not include but inherit from the current field
#define TAFLD_UNALIGNED 0x0040  // field: unaligned field
#define TAFLD_VIRTBASE  0x0080  // field: virtual base (not supported yet)

// type attributes for pointers, one of 3 values:
#define TAPTR_PTR32     0x0020  // ptr: __ptr32
#define TAPTR_PTR64     0x0040  // ptr: __ptr64
#define TAPTR_RESTRICT  0x0060  // ptr: __restrict

// type attributes for enums
#define TAENUM_64BIT    0x0020  // enum: store 64-bit values

#define TAH_ALL         0x00F0  // all defined bits

#define TAH_BYTE        0xFE    // type attribute header byte
#define FAH_BYTE        0xFF    // function argument attribute header byte

// The TAH byte (type attribute header byte) denotes the start of type attributes.
// (see "tah-typeattrs" in the type bit definitions)
inline bool is_tah_byte(type_t t)
{
  return t == TAH_BYTE;
}

// The first sdacl byte has the following format: 11xx000x
// The sdacl bytes are appended to udt fields. They indicate the start of type
// attributes (as the tah-bytes do). The sdacl bytes are used in the udt
// headers instead of the tah-byte. This is done for compatibility with old
// databases, they were already using sdacl bytes in udt headers and as udt
// field postfixes.
// (see "sdacl-typeattrs" in the type bit definitions)
inline bool is_sdacl_byte(type_t t)
{
  return ((t & ~TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID;
}

#ifndef SWIG
inline bool operator < (const bytevec_t &v1, const bytevec_t &v2)
{
  int n = qmin(v1.size(), v2.size());
  for ( int i=0; i < n; i++ )
  {
    uchar k1 = v1[i];
    uchar k2 = v2[i];
    if ( k1 < k2 )
      return true;
    if ( k1 > k2 )
      return false;
  }
  return v1.size() < v2.size();
}
#endif

// Extended type attributes.
struct type_attr_t
{
  qstring key;          // one symbol keys are reserved to be used by the kernel
                        // the ones starting with an underscore are reserved too
  bytevec_t value;
#ifndef SWIG
  bool operator < (const type_attr_t &r) const { return key < r.key; }
  bool operator >= (const type_attr_t &r) const { return !(*this < r); }
#endif
};
DECLARE_TYPE_AS_MOVABLE(type_attr_t);

// this vector must be sorted by keys
typedef qvector<type_attr_t> type_attrs_t;

typedef int type_sign_t;
const type_sign_t
  no_sign       = 0,    // or unknown
  type_signed   = 1,    // signed type
  type_unsigned = 2;    // unsigned type

//---------------------------------------------------------------------------
idaman bool ida_export get_de(const type_t **ptype, uint32 *val);
idaman bool ida_export append_argloc(qtype *out, const argloc_t &vloc);
idaman bool ida_export extract_argloc(const type_t **ptype, argloc_t *vloc, bool is_retval);

idaman bool ida_export is_restype_const  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_void   (const til_t *til, const type_t *type); // really void?
idaman bool ida_export is_restype_ptr    (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_func   (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_array  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_complex(const til_t *til, const type_t *type);
idaman bool ida_export is_restype_struct (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_union  (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_struni (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_enum   (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_bitfld (const til_t *til, const type_t *type);
idaman bool ida_export is_restype_floating(const til_t *til, const type_t *type);

idaman type_t ida_export get_int_type_bit(int size); // size should be 1,2,4,8,16
idaman type_t ida_export get_unk_type_bit(int size); // size should be 1,2,4,8,16

//------------------------------------------------------------------------
// Type Information Library
//------------------------------------------------------------------------

struct til_t
{
  char *name;           // short file name (without path and extension)
  char *desc;           // human readable til description
  int nbases;           // number of base tils
  struct til_t **base;  // tils that our til is based on
  uint32 flags;
#define TIL_ZIP 0x0001  // pack buckets using zip
#define TIL_MAC 0x0002  // til has macro table
#define TIL_ESI 0x0004  // extended sizeof info (short, long, longlong)
#define TIL_UNI 0x0008  // universal til for any compiler
#define TIL_ORD 0x0010  // type ordinal numbers are present
#define TIL_ALI 0x0020  // type aliases are present (this bit is used only on the disk)
#define TIL_MOD 0x0040  // til has been modified, should be saved
#define TIL_STM 0x0080  // til has extra streams
  inline bool is_dirty(void) const { return (flags & TIL_MOD) != 0; }
  inline void set_dirty(void) { flags |= TIL_MOD; }
  compiler_info_t cc;
  struct til_bucket_t *syms;
  struct til_bucket_t *types;
  struct til_bucket_t *macros;
  int nrefs;            // number of references to the til
  int nstreams;         // number of extra streams
  struct til_stream_t **streams;
  til_t(void) { memset(this, 0, sizeof(*this)); }
};

// Initialize a til
idaman til_t *ida_export new_til(const char *name, const char *desc);

// Add a base til
// bases - comma separated list of til names
// returns: !=0-ok, otherwise the error message is in errbuf
int add_base_tils(til_t *ti, const char *tildir, const char *bases, char *errbuf, size_t bufsize);

#define TIL_ADD_FAILED  0
#define TIL_ADD_OK      1       // some tils were added
#define TIL_ADD_ALREADY 2       // the base til was already added


// Load til from a file
// tildir: directory where to load the til from. NULL means current directory.
// name: filename of the til. If it's an absolute path, tildir is ignored.
// NB: the file extension is forced to .til
// Failure to load base tils are reported into 'errbuf'. They do not prevent
// loading of the main til.
// returns: !NULL-ok, otherwise the error message is in errbuf

idaman til_t *ida_export load_til(const char *tildir, const char *name, char *errbuf, size_t bufsize);


// Sort til (use after modifying it)
// returns false - no memory or bad parameter

idaman bool ida_export sort_til(til_t *ti);


// Collect garbage in til. Must be called before storing the til
// Returns true is freed some memory

idaman bool ida_export compact_til(til_t *ti);


// Store til to a file
// If the til contains garbage, it will be collected before storing the til.
// Your plugin should call compact_til() before calling store_til()
// tildir: directory where to store the til. NULL means current directory.
// name: filename of the til. If it's an absolute path, tildir is ignored.
// NB: the file extension is forced to .til

idaman bool ida_export store_til(til_t *ti, const char *tildir, const char *name);


// Free memory allocated by til

idaman void ida_export free_til(til_t *ti);


// Get human-readable til description

idaman til_t *ida_export load_til_header(const char *tildir, const char *name, char *errbuf, size_t bufsize);


//------------------------------------------------------------------------
// CM (calling convention & model)

// default pointer size
const cm_t CM_MASK = 0x03;
const cm_t  CM_UNKNOWN   = 0x00;
const cm_t  CM_N8_F16    = 0x01;  // 1: near 1byte,  far 2bytes
const cm_t  CM_N64       = 0x01;  // if sizeof(int)>2 then ptr size is 8bytes
const cm_t  CM_N16_F32   = 0x02;  // 2: near 2bytes, far 4bytes
const cm_t  CM_N32_F48   = 0x03;  // 4: near 4bytes, far 6bytes
// model
const cm_t CM_M_MASK = 0x0C;
const cm_t  CM_M_NN      = 0x00;  // small:   code=near, data=near (or unknown if CM_UNKNOWN)
const cm_t  CM_M_FF      = 0x04;  // large:   code=far, data=far
const cm_t  CM_M_NF      = 0x08;  // compact: code=near, data=far
const cm_t  CM_M_FN      = 0x0C;  // medium:  code=far, data=near

inline bool is_code_far(cm_t cm) { return((cm & 4) != 0); }
inline bool is_data_far(cm_t cm) { return((cm &= CM_M_MASK) && cm != CM_M_FN); }

// calling convention
const cm_t CM_CC_MASK = 0xF0;
const cm_t  CM_CC_INVALID  = 0x00;  // this value is invalid
const cm_t  CM_CC_UNKNOWN  = 0x10;  // unknown calling convention
const cm_t  CM_CC_VOIDARG  = 0x20;  // function without arguments
                                    // ATT7: if has other cc and argnum == 0,
                                    // represent as f() - unknown list
const cm_t  CM_CC_CDECL    = 0x30;  // stack
const cm_t  CM_CC_ELLIPSIS = 0x40;  // cdecl + ellipsis
const cm_t  CM_CC_STDCALL  = 0x50;  // stack, purged
const cm_t  CM_CC_PASCAL   = 0x60;  // stack, purged, reverse order of args
const cm_t  CM_CC_FASTCALL = 0x70;  // stack, purged (x86), first args are in regs (compiler-dependent)
const cm_t  CM_CC_THISCALL = 0x80;  // stack, purged (x86), first arg is in reg (compiler-dependent)
const cm_t  CM_CC_MANUAL   = 0x90;  // special case for compiler specific
const cm_t  CM_CC_SPOILED  = 0xA0;  // This is NOT a cc! Mark of __spoil record
                                    // the low nibble is count and after n {spoilreg_t}
                                    // present real cm_t byte. if n == 15,
                                    // the next byte is the function attribute byte.
const cm_t  CM_CC_RESERVE4 = 0xB0;
const cm_t  CM_CC_RESERVE3 = 0xC0;
const cm_t  CM_CC_SPECIALE = 0xD0;  // CM_CC_SPECIAL with ellipsis
const cm_t  CM_CC_SPECIALP = 0xE0;  // Equal to CM_CC_SPECIAL, but with purged stack
const cm_t  CM_CC_SPECIAL  = 0xF0;  // locations of all arguments and the return
                                    // value are present in the function declaration.

// Function attribute byte. Zero attribute byte is forbidden
// See also FTI_... constants
const type_t BFA_NORET  = 0x01;    // __noreturn
const type_t BFA_PURE   = 0x02;    // __pure
const type_t BFA_HIGH   = 0x04;    // high level prototype (with possibly hidden args)
const type_t BFA_STATIC = 0x08;    // static
const type_t BFA_VIRTUAL= 0x10;    // virtual

#ifndef SWIG
#define ARGLOC_HELPER_DEFINITIONS(decl) \
decl void ida_export copy_argloc(argloc_t *dst, const argloc_t *src); \
decl void ida_export cleanup_argloc(argloc_t *vloc);\
decl int ida_export compare_arglocs(const argloc_t &a, const argloc_t &b);
#else
#define ARGLOC_HELPER_DEFINITIONS(decl)
#endif // SWIG
ARGLOC_HELPER_DEFINITIONS(idaman)

typedef int argloc_type_t;
const argloc_type_t
  ALOC_NONE   = 0,  // none
  ALOC_STACK  = 1,  // stack offset
  ALOC_DIST   = 2,  // distributed (scattered)
  ALOC_REG1   = 3,  // one register (and offset within it)
  ALOC_REG2   = 4,  // register pair
  ALOC_RREL   = 5,  // register relative
  ALOC_STATIC = 6,  // global address
  ALOC_CUSTOM = 7;  // custom argloc (7 or higher)

struct rrel_t
{
  sval_t off;   // displacement from the address pointed by the register
  int reg;      // register index (into ph.regNames)
};

class scattered_aloc_t;

// Description of custom argloc. Custom arglocs can be added by plugins in order
// to describe the locations unsupported by the ida kernel.
struct custloc_desc_t
{
  size_t cbsize;                        // size of this structure
  const char *name;                     // name of the custom argloc type. must be unique
  void (idaapi *copy)(argloc_t *empty_dst, const argloc_t &src);
  void (idaapi *cleanup)(argloc_t *loc);// may be NULL
  bool (idaapi *verify)(                // may be NULL
        const argloc_t &loc,
        int size,
        const areaset_t *gaps,
        bool part_of_scattered);
  int (idaapi *compare)(const argloc_t &a, const argloc_t &b);
  // return textual description of the location (not the value at the location!)
  size_t (idaapi *print)(
        char *buf,
        size_t bufsize,
        const argloc_t &loc,
        asize_t size,
        int praloc_flags); // PRALOC_...
  // dereference the struct/union pointed by 'strloc': take member at offset 'off'
  // (or use the field name), improve member 'tif' if necessary
  bool (idaapi *deref_field)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &strloc,
        const tinfo_t &struct_tif,
        asize_t off,
        const qstring &name);
  // dereference the array pointed by 'arrloc': take member number 'n'
  // (element size is 'elsize'), improve member 'tif' if necessary
  bool (idaapi *deref_array)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &arrloc,
        const tinfo_t &array_tif,
        asize_t n,
        asize_t elsize);
  // dereference the pointer at 'loc': retrieve location of the pointed object,
  // improve 'tif' of the pointed object if necessary
  bool (idaapi *deref_ptr)(
        argloc_t *out,
        tinfo_t *tif,
        const argloc_t &ptrloc);
  // read the pointer at 'loc': retrieve value of a simple object
  // the object value must fit value_u.
  bool (idaapi *read_value)(
        value_u *value,
        const argloc_t &loc,
        int size,
        const tinfo_t &tif);
  // update value at 'loc'. if idcval is VT_LONG/VT_INT64/VT_FLOAT, the value
  // in native format is copied to 'scalar_value' for your convenience. otherwise
  // please use 'idcval' and not 'scalar_value'.
  bool (idaapi *write_value)(
        const argloc_t &loc,
        const idc_value_t &idcval,
        const value_u &scalar_value,
        int size,
        qstring *errbuf);
  // calc max natural string length at 'loc' in the debugged process memory
  asize_t (idaapi *calc_string_length)(
        const argloc_t &loc,
        const tinfo_t &string_tif);
  // retrieve string at 'loc' from the debugged process memory,
  // returns quoted string value
  bool (idaapi *get_string)(
        qstring *out,
        tinfo_t *elem_tif,
        const argloc_t &loc,
        const tinfo_t &string_tif,
        size_t len);
  // retrieve size of array at 'loc' (number of elements)
  asize_t (idaapi *guess_array_size)(
        const argloc_t &loc,
        const tinfo_t &array_tif);
  // retrieve type of the object at 'loc'
  bool (idaapi *get_tinfo)(
        tinfo_t *out,
        const argloc_t &loc);
  // calculate the number of children for the given location
  // (arrays, structs, ptrs may have children and therefore be expanded)
  int (idaapi *calc_number_of_children)(const argloc_t &loc, const tinfo_t &tif);
  // get string containing a printable representation of the pointer at 'loc'.
  // Returns the number of characters printed.
  // May be NULL.
  size_t (idaapi *print_ptr_value)(
        char *buf,
        size_t bufsize,
        bool *is_valid_ptr,
        const argloc_t &loc,
        const tinfo_t &tif);
};

idaman int ida_export install_custom_argloc(const custloc_desc_t *custloc);
idaman bool ida_export remove_custom_argloc(int idx);
idaman const custloc_desc_t *ida_export retrieve_custom_argloc(int idx);


// A typical argument is stored in one location, either a register either a stack slot.
// However, some arguments can be stored in multiple locations, for example in a pair
// of registers. In some really complex cases an argument can be located in multiple
// registers and some stack slots. The below class can describe all these cases.
class argloc_t // #argloc
{
public:
#ifdef __X64__
  typedef size_t biggest_t;
#else
  typedef ea_t biggest_t;
#endif

private:
  argloc_type_t type;
  union
  {
    sval_t sval;                // ALOC_STACK, ALOC_STATIC
    uint32 reginfo;             // ALOC_REG1, ALOC_REG2
    rrel_t *rrel;               // ALOC_RREL
    scattered_aloc_t *dist;     // ALOC_DIST
    void *custom;               // ALOC_CUSTOM
    biggest_t biggest;          // to facilitate manipulation of this union
  };
  ARGLOC_HELPER_DEFINITIONS(friend)

public:
  argloc_t(void) : type(ALOC_NONE), biggest(0) {}
  argloc_t(const argloc_t &r) : type(ALOC_NONE) { copy_argloc(this, &r); }
  ~argloc_t(void) { cleanup_argloc(this); }
  argloc_t &operator=(const argloc_t &r) { copy_argloc(this, &r); return *this; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(argloc_t &r)
  {
    biggest_t tmp = biggest; biggest = r.biggest; r.biggest = tmp;
    argloc_type_t t = type; type = r.type; r.type = t;
  }
  const char *dstr(void) const;

  argloc_type_t atype(void) const { return type; }
  bool is_reg1(void)       const { return type == ALOC_REG1; }
  bool is_reg2(void)       const { return type == ALOC_REG2; }
  bool is_reg(void)        const { return type == ALOC_REG1 || type == ALOC_REG2; }
  bool is_rrel(void)       const { return type == ALOC_RREL; }
  bool is_ea(void)         const { return type == ALOC_STATIC; }
  bool is_stkoff(void)     const { return type == ALOC_STACK; }
  bool is_scattered(void)  const { return type == ALOC_DIST; }
  bool is_fragmented(void) const { return type == ALOC_DIST || type == ALOC_REG2; }
  bool is_custom(void)     const { return type >= ALOC_CUSTOM; }
  bool is_badloc(void)     const { return type == ALOC_NONE; }

  // if ALOC_REG1 or ALOC_REG2:
  int reg1(void) const { return uint16(reginfo); }
  // if ALOC_REG1:
  int regoff(void) const { return uint16(reginfo >> 16); } // offset from the beginning of the register in bytes
  // if ALOC_REG2:
  int reg2(void) const { return uint16(reginfo >> 16); }
  uint32 get_reginfo(void) const { return reginfo; }
  // if ALOC_STACK:
  sval_t stkoff(void) const { return sval; }
  // if ALOC_STATIC:
  ea_t get_ea(void) const { return sval; }
  // if ALOC_DIST:
        scattered_aloc_t &scattered(void)       { return *dist; }
  const scattered_aloc_t &scattered(void) const { return *dist; }
  // if ALOC_RREL:
        rrel_t &get_rrel(void)       { return *rrel; }
  const rrel_t &get_rrel(void) const { return *rrel; }
  // if ALOC_CUSTOM:
  void *get_custom(void) const { return custom; }
  biggest_t get_biggest(void) const { return biggest; }

  // be careful with these functions, they do not cleanup!
  void _set_badloc(void) { type = ALOC_NONE; }
  void _set_reg1(int reg, int off=0) { type = ALOC_REG1; reginfo = reg | (off << 16); }
  void _set_reg2(int _reg1, int _reg2) { type = ALOC_REG2; reginfo = _reg1 | (_reg2 << 16); }
  void _set_stkoff(sval_t off) { type = ALOC_STACK; sval = off; }
  void _set_ea(ea_t _ea) { type = ALOC_STATIC; sval = _ea; }
  bool _consume_rrel(rrel_t *p) //lint -sem(argloc_t::_consume_rrel, custodial(1))
  {
    if ( p == NULL )
      return false;
    type = ALOC_RREL;
    rrel = p;
    return true;
  }
  bool _consume_scattered(scattered_aloc_t *p)
  {
    if ( p == NULL )
      return false;
    type = ALOC_DIST;
    dist = p;
    return true;
  }
  void _set_custom(argloc_type_t ct, void *pdata) { type = ct; custom = pdata; }
  void _set_biggest(argloc_type_t ct, biggest_t data) { type = ct; biggest = data; }

  // in general, use these functions:
  void set_reg1(int reg, int off=0) { cleanup_argloc(this); _set_reg1(reg, off); }
  void set_reg2(int _reg1, int _reg2) { cleanup_argloc(this); _set_reg2(_reg1, _reg2); }
  void set_stkoff(sval_t off) { cleanup_argloc(this); _set_stkoff(off); }
  void set_ea(ea_t _ea) { cleanup_argloc(this); _set_ea(_ea); }
  void consume_rrel(rrel_t *p) { cleanup_argloc(this); _consume_rrel(p); }
  void consume_scattered(scattered_aloc_t *p) { cleanup_argloc(this); _consume_scattered(p); }
  void set_badloc(void) { cleanup_argloc(this); }

  // calculate offset that can be used to compare 2 similar arglocs
  sval_t calc_offset(void) const
  {
    switch ( type )
    {
      default:
      case ALOC_NONE:
      case ALOC_DIST:
      case ALOC_REG2:
        return -1;
      case ALOC_RREL:
        return rrel->off;
      case ALOC_STACK:
      case ALOC_STATIC:
        return sval;
      case ALOC_REG1:
        return reg1();
    }
  }
  // move the location to point 'delta' bytes further
  bool advance(int delta)
  {
    switch ( type )
    {
      case ALOC_REG1:
        _set_reg1(reg1()+delta, regoff());
        break;
      case ALOC_STACK:
      case ALOC_STATIC:
        sval += delta;
        break;
      case ALOC_RREL:
        rrel->off += delta;
        break;
      default:
        return false;
    }
    return true;
  }
  DECLARE_COMPARISONS(argloc_t)
  {
    return compare_arglocs(*this, r);
  }
};
DECLARE_TYPE_AS_MOVABLE(argloc_t);
typedef qvector<argloc_t> arglocs_t;

struct argpart_t : public argloc_t
{
  ushort off;  // offset from the beginning of the argument
  ushort size; // the number of bytes
  argpart_t(void) : off(0xFFFF), size(0) {}
  bool bad_offset(void) const { return off == 0xFFFF; }
  bool bad_size(void) const { return size == 0; }
  bool operator < (const argpart_t &r) const { return off < r.off; }
  void swap(argpart_t &r)
  {
    argloc_t::swap(r);
    qswap(off, r.off);
    qswap(size, r.size);
  }
};
DECLARE_TYPE_AS_MOVABLE(argpart_t);
class scattered_aloc_t : public qvector<argpart_t>
{
};
DECLARE_TYPE_AS_MOVABLE(scattered_aloc_t);

// Verify argloc_t. Returns 0 if ok, otherwise an interr code.
// size - total size of the variable
// gaps - if not NULL, specifies gaps in structure definition
//        these gaps should not map to any argloc, but everything else must be covered

idaman int ida_export verify_argloc(const argloc_t &vloc, int size, const areaset_t *gaps);


// Verify and optimize scattered argloc into simple form.
// All new arglocs must be processed by this function.
// Return true on success; false if the input argloc is illegal.

idaman bool ida_export optimize_argloc(argloc_t *vloc, int size, const areaset_t *gaps);


// Convert into human readable form

idaman size_t ida_export print_argloc(
        char *buf,
        size_t bufsize,
        const argloc_t &vloc,
        int size=0,
        int vflags=0);
#define PRALOC_VERIFY 0x01    // interr if illegal argloc
#define PRALOC_STKOFF 0x02    // print stack offsets


// Visit all locations. The callback will receive not recieve ALOC_DIST/ALOC_REG2 types,
// they will be converted into smaller argloc types (ALOC_REG1 or other)
struct aloc_visitor_t
{
  virtual int idaapi visit_location(argloc_t &v, int off, int size) = 0;
  DEFINE_VIRTUAL_DTOR(aloc_visitor_t)
};

idaman int ida_export for_all_arglocs(aloc_visitor_t &vv, argloc_t &vloc, int size, int off=0);

struct const_aloc_visitor_t
{
  virtual int idaapi visit_location(const argloc_t &v, int off, int size) = 0;
  DEFINE_VIRTUAL_DTOR(const_aloc_visitor_t)
};

inline int idaapi for_all_const_arglocs(const_aloc_visitor_t &vv, const argloc_t &vloc, int size, int off=0)
{
  return for_all_arglocs(*(aloc_visitor_t*)(&vv),
                         CONST_CAST(argloc_t&)(vloc),
                         size,
                         off);
}

// function argument passing: how GP & FP registers cooperate with each other
enum argreg_policy_t
{
  ARGREGS_POLICY_UNDEFINED,
  ARGREGS_GP_ONLY,     // GP registers used for all arguments
  ARGREGS_INDEPENDENT, // FP/GP registers used separately (like gcc64)
  ARGREGS_BY_SLOTS,    // fixed FP/GP regster per each slot (like vc64)
};

// class helper
class callregs_t;
idaman void ida_export callregs_init_regs(callregs_t *_this, int request);

// Register allocation calling convention:
// (allocation policy, arrays of GP and FP registers)
class callregs_t
{
  static int findreg(const intvec_t &regs, int r)
  {
    intvec_t::const_iterator p = regs.find(r);
    return p == regs.end() ? -1 : (p-regs.begin());
  }
  bool set_inds(int *p_ind1, int *p_ind2, int ind)
  {
    if ( ind == -1 )
      return false;
    *p_ind1 = ind;
    *p_ind2 = (policy == ARGREGS_BY_SLOTS) ? ind : -1;
    return true;
  }

  // copy -1-terminated array to a vector
  static void set_regarray(intvec_t *regvec, const int *regarray)
  {
    regvec->clear();
    if ( regarray != NULL )
      while ( *regarray != -1 )
        regvec->push_back(*regarray++);
  }

public:
  argreg_policy_t policy;
  int nregs;              // max. number of registers may be used in a call
  intvec_t gpregs;
  intvec_t fpregs;

  callregs_t():  policy(ARGREGS_POLICY_UNDEFINED), nregs(0) {}
  // request: ph.get_fastcall_regs3, get_varcall_regs2 or ph.get_thiscall_regs3
  callregs_t(int request)
    : policy(ARGREGS_POLICY_UNDEFINED), nregs(0)
  {
    init_regs(request);
  }

  // init policy & registers using given request
  // request: ph.get_fastcall_regs3, get_varcall_regs2 or ph.get_thiscall_regs3
  void init_regs(int request)
  {
    callregs_init_regs(this, request);
  }

  // init policy & registers with given args (arrays are -1-terminated)
  void set(argreg_policy_t _policy, const int *gprs, const int *fprs)
  {
    policy = _policy;
    set_regarray(&gpregs, gprs);
    set_regarray(&fpregs, fprs);
    nregs = gpregs.size();
    if ( policy == ARGREGS_INDEPENDENT )
      nregs += fpregs.size();
  }

  void reset()
  {
    set(ARGREGS_POLICY_UNDEFINED, NULL, NULL);
  }

  // return max. number of registers may be used in a function call
  // request: ph.get_fastcall_regs3, get_varcall_regs2 or ph.get_thiscall_regs3
  static int regcount(int request)
  {
    callregs_t vr(request); return vr.nregs;
  }

  // return register indexes withing GP/FP arrays
  // (-1 -> is not present in the corresponding array)
  bool reginds(int *gp_ind, int *fp_ind, int r)
  {
    return findregs(gp_ind, fp_ind, r, gpregs, fpregs);
  }

protected:
  bool findregs(int *gp_ind, int *fp_ind, int r, const intvec_t &gprs, const intvec_t &fprs)
  {
    *gp_ind = *fp_ind = -1;
    return set_inds(gp_ind, fp_ind, findreg(gprs, r))
        || set_inds(fp_ind, gp_ind, findreg(fprs, r));
  }
};

//--------------------------------------------------------------------------
// standard C-language models for x86
const cm_t C_PC_TINY    = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_SMALL   = (CM_N16_F32 | CM_M_NN);
const cm_t C_PC_COMPACT = (CM_N16_F32 | CM_M_NF);
const cm_t C_PC_MEDIUM  = (CM_N16_F32 | CM_M_FN);
const cm_t C_PC_LARGE   = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_HUGE    = (CM_N16_F32 | CM_M_FF);
const cm_t C_PC_FLAT    = (CM_N32_F48 | CM_M_NN);
//
inline cm_t get_cc (cm_t cm) { return(cm & CM_CC_MASK); }

// a calling convention that specifies that argument locations explicitly?
inline bool is_user_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc >= CM_CC_SPECIALE;
}

// a calling convention with ellipsis?
inline bool is_vararg_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE;
}

// a calling convention that cleans the stack arguments upon return?
// Note: this function is valid only for x86 code
inline bool is_purging_cc(cm_t cm)
{
  cm_t cc = get_cc(cm);
  return cc == CM_CC_STDCALL || cc == CM_CC_PASCAL || cc == CM_CC_SPECIALP || cc == CM_CC_FASTCALL || cc == CM_CC_THISCALL;
}

//--------------------------------------------------------------------------
// CC (compiler)
const comp_t COMP_MASK   = 0x0F;
const comp_t  COMP_UNK     = 0x00;      // Unknown
const comp_t  COMP_MS      = 0x01;      // Visual C++
const comp_t  COMP_BC      = 0x02;      // Borland C++
const comp_t  COMP_WATCOM  = 0x03;      // Watcom C++
//const comp_t  COMP_         = 0x04
//const comp_t  COMP_         = 0x05
const comp_t  COMP_GNU     = 0x06;      // GNU C++
const comp_t  COMP_VISAGE  = 0x07;      // Visual Age C++
const comp_t  COMP_BP      = 0x08;      // Delphi
//----

const comp_t  COMP_UNSURE  = 0x80;      // uncertain compiler id
//----
inline comp_t get_comp(comp_t comp) { return(comp & COMP_MASK); }
idaman const char *ida_export get_compiler_name(comp_t id);
idaman const char *ida_export get_compiler_abbr(comp_t id);
typedef qvector<comp_t> compvec_t;
idaman void ida_export get_compilers(compvec_t *ids, qstrvec_t *names, qstrvec_t *abbrs);
inline comp_t is_comp_unsure(comp_t comp) { return (comp & COMP_UNSURE); }

inline comp_t default_compiler(void) { return get_comp(inf.cc.id); }

inline bool is_gcc(void) { return default_compiler() == COMP_GNU; }
inline bool is_gcc32(void) { return is_gcc() && !inf.is_64bit(); }
inline bool is_gcc64(void) { return is_gcc() && inf.is_64bit(); }

// Change current compiler
// Returns: success

idaman bool ida_export set_compiler(const compiler_info_t &cc, int flags);

#define SETCOMP_OVERRIDE 0x0001         // may override old compiler info
#define SETCOMP_ONLY_ID  0x0002         // cc has only 'id' field
                                        // the rest will be set to defaults
                                        // corresponding to the program bitness

inline bool idaapi set_compiler_id(comp_t id)
{
  compiler_info_t cc;
  cc.id = id;
  return set_compiler(cc, SETCOMP_ONLY_ID);
}

//--------------------------------------------------------------------------
const size_t BADSIZE = size_t(-1);      // bad type size
#define MAX_FUNC_ARGS   256             // max number of function arguments

//--------------------------------------------------------------------------
enum abs_t    { abs_unk, abs_no, abs_yes };     // abstractness of declaration
enum sclass_t                                   // storage class
{
  sc_unk,       // unknown
  sc_type,      // typedef
  sc_ext,       // extern
  sc_stat,      // static
  sc_reg,       // register
  sc_auto,      // auto
  sc_friend,    // friend
  sc_virt       // virtual
};

#define HTI_CPP    0x00000001          // C++ mode (not implemented)
#define HTI_INT    0x00000002          // debug: print internal representation of types
#define HTI_EXT    0x00000004          // debug: print external representation of types
#define HTI_LEX    0x00000008          // debug: print tokens
#define HTI_UNP    0x00000010          // debug: check the result by unpacking it
#define HTI_TST    0x00000020          // test mode: discard the result
#define HTI_FIL    0x00000040          // "input" is file name
                                       // otherwise "input" contains a C declaration
#define HTI_MAC    0x00000080          // define macros from the base tils
#define HTI_NWR    0x00000100          // no warning messages
#define HTI_NER    0x00000200          // ignore all errors but display them
#define HTI_DCL    0x00000400          // don't complain about redeclarations
#define HTI_NDC    0x00000800          // don't decorate names
#define HTI_PAK    0x00007000          // explicit structure pack value (#pragma pack)
#define HTI_PAK_SHIFT 12               // shift for HTI_PAK. This field should
                                       // be used if you want to remember explicit
                                       // pack value for each structure/union type
                                       // Some valid pack constants:
#define HTI_PAKDEF 0x00000000          //   default pack value
#define HTI_PAK1   0x00001000          //   #pragma pack(1)
#define HTI_PAK2   0x00002000          //   #pragma pack(2)
#define HTI_PAK4   0x00003000          //   #pragma pack(4)
#define HTI_PAK8   0x00004000          //   #pragma pack(8)
#define HTI_PAK16  0x00005000          //   #pragma pack(16)

#define HTI_HIGH   0x00008000          // assume high level prototypes
                                       // (with hidden args, etc)
#define HTI_LOWER  0x00010000          // lower the function prototypes

// this callback will be called for each type/variable declaration
// if it returns T_CBBRKDEF, the type declaration won't be saved in the til
typedef int idaapi h2ti_type_cb(
     const char *name,                 // var/func/type name
     const tinfo_t &tif,               // type info
     const char *cmt,                  // main comment
     const uint64 *value,              // symbol value
     void *cb_data);

typedef AS_PRINTF(1, 2) int printer_t(const char *format, ...);

// convert descriptions to type_t*
// returns number of errors (they are displayed using print_cb)
// zero means ok
// This is a low level function - use parse_... functions below
idaman int ida_export h2ti(
         til_t *ti,
         lexer_t *lx,              // input lexer, may be NULL
                                   // always destroyed by h2ti()
         const char *input,        // file name or C declaration
         int flags=HTI_HIGH,       // see HTI_... above
         h2ti_type_cb *type_cb=NULL,    // for each type
         h2ti_type_cb *var_cb=NULL,     // for each var
         printer_t *print_cb=NULL,      // may pass 'msg' here
         void *_cb_data=NULL,
         abs_t _isabs=abs_unk);


// Parse ONE declaration
//      til     - in: type library to use
//      decl    - in: C declaration to parse
//      name    - out: declared name
//      tif     - out: type info
//      flags   - combination of PT_... constants
// NOTE: name & type & fields might be empty after the call!
// Returns true-ok, false-declaration is bad, the error message is displayed
// If the input string contains more than one declaration, the first complete
// type declaration (PT_TYP) or the last variable declaration (PT_VAR) will be used.

idaman bool ida_export parse_decl2(
        til_t *til,
        const char *decl,
        qstring *name,
        tinfo_t *tif,
        int flags);

#define PT_SIL       0x0001  // silent, no messages
#define PT_NDC       0x0002  // don't decorate names
#define PT_TYP       0x0004  // return declared type information
#define PT_VAR       0x0008  // return declared object information
#define PT_PACKMASK  0x0070  // mask for pack alignment values
#define PT_HIGH      0x0080  // assume high level prototypes
                             // (with hidden args, etc)
#define PT_LOWER     0x0100  // lower the function prototypes

// convert PT_... flags to HTI_...
// PT_.. flags lesser than 0x10 don't have stable meaning and will be ignored
// (more PT_... flags can be seen in idc.idc)
inline int convert_pt_flags_to_hti(int pt_flags)
{
  return ((pt_flags >> 4) & 0x1f) << HTI_PAK_SHIFT;
}

// Parse many declarations and store them in 'til'
//    til       - type library to store the result
//    input     - input string or file name (see hti_flags)
//    printer   - function to output error messages (use msg or NULL or your own callback)
//    hti_flags - combination of HTI_... bits
// Returns number of errors, 0 means ok
// If there are any errors, they will be printed using 'printer'.
// This function uses default include path and predefined macros from the
// database settings. It always uses the HTI_DCL bit.

idaman int ida_export parse_decls(
        til_t *til,
        const char *input,
        printer_t *printer,
        int hti_flags);


// Get type declaration for the specified address
idaman bool ida_export print_type2(ea_t ea, char *buf, size_t bufsize, int prtype_flags);

// flags is a bitwise combination of the following symbols:
#define PRTYPE_1LINE  0x0000 // print to one line
#define PRTYPE_MULTI  0x0001 // print to many lines
#define PRTYPE_TYPE   0x0002 // print type declaration (not variable declaration)
#define PRTYPE_PRAGMA 0x0004 // print pragmas for alignment
#define PRTYPE_SEMI   0x0008 // append ; to the end
#define PRTYPE_CPP    0x0010 // use c++ name (only for print_type2)
#define PRTYPE_DEF    0x0020 // tinfo_t: print definition, if available
#define PRTYPE_NOARGS 0x0040 // tinfo_t: do not print function argument names
#define PRTYPE_NOARRS 0x0080 // tinfo_t: print arguments with FAI_ARRAY as pointers


/////////////////////////////////////////////////////////////////////////////
//              WORK WITH NAMED TYPES
/////////////////////////////////////////////////////////////////////////////

// get named typeinfo
//      til       - pointer to type information library
//      name      - name of type
//      flags     - combination of NTF_... flags
//      type      - ptr to ptr to output buffer for the type info
//      fields    - ptr to ptr to the field/args names. may be NULL
//      cmt       - ptr to ptr to the main comment. may be NULL
//      fieldcmts - ptr to ptr to the field/args comments. may be NULL
//      sclass    - ptr to storage class (sc_...)
//      value     - ptr to symbol value. for types, ptr to the ordinal number
// if name==NULL returns false
// returns: 0 - can't find the named type
//          1  - ok, the buffers are filled with information (if not NULL)
//          2  - ok, found it in a base til
// the returned pointers are pointers to static storage
// they are valid till free_til(), set_named_type(), del_named_type(), rename_named_type(),
// set_numbered_type(), del_numbered_type(), and idb structure/enum manipulation
// (in other words, until til_t is changed)

idaman int ida_export get_named_type(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t **type=NULL,
        const p_list **fields=NULL,
        const char **cmt=NULL,
        const p_list **fieldcmts=NULL,
        sclass_t *sclass=NULL,
        uint32 *value=NULL);

#define NTF_TYPE     0x0001     // type name
#define NTF_SYMU     0x0008     // symbol, name is unmangled ('func')
#define NTF_SYMM     0x0000     // symbol, name is mangled ('_func')
                                // only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used
#define NTF_NOBASE   0x0002     // don't inspect base tils (for get_named_type)
#define NTF_REPLACE  0x0004     // replace original type (for set_named_type)
#define NTF_UMANGLED 0x0008     // name is unmangled (don't use this flag)
#define NTF_NOCUR    0x0020     // don't inspect current til file (for get_named_type)
#define NTF_64BIT    0x0040     // value is 64bit

// See get_named_type() above.
//
// Note: If the value in the 'ti' library is 32-bit, it will
// be sign-extended before being stored in the 'value' pointer.
inline int ida_export get_named_type64(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t **type=NULL,
        const p_list **fields=NULL,
        const char **cmt=NULL,
        const p_list **fieldcmts=NULL,
        sclass_t *sclass=NULL,
        uint64 *value=NULL)
{
  return get_named_type(ti, name, ntf_flags | NTF_64BIT,
                        type, fields, cmt, fieldcmts, sclass, (uint32 *)value);
}


// set named typeinfo
//      til       - pointer to til.
//      name      - name of type (any ascii string)
//      flags     - combination of NTF_...
//      ptr       - pointer to typeinfo to save
//      fields    - ptr to the field/args names. may be NULL
//      cmt       - ptr to the main comment. may be NULL
//      fieldcmts - ptr to the field/args comments. may be NULL
//      sclass    - ptr to storage class (sc_...). may be NULL
//      value     - ptr to symbol value. for types, ptr to the ordinal number. may be NULL
// if name==NULL or ptr==NULL returns false
// returns true if successfully saves the typeinfo

idaman bool ida_export set_named_type(
        til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t *ptr,
        const p_list *fields=NULL,
        const char *cmt=NULL,
        const p_list *fieldcmts=NULL,
        const sclass_t *sclass=NULL,
        const uint32 *value=NULL);

inline bool set_named_type64(
        til_t *ti,
        const char *name,
        int ntf_flags,
        const type_t *ptr,
        const p_list *fields=NULL,
        const char *cmt=NULL,
        const p_list *fieldcmts=NULL,
        const sclass_t *sclass=NULL,
        const uint64 *value=NULL)
{
  return set_named_type(ti, name, ntf_flags | NTF_64BIT,
                        ptr, fields, cmt, fieldcmts, sclass, (uint32 *)value);
}

// get size of the named type
// returns: -1 - error (unknown name)
//           0 - unknown size
//          otherwise returns the size

idaman size_t ida_export get_named_type_size(
        const til_t *ti,
        const char *name,
        int ntf_flags,
        size_t *lp = NULL);


// del information about a symbol
// returns: success

idaman bool ida_export del_named_type(til_t *ti, const char *name, int ntf_flags);


// rename a type or a symbol
//      ti - type library
//      from - source name
//      to - destination name. NULL denotes anonymous name
//      ntf_flags - combination of NTF_.. constants
// If NTF_TYPE is specifed and numbered types are enabled (idati has them enabled)
// then this function can be used to add or delete type names.
// The ordinals can be specified as specially crafter names: '#' followed by set_de(ordinal)
// return error code (see T_... constants above)

idaman int ida_export rename_named_type(til_t *ti, const char *from, const char *to, int ntf_flags);


// Enumerate types
// These functions return mangled names
// They never return anonymous types. To include them, enumerate types by ordinals.

idaman const char *ida_export first_named_type(const til_t *ti, int ntf_flags);
idaman const char *ida_export next_named_type(const til_t *ti, const char *name, int ntf_flags);


// Decorate/undecorate a C symbol name
//      out       - output buffer
//      ti        - pointer to til
//      name      - name of symbol
//      mangle    - true-mangle, false-unmangle
//      cc        - calling convention
// returns true if success

idaman bool ida_export decorate_name3(
        qstring *out,
        const char *name,
        bool mangle,
        cm_t cc=CM_CC_UNKNOWN);

// Generic function for that (may be used in IDP modules):
idaman bool ida_export gen_decorate_name3(
        qstring *out,
        const char *name,
        bool mangle,
        cm_t cc);


// Get C or C++ form of the name
//      buf  - output buffer
//      bufsize - output buffer size
//      name - original (mangled or decorated) name
//      type - name type if known, otherwise NULL
//      ccn_flags - one of CCN_... constants

idaman void ida_export calc_c_cpp_name3(
        char *buf,
        size_t bufsize,
        const char *name,
        const tinfo_t *type,
        int ccn_flags);
#define CCN_C   0x00  // prepare C name
#define CCN_CPP 0x01  // prepare C++ name


//--------------------------------------------------------------------------
// NUMBERED TYPES
// These types may be named or anonymous.
// They are referenced by their ordinal number. Access to them is faster because
// there is no need to resolve their names. Also, they can stay anonymous
// and be aliased. They can be used only in the local type library
// created by IDA (in idati).

// Enable the use of numbered types in til
// Currently it is impossible to disable numbered types once they are enabled

bool enable_numbered_types(til_t *ti, bool enable);


// Retrieve a type by its ordinal number

idaman bool ida_export get_numbered_type(
        const til_t *ti,
        uint32 ordinal,
        const type_t **type=NULL,
        const p_list **fields=NULL,
        const char **cmt=NULL,
        const p_list **fieldcmts=NULL,
        sclass_t *sclass=NULL);


// Allocate a range of ordinal numbers for new types.
//      qty - number of ordinals to allocate
// Returns the first ordinal. 0 means failure.

idaman uint32 ida_export alloc_type_ordinals(til_t *ti, int qty);
inline uint32 alloc_type_ordinal(til_t *ti) { return alloc_type_ordinals(ti, 1); }


// Get number of allocated ordinals
// If failed, returns uint32(-1)

idaman uint32 ida_export get_ordinal_qty(const til_t *ti);


// Store a type in the til
// 'name' may be NULL for anonymous types
// The specified ordinal must be free (no other type is using it)

idaman bool ida_export set_numbered_type(
        til_t *ti,
        uint32 ordinal,
        int ntf_flags,              // only NTF_REPLACE is consulted
        const char *name,
        const type_t *type,
        const p_list *fields=NULL,
        const char *cmt=NULL,
        const p_list *fldcmts=NULL,
        const sclass_t *sclass=NULL);


// Delete a numbered type

idaman bool ida_export del_numbered_type(til_t *ti, uint32 ordinal);


// Create a type alias.
// Redirects all references to source type to the destination type.
// This is equivalent to instantaneous replacement all reference to srctype by dsttype.

idaman bool ida_export set_type_alias(til_t *ti, uint32 src_ordinal, uint32 dst_ordinal);


// Find the final alias destination.
// If the ordinal has not been aliased, return the specified ordinal itself
// If failed, returns 0.

idaman uint32 ida_export get_alias_target(const til_t *ti, uint32 ordinal);


// Get type ordinal by its name

inline int32 get_type_ordinal(const til_t *ti, const char *name)
{
  uint32 ordinal = 0;
  get_named_type(ti, name, NTF_TYPE|NTF_NOBASE, NULL, NULL, NULL, NULL, NULL, &ordinal);
  return ordinal;
}

// Get type name (if exists) by its ordinal
// If the type is anonymous, returns "". If failed, returns NULL

idaman const char *ida_export get_numbered_type_name(const til_t *ti, uint32 ordinal);


// Create anonymous name for numbered type. This name can be used
// to reference a numbered type by its ordinal
// Ordinal names have the following format: '#' + set_de(ord)
// Returns: 0 if error, otherwise the name length

idaman size_t ida_export create_numbered_type_name(int32 ord, char *buf, size_t bufsize);


// Create reference type to a numbered type.
// This type can be used to refer to the numbered type
// (it is BTF_TYPEDEF+ordinal name)

idaman bool ida_export create_numbered_type_reference(qtype *out, uint32 ord);


// Check if the name is an ordinal name
// Ordinal names have the following format: '#' + set_de(ord)

inline bool is_ordinal_name(const char *name, uint32 *ord)
{
  if ( name[0] != '#' )
    return false;

  const type_t *ptr = (const type_t *)name + 1;
  return get_de(&ptr, ord);
}

// Get ordinal number of an idb type (struct/enum)
// The 'type' parameter is used only to determine the kind of the type (struct or enum)
// Use this function to find out the correspondence between idb types and til types

idaman int ida_export get_ordinal_from_idb_type(const char *name, const type_t *type);


// Is the specified idb type automatically synchronized?
inline bool idaapi is_autosync(const char *name, const type_t *type)
{
  return get_ordinal_from_idb_type(name, type) != -1;
}
inline bool idaapi is_autosync(const char *name, const tinfo_t &tif); // see below


// Generate a name like $hex_numbers based on the field types and names

idaman void ida_export build_anon_type_name(
        char *buf,
        size_t bufsize,
        const type_t *type,
        const p_list *fields);


// If the type is a reference to an ordinal type, return the referenced id
// Otherwise returns BADORD

idaman uint32 ida_export get_referred_ordinal(const type_t **ptype);

const uint32 BADORD = uint32(-1);


// Compact numbered types to get rid of empty slots
//      ti      - type library to compact
//      min_ord - minimal ordinal number to start to compact. lower
//                ordinals are not modified
//      ordmap  - the resulting mapping
//                (for example, the new ordinal of min_ord will be in ordmap[0])
//      flags   - reserved
// Returns number of freed type slots

idaman int ida_export compact_numbered_types(
        til_t *ti,
        uint32 min_ord=0,
        intvec_t *p_ordmap=NULL,
        int flags=0);

//--------------------------------------------------------------------------
// ALIGNMENT

// Get default alignment for structure fields
//      cm - the current calling convention and model
// returns: the default alignment for structure fields
//          (something like 1,2,4,8,...)

inline size_t get_default_align(void) { return inf.cc.defalign; }

// Get alignment delta for the a structure field
//      cur_tot_size - the structure size calculated so far
//      elem_size    - size of the current field
//                     the whole structure should be calculated
//      algn         - the structure alignment (0,1,2,4,8...)
inline void align_size(size_t &cur_tot_size, size_t elem_size, size_t algn)
{
  size_t al = elem_size;
  if ( algn != 0 && algn < al )
    al = algn;
  cur_tot_size = align_up(cur_tot_size, al);
}

//--------------------------------------------------------------------------
// Get sizeof(enum)

inline size_t get_default_enum_size(cm_t cm)
  { return ph.ti() ? ph.notify(ph.get_default_enum_size, cm) : BADSIZE; }

//--------------------------------------------------------------------------
// POINTERS

// get maximal pointer size

inline int max_ptr_size(void) { return ph.notify(ph.max_ptr_size)-1; }

// get prefix and size of 'segment based' ptr type (something like char _ss *ptr)
//      ptrt  - the type of pointer to get information about
//              it is calculated as "size - max_ptr_size() - 1"
//      size  - the sizeof of the type will be returned here
// returns: NULL - error (unknown type == bad typeinfo string)
//          else - string in form "_ss",
//                 size contains sizeof of the type
// HINT: the returned value may be an empty string ("")

inline const char *idaapi based_ptr_name_and_size(unsigned ptrt, size_t *size)
{
  if ( !ph.ti() )
    return NULL;
  const char *ptrname;
  *size = ph.notify(ph.based_ptr, ptrt, &ptrname);
  return ptrname;
}


// Dereference a pointer
//      tif         - type of the pointer
//      ptr_ea      - in: address of the pointer
//                    out: the pointed address
//      closure_obj - out: closure object (not used yet)
// Returns: true-success

idaman bool ida_export deref_ptr2(
        const tinfo_t &tif,
        ea_t *ptr_ea,
        ea_t *closure_obj=NULL);


// Remove pointer of a type, i.e. convert "char *" into "char"
// Optionally remove the "lp" (or similar) prefix of the input name
// If the input type is not a pointer, then fail.

idaman bool ida_export remove_tinfo_pointer(const til_t *til, tinfo_t *tif, const char **pname);


// Get offset of the first stack argument

inline int get_stkarg_offset(void)
{
  if ( !ph.ti() )
    return 0;
  return ph.notify(ph.get_stkarg_offset2) - 2;
}

// Copy a named type from til to idb
//      til   - type library
//      idx   - the position of the new type in the list of types (structures or enums)
//              -1 means at the end of the list
//      tname - the type name
//      flags - combination of the following bits:
#define IMPTYPE_VERBOSE  0x0001 // more verbose output (dialog boxes may appear)
#define IMPTYPE_OVERRIDE 0x0002 // override existing type
#define IMPTYPE_LOCAL    0x0004 // the type is local, the struct/enum won't be marked as til type
                                // there is no need to specify this bit if til==idati,
                                // the kernel will set it automatically
// Returns BADNODE - error

idaman tid_t ida_export import_type(const til_t *til, int idx, const char *name, int flags=0);


// Load a til file
// returns one of ADDTIL_... constants

idaman int ida_export add_til2(const char *name, int flags);

// flags argument:
#define ADDTIL_DEFAULT  0x0000  // default behaviour
#define ADDTIL_INCOMP   0x0001  // load incompatible tils
#define ADDTIL_SILENT   0x0002  // do not ask any questions

// return values:
#define ADDTIL_FAILED   0  // something bad, the warning is displayed
#define ADDTIL_OK       1  // ok, til is loaded
#define ADDTIL_COMP     2  // ok, but til is not compatible with the current compiler

// Unload a til file

idaman bool ida_export del_til(const char *name);


// Apply the specified named type to the address
//      ea - linear address
//      name - the type name, e.g. "FILE"
// returns: success

idaman bool ida_export apply_named_type(ea_t ea, const char *name);


// Apply the specified type to the address
//      til - type library
//      ea - linear address
//      type - type string in the internal format
//      fields - field names if required by the type string
//      flags  - combination of TINFO_XXX flags below
// This function sets the type and tries to convert the item at the specified
// address to conform the type.
// returns: success
#define TINFO_GUESSED    0x0000 // this is a guessed type
#define TINFO_DEFINITE   0x0001 // this is a definite type
#define TINFO_DELAYFUNC  0x0002 // if type is a function and no function exists at ea,
                                // schedule its creation and argument renaming to auto-analysis
                                // otherwise try to create it immediately

idaman bool ida_export apply_tinfo2(
        ea_t ea,
        const tinfo_t &tif,
        uint32 flags);


// Apply the specified type to the address
//      til - type library
//      ea - linear address
//      decl - type declaration in C form
//      flags - flags to pass to apply_tinfo (TINFO_DEFINITE is always passed)
// This function parses the declaration and calls apply_tinfo()
// returns: success

idaman bool ida_export apply_cdecl2(til_t *til, ea_t ea, const char *decl, int flags=0);


// Apply the type of the called function to the calling instruction
//      caller - linear address of the calling instruction.
//               must belong to a function.
//      tif    - type info
// This function will append parameter comments and rename the local
// variables of the calling function.

idaman void ida_export apply_callee_tinfo(ea_t caller, const tinfo_t &tif);


// Apply the specified type and name to the address
//      ea - linear address
//      type - type string in the internal format
//      name - new name for the address
// This function checks if the address already has a type. If the old type
// does not exist or the new type is 'better' than the old type, then the
// new type will be applied. A type is considere better if it has more
// information (e.g.e BTMT_STRUCT is better than BT_INT).
// The same logic is with the name: if the address already have a meaningful
// name, it will be preserved. Only if the old name does not exist or it
// is a dummy name like byte_123, it will be replaced by the new name.
// Returns: success

idaman bool ida_export apply_once_tinfo_and_name(
        ea_t dea,
        const tinfo_t &tif,
        const char *name);


// To retrieve the type information attach to an address, use get_tinfo() function
// (see nalt.hpp)

// Generate a type string using information about the function
// from the disassembly. you could use guess_type() function instead of this function

idaman int ida_export guess_func_tinfo2(func_t *pfn, tinfo_t *tif);

#define GUESS_FUNC_FAILED   0   // couldn't guess the function type
#define GUESS_FUNC_TRIVIAL  1   // the function type doesnt' have interesting info
#define GUESS_FUNC_OK       2   // ok, some non-trivial information is gathered


// Generate a type information about the id from the disassembly
// id can be a structure/union/enum id or an address.

idaman int ida_export guess_tinfo2(tid_t id, tinfo_t *tif);


// Various parameters

inline void set_c_header_path(const char *incdir)           { RootNode.supset(RIDX_H_PATH, incdir); }
inline ssize_t get_c_header_path(char *buf, size_t bufsize) { return RootNode.supstr(RIDX_H_PATH, buf, bufsize); }
inline void set_c_macros(const char *macros)                { RootNode.supset(RIDX_C_MACROS, macros); }
inline ssize_t get_c_macros(char *buf, size_t bufsize)      { return RootNode.supstr(RIDX_C_MACROS, buf, bufsize); }

//------------------------------------------------------------------------
// HIGH LEVEL FUNCTIONS TO SUPPORT TILS IN THE IDA KERNEL

// Pointer to the local type library. This til is private for each
// IDB file.

idaman ida_export_data til_t *idati;

idaman char *ida_export get_tilpath(char *tilbuf, size_t tilbufsize);

idaman bool ida_export get_idainfo_by_type3(
        const tinfo_t &tif,
        size_t *psize,
        flags_t *pflags,
        opinfo_t *mt,
        size_t *alsize=NULL);

//-------------------------------------------------------------------------
// Lower type
// Inspect the type and lower all function subtypes using lower_func_type()
// We call the prototypes usually encountered in source files "high level"
// They may have implicit arguments, array arguments, big structure retvals, etc
// We introduce explicit arguments (e.i. 'this' pointer) and call the result
// "low level prototype". See FTI_HIGH
// Returns: 1 if removed FTI_HIGH, 2 is made substantial changes, -1-failure

idaman int ida_export lower_type(til_t *til, tinfo_t *tif, const char *name=NULL);

//------------------------------------------------------------------------
// Type information object: tinfo_t

struct ptr_type_data_t;
struct udt_type_data_t;
struct enum_type_data_t;
struct array_type_data_t;
struct typedef_type_data_t;
struct bitfield_type_data_t;

enum stock_type_id_t
{
  STI_PCHAR,          // char *
  STI_PUCHAR,         // uint8 *
  STI_PCCHAR,         // const char *
  STI_PCUCHAR,        // const uint8 *
  STI_PBYTE,          // _BYTE *
  STI_PINT,           // int *
  STI_PUINT,          // unsigned int *
  STI_PVOID,          // void *
  STI_PPVOID,         // void **
  STI_PCVOID,         // const void *
  STI_ACHAR,          // char[]
  STI_AUCHAR,         // uint8[]
  STI_ACCHAR,         // const char[]
  STI_ACUCHAR,        // const uint8[]
  STI_FPURGING,       // void __userpurge(int)
  STI_FDELOP,         // void __cdecl(void *)
  STI_MSGSEND,        // void *(void *, const char *, ...)
  STI_AEABI_LCMP,     // int __fastcall(int64 x, int64 y)
  STI_AEABI_ULCMP,    // int __fastcall(uint64 x, uint64 y)
  STI_GET_TASK,       // task_struct *func(void)
  STI_LAST
};

// Constants to be used with get_udt_details()
enum gtd_udt_t
{
  GTD_CALC_LAYOUT = 0,              // calculate udt layout
  GTD_NO_LAYOUT   = BTM_VOLATILE,   // don't calculate udt layout
                                    // please note that udt layout may have been
                                    // calculated earlier
  GTD_DEL_BITFLDS = BTM_CONST,      // delete udt bitfields
};

// Constants to be used with get_func_details()
enum gtd_func_t
{
  GTD_CALC_ARGLOCS= 0,              // calculate func arg locations
  GTD_NO_ARGLOCS  = BTM_VOLATILE,   // don't calculate func arg locations
                                    // please note that the locations may have been
                                    // calculated earlier
};

// Constants to be used with get_size()
enum gts_code_t
{
  GTS_NESTED = 0x01,                // nested type (embedded into a udt)
  GTS_BASECLASS = 0x02,             // is baseclass of a udt
};

// Error codes for save_tinfo functions:
enum tinfo_code_t
{
  TERR_OK = 0,          // ok
  TERR_SAVE = -1,       // failed to save
  TERR_SERIALIZE = -2,  // failed to serialize
  TERR_TOOLONGNAME = -3,// name is too long
};

// sudt_flags is a combination of the following bits:
#define SUDT_SORT     0x0001    // fields are not sorted by offset, sort them first
#define SUDT_ALIGN    0x0002    // recalculate field alignments, struct packing, etc
                                // to match the offsets and size info
#define SUDT_GAPS     0x0004    // allow to fill gaps with additional members (_BYTE[])
#define SUDT_UNEX     0x0008    // references to unexisting member types are acceptable
                                // in this case it is better to set the corresponding
                                // udm.fda field to the type alignment. if the udm.fda
                                // field is not set, ida will try to guess the alignment.
#define SUDT_FAST     0x0010    // serialize without verifying offsets and alignments

#define SUDT_CONST    0x0040    // only for serialize_udt: make type const
#define SUDT_VOLATILE 0x0080    // only for serialize_udt: make type volatile

#define SUDT_TRUNC    0x0100    // serialize: truncate useless strings from fields, fldcmts

#define DECLARE_TINFO_HELPERS(decl)\
decl void ida_export copy_tinfo_t(tinfo_t *_this, const tinfo_t &r); \
decl void ida_export clear_tinfo_t(tinfo_t *_this);\
decl bool ida_export create_tinfo(tinfo_t *_this, type_t bt, type_t bt2, void *ptr);\
decl int  ida_export verify_tinfo(uint32 typid);\
decl bool ida_export get_tinfo_details(uint32 typid, type_t bt2, void *buf);\
decl size_t ida_export get_tinfo_size(uint32 typid, uint32 *p_effalign, int gts_code);\
decl size_t ida_export get_tinfo_pdata(uint32 typid, void *outptr, int what);\
decl size_t ida_export get_tinfo_property(uint32 typid, int gta_prop);\
decl size_t ida_export set_tinfo_property(tinfo_t *tif, int sta_prop, size_t x);\
decl bool ida_export serialize_tinfo(qtype *type, qtype *fields, qtype *fldcmts, const tinfo_t *tif, int sudt_flags);\
decl bool ida_export deserialize_tinfo(tinfo_t *tif, const til_t *til, const type_t **ptype, const p_list **pfields, const p_list **pfldcmts);\
decl int  ida_export find_tinfo_udt_member(uint32 typid, int strmem_flags, struct udt_member_t *udm);\
decl bool ida_export print_tinfo(qstring *result, const char *prefix, int indent, int cmtindent, int flags, const tinfo_t *tif, const char *name, const char *cmt);\
decl const char *ida_export dstr_tinfo(const tinfo_t *tif);\
decl int  ida_export visit_subtypes(struct tinfo_visitor_t *visitor, struct type_mods_t *out, const tinfo_t &tif, const char *name, const char *cmt);\
decl bool ida_export compare_tinfo(uint32 t1, uint32 t2, int tcflags);\
decl int  ida_export lexcompare_tinfo(uint32 t1, uint32 t2, int);\
decl bool ida_export get_stock_tinfo(tinfo_t *tif, stock_type_id_t id);\
decl uint64 ida_export read_tinfo_bitfield_value(uint32 typid, uint64 v, int bitoff);\
decl uint64 ida_export write_tinfo_bitfield_value(uint32 typid, uint64 dst, uint64 v, int bitoff);\
decl bool ida_export get_tinfo_attr(uint32 typid, const qstring &key, bytevec_t *bv, bool all_attrs);\
decl bool ida_export set_tinfo_attr(tinfo_t *tif, const type_attr_t &ta, bool may_overwrite);\
decl bool ida_export del_tinfo_attr(tinfo_t *tif, const qstring &key);\
decl bool ida_export get_tinfo_attrs(uint32 typid, type_attrs_t *tav, bool include_ref_attrs);\
decl bool ida_export set_tinfo_attrs(tinfo_t *tif, type_attrs_t *ta);\
decl uint32 ida_export score_tinfo(const tinfo_t *tif);\
decl tinfo_code_t ida_export save_tinfo(til_t *til, size_t ord, const char *name, int ntf_flags, tinfo_t *tif);\

DECLARE_TINFO_HELPERS(idaman)

// bits 0..5:  base type
// bits 6..7:  const & volatile bits
// bit  8:     'is_typeref' bit
// bits 9..31: type detail idx
const int FIRST_NONTRIVIAL_TYPID = 0x100;
const int TYPID_ISREF = 0x100;
const int TYPID_SHIFT = 9;

class tinfo_t // #tinfo_t #tif
{
  uint32 typid;
  bool create_type(type_t decl_type, type_t bt2, void *details)
  {
    return create_tinfo(this, decl_type, bt2, details);
  }
  bool get_type_details(type_t bt2, void *buf) const { return get_tinfo_details(typid, bt2, buf); }
  void copy(const tinfo_t &r) { copy_tinfo_t(this, r); }
  DECLARE_TINFO_HELPERS(friend)
  friend struct type_detail_t;
  friend tinfo_t remove_pointer(const tinfo_t &tif);
  // Various type properties (properties are a 32-bit scalar values)
  enum gta_prop_t
  {
    GTA_DECLALIGN,      // declared alignment
    GTA_RESOLVE,        // real type (fully resolve eventual type references)
    GTA_REALTYPE,       // real type (do not fully resolve type refs)
    GTA_TYPE_SIGN,      // get type sign
    GTA_FROM_SUBTIL,    // is from a subtil (not from main til)
    GTA_IS_FORWARD,     // is forward declaration?
    GTA_IS_FUNCPTR,     // is a pointer to a function?
    GTA_ORDINAL,        // get initial type ordinal
    GTA_FINAL_ORDINAL,  // get final (resolved) type ordinal
    GTA_PTR_OBJ,        // ptr: pointed type
    GTA_SAFE_PTR_OBJ,   // ptr: pointed type or type itself
    GTA_ARRAY_ELEM,     // array: array element
    GTA_ARRAY_NELEMS,   // array: number of elements
    GTA_PTRARR_SUBTIF,  // ptr&array: pointed object or array element (nb: deletes current tif)
    GTA_PTRARR_SIZE,    // ptr&array: get size of subtype
    GTA_UNPADDED_SIZE,  // udt: sizeof baseclass when embedded into a derived class
    GTA_UDT_NMEMBERS,   // udt: get number of udt members
    GTA_IS_SMALL_UDT,   // udt: is small udt (can be passed in regs)
    GTA_ONEMEM_TYPE,    // udt&array: object consisting of one member: type of the member
    GTA_ENUM_BASE_TYPE, // enum: get enum base type
    GTA_FUNC_CC,        // func: calling convention
    GTA_PURGED_BYTES,   // func: number of purged bytes
    GTA_IS_HIGH_TYPE,   // func: is high type
    GTA_FUNC_NARGS,     // func: number of arguments
    GTA_FUNC_RET,       // func: get function return type
    GTA_FUNC_ARG,       // func: get type of function arg
    GTA_LAST_FUNC_ARG = GTA_FUNC_ARG + 255,
    GTA_IS_SSE_TYPE,    // is a SSE vector type
  };
  enum sta_prop_t       // set type property
  {
    STA_DECLALIGN,      // set declared alignment
    STA_TYPE_SIGN,      // set type sign
    STA_UDT_ALIGN,      // calculate udt field alignments
  };
  enum gta_pdata_t      // get info returned by pointer
  {
    GTP_NAME,           // get referenced name
    GTP_NEXT_NAME,      // get immediately next referenced name
    GTP_FINAL_NAME,     // get final referenced name
    GTP_TIL,            // get type library
  };

public:
  explicit tinfo_t(type_t decl_type=BT_UNK) : typid(decl_type) {} // can be used to initialize only simple types!
  tinfo_t(const tinfo_t &r) : typid(0) { copy(r); }
  tinfo_t &operator=(const tinfo_t &r) { copy(r); return *this; }
  ~tinfo_t(void) { clear(); }
  void clear(void) { clear_tinfo_t(this); }
  void swap(tinfo_t &r) { uint32 tmp = typid; typid = r.typid; r.typid = tmp; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  // Create a tinfo_t object for an existing named type.
  //  til       - type library to use
  //  name      - name of the type to link to
  //  decl_type - if the reference was explicitly specified with the type tag
  //              (BTF_STRUCT/BTF_UNION/BTF_ENUM) you may specify it.
  //              the kernel will accept only the specified tag after resolving
  //              the type. If the resolved type does not correspond to the
  //              explicitly specified tag, the type will be considered as undefined
  //  resolve   - true: immediately resolve the type and return success code
  //              false: return true but do not immediately resolve the type
  inline bool get_named_type(
        const til_t *til,
        const char *name,
        type_t decl_type=BTF_TYPEDEF,
        bool resolve=true);

  // Create a tinfo_t object for an existing ordinal type.
  //  til       - type library to use
  //  ordinal   - number of the type to link to
  //  decl_type - if the reference was explicitly specified with the type tag
  //              (BTF_STRUCT/BTF_UNION/BTF_ENUM) you may specify it.
  //              the kernel will accept only the specified tag after resolving
  //              the type. If the resolved type does not correspond to the
  //              explicitly specified tag, the type will be considered as undefined
  //  resolve   - true: immediately resolve the type and return success code
  //              false: return true but do not immediately resolve the type
  inline bool get_numbered_type(
        const til_t *til,
        uint32 ordinal,
        type_t decl_type=BTF_TYPEDEF,
        bool resolve=true);

  // Serialize tinfo_t object into a type string.
  bool serialize(
        qtype *type,
        qtype *fields=NULL,
        qtype *fldcmts=NULL,
        int sudt_flags=SUDT_FAST|SUDT_TRUNC) const
  {
    return serialize_tinfo(type, fields, fldcmts, this, sudt_flags);
  }

  // Deserialize a type string into a tinfo_t object
  bool deserialize(
        const til_t *til,
        const type_t **ptype,
        const p_list **pfields=NULL,
        const p_list **pfldcmts=NULL)
  {
    return deserialize_tinfo(this, til, ptype, pfields, pfldcmts);
  }
  bool deserialize(
        const til_t *til,
        const qtype *ptype,
        const qtype *pfields=NULL,
        const qtype *pfldcmts=NULL)
  {
    const type_t *tp = ptype->begin();
    const p_list *fp = pfields == NULL ? NULL : pfields->begin();
    const p_list *cp = pfldcmts == NULL ? NULL : pfldcmts->begin();
    return deserialize(til, &tp, fp == NULL ? NULL : &fp, cp == NULL ? NULL : &cp);
  }

  // Is the type object correct?
  // It is possible to create incorrect types. For example, we can define a
  // function that returns a enum and then delete the enum type.
  // If this function returns false, the type should not be used in
  // disassembly. Please note that this function does not verify all
  // involved types: for example, pointers to undefined types are permitted.
  bool is_correct(void) const { return verify_tinfo(typid) == 0; }

  // Get the resolved base type.
  // if full=true, the referenced type will be deserialized fully,
  //               this may not always be desirable (slows down things)
  // if full=false, we just return the base type, the referenced type will be
  //                resolved again later if necessary
  //                (this may lead to multiple resolvings of the same type)
  // imho full=false is a better approach because it does not perform
  // unnecessary actions just in case. however, in some cases the caller knows
  // that it is very likely that full type info will be required. in those cases
  // full=true makes sense
  type_t get_realtype(bool full=false) const { return get_tinfo_property(typid, full ? GTA_RESOLVE : GTA_REALTYPE); }

  // Get declared type (without resolving type references; they are returned as is)
  // Obviously this is a very fast function and should be used instead of get_realtype()
  // if possible.
  type_t get_decltype(void) const { return type_t(typid); }

  // Was tinfo_t initialized with some type info or not?
  bool empty(void) const { return get_decltype() == BT_UNK; }
  // Is the type really present? (not a reference to a missing type, for example)
  bool present(void) const { return get_realtype() != BT_UNK; }

  // Get the type size in bytes.
  //   p_effalign - buffer for the alignment value
  //   gts_code   - combination of GTS_... constants
  // Returns BADSIZE in case of problems
  size_t get_size(uint32 *p_effalign=NULL, int gts_code=0) const { return get_tinfo_size(typid, p_effalign, gts_code); }
  // Get the type size in bytes without the final padding.
  // For some UDTs get_unpadded_size() != get_size()
  size_t get_unpadded_size(void) const { return get_tinfo_property(typid, GTA_UNPADDED_SIZE); }

  // Get type sign
  type_sign_t get_sign(void) const { return get_tinfo_property(typid, GTA_TYPE_SIGN); }
  bool is_signed(void) const { return get_sign() == type_signed; }
  bool is_unsigned(void) const { return get_sign() == type_unsigned; }

  // Get declared alignment of the type.
  uchar get_declalign(void) const { return get_tinfo_property(typid, GTA_DECLALIGN); }
  bool set_declalign(uchar declalign) { return set_tinfo_property(this, STA_DECLALIGN, declalign) != 0; }

  // Type references can not be modified. Once created, they do not change.
  // Because of this, the set_... functions applied to typerefs create
  // a new type id. Other types are modified directly.
  bool is_typeref(void) const { return (typid & TYPID_ISREF) != 0; }
  bool has_details(void) const { return typid >= FIRST_NONTRIVIAL_TYPID; }
  // Does a type refer to a name?
  // If yes, full the provided buffer with the type name and return true.
  // Names are returned for numbered types too: either a user-defined nice name
  // or, if a user-provided name does not exist, an ordinal name
  // (like #xx, see create_numbered_type_name())
  bool get_type_name(qstring *name) const { return is_typeref() && get_tinfo_pdata(typid, name, GTP_NAME); }
  // In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn)
  // returns the name of the last type in the chain (TYPEn)
  // if there is no chain, returns TYPE1
  bool get_final_type_name(qstring *name) const { return is_typeref() && get_tinfo_pdata(typid, name, GTP_FINAL_NAME); }
  // In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3...TYPEn)
  // returns the name of the next type in the chain (TYPE2)
  // if there is no chain, returns failure
  bool get_next_type_name(qstring *name) const { return is_typeref() && get_tinfo_pdata(typid, name, GTP_NEXT_NAME); }
  // Get type ordinal (only if the type was created as a numbered type, 0 if none)
  uint32 get_ordinal(void) const { return get_tinfo_property(typid, GTA_ORDINAL); }
  // Get final type ordinal (0 is none)
  uint32 get_final_ordinal(void) const { return get_tinfo_property(typid, GTA_FINAL_ORDINAL); }
  // Get the type library for tinfo_t
  const til_t *get_til(void) const { const til_t *til; get_tinfo_pdata(typid, &til, GTP_TIL); return til; }
  // Was the named type found in some base type library (not the top level type libary)?
  // If yes, it usually means that the type comes from some loaded type library,
  // not the local type library for the database
  bool is_from_subtil(void) const { return is_typeref() && get_tinfo_property(typid, GTA_FROM_SUBTIL); }

  // Is this a forward declaration?
  // Forward declarations are placeholders: the type definition does not exist
  bool is_forward_decl(void) const { return get_tinfo_property(typid, GTA_IS_FORWARD) != 0; }

  // Probe the declared (unresolved) type for various attributes:
  bool is_decl_const(void) const    { return is_type_const(get_decltype());  }
  bool is_decl_volatile(void) const { return is_type_volatile(get_decltype()); }
  bool is_decl_void(void) const     { return is_type_void(get_decltype());     }
  bool is_decl_partial(void) const  { return is_type_partial(get_decltype());  }
  bool is_decl_unknown(void) const  { return is_type_unknown(get_decltype());  }
  bool is_decl_last(void) const     { return is_typeid_last(get_decltype());   }
  bool is_decl_ptr(void) const      { return is_type_ptr(get_decltype());      }
  bool is_decl_array(void) const    { return is_type_array(get_decltype());    }
  bool is_decl_func(void) const     { return is_type_func(get_decltype());     }
  bool is_decl_complex(void) const  { return is_type_complex(get_decltype());  }
  bool is_decl_typedef(void) const  { return is_type_typedef(get_decltype());  }
  bool is_decl_sue(void) const      { return is_type_sue(get_decltype());      }
  bool is_decl_struct(void) const   { return is_type_struct(get_decltype());   }
  bool is_decl_union(void) const    { return is_type_union(get_decltype());    }
  bool is_decl_udt(void) const      { return is_type_struni(get_decltype());   }
  bool is_decl_enum(void) const     { return is_type_enum(get_decltype());     }
  bool is_decl_bitfield(void) const { return is_type_bitfld(get_decltype());   }
  bool is_decl_int128(void) const   { return is_type_int128(get_decltype());   }
  bool is_decl_int64(void) const    { return is_type_int64(get_decltype());    }
  bool is_decl_int32(void) const    { return is_type_int32(get_decltype());    }
  bool is_decl_int16(void) const    { return is_type_int16(get_decltype());    }
  bool is_decl_char(void) const     { return is_type_char(get_decltype());     }
  bool is_decl_uint(void) const     { return is_type_uint(get_decltype());     }
  bool is_decl_uchar(void) const    { return is_type_uchar(get_decltype());    }
  bool is_decl_uint16(void) const   { return is_type_uint16(get_decltype());   }
  bool is_decl_uint32(void) const   { return is_type_uint32(get_decltype());   }
  bool is_decl_uint64(void) const   { return is_type_uint64(get_decltype());   }
  bool is_decl_uint128(void) const  { return is_type_uint128(get_decltype());  }
  bool is_decl_ldouble(void) const  { return is_type_ldouble(get_decltype());  }
  bool is_decl_double(void) const   { return is_type_double(get_decltype());   }
  bool is_decl_float(void) const    { return is_type_float(get_decltype());    }
  bool is_decl_floating(void) const { return is_type_floating(get_decltype()); }
  bool is_decl_bool(void) const     { return is_type_bool(get_decltype());     }
  bool is_decl_paf(void) const      { return is_type_paf(get_decltype());      }
  bool is_well_defined(void) const  { return !empty() && !is_decl_partial();   }

  // Probe the resolved type for various attributes:
  bool is_const(void) const    { return is_type_const(get_realtype());    }
  bool is_volatile(void) const { return is_type_volatile(get_realtype()); }
  bool is_void(void) const     { return is_type_void(get_realtype());     }
  bool is_partial(void) const  { return is_type_partial(get_realtype());  }
  bool is_unknown(void) const  { return is_type_unknown(get_realtype());  }
  bool is_ptr(void) const      { return is_type_ptr(get_realtype());      }
  bool is_array(void) const    { return is_type_array(get_realtype());    }
  bool is_func(void) const     { return is_type_func(get_realtype());     }
  bool is_complex(void) const  { return is_type_complex(get_realtype());  }
  bool is_struct(void) const   { return is_type_struct(get_realtype());   }
  bool is_union(void) const    { return is_type_union(get_realtype());    }
  bool is_udt(void) const      { return is_type_struni(get_realtype());   }
  bool is_enum(void) const     { return is_type_enum(get_realtype());     }
  bool is_sue(void) const      { return is_type_sue(get_realtype());      }
  bool is_bitfield(void) const { return is_type_bitfld(get_realtype());   }
  bool is_int128(void) const   { return is_type_int128(get_realtype());   }
  bool is_int64(void) const    { return is_type_int64(get_realtype());    }
  bool is_int32(void) const    { return is_type_int32(get_realtype());    }
  bool is_int16(void) const    { return is_type_int16(get_realtype());    }
  bool is_char(void) const     { return is_type_char(get_realtype());     }
  bool is_uint(void) const     { return is_type_uint(get_realtype());     }
  bool is_uchar(void) const    { return is_type_uchar(get_realtype());    }
  bool is_uint16(void) const   { return is_type_uint16(get_realtype());   }
  bool is_uint32(void) const   { return is_type_uint32(get_realtype());   }
  bool is_uint64(void) const   { return is_type_uint64(get_realtype());   }
  bool is_uint128(void) const  { return is_type_uint128(get_realtype());  }
  bool is_ldouble(void) const  { return is_type_ldouble(get_realtype());  }
  bool is_double(void) const   { return is_type_double(get_realtype());   }
  bool is_float(void) const    { return is_type_float(get_realtype());    }
  bool is_bool(void) const     { return is_type_bool(get_realtype());     }
  bool is_paf(void) const      { return is_type_paf(get_realtype());      }
  bool is_ptr_or_array(void) const { return is_type_ptr_or_array(get_realtype());}
  bool is_integral(void) const { return is_type_integral(get_realtype());}
  bool is_ext_integral(void) const { return is_type_ext_integral(get_realtype());}
  bool is_floating(void) const { return is_type_floating(get_realtype()); }
  bool is_arithmetic(void) const { return is_type_arithmetic(get_realtype()); }
  bool is_ext_arithmetic(void) const { return is_type_ext_arithmetic(get_realtype()); }
  bool is_scalar(void) const  { type_t bt = get_realtype(); return get_base_type(bt) <= BT_PTR || is_type_enum(bt); }

  // Get the type details.
  // The information is copied to the user-supplied buffer.
  // Also check out convenience functions below, they work faster because
  // they do not copy the entire type info but only the desired part of it.
  bool get_ptr_details(ptr_type_data_t *pi) const           { return get_type_details(BT_PTR, pi); }
  bool get_array_details(array_type_data_t *ai) const       { return get_type_details(BT_ARRAY, ai); }
  bool get_enum_details(enum_type_data_t *ei) const         { return get_type_details(BTF_ENUM, ei); }
  bool get_bitfield_details(bitfield_type_data_t *bi) const { return get_type_details(BT_BITFIELD, bi); }
  bool get_udt_details(udt_type_data_t *udt, gtd_udt_t gtd=GTD_CALC_LAYOUT) const
  {
    return get_type_details(BTF_STRUCT|gtd, udt);
  }
  bool get_func_details(func_type_data_t *fi, gtd_func_t gtd=GTD_CALC_ARGLOCS) const
  {
    return get_type_details(BT_FUNC|gtd, fi);
  }

  // Is a pointer to a function?
  bool is_funcptr(void) const { return get_tinfo_property(typid, GTA_IS_FUNCPTR) != 0; }

  // BT_PTR & BT_ARRAY: get size of pointed object or array element. On error returns -1
  int get_ptrarr_objsize(void) const { return get_tinfo_property(typid, GTA_PTRARR_SIZE); }

  // BT_PTR & BT_ARRAY: get the pointed object or array element
  // If the current type is not a pointer or array, return empty type info.
  tinfo_t get_ptrarr_object(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_PTRARR_SUBTIF); return r; }

  // BT_PTR: get type of pointed object.
  // If the current type is not a pointer, return empty type info.
  // See also get_ptrarr_object() and remove_pointer()
  tinfo_t get_pointed_object(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_PTR_OBJ); return r; }

  // Is "void *"? This function does not check the pointer attributes and type modifiers
  bool is_pvoid(void) const { return get_pointed_object().is_void(); }

  // BT_ARRAY: get type of array element. See also get_ptrarr_object()
  tinfo_t get_array_element(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_ARRAY_ELEM); return r; }

  // BT_ARRAY: get number of elements (-1 means error)
  int get_array_nelems(void) const { return get_tinfo_property(typid, GTA_ARRAY_NELEMS); }

  // BT_FUNC or BT_PTR BT_FUNC: get type of n-th arg (-1 means return type, see get_rettype)
  tinfo_t get_nth_arg(int n) const
  {
    tinfo_t r;
    if ( n >= -1 && n < MAX_FUNC_ARGS )
      r.typid = get_tinfo_property(typid, GTA_FUNC_ARG+n);
    return r;
  }
  tinfo_t get_rettype(void) const { return get_nth_arg(-1); }

  // BT_FUNC or BT_PTR BT_FUNC: calculate number of arguments (-1 - error)
  int get_nargs(void) const { return get_tinfo_property(typid, GTA_FUNC_NARGS); }

  // BT_FUNC or BT_PTR BT_FUNC: get calling convention
  cm_t get_cc(void) const { return get_tinfo_property(typid, GTA_FUNC_CC); }
  bool is_user_cc(void) const { return ::is_user_cc(get_cc()); }
  bool is_vararg_cc(void) const { return ::is_vararg_cc(get_cc()); }
  bool is_purging_cc(void) const { return ::is_purging_cc(get_cc()); }

  // BT_FUNC: calculate number of purged bytes
  int calc_purged_bytes(void) const { return get_tinfo_property(typid, GTA_PURGED_BYTES); }

  // BT_FUNC: is high level type?
  bool is_high_func(void) const { return get_tinfo_property(typid, GTA_IS_HIGH_TYPE) != 0; }

  // BTF_STRUCT,BTF_UNION: find a udt member:
  //   - at the specified offset  (STRMEM_OFFSET)
  //   - with the specified index (STRMEM_INDEX)
  //   - with the specified type  (STRMEM_TYPE)
  //   - with the specified name  (STRMEM_NAME)
  // returns the index of the found member or -1
  int find_udt_member(int strmem_flags, struct udt_member_t *udm) const { return find_tinfo_udt_member(typid, strmem_flags, udm); }
#define STRMEM_MASK    0x0007  // the search type:
#define   STRMEM_OFFSET 0x0000 //   get member by offset
                               //   in:  udm->offset - is a member offset in bits
#define   STRMEM_INDEX  0x0001 //   get member by number
                               //   in:  udm->offset - is a member number
#define   STRMEM_AUTO   0x0002 //   get member by offset if struct
                               //   get member by index if union
                               //     nb: union: index is stored in the udm->offset field!
                               //     nb: struct: offset is in bytes (not in bits)!
#define   STRMEM_NAME   0x0003 //   get member by name
                               //   in:  udm->name - the desired member name.
#define   STRMEM_TYPE   0x0004 //   get member by type.
                               //   in:  udm->type - the desired member type.
                               //   member types are compared with tinfo_t::equals_to()
#define   STRMEM_SIZE   0x0005 //   get member by size.
                               //   in:  udm->size - the desired member size.
#define   STRMEM_MINS   0x0006 //   get smallest member by size.
#define   STRMEM_MAXS   0x0007 //   get biggest member by size.
#define STRMEM_ANON 0x80000000 // can be combined with STRMEM_NAME:
                               //   look inside anonymous members too.
#define STRMEM_CASTABLE_TO 0x40000000
                               // can be combined with STRMEM_TYPE:
                               //   member type must be castable to the specified type
  // get number of udt members. -1-error
  int get_udt_nmembers(void) const { return get_tinfo_property(typid, GTA_UDT_NMEMBERS); }
  // Is an empty struct/union? (has no fields)
  bool is_empty_udt(void) const { return get_udt_nmembers() == 0; }
  // Is a small udt? (can fit a register or a pair of registers)
  bool is_small_udt(void) const { return get_tinfo_property(typid, GTA_IS_SMALL_UDT) != 0; }
  // floating value or an onject  consisting of one floating member entirely
  bool is_one_fpval(void) const { return get_onemember_type().is_floating(); }
  // is a SSE vector type?
  bool is_sse_type(void) const { return get_tinfo_property(typid, GTA_IS_SSE_TYPE) != 0; }

  // Get enum base type (convert enum to integer type)
  // Returns BT_UNK if failed to convert
  type_t get_enum_base_type(void) const { return get_tinfo_property(typid, GTA_ENUM_BASE_TYPE); }

  // For objects consisting of one member entirely: return type of the member
  tinfo_t get_onemember_type(void) const { tinfo_t r; r.typid = get_tinfo_property(typid, GTA_ONEMEM_TYPE); return r; }
  // Calculate the type score (the higher - the nicer is the type)
  uint32 calc_score(void) const { return score_tinfo(this); }

  bool print(
        qstring *out,
        const char *name=NULL,
        int prtype_flags=PRTYPE_1LINE,
        int indent=0,
        int cmtindent=0,
        const char *prefix=NULL,
        const char *cmt=NULL) const
  {
    return print_tinfo(out, prefix, indent, cmtindent, prtype_flags, this, name, cmt);
  }
  const char *dstr(void) const { return dstr_tinfo(this); }

  // get type attributes (all_attrs: include attributes of referenced types, if any)
  bool get_attrs(type_attrs_t *tav, bool all_attrs=false) const { return get_tinfo_attrs(typid, tav, all_attrs); }
  // get a type attribute
  bool get_attr(const qstring &key, bytevec_t *bv, bool all_attrs=true) const { return get_tinfo_attr(typid, key, bv, all_attrs); }
  // set type attributes. if necessary, a new typid will be created.
  // this function modifies tav! (returns old attributes, if any)
  // returns false: bad attributes
  bool set_attrs(type_attrs_t *tav) { return set_tinfo_attrs(this, tav); }
  // set a type attribute. if necessary, a new typid will be created.
  bool set_attr(const type_attr_t &ta, bool may_overwrite=true) { return set_tinfo_attr(this, ta, may_overwrite); }
  // del all type attributes. typerefs can not be modified by this function.
  void del_attrs(void) { set_tinfo_attrs(this, NULL); }
  // del a type attribute. typerefs can not be modified by this function.
  bool del_attr(const qstring &key) { return del_tinfo_attr(this, key); }

  bool create_simple_type(type_t decl_type) { return create_type(decl_type, BT_INT, NULL); }
  bool create_ptr(const ptr_type_data_t &p, type_t decl_type=BT_PTR) { return create_type(decl_type, BT_PTR, (void*)&p); }
  bool create_array(const array_type_data_t &p, type_t decl_type=BT_ARRAY) { return create_type(decl_type, BT_ARRAY, (void*)&p); }
  bool create_typedef(const typedef_type_data_t &p, type_t decl_type=BTF_TYPEDEF) { return create_type(decl_type, BTF_TYPEDEF, (void *)&p); }
  bool create_bitfield(const bitfield_type_data_t &p, type_t decl_type=BT_BITFIELD) { return create_type(decl_type, BT_BITFIELD, (void*)&p); }

  // convenience functions
  inline bool create_ptr(const tinfo_t &tif, uchar bps=0, type_t decl_type=BT_PTR);
  inline bool create_array(const tinfo_t &tif, uint32 nelems=0, uint32 base=0, type_t decl_type=BT_ARRAY);
  inline void create_typedef(const til_t *til, const char *name, type_t decl_type=BTF_TYPEDEF) { get_named_type(til, name, decl_type, false); }
  inline void create_typedef(const til_t *til, uint ord, type_t decl_type=BTF_TYPEDEF) { get_numbered_type(til, ord, decl_type, false); }
  inline bool create_bitfield(uchar nbytes, uchar width, bool is_unsigned=false, type_t decl_type=BT_BITFIELD);
  // these functions consume 'p' (make it empty)
  bool create_udt(udt_type_data_t &p, type_t decl_type) { return create_type(decl_type, BTF_STRUCT, &p); }
  bool create_enum(enum_type_data_t &p, type_t decl_type=BTF_ENUM) { return create_type(decl_type, BTF_ENUM, &p); }
  bool create_func(func_type_data_t &p, type_t decl_type=BT_FUNC) { return create_type(decl_type, BT_FUNC, &p); }

  // Store the type info in the type library as a named or numbered type.
  // The tinfo_t object will be replaced by a reference to the created type.
  // Allowed bits for ntf_flags: NTF_NOBASE, NTF_REPLACE
  tinfo_code_t set_named_type(til_t *til, const char *name, int ntf_flags=0) { return save_tinfo(til, 0, name, ntf_flags, this); }
  tinfo_code_t set_numbered_type(til_t *til, uint32 ord, int ntf_flags=0, const char *name=NULL) { return save_tinfo(til, ord, name, ntf_flags, this); }

  // Create a forward declaration
  // decl_type: BTF_STRUCT, BTF_UNION, or BTF_ENUM
  bool create_forward_decl(til_t *til, type_t decl_type, const char *name, int ntf_flags=0)
  {
    create_typedef(til, "", decl_type);
    return set_named_type(til, name, ntf_flags) == TERR_OK;
  }

  // Get stock type information.
  // This function can be used to get tinfo_t for some common types.
  // The same tinfo_t will be returned for the same id, thus saving memory
  // and increasing the speed
  static tinfo_t get_stock(stock_type_id_t id) { tinfo_t t; get_stock_tinfo(&t, id); return t; }

  // Convert an array into a pointer.
  // type[] => type *
  inline bool convert_array_to_ptr(void);

  // Replace the current type with the ptr obj or array element.
  // This function performs one of the following conversions:
  //    type[] => type
  //    type*  => type
  // If the conversion is performed successfully, return true
  inline bool remove_ptr_or_array(void)
  {
    tinfo_t tif = get_ptrarr_object();
    if ( tif.empty() )
      return false;
    swap(tif);
    return true;
  }

  // Change the type sign. Works only for the types that may have sign
  bool change_sign(type_sign_t sign) { return set_tinfo_property(this, STA_TYPE_SIGN, sign) != 0; }

  // Calculate the udt alignments using the field offsets/sizes and the total udt size
  // This function does not work on typerefs
  bool calc_udt_aligns(int sudt_flags=SUDT_GAPS)
    { return set_tinfo_property(this, STA_UDT_ALIGN, sudt_flags) != 0; }

  // Helper functions to store/extract bitfield values
  uint64 read_bitfield_value(uint64 v, int bitoff) const { return read_tinfo_bitfield_value(typid, v, bitoff); }
  uint64 write_bitfield_value(uint64 dst, uint64 v, int bitoff) const { return write_tinfo_bitfield_value(typid, dst, v, bitoff); }

  // Work with type modifiers: const and volatile
  type_t get_modifiers(void) const { return typid & TYPE_MODIF_MASK; }
  void set_modifiers(type_t mod) { if ( !empty() ) typid = (typid & ~TYPE_MODIF_MASK) | (mod & TYPE_MODIF_MASK); }
  void set_const(bool on=true) { if ( !empty() ) setflag(typid, BTM_CONST, on); }
  void set_volatile(bool on=true) { if ( !empty() ) setflag(typid, BTM_VOLATILE, on); }

  DECLARE_COMPARISONS(tinfo_t)
  { // simple comparison: good enough to organize std::map, etc
    // for this function "unsigned char" and "uchar" are different
    // for deeper comparison see compare_with()
    return lexcompare_tinfo(typid, r.typid, 0);
  }
#define TCMP_EQUAL    0x0000 // are types equal?
#define TCMP_IGNMODS  0x0001 // ignore const/volatile modifiers
#define TCMP_AUTOCAST 0x0002 // can t1 be cast into t2 automatically?
#define TCMP_MANCAST  0x0004 // can t1 be cast into t2 manually?
#define TCMP_CALL     0x0008 // can t1 be called with t2 type?
#define TCMP_DELPTR   0x0010 // remove pointer from types before comparing
#define TCMP_DECL     0x0020 // compare declarations without resolving them
  bool compare_with(const tinfo_t &r, int tcflags=0) const { return compare_tinfo(typid, r.typid, tcflags); }
  bool equals_to(const tinfo_t &r) const { return compare_with(r, 0); }
  bool is_castable_to(const tinfo_t &target) const { return compare_with(target, TCMP_AUTOCAST); }
  bool is_manually_castable_to(const tinfo_t &target) const { return compare_with(target, TCMP_MANCAST); }
};
DECLARE_TYPE_AS_MOVABLE(tinfo_t);
typedef qvector<tinfo_t> tinfovec_t;

//------------------------------------------------------------------------
// Do not use these functions directly, use class member functions
idaman cm_t ida_export guess_func_cc(
        const func_type_data_t &fti,
        int npurged,
        int cc_flags);

struct ptr_type_data_t          // #ptr
{
  tinfo_t obj_type;             // pointed object type
  tinfo_t closure;              // can not have both closure and based_ptr_size
  uchar based_ptr_size;
  uchar taptr_bits;             // tah bits
  ptr_type_data_t(tinfo_t c=tinfo_t(), uchar bps=0)
    : closure(c), based_ptr_size(bps), taptr_bits(0) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(ptr_type_data_t &r) { qswap(*this, r); }
  bool operator == (const ptr_type_data_t &r) const
  {
    return obj_type == r.obj_type
        && closure == r.closure
        && based_ptr_size == r.based_ptr_size;
  }
  bool operator != (const ptr_type_data_t &r) const { return !(*this == r); }
  bool is_code_ptr(void) const { return obj_type.is_func(); }
};
DECLARE_TYPE_AS_MOVABLE(ptr_type_data_t);

struct array_type_data_t // #array
{
  tinfo_t elem_type;
  uint32 base;          // array base
  uint32 nelems;        // number of elements
  array_type_data_t(size_t b=0, size_t n=0) : base(b), nelems(n) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(array_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(array_type_data_t);

//-------------------------------------------------------------------------
struct funcarg_t
{
  argloc_t argloc;      // argument location
  qstring name;         // argument name (may be empty)
  qstring cmt;          // argument name (may be empty)
  tinfo_t type;         // argument type
  uint32 flags;         // various argument features
#define FAI_HIDDEN 0x0001 // hidden argument
#define FAI_RETPTR 0x0002 // pointer to return value. implies hidden
#define FAI_STRUCT 0x0004 // was initially a structure
#define FAI_ARRAY  0x0008 // was initially an array
                          // see "__org_typedef" or "__org_arrdim" type attributes
                          // to determine the original type
#define TA_ORG_TYPEDEF "__org_typedef" // the original typedef name (simple string)
#define TA_ORG_ARRDIM  "__org_arrdim"  // the original array dimension (append_dd)
  funcarg_t(void) : flags(0) {}
  bool operator == (const funcarg_t &r) const
  {
    return argloc == r.argloc
        && name == r.name
//        && cmt == r.cmt
        && type == r.type;
  }
  bool operator != (const funcarg_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(funcarg_t);
typedef qvector<funcarg_t> funcargvec_t;

struct func_type_data_t : public funcargvec_t // #func
{
  int flags;
#define FTI_SPOILED  0x0001 // information about spoiled registers is present
#define FTI_NORET    0x0002 // noreturn
#define FTI_PURE     0x0004 // __pure
#define FTI_HIGH     0x0008 // high level prototype (with possibly hidden args)
#define FTI_STATIC   0x0010 // static
#define FTI_VIRTUAL  0x0020 // virtual
#define FTI_CALLTYPE 0x00C0 //
#define FTI_DEFCALL  0x0000 // default call
#define FTI_NEARCALL 0x0040 // near call
#define FTI_FARCALL  0x0080 // far call
#define FTI_INTCALL  0x00C0 // interrupt call
#define FTI_ARGLOCS  0x0100 // info about argument locations has been calculated
                            // (stkargs and retloc too)
#define FTI_ALL      0x01FF // all defined bits
  tinfo_t rettype;      // return type
  argloc_t retloc;      // return location
  uval_t stkargs;       // size of stack arguments (not used in build_func_type)
  reginfovec_t spoiled; // spoiled register information
                        // if spoiled register info is present, it overrides
                        // the standard spoil info (eax, edx, ecx for x86)
  cm_t cc;              // calling convention
  func_type_data_t(): flags(0), stkargs(0), cc(0) {}
  void swap(func_type_data_t &r) { qswap(*this, r); }
  bool is_high(void) const { return (flags & FTI_HIGH) != 0; }
  int get_call_method(void) const { return flags & FTI_CALLTYPE; }
  cm_t get_cc(void) const
  {
    cm_t ret = ::get_cc(cc);
    // if the calling convention is not specified, use the default one
    if ( ret <= CM_CC_UNKNOWN )
      ret = ::get_cc(inf.cc.cm);
    return ret;
  }
  // guess function calling convention
  // use the following info: argument locations and 'stkargs'
  cm_t guess_cc(int purged, int cc_flags) const
  {
    return guess_func_cc(*this, purged, cc_flags);
  }
#define CC_CDECL_OK        0x01 // can use __cdecl calling convention?
#define CC_ALLOW_ARGPERM   0x02 // disregard argument order?
#define CC_ALLOW_REGHOLES  0x04 // allow holes in register argument list?
#define CC_HAS_ELLIPSIS    0x08 // function has a variable list of arguments?
};

const int FTI_CALLSHIFT = 2;
CASSERT(BTMT_NEARCALL << FTI_CALLSHIFT == FTI_NEARCALL
     && BTMT_FARCALL  << FTI_CALLSHIFT == FTI_FARCALL
     && BTMT_INTCALL  << FTI_CALLSHIFT == FTI_INTCALL);

//-------------------------------------------------------------------------
struct enum_member_t
{
  qstring name;
  qstring cmt;
  uint64 value;
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  bool operator == (const enum_member_t &r) const
  {
    return name == r.name
//        && cmt == r.cmt
        && value == r.value;
  }
  bool operator != (const enum_member_t &r) const { return !(*this == r); }
  void swap(enum_member_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(enum_member_t);

struct enum_type_data_t : public qvector<enum_member_t> // #enum
{
  intvec_t group_sizes; // if present, specifies bitfield group sizes
                        // each group starts with a mask member
  uint32 taenum_bits;   // TAENUM_... bits
  bte_t bte;            // enum member sizes (shift amount) and style
  enum_type_data_t(bte_t _bte=BTE_ALWAYS|BTE_HEX) : taenum_bits(0), bte(_bte) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  bool is_64bit(void) const { return (taenum_bits & TAENUM_64BIT) != 0; }
  bool is_hex(void) const  { return (bte & BTE_OUT_MASK) == BTE_HEX;  }
  bool is_char(void) const { return (bte & BTE_OUT_MASK) == BTE_CHAR; }
  bool is_sdec(void) const { return (bte & BTE_OUT_MASK) == BTE_SDEC; }
  bool is_udec(void) const { return (bte & BTE_OUT_MASK) == BTE_UDEC; }
  int calc_nbytes(void) const
  {
    int emsize = bte & BTE_SIZE_MASK;
    return emsize != 0 ? 1 << (emsize-1) : int(get_default_enum_size(inf.cc.cm));
  }
  uint64 calc_mask(void) const { return left_shift(uint64(1), calc_nbytes()*8) - 1; }
  bool is_unsigned(void) const { return get_sign() == type_unsigned; }
  bool is_signed(void) const { return !is_unsigned(); }
  type_sign_t get_sign(void) const;      // do not use. use tinfo_t::get_sign()
  type_t get_enum_base_type(void) const; // do not use. use tinfo_t::get_enum_base_type()
  bool deserialize_enum(                 // do not use.
        int cnt,
        const type_t **ptype,
        const p_list **pfields,
        const p_list **pfldcmts);
  void swap(enum_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(enum_type_data_t);

//-------------------------------------------------------------------------
struct typedef_type_data_t // #typedef
{
  const til_t *til;     // type library to use when resolving
  union
  {
    const char *name;   // is_ordref=false: target type name. we do not own this pointer!
    uint32 ordinal;     // is_ordref=true: type ordinal number
  };
  bool is_ordref;       // is reference by ordinal?
  bool resolve;         // should resolve immediately?
  typedef_type_data_t(const til_t *_til, const char *_name, bool _resolve=false)
    : til(_til), name(_name), is_ordref(false), resolve(_resolve) {}
  typedef_type_data_t(const til_t *_til, uint32 ord, bool _resolve=false)
    : til(_til), ordinal(ord), is_ordref(true), resolve(_resolve) {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(typedef_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(typedef_type_data_t);

//-------------------------------------------------------------------------
// An object to represent struct or union members
struct udt_member_t     // #udm
{
  uint64 offset;        // member offset in bits
  uint64 size;          // size in bits
  qstring name;         // member name
  qstring cmt;          // member comment
  tinfo_t type;         // member type
  int effalign;         // effective field alignment (in bytes)
  uint32 tafld_bits;    // TAH bits
  uchar fda;            // field alignment (shift amount)
  udt_member_t(void)
    : offset(0), size(0), effalign(0), tafld_bits(0), fda(0)
  {
  }
  bool is_bitfield(void) const { return type.is_decl_bitfield(); }
  bool is_zero_bitfield(void) const { return size == 0 && is_bitfield(); }
  bool is_unaligned(void) const { return (tafld_bits & TAFLD_UNALIGNED) != 0; }
  bool is_baseclass(void) const { return (tafld_bits & TAFLD_BASECLASS) != 0; }
  bool is_virtbase(void)  const { return (tafld_bits & TAFLD_VIRTBASE) != 0; }
  void set_unaligned(void) { tafld_bits |= TAFLD_UNALIGNED; }
  void set_baseclass(void) { tafld_bits |= TAFLD_BASECLASS; }
  void set_virtbase(void) { tafld_bits |= TAFLD_VIRTBASE; }
  void clr_unaligned(void) { tafld_bits &= ~TAFLD_UNALIGNED; }
  void clr_baseclass(void) { tafld_bits &= ~TAFLD_BASECLASS; }
  void clr_virtbase(void) { tafld_bits &= ~TAFLD_VIRTBASE; }
  uint64 begin(void) const { return offset; }
  uint64 end(void) const { return offset + size; }
  bool operator < (const udt_member_t &r) const
  {
    return offset < r.offset;
  }
  bool operator == (const udt_member_t &r) const
  {
    return offset == r.offset
        && size == r.size
        && name == r.name
//        && cmt == r.cmt
        && type == r.type
        && fda == r.fda
        && tafld_bits == r.tafld_bits
        && effalign == r.effalign;
  }
  bool operator != (const udt_member_t &r) const { return !(*this == r); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(udt_member_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(udt_member_t);

// An object to represent struct or union types
struct udt_type_data_t : public qvector<udt_member_t> // #udt
{
  size_t total_size;    // total structure size in bytes
  size_t unpadded_size; // unpadded structure size in bytes (unpadded, for c++ objects)
  uint32 effalign;      // effective structure alignment (in bytes)
  uint32 taudt_bits;    // TA... and TAUDT... bits
  uchar sda;            // declared structure alignment (shift amount)
  uchar pack;           // #pragma pack() alignment (shift amount)
  bool is_union;        // is union or struct?

  udt_type_data_t(void)
    : total_size(0), unpadded_size(0), effalign(0),
      taudt_bits(0), sda(0), pack(0),
      is_union(false)
  {
  }
  void swap(udt_type_data_t &r) { qswap(*this, r); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  bool is_unaligned(void) const { return (taudt_bits & TAUDT_UNALIGNED) != 0; }
  bool is_msstruct(void) const { return (taudt_bits & TAUDT_MSSTRUCT) != 0; }
  bool is_cppobj(void) const { return (taudt_bits & TAUDT_CPPOBJ) != 0; }
};
DECLARE_TYPE_AS_MOVABLE(udt_type_data_t);

//-------------------------------------------------------------------------
struct bitfield_type_data_t // #bitfield
{
  uchar nbytes;         // enclosing type size (1,2,4,8 bytes)
  uchar width;          // number of bits
  bool is_unsigned;     // is bitfield unsigned?
  bitfield_type_data_t(uchar _nbytes=0, uchar _width=0, bool _is_unsigned=false)
    : nbytes(_nbytes), width(_width), is_unsigned(_is_unsigned)
  {
  }
  bool serialize(qtype *type, type_t mods) const;
  DECLARE_COMPARISONS(bitfield_type_data_t)
  {
    if ( nbytes != r.nbytes )
      return nbytes > r.nbytes ? 1 : -1;
    if ( width != r.width )
      return width > r.width ? 1 : -1;
    if ( is_unsigned )
    {
      if ( !r.is_unsigned )
        return 1;
    }
    else
    {
      if ( r.is_unsigned )
        return -1;
    }
    return 0;
  }
  void swap(bitfield_type_data_t &r) { qswap(*this, r); }
};
DECLARE_TYPE_AS_MOVABLE(bitfield_type_data_t);

//-------------------------------------------------------------------------
inline bool tinfo_t::get_named_type(
        const til_t *til,
        const char *name,
        type_t decl_type,
        bool resolve)
{
  typedef_type_data_t tp(til, name, resolve);
  return create_typedef(tp, decl_type);
}

inline bool tinfo_t::get_numbered_type(
        const til_t *til,
        uint32 ordinal,
        type_t decl_type,
        bool resolve)
{
  typedef_type_data_t tp(til, ordinal, resolve);
  return create_typedef(tp, decl_type);
}

inline bool tinfo_t::create_ptr(
        const tinfo_t &tif,
        uchar bps,
        type_t decl_type)
{
  ptr_type_data_t pi(tinfo_t(), bps);
  pi.obj_type = tif;
  return create_ptr(pi, decl_type);
}

inline bool tinfo_t::create_array(
        const tinfo_t &tif,
        uint32 nelems,
        uint32 base,
        type_t decl_type)
{
  array_type_data_t ai(base, nelems);
  ai.elem_type = tif;
  return create_array(ai, decl_type);
}

inline bool tinfo_t::create_bitfield(
        uchar nbytes,
        uchar width,
        bool _is_unsigned,
        type_t decl_type)
{
  bitfield_type_data_t bi(nbytes, width, _is_unsigned);
  return create_bitfield(bi, decl_type);
}

inline bool tinfo_t::convert_array_to_ptr(void)
{
  bool ok = false;
  array_type_data_t ai;
  if ( get_array_details(&ai) )
  {
    ptr_type_data_t pi;
    pi.obj_type.swap(ai.elem_type);
    create_ptr(pi);
    ok = true;
  }
  return ok;
}

// BT_PTR: If the current type is a pointer, return the pointed object
// If the current type is not a pointer, return the current type.
// See also get_ptrarr_object() and get_pointed_object()
inline tinfo_t remove_pointer(const tinfo_t &tif)
{
  tinfo_t r;
  r.typid = get_tinfo_property(tif.typid, tinfo_t::GTA_SAFE_PTR_OBJ);
  return r;
}

// information how to modify the current type. used by tinfo_visitor_t.
struct type_mods_t
{
  tinfo_t type;
  qstring name;
  qstring cmt;
  int flags;
#define TVIS_TYPE  0x0001       // new type info is present
#define TVIS_NAME  0x0002       // new name is present
#define TVIS_CMT   0x0004       // new comment is present
  type_mods_t(void) : flags(0) {}
  void clear(void) { flags = 0; }

  // The visit_type() function may optionally save the modified type info.
  // Use the following functions for that. The new name and comment will be applied
  // only if the current tinfo element has storage for them.
  void set_new_type(const tinfo_t &t) { type = t; flags |= TVIS_TYPE; }
  void set_new_name(const qstring &n) { name = n; flags |= TVIS_NAME; }
  void set_new_cmt(const qstring &c)  { cmt = c;  flags |= TVIS_CMT; }

  bool has_type(void) const { return (flags & TVIS_TYPE) != 0; }
  bool has_name(void) const { return (flags & TVIS_NAME) != 0; }
  bool has_cmt(void)  const { return (flags & TVIS_CMT) != 0; }
  bool has_info(void) const { return flags != 0; }
};

// Visit all subtypes of a type. Derive your visitor from this class and use apply_to()
struct tinfo_visitor_t
{
  int state;
#define TVST_PRUNE 0x01
#define TVST_DEF   0x02 // typeref: visit type definition

  tinfo_visitor_t(int s=0) : state(s) {} // may use TVST_DEF the type definition
                                         // needs to be visited (meaningful for typerefs)
  DEFINE_VIRTUAL_DTOR(tinfo_visitor_t)

  // visit a subtype.
  // this function must be implemented in the derived class.
  // it may optionally fill out with the new type info. this can be used to
  // modify types (in this case the 'out' argument of apply_to() may not be NULL)
  // return 0 to continue the traversal.
  // return !=0 to stop the traveral.
  virtual int idaapi visit_type(
        type_mods_t *out,
        const tinfo_t &tif,
        const char *name,
        const char *cmt) = 0;

  // to refuse to visit children of the current type, use this:
  void prune_now(void) { state |= TVST_PRUNE; }

  // call this function to initiate the traversal
  int apply_to(const tinfo_t &tif, type_mods_t *out=NULL, const char *name=NULL, const char *cmt=NULL)
  {
    return visit_subtypes(this, out, tif, name, cmt);
  }
};


//------------------------------------------------------------------------
// Definitions for packing/unpacking idc objects

struct regobj_t                         // object that represents a register
{
  int regidx;                           // index into dbg->registers
  int relocate;                         // 0-plain num, 1-must relocate
  bytevec_t value;
  size_t size(void) const { return value.size(); }
};
struct regobjs_t : public qvector<regobj_t>
{
};

// Read a typed idc object from the database
idaman error_t ida_export unpack_idcobj_from_idb(
        idc_value_t *obj,
        const tinfo_t &tif,
        ea_t ea,
        const bytevec_t *off0,  // if !NULL: bytevec that represents object at 'ea'
        int pio_flags=0);
#define PIO_NOATTR_FAIL 0x0004  // missing attributes are not ok
#define PIO_IGNORE_PTRS 0x0008  // do not follow pointers

// Read a typed idc object from the byte vector
idaman error_t ida_export unpack_idcobj_from_bv(
        idc_value_t *obj,
        const tinfo_t &tif,
        const bytevec_t &bytes,
        int pio_flags=0);

// Write a typed idc object to the database
idaman error_t ida_export pack_idcobj_to_idb(
        const idc_value_t *obj,
        const tinfo_t &tif,
        ea_t ea,
        int pio_flags=0);

// Write a typed idc object to the byte vector
// Byte vector may be non-empty, this function will append data to it
idaman error_t ida_export pack_idcobj_to_bv(
        const idc_value_t *obj,
        const tinfo_t &tif,
        relobj_t *bytes,
        void *objoff,         // NULL - append object to 'bytes'
                              // if not NULL:
                              //   in: int32*: offset in 'bytes' for the object
                              //       -1 means 'do not store the object itself in bytes
                              //                 store only pointed objects'
                              //   out: data for object (if *(int32*)objoff == -1)
        int pio_flags=0);


struct get_strmem_t
{
  int flags;            // STRMEM_.. flags
  int index;            // member index
  asize_t offset;       // member offset
  asize_t delta;        // search by offset: offset from the member start
  qstring name;         // member name
  qtype ftype;          // member type
  qtype fnames;         // member field names
  qstring sname;        // structure type name
};

// get a structure member:
//   - at the specified offset  (STRMEM_OFFSET)
//   - with the specified index (STRMEM_INDEX)
//   - with the specified type  (STRMEM_TYPE)
//   - with the specified name  (STRMEM_NAME)
idaman bool ida_export get_strmem2(
        const til_t *til,
        const type_t *type,   // in: type
        const p_list *fields, // in: fields. for typedefs may be NULL
        get_strmem_t *info);  // in/out


// helper function for the processor modules
// to be called from ph.use_stkarg_type
idaman bool ida_export apply_tinfo_to_stkarg(
        const op_t &x,
        uval_t v,
        const tinfo_t &tif,
        const char *name);

//------------------------------------------------------------------------
// helper function for the processor modules
// to be called from ph.use_arg_types() to do everything
// 3 callbacks should be provided:

// set the operand type as specified

typedef bool idaapi set_op_tinfo_t(op_t &x, const tinfo_t &type, const char *name);


// is the current insn a stkarg load?
// if yes, src - index of the source operand in Cmd.Operands
//         dst - index of the destination operand in Cmd.Operands
//               cmd.Operands[dst].addr is expected to have the stack offset

typedef bool idaapi is_stkarg_load_t(int *src, int *dst);


// the call instruction with a delay slot?

typedef bool idaapi has_delay_slot_t(ea_t caller);


// the main function using these callbacks:

idaman void ida_export gen_use_arg_tinfos(
        ea_t caller,
        func_type_data_t *fti,
        funcargvec_t *rargs,
        set_op_tinfo_t *set_optype,
        is_stkarg_load_t *is_stkarg_load,
        has_delay_slot_t *has_delay_slot);

enum update_type_t
{
  UTP_ENUM,
  UTP_STRUCT,
};

// If you plan to add or modify types massively then use
// the following functions to mark the beginning and the end
// of the update operation. For example, these functions
// can be used with add_enum_member(), add_struc_member(), etc...
idaman void ida_export begin_type_updating(update_type_t utp);
idaman void ida_export end_type_updating(update_type_t utp);

//--------------------------------------------------------------------------
struct format_data_info_t
{
  int ptvf;             // combination of PTV_... constants:
#define PTV_DEREF  0x0001  // take value to print from the debugged process.
                           // VT_LONG: the address is specifed by idc_value.num
                           // VT_PVOID: argloc_t is pointed by idc_value.pvoid
#define PTV_QUEST  0x0002  // print '?' for uninited data
#define PTV_EMPTY  0x0004  // return empty string for uninited data
                           // should not specify PTV_QUEST and PTV_EMPTY together
#define PTV_CSTR   0x0008  // print constant strings inline
#define PTV_EXPAND 0x0010  // print only top level on separate lines
                           // max_length applies to separate lines
                           // margin is ignored
#define PTV_LZHEX  0x0020  // print hex numbers with leading zeroes
#define PTV_STPFLT 0x0040  // fail on bad floating point numbers
                           // (if not set, just print ?flt for them)
#define PTV_SPACE  0x0080  // add spaces after commas and around braces
#define PTV_DEBUG  0x0100  // format output for debugger
#define PTV_NTOP   0x40000000 // internal flag, do not use
#define PTV_KEEP   0x80000000 // internal flag, do not use
  int radix;            // number representation (8,10,16)
  int max_length;       // max length of the formatted text (0 means no limit)
                        // should be used to format huge arrays for the screen,
                        // we can not display the whole array anyway
                        // if this limit is hit, the function returns false
                        // and qerrno is set to eMaxLengthExceeded
  int arrbase;          // for arrays: the first element of array to print
  int arrnelems;        // for arrays: number of elements to print
  int margin;           // length of one line (0 means to print everything on one line)
                        // if an item can not be printed in a shorter way,
                        // some output lines can be considerably longer
                        // 1 means each item on its own line
  int indent;           // how many spaces to use to indent nested structures/arrays

  format_data_info_t(void)
    : ptvf(PTV_EMPTY|PTV_CSTR|PTV_SPACE), radix(10), max_length(0),
      arrbase(0), arrnelems(0),
      margin(80), indent(2) {}
};

// Additional information about the output lines
struct valinfo_t
{
  argloc_t loc;
  qstring label;
  tinfo_t type;
  valinfo_t(argloc_t l=argloc_t(), const char *name=NULL, const tinfo_t tif=tinfo_t())
    : loc(l), label(name), type(tif) {}
  void swap(valinfo_t &r)
  {
    loc.swap(r.loc);
    label.swap(r.label);
    type.swap(r.type);
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(valinfo_t);


// Text representation of a data value (value_string).
// This structure is used before we decide how to represent it,
// on one line or on many lines
class valstr_t
{
public:
  qstring oneline;              // result if printed on one line in utf-8 encoding
  size_t length;                // length if printed on one line
  struct valstrs_t *members;    // strings for members, each member separately
  valinfo_t *info;              // additional info
  int props;                    // temporary properties, used internally
#define VALSTR_OPEN 0x01        //   printed opening curly brace '{'

  valstr_t(void) : length(0), members(NULL), info(NULL), props(0) {}
  ~valstr_t(void);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
private:
  struct flatten_args_t
  {
    const valstr_t *may_not_collapse;
    int ptvf;
    int max_length;
    int margin;
    int indent;
  };
  friend struct valstr_sink_t;
  void update_length(int ptvf);
  void set_oneline(const char *line, int len)
  {
    oneline.append(line, len);
    length = oneline.length();
  }
  void consume_oneline(const qstring &line)
  {
    oneline.append(line);
    length = oneline.length();
  }
  bool append_char(char c, int max_length);
  bool convert_to_one_line(int ptvf, int max_length);
  bool flatten(const flatten_args_t &flargs, int level);
};
DECLARE_TYPE_AS_MOVABLE(valstr_t);
struct valstrs_t : public qvector<valstr_t> {};

inline valstr_t::~valstr_t(void)
{
  delete members;
  delete info;
}


// Format a data value as a C initializer
//  outvec     - buffer for the formatted string(s). may be NULL
//  idc_value  - value to format
//  tif        - type of the data to format
//               if NULL and PTV_DEREF is specified, take tinfo from idb
//  vtree      - more detailed output info
//  fdi        - formatting options. points to the following struct
// Returns: success. if failed, see qerrno for more info

idaman bool ida_export format_cdata2(
        qstrvec_t *outvec,
        const idc_value_t &idc_value,
        const tinfo_t *tif,
        valstr_t *vtree=NULL,
        const format_data_info_t *fdi=NULL);

struct text_sink_t
{
  // flush formatted text. returns 0-ok, otherwise print_cdata will stop
  virtual int idaapi print(const char *str) = 0;
};

// The same as above, but instead of returning the answer in a vector, print it.
// This function can handle very huge data volume without using too much memory.
// As soon as the output text becomes too long, the function prints it and
// flushes its internal buffers.
// Returns 0  - ok
//         -1 - printing failed, check qerrno
//         other values - code returned by text_sink_t::print()

idaman int ida_export print_cdata(
        text_sink_t &printer,
        const idc_value_t &idc_value,
        const tinfo_t *tif,
        const format_data_info_t *fdi=NULL);

// Calculate max number of lines of a formatted c data, when expanded (PTV_EXPAND)
//  loc        - location of the data (ALOC_STATIC or ALOC_CUSTOM)
//  tif        - type info
//  dont_deref_ptr - consider 'ea' as the ptr value
// Returns: 0-data is not expandable, -1-error, see qerrno
//          otherwise the max number of lines

idaman int ida_export calc_number_of_children(
        const argloc_t &loc,
        const tinfo_t &tif,
        bool dont_deref_ptr=false);


// Format a C number
//      buf     - output buffer
//      bufsize - size of the output buffer
//      value   - number to format
//      size    - size of the number in bytes (1,2,4,8,16)
//      flags   - how to represent the number (dec,hex,...)
//      color   - color tag to use. 0 means do not color
//      pcn     - combination of PCN_... bits

idaman size_t ida_export format_c_number(
        char *buf,
        size_t bufsize,
        uint128 value,
        int size,
        int pcn=0);
#define PCN_RADIX    0x07 // number base to use:
#define PCN_DEC      0x00 //   decimal
#define PCN_HEX      0x01 //   hexadecimal
#define PCN_OCT      0x02 //   octal
#define PCN_CHR      0x03 //   character
#define PCN_UNSIGNED 0x08 // add 'u' suffix
#define PCN_LZHEX    0x10 // print leading zeroes for hexdecimal number
#define PCN_NEGSIGN  0x20 // print negated value (-N) for negative numbers


// Return a C expression that can be used to represent a enum member
//      type    - enumeration type
//      serial  - which enumeration member to use (0 means the first with the given value)
//      value   - value to search in the enumeration type. only 32-bit number can be handled yet
//      buf     - output buffer
//      bufsize - size of the output buffer
// If the value does not correspond to any single enum member, this function tries
// to find a bitwise combination of enum members that correspond to it.
// If more than half of value bits do not match any enum members, it fails.
// Returns: success.

idaman bool ida_export get_enum_member_expr2(
        char *buf,
        size_t bufsize,
        const tinfo_t &tif,
        int serial,
        uint64 value);

inline bool idaapi is_autosync(const char *name, const tinfo_t &tif)
{
  type_t decl_type = tif.get_decltype();
  return get_ordinal_from_idb_type(name, &decl_type) != -1;
}

//-------------------------------------------------------------------------
// Dialogs to choose a symbol from a type library
//------------------------------------------------------------------------

struct til_symbol_t
{
  const char *name;         // symbol name
  const til_t *til;         // pointer to til
  til_symbol_t(const char *n = NULL, const til_t *t = NULL): name(n), til(t) {}
};
DECLARE_TYPE_AS_MOVABLE(til_symbol_t);

// Choose a type from a type library
//      root_til  - pointer to starting til (the function will inspect the base tils if allowed by flags)
//      title     - title of listbox to display
//      ntf_flags - combination of NTF_... flags
//      func      - predicate to select types to display (maybe NULL)
//      sym       - pointer to be filled with the chosen type
// returns: false-nothing is chosen, otherwise true

typedef bool idaapi predicate_t(const char *name, const type_t *type, const p_list *fields);

idaman bool ida_export choose_named_type2(
                const til_t *root_til,
                const char *title,
                int ntf_flags,
                predicate_t *func,
                til_symbol_t* sym);

idaman const char *ida_export choose_named_type(
                const til_t *root_til,
                const char *title,
                int ntf_flags,
                predicate_t *func);


// Choose a type from the local type library
//      ti        - pointer to til
//      title     - title of listbox to display
//      func      - predicate to select types to display (maybe NULL)
//                   0 - skip type, 1-include, 2-preselect
// returns: <=0-nothing is chosen, otherwise an ordinal number

typedef int idaapi local_tinfo_predicate_t(uint32 ord, const tinfo_t &type, void *ud);

idaman uint32 ida_export choose_local_tinfo(
                const til_t *ti,
                const char *title,
                local_tinfo_predicate_t *func,
                void *ud);

// FIXME: DEPREC
typedef int idaapi local_predicate_t(uint32 ord, const type_t *type, const p_list *fields, void *ud);

idaman uint32 ida_export choose_local_type(
                const til_t *ti,
                const char *title,
                local_predicate_t *func,
                void *ud);

//------------------------------------------------------------------------
// The rest of the file contains deprecated declarations.
// They are useful to compile old plugins but ideally all plugins should
// switch to newer functions instead of using deprecated ones.
//------------------------------------------------------------------------
#if !defined(NO_OBSOLETE_FUNCS) || defined(DATAVALS_SOURCE)
struct valinfo_deprecated2_t
{
  ea_t ea;
  qstring label;
  tinfo_t type;
  valinfo_deprecated2_t(ea_t e=BADADDR, const char *name=NULL, const tinfo_t tif=tinfo_t())
    : ea(e), label(name), type(tif) {}
  void swap(valinfo_deprecated2_t &r)
  {
    ea_t tmp = ea; ea = r.ea; r.ea = tmp;
    label.swap(r.label);
    type.swap(r.type);
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(valinfo_deprecated2_t);
class valstr_deprecated2_t
{
public:
  qstring oneline;
  size_t length;
  struct valstrs_deprecated2_t *members;
  valinfo_deprecated2_t *info;

  valstr_deprecated2_t(void) : length(0), members(NULL), info(NULL) {}
  ~valstr_deprecated2_t(void);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void cvt_from(const valstr_t &v);
};
DECLARE_TYPE_AS_MOVABLE(valstr_deprecated2_t);
struct valstrs_deprecated2_t : public qvector<valstr_deprecated2_t> {};
inline valstr_deprecated2_t::~valstr_deprecated2_t(void)
{
  delete members;
  delete info;
}
struct valinfo_deprecated_t
{
  ea_t ea;
  qstring label;
  qtype type;
  qtype fields;
  valinfo_deprecated_t(ea_t e=BADADDR, const char *name=NULL, const type_t *t=NULL, const p_list *f=NULL)
    : ea(e), label(name), type(t), fields(f) {}
  void swap(valinfo_deprecated_t &r)
  {
    ea_t tmp = ea; ea = r.ea; r.ea = tmp;
    label.swap(r.label);
    type.swap(r.type);
    fields.swap(r.fields);
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(valinfo_deprecated_t);
class valstr_deprecated_t
{
public:
  qstring oneline;
  size_t length;
  struct valstrs_deprecated_t *members;
  valinfo_deprecated_t *info;

  valstr_deprecated_t(void) : length(0), members(NULL), info(NULL) {}
  ~valstr_deprecated_t(void);
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void cvt_from(const valstr_deprecated2_t &v);
};
DECLARE_TYPE_AS_MOVABLE(valstr_deprecated_t);
struct valstrs_deprecated_t : public qvector<valstr_deprecated_t> {};
inline valstr_deprecated_t::~valstr_deprecated_t(void)
{
  delete members;
  delete info;
}
#endif
#if !defined(NO_OBSOLETE_FUNCS) || defined(VARLOCS_SOURCE)
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4996)
#endif
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
class varloc_t;
class scattered_vloc_t;
#ifdef __X64__
idaman DEPRECATED scattered_vloc_t *ida_export get_scattered_varloc(int idx);
idaman DEPRECATED int ida_export set_scattered_varloc(scattered_vloc_t *);
#else
CASSERT(sizeof(int32) == sizeof(scattered_vloc_t *));
inline scattered_vloc_t *get_scattered_varloc(int idx);
inline int set_scattered_varloc(scattered_vloc_t *ptr);
#endif
#define VARLOC_HELPER_DEFINITIONS(decl) \
decl DEPRECATED void ida_export copy_varloc(varloc_t *dst, const varloc_t *src); \
decl DEPRECATED void ida_export cleanup_varloc(varloc_t *vloc);
VARLOC_HELPER_DEFINITIONS(idaman)

#define BAD_VARLOC (-1)
class varloc_t // #varloc
{
  int32 value;
#define VLOC_MASK  0xC0000000
#define VLOC_STACK 0x00000000
#define VLOC_PTR   0x40000000
#define VLOC_REG1  0x80000000
#define VLOC_REG2  0xC0000000
#define VLOC_MAX_STKOFF 0x1FFFFFFF
  scattered_vloc_t *get_ptr(void) { return get_scattered_varloc(index()); }
  int index(void) const { return value & ~VLOC_MASK; }
  VARLOC_HELPER_DEFINITIONS(friend)

public:
  varloc_t(void) : value(BAD_VARLOC) {}
  varloc_t(const varloc_t &r) : value(BAD_VARLOC) { copy_varloc(this, &r); }
  ~varloc_t(void) { cleanup_varloc(this); }
  varloc_t &operator=(const varloc_t &r) { copy_varloc(this, &r); return *this; }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void swap(varloc_t &r) { int32 tmp = value; value = r.value; r.value = tmp; }
  int32 get_value(void) const { return value; }
  uint32 type(void) const { return value & VLOC_MASK; }

  bool is_reg1(void)       const { return type() == VLOC_REG1; }
  bool is_reg2(void)       const { return type() == VLOC_REG2 && value != BAD_VARLOC; }
  bool is_reg(void)        const { return (value+1) < 0; } // high bit set but not -1
  bool is_stkoff(void)     const { return type() == VLOC_STACK; }
  bool is_scattered(void)  const { return type() == VLOC_PTR; }
  bool is_fragmented(void) const { return (value & 0x40000000) != 0; } // scattered or register pair
  bool is_badloc(void)     const { return value == BAD_VARLOC; }

  int reg1(void) const { return (value << 17) >> 17; }
  int regoff(void) const { return (value << 2) >> 17; } // offset from the beginning of the register in bytes
  int reg2(void) const { return (value << 2) >> 17; }
  int stkoff(void) const { return (value << 2) >> 2; }
        scattered_vloc_t &scattered(void)       { return *get_ptr(); }
  const scattered_vloc_t &scattered(void) const { return *CONST_CAST(varloc_t *)(this)->get_ptr(); }
  void _set_badloc(void) { value = BAD_VARLOC; }
  void _set_reg1(int reg, int off=0) { value = (((off << 15) | reg) & ~VLOC_MASK) | VLOC_REG1; }
  void _set_reg2(int _reg1, int _reg2) { value = (((_reg2 << 15) | _reg1) & ~VLOC_MASK) | VLOC_REG2; }
  void _set_stkoff(int off) { value = off & ~VLOC_MASK; }
  bool _consume_scattered(scattered_vloc_t *p)
  {
    if ( p == NULL )
      return false;
    value = set_scattered_varloc(p) | VLOC_PTR;
    return true;
  }
  void set_reg1(int reg, int off=0) { cleanup_varloc(this); _set_reg1(reg, off); }
  void set_reg2(int _reg1, int _reg2) { cleanup_varloc(this); _set_reg2(_reg1, _reg2); }
  void set_stkoff(int off) { cleanup_varloc(this); _set_stkoff(off); }
  void consume_scattered(scattered_vloc_t *p) { cleanup_varloc(this); _consume_scattered(p); }
  void set_badloc(void) { cleanup_varloc(this); }
  int calc_offset(void) const
  {
    if ( type() == VLOC_REG1 )
      return reg1();
    if ( type() == VLOC_STACK )
      return stkoff();
    return -1;
  }
  bool advance(int delta)
  {
    if ( type() == VLOC_REG1 )
    {
      _set_reg1(reg1()+delta, regoff());
      return true;
    }
    if ( type() == VLOC_STACK )
    {
      _set_stkoff(stkoff()+delta);
      return true;
    }
    return false;
  }
};
DECLARE_TYPE_AS_MOVABLE(varloc_t);
typedef qvector<varloc_t> varlocs_t;
struct varpart_t : public varloc_t
{
  ushort off;
  ushort size;
  varpart_t(void) : off(0xFFFF), size(0) {}
  bool bad_offset(void) const { return off == 0xFFFF; }
  bool bad_size(void) const { return size == 0; }
};
DECLARE_TYPE_AS_MOVABLE(varpart_t);
class scattered_vloc_t : public qvector<varpart_t>
{
};
DECLARE_TYPE_AS_MOVABLE(scattered_vloc_t);
#ifndef __X64__
inline scattered_vloc_t *get_scattered_varloc(int idx)
{
  return (scattered_vloc_t *)(idx << 2);
}
inline int set_scattered_varloc(scattered_vloc_t *ptr)
{
  return size_t(ptr) >> 2;
}
#endif
typedef bool idaapi predicate_t(const char *name, const type_t *type, const p_list *fields);
typedef int idaapi local_predicate_t(uint32 ord, const type_t *type, const p_list *fields, void *ud);
#endif
#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED int ida_export add_til(const char *name);
inline DEPRECATED bool is_type_voiddef(type_t t) { return(get_full_type(t) == BTF_VOID); }
inline DEPRECATED bool is_type_void_obsolete(type_t t) { return(get_base_type(t) == BT_VOID); }
inline DEPRECATED bool is_type_unk(type_t t)     { return(get_base_type(t) == BT_UNK); }
inline DEPRECATED bool is_type_only_size(type_t t){ return get_base_type(t) <= BT_VOID; }
idaman DEPRECATED bool ida_export apply_type(ea_t ea, const type_t *type, const p_list *fields);
idaman DEPRECATED bool ida_export apply_type2(ea_t ea, const type_t *rtype, const p_list *fields, int userti);
idaman DEPRECATED bool ida_export parse_type(const char *decl, char **name, type_t **type, p_list **fields, int flags=0);
idaman DEPRECATED int ida_export parse_types(const char *input, bool isfile, printer_t *printer);
idaman DEPRECATED int ida_export parse_types2(const char *input, printer_t *printer, int hti_flags);
idaman DEPRECATED bool ida_export resolve_complex_type(const type_t **ptype, const p_list **fields, char *fname, size_t fnamesize, type_t *bt, int *N);
idaman DEPRECATED int ida_export foreach_strmem(const type_t *type, const p_list *fields, int N, bool is_union, int idaapi func(uint32 offset, const type_t *type, const p_list *fields, const char *name, void *ud), void *ud);
idaman DEPRECATED bool ida_export get_struct_member(const type_t *type, const p_list *fields, asize_t offset, asize_t *delta, char *name, size_t namesize, type_t *ftype, size_t typesize, p_list *ffields, size_t ffldsize, char *sname, size_t snamesize);
idaman DEPRECATED bool ida_export apply_cdecl(ea_t ea, const char *decl);
idaman DEPRECATED tid_t ida_export til2idb(int idx, const char *name);
idaman DEPRECATED bool ida_export get_idainfo_by_type(const type_t *&rtype, const p_list *fields, size_t *psize,  flags_t *pflags,  opinfo_t *mt, size_t *alsize=NULL);
idaman DEPRECATED bool ida_export remove_pointerness(const type_t **ptype, const char **pname);
idaman DEPRECATED int  ida_export get_pointer_object_size(const type_t *t);
idaman DEPRECATED bool ida_export is_type_scalar(const type_t *type);
idaman DEPRECATED type_sign_t ida_export get_type_signness(const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_const  (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_void   (const type_t *type); // really void?
idaman DEPRECATED bool ida_export is_resolved_type_ptr    (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_func   (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_array  (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_complex(const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_struct (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_union  (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_struni (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_enum   (const type_t *type);
idaman DEPRECATED bool ida_export is_resolved_type_bitfld (const type_t *type);
idaman DEPRECATED bool ida_export is_castable(const type_t *from, const type_t *to);
idaman DEPRECATED int ida_export guess_func_type(func_t *pfn, type_t *type, size_t tsize, p_list *fields, size_t fsize);
idaman DEPRECATED int ida_export guess_type(tid_t id, type_t *type, size_t tsize, p_list *fields, size_t fsize);
idaman DEPRECATED bool ida_export make_array_type(type_t *buf, size_t bufsize, const type_t *type, int size);
idaman DEPRECATED type_t *ida_export extract_func_ret_type(const type_t *type, type_t *buf, int bufsize);
idaman DEPRECATED int ida_export get_func_nargs(const type_t **type);
idaman DEPRECATED int ida_export build_funcarg_arrays(const type_t *type, const p_list *fields, uint32 *arglocs, type_t **types, char **names, int maxargs, bool remove_constness);
idaman DEPRECATED void ida_export free_funcarg_arrays(type_t **types, char **names, int n);
idaman DEPRECATED int ida_export calc_arglocs(const type_t *&type, uint32 *arglocs, int maxn);
idaman DEPRECATED const type_t *ida_export resolve_typedef(const til_t *ti, const type_t *p, const p_list **fields);
idaman DEPRECATED bool ida_export get_strmem(const til_t *til, const type_t *type, const p_list *fields, asize_t offset, asize_t *delta, qstring *name, qtype *ftype=NULL, qtype *fnames=NULL, qstring *sname=NULL);
idaman DEPRECATED bool ida_export get_strmem_by_name(const til_t *til, const type_t *type, const p_list *fields, const char *name, asize_t *offset, qtype *ftype=NULL, qtype *fnames=NULL, qstring *sname=NULL);
idaman DEPRECATED int ida_export calc_argloc_info(const til_t *til, const type_t *type, varloc_t *arglocs, size_t maxn);
idaman DEPRECATED type_t *ida_export set_argloc(type_t *pt, int reg, int reghi=-1, bool ret=false);
// Old mehod of specifying the argument location
typedef uint32 argloc_old_t;            // In the uint32 form we keep first register
                                    // at the LSB and the second register shifted << 8
                                    // The 2 high bits of argloc_old_t denote the presence
                                    // of the registers; if none is present, it
                                    // is a stack argument and the argloc_old_t value
                                    // denotes the offset from the stack top (usually
                                    // 0 for the first stack argument)
typedef qvector<argloc_old_t> old_arglocvec_t;

#define BAD_ARGLOC      argloc_old_t(-1) // invalid argloc value
#define ARGLOC_REG      0x80000000L // argument is in a register
#define ARGLOC_REG2     0x40000000L // second register is present
inline DEPRECATED bool is_reg_argloc(uint32 argloc) { return (argloc & ARGLOC_REG) != 0; }
inline DEPRECATED bool is_stack_argloc(uint32 argloc) { return !is_reg_argloc(argloc); }
inline DEPRECATED bool is_reg2_argloc(uint32 reg_argloc) { return (reg_argloc & ARGLOC_REG2) != 0; }
// get the first register
inline DEPRECATED int get_argloc_r1(uint32 reg_argloc) { return (reg_argloc & 0x7FFF); }
// get the second register
inline DEPRECATED int get_argloc_r2(uint32 reg_argloc) { return (reg_argloc >> 15) & 0x7FFF; }
inline DEPRECATED argloc_old_t make_old_argloc(int r1, int r2)
{
  argloc_old_t a = 0;
  if ( r1 != -1 ) a |= ARGLOC_REG | r1;
  if ( r2 != -1 ) a |= ARGLOC_REG2 | (r2 << 15);
  return a;
}
inline DEPRECATED void split_old_argloc(argloc_old_t al, int *r1, int *r2)
{
  if ( is_reg_argloc(al) )
  {
    *r1 = get_argloc_r1(al);
    *r2 = is_reg2_argloc(al) ? get_argloc_r2(al) : -1;
  }
  else
  {
    *r1 = -1;
    *r2 = -1;
  }
}
inline DEPRECATED void extract_old_argloc(const type_t *&ptr, int *p1, int *p2)
{
  type_t high = *ptr++;
  *p1 = (high & 0x7F) - 1;
  if ( high > 0x80 )
    *p2 = *ptr++ - 1;
  else
    *p2 = -1;
}

inline DEPRECATED argloc_old_t extract_old_argloc(const type_t *&ptr)
{
  int p1, p2;
  extract_old_argloc(ptr, &p1, &p2);
  return make_old_argloc(p1, p2);
}

// returns 0 if a stack argument
inline DEPRECATED uint32 extract_and_convert_old_argloc(const type_t *&tp)
{
  int r1, r2;
  extract_old_argloc(tp, &r1, &r2);
  if ( r1 == -1 ) // stack argument
    return 0;
  return make_old_argloc(r1, r2);
}
idaman DEPRECATED void ida_export calc_cpp_name(const char *name, const type_t *type, char *buf, size_t bufsize);
idaman DEPRECATED bool ida_export print_type(ea_t ea, char *buf, size_t bufsize, bool one_line);
#define NTF_NOIDB    0x0010     // ignored
idaman DEPRECATED size_t ida_export get_type_size(const til_t *ti, const type_t *&ptr, size_t *lp=NULL);
inline DEPRECATED size_t get_type_size0(const til_t *ti, const type_t *ptr, size_t *lp=NULL)
{
  return get_type_size(ti, ptr, lp);
}
idaman DEPRECATED bool ida_export build_func_type(qtype *p_type, qtype *p_fields, const func_type_data_t &fi);
struct type_visitor_t
{
  virtual int idaapi visit_type(const type_t *type) = 0;
  DEFINE_VIRTUAL_DTOR(type_visitor_t)
};
idaman DEPRECATED int ida_export for_all_types(const type_t **ptype, type_visitor_t &tv);
struct type_pair_t
{
  qtype type1;
  qtype type2;
  type_pair_t(void) {}
  type_pair_t(const qtype &l) : type1(l) {}
  type_pair_t(const qtype &l, const qtype &g) : type1(l), type2(g) {}
};
struct type_pair_vec_t : qvector<type_pair_t>
{
};
idaman DEPRECATED int ida_export replace_subtypes(qtype &type, const type_pair_vec_t &type_pairs);
struct type_mapper_t
{
  virtual bool map_type(qtype *out, const type_t **type) = 0;
  DEFINE_VIRTUAL_DTOR(type_mapper_t)
};
idaman DEPRECATED int ida_export replace_subtypes2(const til_t *ti, qtype *type, type_mapper_t &mapper);
idaman DEPRECATED bool ida_export get_enum_member_expr(const type_t *type, int serial, uint64 value, char *buf, size_t bufsize);
idaman DEPRECATED bool ida_export print_c_data(text_sink_t &printer, const idc_value_t &idc_value, const til_t *til, const type_t *type, const p_list *fields=NULL, const format_data_info_t *const_fdi=NULL);
idaman DEPRECATED int ida_export calc_max_number_of_children(ea_t ea, const til_t *til, const type_t *type, const p_list *fields=NULL, bool dont_deref_ptr=false);
idaman DEPRECATED bool ida_export format_c_data(qstrvec_t *outvec, const idc_value_t &idc_value, const til_t *til, const type_t *type, const p_list *fields=NULL, valstr_deprecated_t *vtree=NULL, const format_data_info_t *fdi=NULL);
idaman DEPRECATED bool ida_export format_cdata(qstrvec_t *outvec, const idc_value_t &idc_value, const tinfo_t *tif, valstr_deprecated2_t *vtree=NULL, const format_data_info_t *fdi=NULL);
idaman DEPRECATED error_t ida_export unpack_object_from_idb(idc_value_t *obj, const til_t *ti, const type_t *type, const p_list *fields, ea_t ea, const bytevec_t *off0, int pio_flags=0);
idaman DEPRECATED error_t ida_export unpack_object_from_bv(idc_value_t *obj, const til_t *ti, const type_t *type, const p_list *fields, const bytevec_t &bytes, int pio_flags=0);
idaman DEPRECATED error_t ida_export pack_object_to_idb(const idc_value_t *obj, const til_t *ti, const type_t *type, const p_list *fields, ea_t ea, int pio_flags=0);
idaman DEPRECATED error_t ida_export pack_object_to_bv(const idc_value_t *obj, const til_t *ti, const type_t *type, const p_list *fields, relobj_t *bytes, void *objoff, int pio_flags=0);
idaman DEPRECATED bool ida_export deref_ptr(const til_t *ti, const type_t *type, ea_t *ptr_ea, ea_t *closure_obj=NULL);
idaman DEPRECATED int ida_export guess_tinfo(tid_t id, qtype *type, qtype *fields);
idaman DEPRECATED int ida_export guess_func_tinfo(func_t *pfn, qtype *type, qtype *fields);
idaman DEPRECATED const type_t *ida_export get_enum_base_type(const type_t *type);
idaman DEPRECATED type_t *ida_export set_dt(type_t *pt, int value);
idaman DEPRECATED type_t *ida_export set_da(type_t *pt, uint32 num_el, uint32 base = 0);
idaman DEPRECATED type_t *ida_export set_de(type_t *pt, uint32 val);
idaman DEPRECATED type_t *ida_export set_complex_n(type_t *pt, uint32 val, bool is_empty_udt);
idaman DEPRECATED int  ida_export get_dt(const type_t **ptype);                             // returns < 0 - error
idaman DEPRECATED bool ida_export get_da(const type_t **ptype, uint32 *num_el, uint32 *base); // returns false - error
idaman DEPRECATED int ida_export get_complex_n(const type_t **ptype, bool *is_empty_udt);
idaman DEPRECATED bool ida_export append_dt(qtype *type, int n);
idaman DEPRECATED bool ida_export append_de(qtype *type, uint32 n);
idaman DEPRECATED bool ida_export append_da(qtype *type, uint32 n1, uint32 n2);
idaman DEPRECATED bool ida_export append_name(qtype *fields, const char *name);
idaman DEPRECATED bool ida_export append_complex_n(qtype *type, uint32 n, bool is_empty);
idaman DEPRECATED error_t ida_export calc_names_cmts(const til_t *ti, const type_t *type, bool idaapi find_var(int level, void *ud, const char **name, const char **cmt), void *ud, p_list **names, p_list **cmts);
idaman DEPRECATED bool ida_export is_castable2(const til_t *til, const type_t *from, const type_t *to);
idaman DEPRECATED bool ida_export remove_constness(type_t *type);
idaman DEPRECATED bool ida_export build_array_type(qtype *outtype, const type_t *type, int size);
idaman DEPRECATED ssize_t ida_export get_ptr_object_size(const til_t *til, const type_t *type);
idaman DEPRECATED bool ida_export get_name_of_named_type(char *buf, size_t bufsize, const type_t *ptr);
idaman DEPRECATED bool ida_export is_type_scalar2(const til_t *til, const type_t *type);
idaman DEPRECATED type_sign_t ida_export get_type_sign(const til_t *til, const type_t *type);
inline DEPRECATED bool is_type_signed  (const type_t *type) { return get_type_sign(idati, type) == type_signed; }
inline DEPRECATED bool is_type_unsigned(const type_t *type) { return get_type_sign(idati, type) == type_unsigned; }
inline DEPRECATED bool is_type_signed  (const til_t *til, const type_t *type) { return get_type_sign(til, type) == type_signed; }
inline DEPRECATED bool is_type_unsigned(const til_t *til, const type_t *type) { return get_type_sign(til, type) == type_unsigned; }
idaman DEPRECATED bool ida_export get_idainfo_by_type2(const til_t *til, const type_t **ptype, const p_list *fields, size_t *psize, flags_t *pflags, opinfo_t *mt, size_t *alsize=NULL);
idaman DEPRECATED bool ida_export apply_tinfo(const til_t *til, ea_t ea, const type_t *type, const p_list *fields, uint32 flags);
idaman DEPRECATED bool ida_export parse_decl(til_t *til, const char *decl, qstring *name, qtype *type, qtype *fields, int flags);
idaman DEPRECATED bool ida_export apply_type_to_stkarg(const op_t &x, uval_t v, const type_t *type, const char *name);
idaman DEPRECATED int ida_export calc_bare_name(const char *name, const type_t *type, char *buf, size_t bufsize);
idaman DEPRECATED void ida_export calc_c_cpp_name(const char *name, const type_t *type, char *buf, size_t bufsize, int ccn_flags);
idaman DEPRECATED bool ida_export remove_type_pointer(const til_t *til, const type_t **ptype, const char **pname);
idaman DEPRECATED bool ida_export apply_once_type_and_name(ea_t ea, const type_t *type, const char *name);
idaman DEPRECATED int ida_export get_func_rettype(const til_t *til, const type_t **type, const p_list **fields, qtype *rettype, qtype *retfields=NULL, varloc_t *p_retloc=NULL, cm_t *p_cc=NULL);
inline DEPRECATED int idaapi calc_func_nargs(const til_t *til, const type_t *type) { return get_func_rettype(til, &type, NULL, NULL); }
idaman DEPRECATED cm_t ida_export get_func_cc(const til_t *til, const type_t **p_type, const p_list **p_fields=NULL);
idaman DEPRECATED const type_t *ida_export skip_spoiled_info(const type_t *ptr);
idaman DEPRECATED type_t *ida_export set_spoils(type_t *pt, uint reg, uint size);
inline DEPRECATED unsigned get_spoil_cnt(type_t t) { return (unsigned)t & 0xF; }
idaman DEPRECATED bool ida_export is_type_resolvable(const type_t *p, char *namebuf=NULL);
idaman DEPRECATED const type_t *ida_export resolve_typedef2(const til_t *ti, const type_t *p, const p_list **fields=NULL, char *namebuf=NULL);
idaman DEPRECATED size_t ida_export get_funcarg_size(const til_t *til, const type_t **pptr, size_t *lp=NULL);
idaman DEPRECATED const type_t *ida_export skip_type(const til_t *ti, const type_t *&ptr);
inline DEPRECATED bool check_skip_type(const til_t *ti, const type_t *&ptr)
{
  return skip_type(ti, ptr) != NULL;
}
inline DEPRECATED bool is_valid_full_type(const til_t *ti, const type_t *&ptr)
{
  return skip_type(ti, ptr) != NULL && *ptr == '\0';
}
idaman DEPRECATED void ida_export apply_callee_type(ea_t caller, const type_t *type, const p_list *fields);
idaman DEPRECATED int ida_export print_type_to_one_line(char *buf, size_t bufsize, const til_t *ti, const type_t *pt, const char *name = NULL, const char *cmt = NULL, const p_list *field_names = NULL, const p_list *field_cmts = NULL);
idaman DEPRECATED int ida_export print_type_to_many_lines(bool (idaapi*printer)(void *cbdata, const char *buf), void *cbdata, const char *prefix, int indent, int cmtindent, const til_t *ti, const type_t *pt, const char *name = NULL, const char *cmt = NULL, const p_list *field_names = NULL, const p_list *field_cmts = NULL);
idaman DEPRECATED ssize_t ida_export print_type_to_qstring(qstring *result, const char *prefix, int indent,int cmtindent, int flags, const til_t *ti, const type_t *pt, const char *name=NULL, const char *cmt=NULL, const p_list *field_names=NULL, const p_list *field_cmts=NULL);
typedef bool (idaapi*tcbfn)(void *cb_data, int level, const char *str, const char *cmt);
idaman DEPRECATED int ida_export unpack_type(const til_t *ti, const type_t *pt, tcbfn cb_func, void  *cb_data, const char *name = NULL, const char *cmt = NULL, const struct descr_t *Descr = NULL, unsigned int flags=0);
idaman DEPRECATED bool ida_export extract_pstr(const p_list **ptype, char *buf, size_t bufsize);
#endif
#if !defined(NO_OBSOLETE_FUNCS) || defined(VARLOCS_SOURCE)
struct funcarg_info_t
{
  varloc_t argloc;
  qstring name;
  qtype type;
  qtype fields;
};
struct func_type_info_t : public qvector<funcarg_info_t>
{
  int flags;
  qtype rettype;
  qtype retfields;
  varloc_t retloc;
  uval_t stkargs;
  reginfovec_t spoiled;
  cm_t cc;
  type_t basetype;
  func_type_info_t(): flags(0), stkargs(0), cc(0), basetype(0) {}
};
idaman DEPRECATED bool ida_export build_func_type2(const til_t *ti, qtype *p_type, qtype *p_fields, const func_type_info_t &fi);
idaman DEPRECATED int ida_export build_funcarg_info(const til_t *til, const type_t *type, const p_list *fields, func_type_info_t *info, int bfi_flags);
#define BFI_NOCONST 0x0001      // remove constness from all function argument types
#define BFI_NOLOCS  0x0002      // do not calculate arglocs (except __usercall)
typedef bool idaapi set_op_type_t(op_t &x, const type_t *type, const char *name);
idaman DEPRECATED int ida_export gen_use_arg_types(ea_t caller, const type_t * const *types, const char * const *names, const varloc_t *varlocs, int n, const type_t **rtypes, const char **rnames, uint32 *rlocs, int rn, set_op_type_t *set_op_type, is_stkarg_load_t *is_stkarg_load, has_delay_slot_t *has_delay_slot=NULL);
idaman DEPRECATED int ida_export use_regarg_type_cb(ea_t ea, const type_t **rtypes, const char **rnames, uint32 *rlocs, int rn, void *ud=NULL);
idaman DEPRECATED bool ida_export resolve_complex_type2(const til_t *til, const type_t **ptype, const p_list **fields, qstring *type_name, type_t *bt, int *N);
idaman DEPRECATED int ida_export visit_strmems(const til_t *til, const type_t *type, const p_list *fields, int N, bool is_union, int idaapi visitor(uint32 offset, const type_t *type, const p_list *fields, const char *name, void *ud), void *ud);
idaman DEPRECATED int ida_export calc_varloc_info(const til_t *til, const type_t *type, varlocs_t *varlocs);
idaman DEPRECATED bool ida_export append_varloc(qtype *out, const varloc_t &vloc);
idaman DEPRECATED bool ida_export extract_varloc(const type_t **ptype, varloc_t *vloc, bool is_retval);
inline DEPRECATED bool skip_varloc(const type_t **ptype, bool is_retval=false) { return extract_varloc(ptype, NULL, is_retval); }
idaman DEPRECATED int ida_export verify_varloc(const varloc_t &vloc, int size, const areaset_t *gaps);
idaman DEPRECATED bool ida_export optimize_varloc(varloc_t *vloc, int size, const areaset_t *gaps);
idaman DEPRECATED size_t ida_export print_varloc(char *buf, size_t bufsize, const varloc_t &vloc, int size=0, int vflags=0);
#define PRVLOC_VERIFY 0x01    // interr if illegal varloc
#define PRVLOC_STKOFF 0x02    // print stack offsets
idaman DEPRECATED void ida_export convert_varloc_to_argloc(argloc_t *dst, const varloc_t &src);
idaman DEPRECATED bool ida_export convert_argloc_to_varloc(varloc_t *dst, const argloc_t &src);
struct vloc_visitor_t
{
  virtual int idaapi visit_location(varloc_t &v, int off, int size) = 0;
  DEFINE_VIRTUAL_DTOR(vloc_visitor_t)
};
idaman DEPRECATED int ida_export for_all_varlocs(vloc_visitor_t &vv, varloc_t &vloc, int size, int off=0);
struct const_vloc_visitor_t
{
  virtual int idaapi visit_location(const varloc_t &v, int off, int size) = 0;
  DEFINE_VIRTUAL_DTOR(const_vloc_visitor_t)
};
inline int idaapi for_all_const_varlocs(const_vloc_visitor_t &vv, const varloc_t &vloc, int size, int off=0)
{
  return for_all_varlocs(*(vloc_visitor_t*)(&vv),
                         CONST_CAST(varloc_t&)(vloc),
                         size,
                         off);
}
idaman DEPRECATED int ida_export calc_max_children_qty(ea_t ea, const tinfo_t &tif, bool dont_deref_ptr=false);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#ifdef __GNUC__
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
#endif
#endif // !defined(NO_OBSOLETE_FUNCS) || defined(VARLOCS_SOURCE)

// fixme: declare deprecated!
idaman bool ida_export gen_decorate_name(const til_t *ti, const char *name, const type_t *type, char *outbuf, size_t bufsize, bool mangle, cm_t cc);
idaman bool ida_export equal_types(const til_t *ti, const type_t *t1, const type_t *t2);

#pragma pack(pop)
#endif // _TYPEINF_HPP
