#pragma once
#include <cstdint>
#include <memory>

struct lua_State;
struct global_State;
struct Proto;
struct LuaTable;
struct TString;
struct GCObject;
struct CallInfo;
struct UpVal;
struct lua_Page;
struct extraspace_t;
struct shared_t;
struct continuations_t;
using lua_CFunction    = int  (*)(lua_State* L);
using lua_Continuation = int  (*)(lua_State* L, int status);
using lua_Alloc        = void*(*)(void* ud, void* ptr, size_t osize, size_t nsize);
using lua_Destructor   = void (*)(lua_State* L, void* ud);
using StkId            = struct TValue*;
using Instruction      = uint32_t;
using identity_t       = uint8_t;

// Tagged value cell. 16 bytes - value (8) + tag (4) + pad (4).
struct TValue {
    union {
        double   n;       // LUA_TNUMBER
        int      b;       // LUA_TBOOLEAN
        void*    p;       // LUA_TLIGHTUSERDATA / LUA_TUSERDATA
        GCObject* gc;     // all GC'd types
    } value;              // +0x00
    int tt;               // +0x08   type tag (lower 5 bits used)
    int _pad;             // +0x0C
};
static_assert(sizeof(TValue) == 0x10, "TValue must be 16 bytes");

struct GCObject {
    GCObject* next;       // +0x00
    uint8_t   tt;         // +0x08   GC type tag
    uint8_t   marked;     // +0x09
    uint8_t   memcat;     // +0x0A
};

#define CommonHeader  uint8_t tt; uint8_t marked; uint8_t memcat


// Roblox obfuscates certain struct fields using a rotating XOR/offset scheme
// (VMValue1–VMValue4 in their source).  Each wrapper stores the encoded value
// and provides an implicit conversion that strips the encoding.
//
// The four encoding schemes for this build:
//
//   vmvalue1_t  - value ^ ENCODE_KEY1   (confirmed: PROTO_LOCVARS, PROTO_UPVALUES,
//                                         CLOSURE_DEBUGNAME)
//   vmvalue2_t  - value ^ ENCODE_KEY2   (confirmed: PROTO_SOURCE, PROTO_DEBUGINSN,
//                                         PROTO_TYPEINFO)
//   vmvalue3_t  - value ^ ENCODE_KEY3   (confirmed: PROTO_ABSLINEINFO, PROTO_USERDATA,
//                                         CLOSURE_CONT, LSTATE_STACKSIZE)
//   vmvalue4_t  - value ^ ENCODE_KEY4   (confirmed: PROTO_LINEINFO, PROTO_DEBUGNAME,
//                                         TSTRING_HASH, UDATA_META)
//
// The actual key values are not exported from Roblox's binary and change each
// plain field next to each encoded field and computing the XOR residual.
// For offline struct layout purposes the wrappers below store raw encoded
// values; call .decode(key) to recover the plaintext pointer/integer.
//
// If you only need field offsets for cross-process reads,
// ignore the wrappers entirely and use the raw byte offsets from the comments.

template<typename T>
struct vmvalue1_t {
    uintptr_t encoded;                       // raw encoded storage
    T decode(uintptr_t key1) const noexcept {
        return reinterpret_cast<T>(encoded ^ key1);
    }
    // Implicit read without key - returns encoded bits (use only for offset checks)
    explicit operator T() const noexcept { return reinterpret_cast<T>(encoded); }
};

template<typename T>
struct vmvalue2_t {
    uintptr_t encoded;
    T decode(uintptr_t key2) const noexcept {
        return reinterpret_cast<T>(encoded ^ key2);
    }
    explicit operator T() const noexcept { return reinterpret_cast<T>(encoded); }
};

template<typename T>
struct vmvalue3_t {
    uintptr_t encoded;
    T decode(uintptr_t key3) const noexcept {
        return reinterpret_cast<T>(encoded ^ key3);
    }
    explicit operator T() const noexcept { return reinterpret_cast<T>(encoded); }
};

template<typename T>
struct vmvalue4_t {
    uintptr_t encoded;
    T decode(uintptr_t key4) const noexcept {
        return reinterpret_cast<T>(encoded ^ key4);
    }
    explicit operator T() const noexcept { return reinterpret_cast<T>(encoded); }
};

// Specialisation for non-pointer integral types (e.g. uint32_t, int)
template<>
struct vmvalue4_t<unsigned int> {
    unsigned int encoded;
    unsigned int decode(unsigned int key4) const noexcept { return encoded ^ key4; }
    explicit operator unsigned int() const noexcept { return encoded; }
};

template<>
struct vmvalue3_t<int> {
    int encoded;
    int decode(int key3) const noexcept { return encoded ^ key3; }
    explicit operator int() const noexcept { return encoded; }
};

// Per-build VMValue #defines
// These map the Luau source macro names to the correct encoding template
#define CLOSURE_CONT_ENC         vmvalue3_t
#define CLOSURE_DEBUGNAME_ENC    vmvalue1_t
#define LSTATE_STACKSIZE_ENC     vmvalue3_t
#define PROTO_ABSLINEINFO_ENC    vmvalue3_t
#define PROTO_DEBUGINSN_ENC      vmvalue2_t
#define PROTO_DEBUGNAME_ENC      vmvalue3_t
#define PROTO_LINEINFO_ENC       vmvalue4_t
#define PROTO_LOCVARS_ENC        vmvalue1_t
#define PROTO_SOURCE_ENC         vmvalue2_t
#define PROTO_TYPEINFO_ENC       vmvalue2_t
#define PROTO_UPVALUES_ENC       vmvalue1_t
#define PROTO_USERDATA_ENC       vmvalue3_t
#define TSTRING_HASH_ENC         vmvalue4_t
#define UDATA_META_ENC           vmvalue4_t

struct stringtable {
    int       size;   // +0x00
    uint32_t  nuse;   // +0x04
    TString** hash;   // +0x08
};

struct TString {
    CommonHeader;                        // +0x00–0x02
    int16_t  bitnancer;                  // +0x04   (atom low half in vanilla Luau)
    int16_t  atom;                       // +0x06
    TString* next;                       // +0x08
    TSTRING_HASH_ENC<unsigned int> hash; // +0x10   encoded hash
    unsigned int len;                    // +0x14
    char data[1];                        // +0x18   null-terminated string data
};
// Raw offsets for external/cross-process reads:
//   +0x10  hash (encoded)
//   +0x14  len
//   +0x18  data (inline for all lengths; Roblox doesn't use the SSO trick here)

struct UpVal {
    CommonHeader;         // +0x00
    uint8_t _pad[5];
    TValue* v;            // +0x08   pointer to the TValue (open) or to closed value
    union {
        TValue  value;    // +0x10   closed value
        struct {
            UpVal* prev;
            UpVal* next;
        } open;
    };
};
struct LocVar {
    TString* varname;   // +0x00
    int      startpc;   // +0x08
    int      endpc;     // +0x0C
    uint8_t  reg;       // +0x10
};
struct Proto {
    CommonHeader;                                     // +0x00–0x02
    uint8_t  nups;                                    // +0x03   number of upvalues
    uint8_t  is_vararg;                               // +0x04
    uint8_t  maxstacksize;                            // +0x05
    uint8_t  flags;                                   // +0x06
    uint8_t  numparams;                               // +0x07
    PROTO_TYPEINFO_ENC<uint8_t*>   typeinfo;          // +0x08   encoded
    Proto**                         p;                // +0x10   sub-protos
    PROTO_DEBUGNAME_ENC<TString*>  debugname;         // +0x18   encoded
    PROTO_DEBUGINSN_ENC<uint8_t*>  debuginsn;         // +0x20   encoded
    PROTO_ABSLINEINFO_ENC<int*>    abslineinfo;        // +0x28   encoded
    PROTO_LINEINFO_ENC<uint8_t*>   lineinfo;           // +0x30   encoded
    PROTO_SOURCE_ENC<TString*>     source;             // +0x38   encoded  ← script name
    PROTO_LOCVARS_ENC<LocVar*>     locvars;            // +0x40   encoded
    PROTO_USERDATA_ENC<void*>      userdata;           // +0x48   encoded
    GCObject*                       gclist;            // +0x50
    PROTO_UPVALUES_ENC<TString**>  upvalues;           // +0x58   encoded
    TValue*                         k;                 // +0x60   constants array
    Instruction*                    code;              // +0x68   bytecode
    void*                           execdata;          // +0x70
    std::uintptr_t                  exectarget;        // +0x78
    const Instruction*              codeentry;         // +0x80
    int   sizeupvalues;                                // +0x88
    int   sizek;                                       // +0x8C   number of constants
    int   sizetypeinfo;                                // +0x90
    int   sizelineinfo;                                // +0x94
    int   sizep;                                       // +0x98   number of sub-protos
    int   linegaplog2;                                 // +0x9C
    int   bytecodeid;                                  // +0xA0
    int   sizecode;                                    // +0xA4
    int   linedefined;                                 // +0xA8
    int   sizelocvars;                                 // +0xAC
};
//   +0x38  source  (encoded TString* - decode to get script name)
//   +0x60  k[]    (TValue* constants array)
//   +0x88  sizeupvalues
//   +0x8C  sizek
//   +0x98  sizep

struct Closure {
    CommonHeader;                                         // +0x00–0x02
    uint8_t   stacksize;                                  // +0x03
    uint8_t   preload;                                    // +0x04
    uint8_t   isC;                                        // +0x05   1 = C closure
    uint8_t   nupvalues;                                  // +0x06
    GCObject* gclist;                                     // +0x08
    LuaTable* env;                                        // +0x10   function environment
    union {
        struct {
            CLOSURE_DEBUGNAME_ENC<const char*> debugname; // +0x18  encoded
            CLOSURE_CONT_ENC<lua_Continuation> cont;       // +0x20  encoded continuation
            lua_CFunction                      f;          // +0x28  raw C function pointer
            TValue upvals[1];                              // +0x30  C upvalues (TValues)
        } c;
        struct {
            Proto*  p;                                     // +0x18  Lua prototype
            TValue  uprefs[1];                             // +0x20  upvalue references
        } l;
    };
};
//   +0x05  isC       (0 = Lua closure, 1 = C closure)
//   +0x06  nupvalues
//   +0x18  l.p / c.debugname  (Proto* for Lua closures)
//   +0x28  c.f                (lua_CFunction for C closures)

struct LuaNode {
    TValue val;   // +0x00
    TValue key;   // +0x10
};

struct LuaTable {
    CommonHeader;          // +0x00–0x02
    uint8_t   tmcache;     // +0x03
    uint8_t   safeenv;     // +0x04
    uint8_t   nodemask8;   // +0x05
    uint8_t   readonly;    // +0x06
    uint8_t   lsizenode;   // +0x07   log2 of hash part size
    int       sizearray;   // +0x08
    union {
        int lastfree;      // +0x0C
        int aboundary;
    };
    LuaTable* metatable;   // +0x10
    GCObject* gclist;      // +0x18
    LuaNode*  node;        // +0x20   hash part
    TValue*   array;       // +0x28   array part
};
//   +0x07  lsizenode  (1 << lsizenode = hash bucket count)
//   +0x08  sizearray
//   +0x20  node       (LuaNode* hash part)
//   +0x28  array      (TValue* array part)

struct CallInfo {
    const Instruction* savedpc;  // +0x00
    StkId              func;     // +0x08   function (TValue* on stack)
    StkId              top;      // +0x10
    StkId              base;     // +0x18
    int                nresults; // +0x20
    unsigned int       flags;    // +0x24
};
struct lua_Debug;
struct lua_Callbacks {
    void*    userdata;                                             // +0x00
    void   (*debuginterrupt)(lua_State* L, lua_Debug* ar);        // +0x08
    void   (*userthread)(lua_State* LP, lua_State* L);            // +0x10
    void   (*debugbreak)(lua_State* L, lua_Debug* ar);            // +0x18
    void   (*onallocate)(lua_State* L, size_t osize, size_t nsize); // +0x20
    void   (*panic)(lua_State* L, int errcode);                   // +0x28
    void   (*debugstep)(lua_State* L, lua_Debug* ar);             // +0x30
    void   (*interrupt)(lua_State* L, int gc);                    // +0x38
    int16_t(*useratom)(lua_State* L, const char* s, size_t l);   // +0x40
    void   (*debugprotectederror)(lua_State* L);                  // +0x48
};
static_assert(sizeof(lua_Callbacks) == 0x50, "lua_Callbacks size check");

// These are opaque blocks - we only need their sizes for global_State layout.
struct lua_ExecutionCallbacks { uint8_t _opaque[0x58]; }; // 0x538–0x57F in global_State
struct lua_UdataDirectAccessData { uint8_t _opaque[0x10]; };
struct GCStats  { uint8_t _opaque[0x58]; };
struct GCMetrics{ uint8_t _opaque[0x78]; };
struct lua_jmpbuf;
struct global_State {
    uint8_t      currentwhite;           // +0x00
    uint8_t      gcstate;                // +0x01
    uint8_t      _pad0[6];
    lua_Alloc    frealloc;               // +0x08
    void*        ud;                     // +0x10
    GCObject*    gray;                   // +0x18
    GCObject*    grayagain;              // +0x20
    GCObject*    weak;                   // +0x28
    size_t       GCthreshold;            // +0x30
    size_t       totalbytes;             // +0x38
    int          gcstepsize;             // +0x40
    int          gcstepmul;              // +0x44
    int          gcgoal;                 // +0x48
    uint8_t      _pad1[4];
    stringtable  strt;                   // +0x50   string intern table
    lua_Page*    freepages[40];          // +0x60   slab free lists
    lua_State*   mainthread;             // +0x1A0
    UpVal        uvhead;                 // +0x1A8  sentinel for open upvalue list
    uint8_t      _pad1_uvhead[0x08];     // +0x1C8  alignment padding
    lua_Page*    freegcopages[40];       // +0x1D0
    lua_Page*    allgcopages;            // +0x310
    lua_Page*    allpages;               // +0x318
    lua_Page*    sweepgcopage;           // +0x320
    TString*     tmname[21];             // +0x328  tag method names
    TString*     ttname[12];             // +0x3D0  type names
    LuaTable*    mt[12];                 // +0x430  per-type metatables
    TValue       pseudotemp;             // +0x490
    TValue       registry;              // +0x4A0  Lua registry
    int          registryfree;           // +0x4B0
    uint8_t      _pad2[4];
    lua_jmpbuf*  errorjmp;              // +0x4B8
    uint64_t     rngstate;              // +0x4C0
    lua_Callbacks cb;                   // +0x4C8
    uint64_t     ptrenckey[4];          // +0x518
    lua_ExecutionCallbacks ecb;         // +0x538
    alignas(16) uint8_t ecbdata[512];   // +0x580
    lua_UdataDirectAccessData udatadirect[128]; // +0x780
    size_t       memcatbytes[256];      // +0x2B80
    lua_Destructor udatagc[128];        // +0x3380
    LuaTable*    udatamt[128];          // +0x3780
    TString*     lightuserdataname[128];// +0x3B80
    GCStats      gcstats;               // +0x3F80
    GCMetrics    gcmetrics;             // +0x4038
};
//   +0x1A0  mainthread  (lua_State*)   - follow for populated extraspace
//   +0x4A0  registry    (TValue)       - used by getreg
struct lua_State {
    CommonHeader;                          // +0x00–0x02
    uint8_t        status;                 // +0x03
    uint8_t        activememcat;           // +0x04
    bool           singlestep;             // +0x05
    bool           isactive;              // +0x06
    uint8_t        _pad0[1];
    LuaTable*      gt;                     // +0x08   global environment table
    unsigned short nCcalls;               // +0x10
    unsigned short baseCcalls;            // +0x12
    int            cachedslot;            // +0x14
    UpVal*         openupval;             // +0x18
    TString*       namecall;              // +0x20   ← getnamecallmethod reads here
    CallInfo*      ci;                    // +0x28   current CallInfo
    global_State*  global;               // +0x30
    StkId          stack;                 // +0x38
    StkId          top;                   // +0x40
    StkId          base;                  // +0x48
    StkId          stack_last;            // +0x50
    CallInfo*      end_ci;               // +0x58
    CallInfo*      base_ci;              // +0x60
    void*          userdata;             // +0x68   RobloxExtraSpace*  ← key for elevation
    GCObject*      gclist;               // +0x70
    LSTATE_STACKSIZE_ENC<int> stacksize; // +0x78   encoded stack size
    int            size_ci;              // +0x7C
};
//   +0x08  gt        (LuaTable*)     - global env
//   +0x20  namecall  (TString*)      - getnamecallmethod
//   +0x68  userdata  (extraspace_t*) - elevation / identity read

struct lua_Page {
    lua_Page* listprev;  // +0x00
    lua_Page* listnext;  // +0x08
    lua_Page* prev;      // +0x10
    lua_Page* next;      // +0x18
    int       pageSize;  // +0x20
    int       blockSize; // +0x24
    void*     freeList;  // +0x28
    int       freeNext;  // +0x30
    int       busyBlocks;// +0x34
    uint8_t   _pad[8];
    char      data[1];   // +0x40   first block
};

// ─────────────────────────────────────────────────────────────────────────────
// RobloxExtraSpace  (extraspace_t)
//
// Layout reconciled from two sources:
//
//     +0x60 = 0x746e6f4300000008  → low 32 bits = 8  → identity confirmed here
//     +0x78 = 0xffffffffffffffff  → capabilities confirmed here
//
//     Extraspace::Capabilities = 0x70
//     Extraspace::Actor        = 0x78
//     Extraspace::Context      = 0x88
//     Extraspace::Continuations= 0x40
//     Extraspace::Shared       = 0x18
//     Extraspace::Source       = 0x50
//
// Reconciliation:
//   +0x18  shared       (shared_ptr<shared_t>)      - both agree
//   +0x40  continuations (unique_ptr<continuations_t>) - both agree
//   +0x50  source       (weak_ptr<uintptr_t>)        - both agree
//   +0x60  identity / thread-local context word       - Source A: low dword = identity
//   +0x68  _pad
//   +0x70  capabilities (uint64_t)                   - Source B: Extraspace::Capabilities
//                                                       Source A esDump +0x70 showed a
//                                                       non-0xFF value (partial capabilities)
//   +0x78  actor / full capabilities                  - Source B: Extraspace::Actor;
//                                                       Source A: esDump showed 0xFFFF…
//   +0x80  _pad
//   +0x88  context      (uintptr_t ScriptContext)    - Source B: Extraspace::Context
//
// Practical resolution:
//   Use Extraspace::Capabilities (0x70) for reading.
//   Use our confirmed-elevation offset (0x78) for writing full caps at injection.
//   Both targets sit within the same uint128 "capabilities" region; the write at
//   0x78 also sets the high half when read by code expecting the field at 0x70.
// ─────────────────────────────────────────────────────────────────────────────
struct extraspace_t {
    extraspace_t*                    next;           // +0x00
    std::uintptr_t                   _container;     // +0x08
    extraspace_t*                    prev;           // +0x10
    std::shared_ptr<shared_t>        shared;         // +0x18   Extraspace::Shared
    uint8_t                          _pad1[0x18];    // +0x28
    std::unique_ptr<continuations_t> continuations;  // +0x40   Extraspace::Continuations
    uint8_t                          _pad2[0x08];    // +0x48
    std::weak_ptr<std::uintptr_t>    source;         // +0x50   Extraspace::Source

    // +0x60  identity / context word.
    //   Low 32-bit dword = thread identity (esDump confirmed = 8 after elevation).
    //   High bytes = internal context flags (read-only from our perspective).
    uint32_t     identity;                           // +0x60   low dword = identity_t
    uint32_t     _context_flags;                     // +0x64   Roblox internal flags

    // +0x68  padding between identity and capabilities
    uint8_t      _pad3[0x08];                        // +0x68

    // +0x70  Extraspace::Capabilities - low 64 bits of the capability word.
    //   Reading from here gives the effective capability mask for the thread.
    uint64_t     capabilities;                       // +0x70   Extraspace::Capabilities

    // +0x78  Extraspace::Actor - also the high half of the capability region.
    //   Our elevation writes 0xFFFFFFFFFFFFFFFF here to guarantee all caps bits are
    //   set regardless of which half the VM checks.  After elevation Source A esDump
    //   showed 0xFFFF… at this offset confirming the write landed correctly.
    std::weak_ptr<std::uintptr_t> actor;             // +0x78   Extraspace::Actor

    // +0x88  Extraspace::Context - pointer back to the ScriptContext.
    std::uintptr_t context;                          // +0x88   Extraspace::Context
};
//   +0x18  shared        shared_ptr<shared_t>
//   +0x40  continuations unique_ptr<continuations_t>
//   +0x50  source        weak_ptr<uintptr_t>
//   +0x60  identity      uint32_t  (low byte = identity level)
//   +0x70  capabilities  uint64_t  (Extraspace::Capabilities - READ from here)
//   +0x78  actor / caps  weak_ptr  (elevation WRITE target - sets high cap bits)
//   +0x88  context       uintptr_t (ScriptContext*)
//
// Elevation strategy: write identity at +0x60, write 0xFFFFFFFFFFFFFFFF at +0x78.
// This covers both the EthanU read site (+0x70) and our original esDump write site.

// shared_t  - pointed to by extraspace_t::shared
struct shared_t {
    uint8_t       _pad1[0x18];        // +0x00–0x17
    extraspace_t* all_threads;        // +0x18   linked list head
    uint8_t       _pad2[0x08];        // +0x20–0x27
    void*         script_context;     // +0x28   ScriptContext*
};

// RBX::Addresses  - module-relative RVAs for RobloxPlayerBeta.exe
// RBX::Offsets    - struct field offsets for Roblox-specific types
// EthanU          - additional RVAs and ExtraSpace offsets from cosmic build
//
// All values are RVAs (relative to moduleBase) unless otherwise noted.
// Add moduleBase to convert to an absolute VA for ReadRemoteValue / WriteProcessMemory.
namespace RBX
{
    namespace Addresses
    {
        namespace Pointers
        {
            inline constexpr uintptr_t fastFlagDatabankPointer = 0x7723F28;
            inline constexpr uintptr_t performanceCheckKey     = 0x7410958;
            inline constexpr uintptr_t propertyMaskList        = 0x7723248;
            inline constexpr uintptr_t securityContext         = 0x74D84B8;
            inline constexpr uintptr_t taskSchedulerPointer    = 0x7B68F00;
            inline constexpr uintptr_t taskSchedulerRun        = 0x6FA5B10;
        } // namespace Pointers

        namespace Functions
        {
            inline constexpr uintptr_t allClassDescriptors      = 0x435C4A0;
            inline constexpr uintptr_t clockTime                = 0x4642F30;
            inline constexpr uintptr_t disconnectSlotConnection  = 0x4651440;
            inline constexpr uintptr_t fireClickDetectorHover1   = 0x2544BE0;
            inline constexpr uintptr_t fireClickDetectorHover2   = 0x2544D80;
            inline constexpr uintptr_t fireClickDetectorMouse1   = 0x2543640;
            inline constexpr uintptr_t fireClickDetectorMouse2   = 0x25437E0;
            inline constexpr uintptr_t fireProximityPrompt       = 0x25D4170;
            inline constexpr uintptr_t getCreator               = 0x4360240;
            inline constexpr uintptr_t getGlobalState           = 0x1CD7950;
            inline constexpr uintptr_t getPropertyDescriptor    = 0xC53810;
            inline constexpr uintptr_t getPropertyMask          = 0x45DF2D0;
            inline constexpr uintptr_t getTlsPointer            = 0x7FB0;
            inline constexpr uintptr_t initializePropertyMaskList = 0x45DED80;
            inline constexpr uintptr_t lookupRbxName            = 0x45DF170;
            inline constexpr uintptr_t luaArgumentsGet          = 0x1BE1520;
            inline constexpr uintptr_t pushInstance             = 0x1CCF050;
            inline constexpr uintptr_t reportTouchInfo          = 0x2965290;
            inline constexpr uintptr_t scriptContextResume      = 0x1D08A20;
        } // namespace Functions
    } // namespace Addresses

    namespace Offsets
    {
        namespace BasePart
        {
            constexpr std::ptrdiff_t primitive = 0x148;
        }

        namespace ClassDescriptor
        {
            constexpr std::ptrdiff_t descriptorsList = 0x248;
            constexpr std::ptrdiff_t name            = 0x8;
        }

        namespace Instance
        {
            constexpr std::ptrdiff_t children        = 0x78;
            constexpr std::ptrdiff_t classDescriptor = 0x18;
            constexpr std::ptrdiff_t name            = 0xB0;
            constexpr std::ptrdiff_t parent          = 0x70;
        }

        namespace LocalScript
        {
            constexpr std::ptrdiff_t embeddedCode = 0x1A0;
        }

        namespace ModuleScript
        {
            constexpr std::ptrdiff_t lock   = 0x180;
            constexpr std::ptrdiff_t source = 0x148;
        }

        namespace Primitive
        {
            constexpr std::ptrdiff_t world = 0x1E8;
        }

        namespace RenderJob
        {
            constexpr std::ptrdiff_t renderView = 0x1D0;
        }

        namespace ScriptContext
        {
            // globalStatesMap: map<thread_id, lua_State*> - used to find the client VM
            constexpr std::ptrdiff_t actorPool      = 0x160;
            constexpr std::ptrdiff_t decryptKey      = 0x218;
            constexpr std::ptrdiff_t globalStatesMap = 0x148;
            constexpr std::ptrdiff_t resumeFacet     = 0x840;
        }

        namespace TaskScheduler
        {
            constexpr std::ptrdiff_t fpsCap   = 0xB0;
            constexpr std::ptrdiff_t jobEnd   = 0xD0;
            constexpr std::ptrdiff_t jobStart = 0xC8;
        }

        namespace VisualEngine
        {
            constexpr std::ptrdiff_t d3D11Device = 0xA0;
        }
    } // namespace Offsets
} // namespace RBX

namespace EthanU
{
    namespace Addresses
    {
        // RVAs for Luau VM internals exported/accessible in this build.
        // Add moduleBase to convert to absolute VA.
        inline constexpr uintptr_t LoadSafe         = 0x4270560; // luaD_call / safe load
        inline constexpr uintptr_t LuaCStep         = 0x426E560; // lua_cstep (C protected call step)
        inline constexpr uintptr_t LuaRef           = 0x425DEE0; // luaL_ref
        inline constexpr uintptr_t LuaUnRef         = 0x425E020; // luaL_unref
        inline constexpr uintptr_t LuauExecute      = 0x4277D20; // luau_execute (VM dispatch loop)
        inline constexpr uintptr_t rluaH_dummynode  = 0x5DFE0D8; // &luaH_dummynode (sentinel hash node)
        inline constexpr uintptr_t rluaO_nilobject  = 0x5DFE898; // &luaO_nilobject (nil TValue)
        inline constexpr uintptr_t sizeOfClass      = 0x6F91510; // ClassDescriptor size table
    } // namespace Addresses

    namespace Extraspace
    {
        // Offsets within RobloxExtraSpace (extraspace_t).
        // These are the authoritative READ offsets from this executor build.
        // See the extraspace_t struct definition above for full reconciliation notes.
        constexpr std::ptrdiff_t Shared        = 0x18; // shared_ptr<shared_t>
        constexpr std::ptrdiff_t Continuations = 0x40; // unique_ptr<continuations_t>
        constexpr std::ptrdiff_t Source        = 0x50; // weak_ptr<uintptr_t>  (script source)
        constexpr std::ptrdiff_t Capabilities  = 0x70; // uint64_t  (effective capability mask - READ)
        constexpr std::ptrdiff_t Actor         = 0x78; // weak_ptr / high caps half (elevation WRITE)
        constexpr std::ptrdiff_t Context       = 0x88; // uintptr_t ScriptContext*
        // Identity is at extraspace_t::identity (+0x60, low 32 bits).
        // Not listed in Extraspace because it is read via the low dword
        // of the +0x60 field, which EthanU reads as part of the context word.
        constexpr std::ptrdiff_t Identity      = 0x60; // uint32_t low byte = identity level
    }
} // namespace

static_assert(offsetof(lua_State, gt)       == 0x08,  "lua_State::gt offset");
static_assert(offsetof(lua_State, namecall) == 0x20,  "lua_State::namecall offset");
static_assert(offsetof(lua_State, global)   == 0x30,  "lua_State::global offset");
static_assert(offsetof(lua_State, userdata) == 0x68,  "lua_State::userdata offset");
static_assert(offsetof(LuaTable, lsizenode) == 0x07,  "LuaTable::lsizenode offset");
static_assert(offsetof(LuaTable, sizearray) == 0x08,  "LuaTable::sizearray offset");
static_assert(offsetof(LuaTable, node)      == 0x20,  "LuaTable::node offset");
static_assert(offsetof(LuaTable, array)     == 0x28,  "LuaTable::array offset");
static_assert(offsetof(Closure, isC)        == 0x05,  "Closure::isC offset");
static_assert(offsetof(Closure, nupvalues)  == 0x06,  "Closure::nupvalues offset");
static_assert(offsetof(Proto, k)            == 0x60,  "Proto::k offset");
static_assert(offsetof(Proto, sizek)        == 0x8C,  "Proto::sizek offset");
static_assert(offsetof(Proto, sizep)        == 0x98,  "Proto::sizep offset");
static_assert(offsetof(global_State, mainthread) == 0x1A0, "global_State::mainthread offset");
static_assert(offsetof(global_State, registry)   == 0x4A0, "global_State::registry offset");
static_assert(offsetof(extraspace_t, shared)        == Extraspace::Shared,        "extraspace_t::shared offset");
static_assert(offsetof(extraspace_t, continuations)  == Extraspace::Continuations, "extraspace_t::continuations offset");
static_assert(offsetof(extraspace_t, source)        == Extraspace::Source,        "extraspace_t::source offset");
static_assert(offsetof(extraspace_t, identity)      == Extraspace::Identity,      "extraspace_t::identity offset");
static_assert(offsetof(extraspace_t, capabilities)  == Extraspace::Capabilities,  "extraspace_t::capabilities offset");
static_assert(offsetof(extraspace_t, actor)         == Extraspace::Actor,         "extraspace_t::actor offset");
static_assert(offsetof(extraspace_t, context)       == Extraspace::Context,       "extraspace_t::context offset");
