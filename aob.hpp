#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

// mask: 'x' = match byte, '?' = wildcard
inline uintptr_t AOBScan(
    uintptr_t   start,
    size_t      length,
    const char* pattern,
    const char* mask)
{
    size_t patLen = strlen(mask);
    for (size_t i = 0; i < length - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (mask[j] == 'x'
             && ((uint8_t*)start)[i + j] != (uint8_t)pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }
    return 0;
}

inline uintptr_t AOBScanRemote(
    HANDLE      hProc,
    uintptr_t   modBase,
    size_t      modSize,
    const char* pattern,
    const char* mask)
{
    std::vector<uint8_t> buf(modSize);
    SIZE_T br = 0;
    ReadProcessMemory(hProc, (LPCVOID)modBase, buf.data(), modSize, &br);
    return AOBScan((uintptr_t)buf.data(), br, pattern, mask)
           - (uintptr_t)buf.data() + modBase;
}

namespace Patterns
{
    // luaL_loadbuffer - looks for the bytecode magic 0x1B 0x4C 0x75 61 ("\x1BLua")
    // and the call to luaD_throw near the start of the function
    // This is a rough sig - refine with BinNinja/IDA for your build
    inline const char* luaL_loadbuffer_pat  = "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30";
    inline const char* luaL_loadbuffer_mask = "xxxx?xxxx?xxxxx";

    // lua_pcall - push frame, call luaD_pcall, check status
    // 40 53 48 83 EC 20 8B 41 ?? 85 C0
    inline const char* lua_pcall_pat  = "\x40\x53\x48\x83\xEC\x20\x8B\x41\x00\x85\xC0";
    inline const char* lua_pcall_mask = "xxxxxxxx?xx";

    // CFG ControlFlowGuard - 49 BB FF FF FF FF FF 7F 00 00
    // (mov r11, 0x7FFFFFFFFFFF)
    inline const char* cfg_guard_pat  = "\x49\xBB\xFF\xFF\xFF\xFF\xFF\x7F\x00\x00";
    inline const char* cfg_guard_mask = "xxxxxxxxxx";

    // global_State ptr - look for the GC threshold write near luaC_step
    // This varies heavily; use xrefs to lua_newstate in IDA
}
