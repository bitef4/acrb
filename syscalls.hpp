#pragma once
#include <Windows.h>
#include <cstdint>

// Read SSN from the real ntdll on disk (not the hooked in-memory copy).
// Walks the EAT of the mapped ntdll to find the stub, reads mov eax, <ssn>.
inline uint32_t GetSyscallNumber(const char* funcName)
{
    // map ntdll from disk to dodge any in-memory hooks
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, 0, nullptr);

    HANDLE hMap  = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    auto*  base  = (uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    auto* dos  = (IMAGE_DOS_HEADER*)base;
    auto* nt   = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto& exp  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto* edir = (IMAGE_EXPORT_DIRECTORY*)(base + exp.VirtualAddress);

    auto* names    = (uint32_t*)(base + edir->AddressOfNames);
    auto* ordinals = (uint16_t*)(base + edir->AddressOfNameOrdinals);
    auto* funcs    = (uint32_t*)(base + edir->AddressOfFunctions);

    uint32_t ssn = 0xFFFFFFFF;
    for (uint32_t i = 0; i < edir->NumberOfNames; i++) {
        if (strcmp((char*)(base + names[i]), funcName) == 0) {
            uint8_t* stub = base + funcs[ordinals[i]];
            // mov eax, <ssn>  =>  B8 xx xx xx xx
            if (stub[0] == 0xB8)
                ssn = *(uint32_t*)(stub + 1);
            break;
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ssn;
}

// We build a tiny RWX trampoline per-syscall at runtime and call it.
// Avoids needing naked functions or MASM in a header.
struct SyscallStub {
    uint8_t  code[16];
    uint32_t ssn;

    void Init(uint32_t _ssn) {
        ssn = _ssn;
        // mov eax, ssn
        // mov r10, rcx
        // syscall
        // ret
        uint8_t tmpl[] = {
            0xB8, 0,0,0,0,          // mov eax, <ssn>
            0x4C,0x8B,0xD1,         // mov r10, rcx
            0x0F,0x05,              // syscall
            0xC3                    // ret
        };
        *(uint32_t*)(tmpl + 1) = ssn;
        memcpy(code, tmpl, sizeof(tmpl));
    }
};

struct Syscalls {
    SyscallStub NtProtectVirtualMemory;
    SyscallStub NtWriteVirtualMemory;
    SyscallStub NtReadVirtualMemory;
    SyscallStub NtSuspendThread;
    SyscallStub NtResumeThread;
    SyscallStub NtGetContextThread;
    SyscallStub NtSetContextThread;
    void*       exec_page; // RWX page holding all stubs

    void Init() {
        exec_page = VirtualAlloc(nullptr, 0x1000,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        auto build = [&](SyscallStub& s, const char* name, size_t offset) {
            s.Init(GetSyscallNumber(name));
            memcpy((uint8_t*)exec_page + offset, s.code, 16);
        };

        build(NtProtectVirtualMemory, "NtProtectVirtualMemory", 0x00);
        build(NtWriteVirtualMemory,   "NtWriteVirtualMemory",   0x10);
        build(NtReadVirtualMemory,    "NtReadVirtualMemory",    0x20);
        build(NtSuspendThread,        "NtSuspendThread",        0x30);
        build(NtResumeThread,         "NtResumeThread",         0x40);
        build(NtGetContextThread,     "NtGetContextThread",     0x50);
        build(NtSetContextThread,     "NtSetContextThread",     0x60);
    }

    // typed call helpers
    NTSTATUS Protect(HANDLE proc, PVOID* base, PSIZE_T sz, ULONG prot, PULONG old) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
        return ((fn_t)((uint8_t*)exec_page + 0x00))(proc, base, sz, prot, old);
    }
    NTSTATUS Write(HANDLE proc, PVOID addr, PVOID buf, SIZE_T sz, PSIZE_T written) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
        return ((fn_t)((uint8_t*)exec_page + 0x10))(proc, addr, buf, sz, written);
    }
    NTSTATUS Read(HANDLE proc, PVOID addr, PVOID buf, SIZE_T sz, PSIZE_T read) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
        return ((fn_t)((uint8_t*)exec_page + 0x20))(proc, addr, buf, sz, read);
    }
    NTSTATUS Suspend(HANDLE thread) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PULONG);
        return ((fn_t)((uint8_t*)exec_page + 0x30))(thread, nullptr);
    }
    NTSTATUS Resume(HANDLE thread) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PULONG);
        return ((fn_t)((uint8_t*)exec_page + 0x40))(thread, nullptr);
    }
    NTSTATUS GetCtx(HANDLE thread, PCONTEXT ctx) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PCONTEXT);
        return ((fn_t)((uint8_t*)exec_page + 0x50))(thread, ctx);
    }
    NTSTATUS SetCtx(HANDLE thread, PCONTEXT ctx) {
        using fn_t = NTSTATUS(__stdcall*)(HANDLE,PCONTEXT);
        return ((fn_t)((uint8_t*)exec_page + 0x60))(thread, ctx);
    }
};

inline Syscalls g_sc;
