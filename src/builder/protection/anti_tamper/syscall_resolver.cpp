/**
 * @file syscall_resolver.cpp
 * @brief [BUILDER] SyscallResolver implementation — Win32 only.
 *
 * The builder is a Windows x64 binary, so we can use ordinary
 * `GetModuleHandleA` / `GetProcAddress` to find ntdll exports and
 * read the function bytes directly.
 */

#include "mxprotector/protection/anti_tamper/syscall_resolver.hpp"

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <Windows.h>
#endif

namespace mx::anti_tamper {

uint32_t SyscallResolver::resolve(const char* function_name) const noexcept {
#if defined(_WIN32)
    if (function_name == nullptr) return 0;

    HMODULE ntdll = ::GetModuleHandleA("ntdll.dll");
    if (ntdll == nullptr) return 0;

    auto func = reinterpret_cast<const unsigned char*>(
        ::GetProcAddress(ntdll, function_name));
    if (func == nullptr) return 0;

    // Expected prologue of an unhooked NTDLL syscall stub:
    //   4C 8B D1                       ; mov r10, rcx
    //   B8 ?? ?? ?? ??                 ; mov eax, ssn
    //   F6 04 25 08 03 FE 7F 01        ; test byte ptr [...], 1
    //   ...
    // Some Windows versions have a slightly different tail (the
    // wow64 trampoline test), so we only validate the first 4 bytes.
    if (func[0] != 0x4C || func[1] != 0x8B
     || func[2] != 0xD1 || func[3] != 0xB8)
    {
        // Either the export points at a hook (jmp / mov rax, imm64 /
        // ...), or the stub uses a different prologue we don't
        // recognise. Either way, reading bytes 4..7 would give a
        // garbage SSN — refuse.
        return 0;
    }

    // Bytes 4..7 are the SSN immediate, little-endian.
    uint32_t ssn = 0;
    ssn |= static_cast<uint32_t>(func[4]);
    ssn |= static_cast<uint32_t>(func[5]) << 8;
    ssn |= static_cast<uint32_t>(func[6]) << 16;
    ssn |= static_cast<uint32_t>(func[7]) << 24;

    // Sanity bound: SSNs on modern Windows fit in a low 32-bit value
    // but never exceed ~0x10000. A wildly large value indicates the
    // bytes we read were not the SSN immediate.
    if (ssn > 0xFFFFu) return 0;
    return ssn;
#else
    (void)function_name;
    return 0;  // Non-Windows builder: anti-tamper checks are disabled.
#endif
}

} // namespace mx::anti_tamper
