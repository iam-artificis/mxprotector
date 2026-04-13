/**
 * @file syscall_resolver.hpp
 * @brief [BUILDER] Resolves Windows syscall numbers (SSNs) at builder time.
 *
 * The anti-tamper checks in this directory call NTDLL functions via
 * direct `syscall` instructions to defeat user-mode API hooks. To do
 * that they need the System Service Number (SSN) of each function.
 * `SyscallResolver` extracts the SSN from the builder host's local
 * `ntdll.dll` and hands it to the check at construction time, where
 * it gets baked into the emitted code as an imm32.
 *
 * ### Build-time vs runtime
 *
 * The resolver runs once at builder startup. It extracts the SSN
 * from the builder host's loaded `ntdll.dll`, which is correct for
 * targets running on the same Windows build as the builder. Major
 * Windows feature updates routinely renumber syscalls, so a binary
 * built on Win11 22H2 but shipped to Win10 20H2 may `syscall` the
 * wrong service. Emitting a full runtime Hell's Gate resolver in
 * the entry stub itself is a clean follow-up — the check semantics
 * would not change, only the portability story.
 *
 * ### No Win32 API
 *
 * This implementation does NOT use `GetModuleHandleA` /
 * `GetProcAddress` / any Win32 loader surface. It walks the PEB
 * directly via the `__readgsqword(0x60)` compiler intrinsic (which
 * lowers to a single `mov rax, gs:[0x60]`), iterates
 * `InMemoryOrderModuleList` to find ntdll by name, and parses the
 * PE export table by hand to locate the target function. The only
 * thing that reads memory owned by the OS loader is the manual PE
 * walk, and nothing on the path can be intercepted by a user-mode
 * API hook installed via inline patching of `kernel32` /
 * `ntdll` exports.
 *
 * ### Failure mode
 *
 * If the resolver cannot find the function, or the function's first
 * 4 bytes don't match the expected `4C 8B D1 B8` syscall stub
 * prologue (`mov r10, rcx; mov eax, ssn; ...`), `resolve` returns 0.
 * Callers treat 0 as "this syscall is not available, drop the
 * check from the registry". The protected binary remains correct;
 * it just loses one anti-tamper variant.
 */

#pragma once

#include <cstdint>

namespace mx::anti_tamper {

class SyscallResolver final {
public:
    /**
     * @brief Resolve the SSN for an NTDLL function.
     *
     * @param function_name  Plain ANSI name, e.g. "NtGetContextThread".
     * @return The SSN as a 32-bit value, or 0 if the function is
     *         missing or its prologue did not match the expected
     *         direct-syscall shape.
     *
     * Implementation reads bytes 0..7 of the resolved function and
     * checks bytes 0..3 against `{0x4C, 0x8B, 0xD1, 0xB8}` (mov r10,
     * rcx; mov eax, ...). The next 4 bytes are interpreted as a
     * little-endian uint32 and returned as the SSN.
     */
    [[nodiscard]] uint32_t resolve(const char* function_name) const noexcept;
};

} // namespace mx::anti_tamper
