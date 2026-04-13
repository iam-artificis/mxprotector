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
 * ### Why build-time and not runtime
 *
 * Runtime resolution would walk the loaded NTDLL via PEB.Ldr, parse
 * its export table, find the function by name, and read the SSN out
 * of the prologue. That works on every Windows version regardless of
 * which build the protector was compiled on, but it's ~150 bytes of
 * carefully encoded x64 emission per resolved function plus the
 * parsing logic.
 *
 * Build-time extraction is dramatically simpler — the builder is a
 * Windows binary and can call `GetModuleHandleA` / `GetProcAddress`
 * directly — but the resulting SSN is **only valid on Windows builds
 * with the same syscall numbering as the builder host**. Major
 * Windows feature updates routinely renumber syscalls.
 *
 * For now this is acceptable: the builder and target are typically
 * the same machine in a research workflow, and adding runtime Hell's
 * Gate is a clean follow-up that doesn't change the check semantics.
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
