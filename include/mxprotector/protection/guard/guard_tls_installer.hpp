/**
 * @file guard_tls_installer.hpp
 * @brief Emits the TLS callback that installs the guard VEH handler.
 *
 * The runtime-guards subsystem needs its Vectored Exception Handler
 * installed BEFORE any guarded code executes. The cleanest mount
 * point on Windows is a TLS callback: the loader runs every DLL's
 * TLS callback array at `DLL_PROCESS_ATTACH` before calling
 * `AddressOfEntryPoint`. The packer's existing TLS callback
 * (`tls_callback.cpp`) handles the "corrupt one cipher key when
 * under a debugger" gag; our installer sits in the same callback
 * array (inserted by `PackerPass::execute` via the existing
 * TLS-inheritance path) so both run before user code does.
 *
 * ## Emission outline
 *
 * ```
 *     ; rcx = DllHandle, rdx = Reason, r8 = Reserved
 *     cmp  edx, 1                 ; DLL_PROCESS_ATTACH?
 *     jne  .done
 *
 *     sub  rsp, 0x28              ; shadow + align
 *
 *     <Hell's Gate resolver for RtlAddVectoredExceptionHandler>
 *     ; r13 = &RtlAddVectoredExceptionHandler (or 0 on failure)
 *
 *     test r13, r13
 *     jz   .restore
 *
 *     mov  ecx, 1                 ; First = TRUE (install at head)
 *     lea  rdx, [rip + rel32_handler]
 *     call r13
 *
 * .restore:
 *     add  rsp, 0x28
 *
 * .done:
 *     xor  eax, eax
 *     ret
 * ```
 *
 * The only patch site is the rel32 inside `lea rdx` — the caller
 * back-patches it with the offset of the VEH handler's first byte
 * relative to the end of the lea, both measured within the
 * `.mxguard` section. The Hell's Gate block bakes its own salted
 * DJB2 hash and runs `validate_syscall_prologue=false` because
 * `RtlAddVectoredExceptionHandler` is not a syscall stub (its
 * prologue does NOT start with `4C 8B D1 B8`).
 *
 * ## Register-use contract
 *
 * The callback obeys the Windows x64 ABI: it saves nothing
 * explicitly because it only uses volatile regs (rax, rcx, rdx,
 * r8..r11, r13 — the last one is saved as a Hell's Gate scratch
 * and restored by the resolver itself). The `sub rsp, 0x28` before
 * the `call r13` keeps rsp 16-aligned for the call; the matching
 * `add rsp, 0x28` restores it. The loader only reads `eax` on
 * return for no particular purpose (TLS callbacks are `void`), but
 * we zero it anyway for deterministic state.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/randomizer.hpp"

namespace mx::guard {

/**
 * @brief Patch sites produced by `emit_guard_tls_installer`.
 *
 * Two groups of offsets:
 *
 * ### Handler pointer for `AddVectoredExceptionHandler`
 *
 * `handler_rel32_offset` / `handler_rel32_end_offset` form the
 * rip-relative target of `lea rdx, [rip + rel32]` which passes the
 * VEH handler's address to `RtlAddVectoredExceptionHandler`. The
 * caller fills this in the same way as any other in-section rel32:
 *
 * ```
 * rel32 = handler_offset_in_section
 *       - (installer_offset_in_section + handler_rel32_end_offset);
 * ```
 *
 * ### Commit 6 self-CRC
 *
 * Before actually installing the handler, the installer walks the
 * handler byte stream and computes `fnv1a_32` over it, then compares
 * against a build-time-baked expected value. On mismatch the install
 * is silently skipped — the first `int3` on a guard page then
 * propagates as an unhandled breakpoint and terminates the process.
 * This catches any tampering that modifies the handler between
 * build time and the moment the loader runs our TLS callback.
 *
 *   * `crc_walk_rel32_offset` / `crc_walk_rel32_end_offset` — the
 *     rel32 slot inside `lea r11, [rip + rel32]` which sets the
 *     walk cursor to the first byte of the VEH handler. Patched
 *     exactly like `handler_rel32_offset` but to the same target
 *     from a different lea.
 *
 *   * `crc_size_imm32_offset` — the 4-byte imm32 inside
 *     `mov ecx, imm32` that loads the handler byte count.
 *     The caller writes `handler_size`.
 *
 *   * `crc_expected_imm32_offset` — the 4-byte imm32 inside
 *     `cmp r10d, imm32` that holds the build-time
 *     `fnv1a_32(handler_bytes, handler_size)`.
 */
struct GuardTlsInstallerEmit {
    uint32_t handler_rel32_offset     = 0;
    uint32_t handler_rel32_end_offset = 0;

    uint32_t crc_walk_rel32_offset     = 0;
    uint32_t crc_walk_rel32_end_offset = 0;
    uint32_t crc_size_imm32_offset     = 0;
    uint32_t crc_expected_imm32_offset = 0;
};

/**
 * @brief Append the TLS installer thunk to `e`.
 *
 * @param e    Emitter to append bytes to.
 * @param rng  Randomizer used to draw the Hell's Gate salt so each
 *             protected build's resolver hash inputs differ.
 * @return     Patch-site offsets the caller uses to finalise the
 *             rel32 to the VEH handler.
 */
[[nodiscard]] GuardTlsInstallerEmit emit_guard_tls_installer(
    RawEmitter& e,
    Randomizer& rng);

} // namespace mx::guard
