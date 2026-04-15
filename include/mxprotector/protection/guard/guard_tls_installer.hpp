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
 * `handler_rel32_offset` is the offset inside the installer's own
 * bytes of the 4-byte rel32 slot in `lea rdx, [rip + rel32]`.
 *
 * `handler_rel32_end_offset` is the offset of the byte right after
 * the rel32 slot. The rel32 resolves to `rip_after_lea + disp`,
 * which must equal the VEH handler's RVA, so the caller computes:
 *
 * ```
 * rel32 = handler_offset_in_section
 *       - (installer_offset_in_section + handler_rel32_end_offset);
 * ```
 *
 * and writes it into `data[installer_offset + handler_rel32_offset]`.
 */
struct GuardTlsInstallerEmit {
    uint32_t handler_rel32_offset     = 0;
    uint32_t handler_rel32_end_offset = 0;
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
