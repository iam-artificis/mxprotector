/**
 * @file veh_int3_trap.hpp
 * @brief G3 Phase 2 — VEH-based INT3 trap emission helper.
 *
 * Plant a Vectored Exception Handler in the protected binary's
 * packer entry stub and an INT3 instruction whose exception is
 * caught exclusively by that VEH. Static disassemblers see the
 * INT3 as a basic-block terminator or follow through into the six
 * bytes of per-build random junk that immediately follow it; real
 * execution skips the whole 7-byte block via a VEH-modified
 * `CONTEXT.Rip`.
 *
 * ## Mechanism
 *
 * Emission order (all bytes are written to the same RawEmitter,
 * landing as a contiguous region inside the packer stub):
 *
 *     jmp   short .past_handler       ; skip over handler body
 *   .handler:                          ; LONG NTAPI VEH(info)
 *     <filter + rip advance + ret>
 *   .past_handler:
 *     <save rsp + align + scratch frame>
 *     <Hell's Gate resolver → r13 = ntdll!RtlAddVectoredExceptionHandler>
 *     <if r13 == 0: skip install>
 *     call r13(first=1, handler=<lea rip>)
 *     <restore rsp>
 *   .int3_addr:
 *     int3
 *     db 6 × per-build random junk
 *
 * ## VEH filter (the most critical part)
 *
 * The handler MUST return `EXCEPTION_CONTINUE_SEARCH` for any
 * exception whose code is not `STATUS_BREAKPOINT (0x80000003)` OR
 * whose address is not the exact runtime VA of our planted int3.
 * If it ever misfires on a C++ `throw` (code `0xE06D7363`), the
 * protected binary's try/catch machinery silently breaks. The
 * `test_exception.cpp` smoke test guards this property — a passing
 * run under `--anti-tamper-veh` plus `-l strong` proves the filter
 * is doing the right thing in isolation.
 *
 * ## Graceful degradation
 *
 * The Hell's Gate resolver may fail on exotic Windows configurations
 * (e.g., a shim engine that replaces ntdll's prologue bytes the
 * resolver scans for). On failure `r13` stays at 0. The emitted
 * install sequence skips the `call r13` in that case, so the VEH
 * is never installed — but the int3 IS still planted further down,
 * and with no VEH to catch it the process crashes on it.
 *
 * That's an acceptable regression (the same "if the resolver can't
 * find ntdll, it can't find ntdll for any check" pattern the
 * existing Hell's Gate-based anti-tamper checks already accept),
 * and it is gated behind an opt-in flag, so mainstream users are
 * unaffected. A future enhancement could skip the int3 planting
 * too when `r13 == 0`, but that requires a conditional forward
 * emission which complicates the byte-level bookkeeping.
 *
 * ## Why EXE-only
 *
 * A DLL-installed VEH survives the DLL's unload: there is no
 * cleanup hook in our DllMain forwarding stub that removes the
 * VEH before the host process continues. Any subsequent exception
 * in the host would jump into freed memory. The caller is
 * responsible for gating on `pe_type == executable` before
 * emitting the trap.
 */

#pragma once

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::packer {

/**
 * @brief Emit the full VEH handler + install + planted INT3 sequence
 *        into `e`.
 *
 * Clobbered registers: `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`,
 * `r8`, `r9`, `r10`, `r11`, `r12`, `r13`, `r14`, `r15`. Essentially
 * every volatile GPR plus `r12..r15` — the Hell's Gate resolver's
 * own register budget, wrapped in an `rsp` save/restore frame
 * rooted in `r12`. The caller must emit this block BEFORE any
 * downstream code that expects those registers preserved (for the
 * packer cipher body, "downstream" means the anti-debug probe,
 * which rebuilds its state from scratch — so this helper fits
 * naturally right before the probe).
 *
 * Size: ~240 bytes, dominated by the ~155-byte Hell's Gate
 * resolver in the middle. The handler body is ~49 bytes, the
 * install scaffolding adds another ~30, and the planted int3
 * + junk tail is 7.
 *
 * Polymorphism:
 *   * The Hell's Gate salt is freshly drawn from `rng`, so the
 *     `cmp eax, target_hash` comparator and the scan-loop seed
 *     both differ from build to build.
 *   * The 6 junk bytes after the int3 are freshly drawn per
 *     build — they are dead code at runtime, but a linear
 *     disassembler will decode them, so varying them across
 *     builds denies reversers a fingerprint.
 *
 * @param e    Emitter the bytes are appended to.
 * @param rng  Randomiser for the Hell's Gate salt and the junk
 *             tail after the planted int3.
 */
void emit_veh_int3_trap(RawEmitter& e, Randomizer& rng);

} // namespace mx::packer
