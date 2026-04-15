/**
 * @file syscall_scaffold.hpp
 * @brief Shared anti-tamper syscall-check scaffolding helper.
 *
 * Every direct-syscall anti-tamper check (`hw_breakpoint_sweep`,
 * `page_protection`, `debug_object_handle`, and any future one) wraps
 * its check-specific argument setup and detection logic in the same
 * outer skeleton:
 *
 *     mov r12, rsp            ; save caller rsp (preserved across syscall)
 *     sub rsp, <frame_size>   ; allocate syscall scratch/output frame
 *     and rsp, -16            ; 16-align for the Windows x64 ABI
 *     <setup_fn emits args>
 *     mov r10, rcx            ; Windows x64 syscall ABI: rcx → r10
 *     mov eax, r13d           ; SSN from Hell's Gate resolver
 *     syscall
 *     <detection_fn normalises result to eax ∈ {0 clean, -1 tampered}>
 *     mov rsp, r12            ; restore caller rsp (key_slot is rsp-relative)
 *     and eax, <mask>         ; project 0/-1 → 0/mask
 *     xor [rsp + disp], eax   ; silent kill: poison handler-table key slot
 *
 * This helper emits the prologue, the syscall trio, and the epilogue.
 * Concrete checks supply two callables:
 *
 *   * `setup_fn(RawEmitter&)`  — zero output buffers, load rcx/rdx/r8/r9
 *                                 arguments, write stack-argN slots.
 *                                 Does NOT emit the `mov r10, rcx; mov
 *                                 eax, r13d; syscall` trio — the
 *                                 scaffold owns that sequence.
 *
 *   * `detection_fn(RawEmitter&)` — reads the syscall output from the
 *                                    frame, runs the check-specific
 *                                    predicate, and leaves the verdict
 *                                    in `eax` as 0 (clean) or
 *                                    0xFFFFFFFF (tampered). The final
 *                                    `and eax, mask` and `xor [rsp+
 *                                    disp], eax` are emitted by the
 *                                    scaffold and project the verdict
 *                                    onto `{0, corruption_mask}`.
 *
 * ## Register conventions (identical to every syscall check)
 *
 *   * `r12` — holds the saved caller `rsp` for the duration of the
 *             check. Preserved across `syscall` by the kernel, and the
 *             Hell's Gate resolver explicitly avoids r12 so checks can
 *             use it without coordination.
 *   * `r13` — SSN placed there by the Hell's Gate resolver that runs
 *             right before the anti-tamper loop. On resolver failure
 *             r13 is 0, the `syscall` executes with eax=0 (likely
 *             invoking an unrelated service), the output frame stays
 *             as whatever the setup_fn zeroed it to, the detection
 *             returns 0, and the final XOR is a no-op. Graceful
 *             degradation — the check silently skips rather than
 *             corrupting the protected binary on a host where the
 *             resolver couldn't find ntdll.
 *   * `rcx`, `r11` — clobbered by `syscall` itself (saved RIP, RFLAGS).
 *                     Setup_fn may use them freely before the trio
 *                     runs; detection_fn sees them as garbage.
 *
 * ## Why a template (not std::function)
 *
 * Templates force the lambdas to be inlined, so the generated x64
 * bytes are identical to the hand-written original — no std::function
 * type-erasure, no indirect call at build time. The scaffold stays a
 * pure code-layout rearrangement with zero runtime overhead in the
 * protected binary.
 */

#pragma once

#include <cstdint>
#include <type_traits>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::anti_tamper {

/**
 * @brief Emit the canonical anti-tamper syscall check scaffold.
 *
 * @tparam SetupFn      Callable `void(RawEmitter&)` that emits the
 *                      check-specific argument setup immediately
 *                      before the syscall trio.
 * @tparam DetectionFn  Callable `void(RawEmitter&)` that emits the
 *                      check-specific detection logic after the
 *                      syscall returns. Must leave `eax` at 0 for a
 *                      clean host or `-1` for a tampered one.
 *
 * @param e                RawEmitter the bytes are appended to.
 * @param frame_size       Number of bytes to subtract from rsp for the
 *                         syscall's scratch/output frame. Must be
 *                         large enough to hold every buffer and stack
 *                         argument the setup_fn touches, including the
 *                         shadow space for the called kernel routine.
 * @param key_slot_disp    rsp-relative displacement of the VM handler-
 *                         table key slot at the point the check runs.
 *                         Relative to the caller's rsp, i.e. the
 *                         value of rsp before the scaffold's
 *                         `sub rsp, frame_size`.
 * @param corruption_mask  Per-build random non-zero u32 the final XOR
 *                         stamps into the key slot when tamper is
 *                         detected. Callers typically compute this as
 *                         `rng.next_u32() | 1`.
 * @param setup_fn         Argument-setup emitter.
 * @param detection_fn     Detection-logic emitter.
 */
template <class SetupFn, class DetectionFn>
    requires std::is_invocable_v<SetupFn, RawEmitter&> &&
             std::is_invocable_v<DetectionFn, RawEmitter&>
void emit_syscall_check_scaffold(RawEmitter&   e,
                                 uint32_t      frame_size,
                                 int32_t       key_slot_disp,
                                 uint32_t      corruption_mask,
                                 SetupFn&&     setup_fn,
                                 DetectionFn&& detection_fn)
{
    // ---- prologue: save rsp, allocate, align ----
    // mov r12, rsp                             49 89 E4
    e.u8(0x49); e.u8(0x89); e.u8(0xE4);
    // sub rsp, frame_size                      48 81 EC imm32
    e.u8(0x48); e.u8(0x81); e.u8(0xEC);
    e.u32(frame_size);
    // and rsp, -16                             48 83 E4 F0
    e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);

    // ---- check-specific argument setup ----
    setup_fn(e);

    // ---- syscall trio ----
    // mov r10, rcx                             49 89 CA
    e.u8(0x49); e.u8(0x89); e.u8(0xCA);
    // mov eax, r13d                            44 89 E8
    e.u8(0x44); e.u8(0x89); e.u8(0xE8);
    // syscall                                  0F 05
    e.u8(0x0F); e.u8(0x05);

    // ---- check-specific detection (leaves eax = 0 or -1) ----
    detection_fn(e);

    // ---- epilogue: restore rsp, project verdict, silent kill ----
    // mov rsp, r12                             4C 89 E4
    e.u8(0x4C); e.u8(0x89); e.u8(0xE4);
    // and eax, <corruption_mask>               25 imm32
    e.u8(0x25); e.u32(corruption_mask);
    // xor [rsp + key_slot_disp], eax           31 44 24 disp8
    e.u8(0x31); e.u8(0x44); e.u8(0x24);
    e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
}

} // namespace mx::anti_tamper
