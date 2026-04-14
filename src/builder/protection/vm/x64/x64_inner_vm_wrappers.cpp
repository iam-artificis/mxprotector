/**
 * @file x64_inner_vm_wrappers.cpp
 * @brief [BUILDER, x64] Implementation of the G2 outer-handler nested wrappers.
 *
 * Every wrapper follows the same three-stage pattern documented in
 * `x64_inner_vm_wrappers.hpp`: fetch operands → compute slot addrs
 * → `emit_inner_vm_call` with an inline inner bytecode. This file
 * owns the shared tail emitter and the wrappers themselves; it does
 * not know anything about the layout of the inner VM runtime beyond
 * what `InnerVmOp` names — all byte-level work is isolated in
 * `x64_inner_vm.cpp`.
 */

#include "mxprotector/protection/vm/x64/x64_inner_vm_wrappers.hpp"

#include <cassert>
#include <cstdint>

#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

namespace mx::vm::x64 {

void emit_inner_vm_call(RawEmitter& e,
                        const uint8_t* bytecode,
                        size_t bytecode_len,
                        size_t& call_rel32_patch_out)
{
    // A short rel8 `jmp` has to cover the inline bytecode plus the
    // 5-byte `call rel32`. In practice our bytecodes are tiny
    // (≤ 16 bytes) so the max-127 window is never close, but guard
    // against a future lifter that stuffs more into one wrapper.
    assert(bytecode_len <= 0x7F &&
           "inner VM inline bytecode must fit in a rel8 jmp");

    // --- lea r12, [rip + 2] -------------------------------------------
    //
    // `rip` after the LEA = current_offset + 7. The `[rip + 2]`
    // target = current_offset + 9 = the first byte of the inline
    // bytecode (right after the 2-byte `jmp rel8` that follows the
    // LEA). This disp is constant across all wrappers — only the
    // rel8 jmp argument varies with bytecode length.
    //
    //   REX.W|R (0x4C) + 0x8D + ModRM(mod=00 reg=r12&7=100 rm=101 rip-rel)
    //   = 0x4C 0x8D 0x25 disp32
    e.u8(0x4C); e.u8(0x8D); e.u8(0x25);
    e.u32(static_cast<uint32_t>(2));

    // --- jmp rel8 (skip over the inline bytecode) ---------------------
    e.u8(0xEB);
    e.u8(static_cast<uint8_t>(bytecode_len));

    // --- Inline inner VM bytecode -------------------------------------
    //
    // The inner VM's dispatcher starts fetching from r12 (which the
    // LEA above pointed at these exact bytes).
    for (size_t i = 0; i < bytecode_len; ++i) {
        e.u8(bytecode[i]);
    }

    // --- call rel32 <inner_vm_entry> ----------------------------------
    //
    // The rel32 is left at zero; the backend records the offset via
    // `call_rel32_patch_out` and overwrites it once
    // `emit_inner_vm_runtime` has been placed in the blob.
    e.u8(0xE8);
    call_rel32_patch_out = e.size();
    e.u32(0);
}

// ===========================================================================
// Nested wrappers
// ===========================================================================

void emit_handler_alu_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, uint8_t alu_inner_opcode,
                                size_t& call_rel32_patch_out)
{
    // Operand fetch + slot address computation — identical to the
    // direct V0 ALU handler's prologue.
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);

    // Inline inner bytecode: load rhs (src) into r15, load accumulator
    // (dst) into r14, run the r14←r14 OP r15 ALU, store r14 back to
    // [rsi], return. The ALU handler saves rflags into rcx, and
    // `iret` restores them before `ret`, so the outer tail dispatch
    // that runs after this `call` sees the correct guest flags.
    const uint8_t bc[] = {
        static_cast<uint8_t>(InnerVmOp::iload_src),   // 0x00
        static_cast<uint8_t>(InnerVmOp::iload_dst),   // 0x01
        alu_inner_opcode,                              // 0x03..0x07
        static_cast<uint8_t>(InnerVmOp::istore_dst),  // 0x02
        static_cast<uint8_t>(InnerVmOp::iret),        // 0x08
    };
    emit_inner_vm_call(e, bc, sizeof(bc), call_rel32_patch_out);
}

void emit_handler_mov_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, size_t& call_rel32_patch_out)
{
    // Operand layout is the same as the r-r ALU handlers: two slot-
    // index bytes (dst first, then src), computed into rsi / rdi.
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);

    // Inline inner bytecode: load src into the accumulator (r14),
    // store accumulator to dst slot, return without touching flags.
    //
    // `iload_src_accum` (0x09) writes [rdi] into r14 directly — the
    // same destination `istore_dst` reads from — so we need exactly
    // 3 inner ops for a 64-bit memcpy: load, store, return.
    //
    // `iret_noflag` (0x0A) is `ret` without the `push rcx; popfq`
    // pair of normal `iret`. `mov_rr` is flag-transparent on real
    // x86 — `mov` doesn't touch `rflags` — so we must NOT stomp
    // rflags before returning to the outer handler's tail dispatch.
    // If we used `iret` instead, the terminal `popfq` would load
    // `rflags` from `rcx`, which at this point is a stale
    // `dst_vreg * 8` left over from `emit_vmreg_addr_rsi_from_rcx`.
    // That would populate `vflags` with junk on the next tail
    // dispatch and break downstream `vjcc`.
    //
    // With `iret_noflag`, rflags exiting this handler match what a
    // direct V0 `mov_rr` leaves: the shl-flags from the addr
    // compute. That's not semantically "the flags mov should not
    // touch", but it IS exactly what V0 does — so V2 mov_rr has
    // parity with V0 mov_rr, which is the correctness bar we need.
    const uint8_t bc[] = {
        static_cast<uint8_t>(InnerVmOp::iload_src_accum), // 0x09
        static_cast<uint8_t>(InnerVmOp::istore_dst),      // 0x02
        static_cast<uint8_t>(InnerVmOp::iret_noflag),     // 0x0A
    };
    emit_inner_vm_call(e, bc, sizeof(bc), call_rel32_patch_out);
}

} // namespace mx::vm::x64
