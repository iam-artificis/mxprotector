/**
 * @file x64_inner_vm_wrappers.cpp
 * @brief [BUILDER, x64] Implementation of the G2 outer-handler nested wrappers.
 *
 * Every wrapper follows the same three-stage pattern documented in
 * `x64_inner_vm_wrappers.hpp`: fetch operands → compute slot addrs
 * → `emit_inner_vm_call` with an inline logical inner bytecode.
 * This file owns the shared tail emitter and the wrappers themselves;
 * it does not know anything about the byte-level layout of the inner
 * VM runtime beyond what `InnerVmOp` names.
 *
 * Per-build randomization is handled by the shared
 * `emit_inner_vm_call`: it translates every logical `InnerVmOp` into
 * the byte value assigned by the current build's `InnerVmIsa`
 * permutation before writing it to the blob. Wrappers never touch
 * raw opcode bytes directly.
 */

#include "mxprotector/protection/vm/x64/x64_inner_vm_wrappers.hpp"

#include <cassert>
#include <cstdint>

#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

namespace mx::vm::x64 {

void emit_inner_vm_call(RawEmitter& e,
                        const InnerVmIsa& isa,
                        const InnerVmOp* bytecode,
                        size_t bytecode_len,
                        size_t& call_rel32_patch_out)
{
    // A short rel8 `jmp` has to cover the inline bytecode plus the
    // 5-byte `call rel32`. In practice our bytecodes are tiny
    // (≤ 16 opcodes) so the max-127 window is never close, but guard
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

    // --- Inline inner VM bytecode (ISA-permuted) ----------------------
    //
    // Translate each logical opcode through the ISA's permutation
    // before emitting. The inner VM dispatcher starts fetching from
    // r12 (which the LEA above pointed at these exact bytes), and
    // its handler table — emitted by `emit_inner_vm_runtime` under
    // the same ISA — maps each permuted byte back to the correct
    // handler body.
    for (size_t i = 0; i < bytecode_len; ++i) {
        e.u8(isa.byte_of(bytecode[i]));
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
// Register-register ALU + mov + unary wrappers
// ===========================================================================

void emit_handler_alu_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, const InnerVmIsa& isa,
                                InnerVmOp alu_inner_op,
                                size_t& call_rel32_patch_out)
{
    // Operand fetch + slot address computation — identical to the
    // direct V0 ALU handler's prologue.
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);

    // Logical inner bytecode: load rhs (src) into r15, load
    // accumulator (dst) into r14, run the r14←r14 OP r15 ALU,
    // store r14 back to [rsi], return.
    const InnerVmOp bc[] = {
        InnerVmOp::iload_src,
        InnerVmOp::iload_dst,
        alu_inner_op,
        InnerVmOp::istore_dst,
        InnerVmOp::iret,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

void emit_handler_mov_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, const InnerVmIsa& isa,
                                size_t& call_rel32_patch_out)
{
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);

    // Load src into the accumulator r14 directly, store to [rsi],
    // return without touching flags. `mov` is flag-transparent on
    // real x86; V0 `mov_rr` is likewise flag-transparent at the
    // inner-VM boundary.
    const InnerVmOp bc[] = {
        InnerVmOp::iload_src_accum,
        InnerVmOp::istore_dst,
        InnerVmOp::iret_noflag,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

void emit_handler_not_r_nested(RawEmitter& e, int32_t key_disp,
                               bool rolling, const InnerVmIsa& isa,
                               size_t& call_rel32_patch_out)
{
    // Unary handlers only need the dst slot address — no rhs, no
    // src. Fetch one operand byte into cl (dst vreg), compute rsi.
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);

    // Load dst into accumulator, invert all bits, store back,
    // return without touching rflags. `not` is flag-transparent
    // on real x86.
    const InnerVmOp bc[] = {
        InnerVmOp::iload_dst,
        InnerVmOp::inot_r14,
        InnerVmOp::istore_dst,
        InnerVmOp::iret_noflag,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

void emit_handler_neg_r_nested(RawEmitter& e, int32_t key_disp,
                               bool rolling, const InnerVmIsa& isa,
                               size_t& call_rel32_patch_out)
{
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);

    // Load dst, negate, store back, restore the guest-ALU flags
    // from rcx before returning. `neg` IS flag-producing on real
    // x86 (CF, SF, ZF, OF, PF), so we pair with the regular
    // `iret`.
    const InnerVmOp bc[] = {
        InnerVmOp::iload_dst,
        InnerVmOp::ineg_r14,
        InnerVmOp::istore_dst,
        InnerVmOp::iret,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

// ===========================================================================
// Immediate-form wrappers (*_ri32)
// ===========================================================================
//
// The *_ri32 outer handlers fetch an imm32 from the encrypted outer
// bytecode stream. Since the imm only becomes available at runtime
// (after the rolling-key decryption), we can't inline it into the
// inner VM bytecode — inner bytecode is hard-coded at emit time.
//
// Workaround: the outer wrapper uses `emit_fetch_dword` (same helper
// V0 uses) to land the decrypted dword in `eax`, then issues a
// 3-byte `movsxd r14, eax` (mov_ri32) or `movsxd r15, eax` (ALU
// ri32) to pre-populate the inner accumulator/rhs BEFORE calling
// into the inner VM. The inner bytecode then reuses the existing
// multi-step ISA without needing an `iload_imm32` opcode.
//
// Byte encoding of the movsxd:
//   `movsxd r14, eax` = 4C 63 F0   (REX.W|R, opcode 63, ModRM 11 110 000)
//   `movsxd r15, eax` = 4C 63 F8   (REX.W|R, opcode 63, ModRM 11 111 000)

void emit_handler_alu_ri32_nested(RawEmitter& e, int32_t key_disp,
                                  bool rolling, const InnerVmIsa& isa,
                                  InnerVmOp alu_inner_op,
                                  size_t& call_rel32_patch_out)
{
    // Fetch + decrypt 1 operand byte (dst vreg) and 4 bytes of
    // imm32, with the rolling key threaded through both — same as
    // V0 alu_ri32's prologue.
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);

    // movsxd r15, eax — sign-extend the fetched 32-bit imm into
    // the rhs-operand register. This is the handoff point: after
    // this instruction the inner VM can treat the imm exactly like
    // a slot value loaded by `iload_src`, and the regular r-r ALU
    // opcodes apply unchanged.
    e.u8(0x4C); e.u8(0x63); e.u8(0xF8);

    // Logical inner bytecode: the same [iload_dst, ALU, istore_dst,
    // iret] shape as ALU rr, minus the iload_src — r15 is already
    // loaded by the movsxd above.
    const InnerVmOp bc[] = {
        InnerVmOp::iload_dst,
        alu_inner_op,
        InnerVmOp::istore_dst,
        InnerVmOp::iret,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

void emit_handler_mov_ri32_nested(RawEmitter& e, int32_t key_disp,
                                  bool rolling, const InnerVmIsa& isa,
                                  size_t& call_rel32_patch_out)
{
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);

    // movsxd r14, eax — sign-extend the fetched 32-bit imm straight
    // into the accumulator, bypassing any load opcode. `istore_dst`
    // will pick it up directly.
    e.u8(0x4C); e.u8(0x63); e.u8(0xF0);

    // Logical inner bytecode: 2-op [istore_dst, iret_noflag]. No
    // loads, no ALU — `mov` is flag-transparent on x86 so we exit
    // through `iret_noflag`, matching V0 mov_ri32's flag behavior.
    const InnerVmOp bc[] = {
        InnerVmOp::istore_dst,
        InnerVmOp::iret_noflag,
    };
    emit_inner_vm_call(e, isa, bc, sizeof(bc) / sizeof(bc[0]),
                       call_rel32_patch_out);
}

} // namespace mx::vm::x64
