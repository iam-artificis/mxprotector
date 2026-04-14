/**
 * @file x64_handlers.cpp
 * @brief [BUILDER, x64] Handler bodies, fetch helpers and tail dispatch.
 *
 * Implementations for `x64_handlers.hpp`. See the header for an overview;
 * this file is the byte emission for every VM opcode.
 *
 * Extracted from the legacy `vm_runtime_gen.cpp` monolith during the
 * Phase 2 arch refactor.
 */

#include "mxprotector/protection/vm/x64/x64_handlers.hpp"

#include <iterator>

#include "mxprotector/protection/vm/x64/x64_emitters.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_vflags.hpp"

namespace mx::vm::x64 {

// ============================================================================
// Bytecode fetch helpers
// ============================================================================
//
// Each fetch:
//    1) movzx r32, byte [r11]           — load encrypted byte
//    2) xor r8_low, [rsp + keyDisp]     — decrypt with current key
//    3) xor [rsp + keyDisp], r8_low     — update key ^= decrypted_byte
//    4) inc r11                         — advance vpc
//
// After step 2, the low 8 bits of the destination register hold the plain
// byte; the upper bits are zero (from the movzx).

void emit_fetch_byte(RawEmitter& e, uint8_t dst_reg, int32_t key_disp,
                     bool rolling)
{
    emit_movzx_r32_byte_mem(e, dst_reg, 11, 0);
    emit_xor_r8l_rsp_disp(e, dst_reg, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, dst_reg, key_disp);
    }
    emit_inc_r11(e);
}

void emit_fetch_dword(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 4; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x09); e.u8(0xC8);
    }
}

void emit_fetch_qword(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 8; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x48); e.u8(0x09); e.u8(0xC8);
    }
}

void emit_fetch_2_operand_bytes(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
    emit_fetch_byte(e, 2 /*rdx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE2); e.u8(0x0F);
}

void emit_fetch_1_operand_byte(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
}

// ============================================================================
// VM-reg address helpers
// ============================================================================

void emit_vmreg_addr_rsi_from_rcx(RawEmitter& e) {
    // shl rcx, 3                     48 C1 E1 03
    // lea rsi, [rsp + rcx*1]         48 8D 34 0C
    e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x34); e.u8(0x0C);
}

void emit_vmreg_addr_rdi_from_rdx(RawEmitter& e) {
    // shl rdx, 3                     48 C1 E2 03
    // lea rdi, [rsp + rdx*1]         48 8D 3C 14
    e.u8(0x48); e.u8(0xC1); e.u8(0xE2); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x14);
}

// ============================================================================
// Junk prologue + dispatch shape selectors
// ============================================================================

void emit_junk_prologue(RawEmitter& e, Randomizer& rng, uint32_t max_bytes) {
    if (max_bytes == 0) return;
    // Zero-byte prologue is a valid variant (roughly 1/N of handlers).
    const uint32_t total = rng.next_range(0, max_bytes);
    uint32_t remaining = total;
    while (remaining > 0) {
        // Single NOPs of length 1..9 — Intel documents up to NOP9 in the
        // optimization manual. Larger NOPs are synthesized from smaller ones.
        const uint8_t chunk = static_cast<uint8_t>(
            (remaining > 9) ? 9 : remaining);
        emit_nop_run(e, chunk);
        remaining -= chunk;
    }
}

DispatchShape pick_dispatch_shape(Randomizer& rng) {
    return static_cast<DispatchShape>(rng.next_range(0,
        static_cast<uint32_t>(DispatchShape::kCount) - 1));
}

uint8_t pick_table_base_reg(Randomizer& rng) {
    static constexpr uint8_t candidates[] = {
        1,   // rcx
        2,   // rdx
        3,   // rbx
        6,   // rsi
        7,   // rdi
        8,   // r8
        9,   // r9
        10,  // r10
        12,  // r12
        13,  // r13
        14,  // r14
        15,  // r15
    };
    const uint32_t idx = rng.next_range(0,
        static_cast<uint32_t>(std::size(candidates)) - 1);
    return candidates[idx];
}

// ============================================================================
// Tail dispatch
// ============================================================================

TailDispatchPatch emit_tail_dispatch(RawEmitter& e, int32_t key_disp,
                                     bool rolling,
                                     bool save_rflags,
                                     std::vector<size_t>& table_key_patches,
                                     uint32_t vflags_key,
                                     uint32_t vflags_rol,
                                     int32_t rflags_disp,
                                     Randomizer* rng,
                                     int32_t imagebase_key_disp)
{
    // Optionally save CPU rflags into the VM context BEFORE clobbering them
    // with the fetch logic (movzx/xor). This is the single collection point
    // for flag preservation — every handler's body has just finished, and the
    // CPU flags still reflect the last ALU/native operation.
    if (save_rflags) {
        const auto v = (rng != nullptr) ? pick_store_variant(*rng)
                                         : VflagsStoreV::RaxRolFirst;
        emit_vflags_store(e, v, vflags_key, vflags_rol, rflags_disp);
    }

    emit_movzx_r32_byte_mem(e, 0 /*rax*/, 11, 0);
    emit_xor_r8l_rsp_disp(e, 0, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, 0, key_disp);
    }
    emit_inc_r11(e);

    // Pick polymorphism variants. When rng is null (deprecated callers that
    // predate polymorphism) fall back to the original rcx+jmp shape.
    const uint8_t       base_reg = (rng != nullptr) ? pick_table_base_reg(*rng) : 1;
    const DispatchShape shape    = (rng != nullptr) ? pick_dispatch_shape(*rng)
                                                     : DispatchShape::JmpReg;

    // lea <base>, [rip + rel32]  — rel32 patched to point at the handler_table
    const auto patch_off = emit_lea_reg_rip_rel32(e, base_reg);
    const auto patch_end = e.size();

    // mov eax, dword [base + rax*4]    — zero-extends the 32-bit table entry
    emit_mov_eax_from_base_rax4(e, base_reg);

    // xor eax, TABLE_KEY — decrypt the table entry.
    if (imagebase_key_disp >= 0) {
        // xor eax, [rsp + disp8]    33 44 24 disp8
        e.u8(0x33);
        e.u8(0x44);
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(imagebase_key_disp)));
    } else {
        // xor eax, imm32    35 imm32  (placeholder, patched later)
        e.u8(0x35);
        table_key_patches.push_back(e.size());
        e.u32(0);
    }

    // movsxd rax, eax   — sign-extend AFTER decryption    48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // add <base>, rax
    emit_add_base_rax(e, base_reg);

    // Indirect branch — polymorphic shape.
    switch (shape) {
        case DispatchShape::JmpReg:
            emit_jmp_reg(e, base_reg);
            break;
        case DispatchShape::PushRegRet:
            // push <base>; ret  — net rsp change is zero: push -8, ret +8.
            emit_push_reg(e, base_reg);
            e.u8(0xC3);
            break;
        case DispatchShape::kCount:
            break;
    }

    return {patch_off, patch_end};
}

// ============================================================================
// Handler bodies — ALU / logic / shift / mov / branch
// ============================================================================

void emit_handler_mov_rr(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]   48 8B 07
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // mov [rsi], rax   48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_alu_rr(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // OP [rsi], rax     48 op_mr 06
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

// MBA variants — mathematically equivalent alternatives that defeat simple
// opcode-table recovery in a decompiler.

/// ADD: x + y ≡ (x ^ y) + 2 * (x & y)
void emit_handler_add_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);   // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);   // rdx = x = [rsi]
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);   // rcx = rdx
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);   // rcx = x & y
    e.u8(0x48); e.u8(0xD1); e.u8(0xE1);   // rcx = 2 * (x & y)
    e.u8(0x48); e.u8(0x31); e.u8(0xC2);   // rdx = x ^ y
    e.u8(0x48); e.u8(0x01); e.u8(0xCA);   // rdx = (x^y) + 2*(x&y)
    e.u8(0x48); e.u8(0x89); e.u8(0x16);   // [rsi] = rdx
}

/// SUB: x - y ≡ x + (-y)
void emit_handler_sub_rr_neg(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);   // rax = y = [rdi]
    e.u8(0x48); e.u8(0xF7); e.u8(0xD8);   // neg rax
    e.u8(0x48); e.u8(0x01); e.u8(0x06);   // add [rsi], rax
}

/// XOR: x ^ y ≡ (x | y) - (x & y)
void emit_handler_xor_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);   // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);   // rdx = x = [rsi]
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);   // rcx = rdx
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);   // rcx = x & y
    e.u8(0x48); e.u8(0x09); e.u8(0xC2);   // rdx = x | y
    e.u8(0x48); e.u8(0x29); e.u8(0xCA);   // rdx = (x|y) - (x&y)
    e.u8(0x48); e.u8(0x89); e.u8(0x16);   // [rsi] = rdx
}

// ---------------------------------------------------------------------------
// G4 — handler-id polymorphism: alternative emitter variants.
//
// Each of these produces the same semantic effect as the canonical
// handler for the corresponding VmOp but with a different x64 byte
// sequence. The backend's encoder picks one per bytecode slot at
// random so two consecutive `and_rr` ops end up at two completely
// different handler bodies — different opcodes, different
// register traffic, different body lengths. Static recovery of the
// guest-opcode table via "one canonical body per VmOp" no longer
// works.
// ---------------------------------------------------------------------------

/// mov_rr V1: `push [src]; pop [dst]`. No scratch register, the
/// stack does the actual data transfer.
void emit_handler_mov_rr_pushpop(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // push qword [rdi]   FF 37  (PUSH r/m64, /6)
    e.u8(0xFF); e.u8(0x37);
    // pop qword [rsi]    8F 06  (POP  r/m64, /0)
    e.u8(0x8F); e.u8(0x06);
}

/// and_rr V1: `x & y ≡ ~(~x | ~y)`.
void emit_handler_and_rr_demorgan(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = x = [rsi]        48 8B 06
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // rdx = y = [rdi]        48 8B 17
    e.u8(0x48); e.u8(0x8B); e.u8(0x17);
    // not rax                48 F7 D0
    e.u8(0x48); e.u8(0xF7); e.u8(0xD0);
    // not rdx                48 F7 D2
    e.u8(0x48); e.u8(0xF7); e.u8(0xD2);
    // or rax, rdx            48 09 D0  (or r/m64, r64: reg=rdx src)
    e.u8(0x48); e.u8(0x09); e.u8(0xD0);
    // not rax                48 F7 D0
    e.u8(0x48); e.u8(0xF7); e.u8(0xD0);
    // mov [rsi], rax         48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/// or_rr V1: `x | y ≡ ~(~x & ~y)`.
void emit_handler_or_rr_demorgan(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = x = [rsi]        48 8B 06
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // rdx = y = [rdi]        48 8B 17
    e.u8(0x48); e.u8(0x8B); e.u8(0x17);
    // not rax                48 F7 D0
    e.u8(0x48); e.u8(0xF7); e.u8(0xD0);
    // not rdx                48 F7 D2
    e.u8(0x48); e.u8(0xF7); e.u8(0xD2);
    // and rax, rdx           48 21 D0  (and r/m64, r64)
    e.u8(0x48); e.u8(0x21); e.u8(0xD0);
    // not rax                48 F7 D0
    e.u8(0x48); e.u8(0xF7); e.u8(0xD0);
    // mov [rsi], rax         48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/// not_r V1: `xor qword [slot], -1` (imm32, sign-extended to int64).
void emit_handler_not_r_xor(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // xor qword [rsi], -1    48 81 /6 imm32
    //   REX.W (48) + 81 + ModRM(00 110 110 = 0x36, /6=xor) + disp0 + imm32
    e.u8(0x48); e.u8(0x81); e.u8(0x36);
    e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);
}

/// neg_r V1: `~x + 1`. Encoded as `not [slot]; inc qword [slot]`.
void emit_handler_neg_r_notinc(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // not qword [rsi]        48 F7 16  (/2 = not, rm=rsi=6 → ModRM 00 010 110)
    e.u8(0x48); e.u8(0xF7); e.u8(0x16);
    // inc qword [rsi]        48 FF 06  (/0 = inc, rm=rsi=6 → ModRM 00 000 110)
    e.u8(0x48); e.u8(0xFF); e.u8(0x06);
}

// The G2 nested-VM outer-handler wrappers (emit_handler_*_nested)
// have moved to `x64_inner_vm_wrappers.cpp` — see that file for
// the add/sub/xor/and/or/mov nested variants and the shared
// `emit_inner_vm_call` tail.

void emit_handler_imul_rr(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // imul rax, [rdi]
    e.u8(0x48); e.u8(0x0F); e.u8(0xAF); e.u8(0x07);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri32(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);
    // movsxd rax, eax   48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri64(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_qword(e, key_disp, rolling);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_alu_ri32(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp, rolling);
    // movsxd rax, eax
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // OP [rsi], rax
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

/// not/neg [rsi]  (/2 for not, /3 for neg)
void emit_handler_unary(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op) {
    emit_fetch_1_operand_byte(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // 48 F7 /sub_op,rm=6(rsi)
    e.u8(0x48); e.u8(0xF7);
    e.u8(static_cast<uint8_t>((sub_op << 3) | 0x06));
}

void emit_handler_shift(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op) {
    emit_fetch_2_operand_bytes(e, key_disp, rolling);
    emit_vmreg_addr_rsi_from_rcx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // mov cl, dl         88 D1
    e.u8(0x88); e.u8(0xD1);
    // OP rax, cl         48 D3 /sub_op
    e.u8(0x48); e.u8(0xD3);
    e.u8(static_cast<uint8_t>(0xC0 | (sub_op << 3)));
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

// ---------------------------------------------------------------------------
// VJMP / VJCC handlers
// ---------------------------------------------------------------------------

/// VJMP — unconditional virtual branch. Operand: rel32. Adds the rel32 to
/// r11 (vpc) so the next tail dispatch reads from the target.
void emit_handler_vjmp(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);          // movsxd rax, eax
    e.u8(0x49); e.u8(0x01); e.u8(0xC3);          // add r11, rax
}

/// VJCC — conditional virtual branch with `cc` baked in at emit time.
/// Tests bits in the saved (descrambled) RFLAGS qword from the ctx slot;
/// avoids fragile pushfq/popfq round-trips through CPU EFLAGS.
void emit_handler_vjcc(RawEmitter& e, int32_t key_disp, bool rolling,
                       uint8_t cc, uint32_t vflags_key,
                       uint32_t vflags_rol, int32_t rflags_disp,
                       Randomizer& rng,
                       const InnerVmIsa* isa,
                       size_t* inner_vm_call_patch_out)
{
    // V2 (nested) taken-path layout, byte by byte:
    //
    //   mov r15, rax                  49 89 C7       (3 bytes)
    //   lea r12, [rip + 2]            4C 8D 25 02 00 00 00  (7)
    //   jmp +2                         EB 02          (2)
    //   <bc[0]> <bc[1]>                               (2)
    //   call rel32 inner_vm_entry     E8 ?? ?? ?? ??  (5)
    //
    // Total: 19 bytes (vs 3 bytes for V0's direct `add r11, rax`).
    //
    // bc[0] = byte value of InnerVmOp::itake_branch in this ISA
    // bc[1] = byte value of InnerVmOp::iret_noflag in this ISA
    //
    // `itake_branch` does `add r11, r15; jmp .loop`. `r15` was
    // pre-loaded with the sign-extended rel32 by the `mov r15, rax`
    // above. `iret_noflag` then returns to the instruction after
    // the `call`, converging with the "not taken" path.
    const bool nested_taken = (isa != nullptr);
    const uint8_t jmp_short_over_taken = nested_taken ? 19u : 3u;

    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);          // movsxd rax, eax

    // Load and fully descramble saved RFLAGS into ecx (polymorphic).
    emit_vflags_to_ecx(e, pick_to_ecx_variant(rng),
                       vflags_key, vflags_rol, rflags_disp);

    // Flag bit positions: CF=0, PF=2, ZF=6, SF=7, OF=11.
    struct CcInfo { uint32_t mask; bool jump_if_set; };
    constexpr CcInfo cc_table[16] = {
        /* 0  O  */ {1u << 11, true },
        /* 1  NO */ {1u << 11, false},
        /* 2  B  */ {1u << 0,  true },
        /* 3  NB */ {1u << 0,  false},
        /* 4  E  */ {1u << 6,  true },
        /* 5  NE */ {1u << 6,  false},
        /* 6  BE */ {(1u<<0)|(1u<<6), true },
        /* 7  A  */ {(1u<<0)|(1u<<6), false},
        /* 8  S  */ {1u << 7,  true },
        /* 9  NS */ {1u << 7,  false},
        /* 10 P  */ {1u << 2,  true },
        /* 11 NP */ {1u << 2,  false},
        /* 12 L  */ {0, true },
        /* 13 GE */ {0, false},
        /* 14 LE */ {0, true },
        /* 15 G  */ {0, false},
    };

    const auto& info = cc_table[cc & 0xF];

    if (cc <= 11 && cc != 6 && cc != 7) {
        // Simple single-bit test: test ecx, mask    F7 C1 mask32
        e.u8(0xF7); e.u8(0xC1);
        e.u8(static_cast<uint8_t>(info.mask & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 8) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 16) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 24) & 0xFF));
    } else if (cc == 6 || cc == 7) {
        // BE / A: test CF|ZF.
        e.u8(0xF7); e.u8(0xC1);
        e.u8(static_cast<uint8_t>(info.mask & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 8) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 16) & 0xFF));
        e.u8(static_cast<uint8_t>((info.mask >> 24) & 0xFF));
    } else {
        // CC 12-15 (L/GE/LE/G): SF vs OF comparison.
        //   mov edx, ecx         89 CA
        //   shr edx, 4           C1 EA 04   — bring OF (bit 11) down to bit 7
        //   xor edx, ecx         31 CA      — bit 7 of edx: SF ^ OF
        e.u8(0x89); e.u8(0xCA);
        e.u8(0xC1); e.u8(0xEA); e.u8(0x04);
        e.u8(0x31); e.u8(0xCA);
        if (cc == 14 || cc == 15) {
            // LE: ZF || (SF != OF). G: !ZF && (SF == OF).
            //   or edx, ecx          09 CA   — bit 6 = ZF from ecx
            //   test edx, 0xC0       F7 C2 imm32   — test bits 6+7
            e.u8(0x09); e.u8(0xCA);
            e.u8(0xF7); e.u8(0xC2);
            e.u8(0xC0); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        } else {
            // L/GE: just test bit 7 of edx (SF ^ OF).
            e.u8(0xF7); e.u8(0xC2);
            e.u8(0x80); e.u8(0x00); e.u8(0x00); e.u8(0x00);
        }
    }

    // jcc/jnc + jmp short / taken body — branchless target select.
    const uint8_t jcc_opcode = info.jump_if_set ? 0x75 : 0x74;
    e.u8(jcc_opcode);
    e.u8(0x02);                      // skip the `jmp short` below
    // NOT TAKEN
    e.u8(0xEB); e.u8(jmp_short_over_taken);

    // TAKEN
    if (!nested_taken) {
        // V0 direct path: `add r11, rax`.
        e.u8(0x49); e.u8(0x01); e.u8(0xC3);
    } else {
        // V2 nested path. Pre-load r15 with the rel32 target, set
        // r12 to the inline inner bytecode, jump over the bytecode,
        // call into the inner VM which will `add r11, r15; ret`.

        // mov r15, rax   — REX.W|B (dst=r15 high) + 0x89 + ModRM
        //                  (mod=11 reg=rax=000 rm=r15&7=111 → 0xC7)
        e.u8(0x49); e.u8(0x89); e.u8(0xC7);

        // lea r12, [rip + 2]  — 7 bytes, points at the inline bc
        e.u8(0x4C); e.u8(0x8D); e.u8(0x25);
        e.u32(static_cast<uint32_t>(2));

        // jmp short +2   — skip the 2-byte inline bytecode
        e.u8(0xEB); e.u8(0x02);

        // Inline inner bytecode: [itake_branch, iret_noflag]
        //
        // Both opcodes go through the active ISA's permutation,
        // so the byte values emitted here depend on the current
        // build. The corresponding handler table entries (emitted
        // by `emit_inner_vm_runtime` under the same ISA) line up
        // by construction.
        e.u8(isa->byte_of(InnerVmOp::itake_branch));
        e.u8(isa->byte_of(InnerVmOp::iret_noflag));

        // call rel32 <inner_vm_entry>  — rel32 patched by backend
        // once the inner VM entry offset is known.
        e.u8(0xE8);
        if (inner_vm_call_patch_out != nullptr) {
            *inner_vm_call_patch_out = e.size();
        }
        e.u32(0);
    }

    // Both paths converge → tail dispatch follows (emitted by caller).
}

// ============================================================================
// Specialised handlers (G1)
// ============================================================================
//
// Both bodies emit exactly 10 bytes followed by the standard tail dispatch
// (appended by the caller). The operand fetch present in every generic
// handler — `movzx eax, byte [r11]; xor al, [rsp + key_disp]; ...; shl rcx, 3;
// lea rsi, [rsp + rcx]` — is gone. Reverser pattern matching for that
// fetch shape will not catch specialised bodies.

void emit_handler_mov_rr_specialized(RawEmitter& e,
                                     uint8_t dst_disp, uint8_t src_disp)
{
    // mov rax, [rsp + src_disp]    48 8B 44 24 disp8
    //   ModRM: mod=01, reg=rax=0, rm=100 (SIB)
    //   SIB:   scale=00, index=100 (none), base=100 (rsp)
    e.u8(0x48); e.u8(0x8B); e.u8(0x44); e.u8(0x24); e.u8(src_disp);
    // mov [rsp + dst_disp], rax    48 89 44 24 disp8
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(dst_disp);
}

void emit_handler_alu_rr_specialized(RawEmitter& e, uint8_t op_mr,
                                     uint8_t dst_disp, uint8_t src_disp)
{
    // mov rax, [rsp + src_disp]    48 8B 44 24 disp8
    e.u8(0x48); e.u8(0x8B); e.u8(0x44); e.u8(0x24); e.u8(src_disp);
    // OP [rsp + dst_disp], rax     48 op_mr 44 24 disp8
    //   op_mr is the ALU r/m, r form opcode: add=01, sub=29, xor=31,
    //   and=21, or=09. Same ModRM/SIB as the mov above.
    e.u8(0x48); e.u8(op_mr); e.u8(0x44); e.u8(0x24); e.u8(dst_disp);
}

} // namespace mx::vm::x64
