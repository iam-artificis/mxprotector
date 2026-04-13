/**
 * @file x64_emitters.cpp
 * @brief [BUILDER, x64] Atomic byte-level encoders for the VM runtime.
 *
 * Pure machine-code byte appenders. Each function emits one x86-64
 * instruction (or a small fixed group) into a `RawEmitter`. No state,
 * no side channels, no allocations beyond what `RawEmitter` does.
 *
 * Extracted verbatim from the legacy `vm_runtime_gen.cpp` monolith
 * during the Phase 2 arch refactor so that future arm64 work can
 * sit alongside under `arm64/` without colliding with x64 specifics.
 */

#include "mxprotector/protection/vm/x64/x64_emitters.hpp"

#include <cstring>

#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::vm::x64 {

void emit_movzx_r32_byte_mem(RawEmitter& e, uint8_t dst_reg,
                              uint8_t base_reg, int32_t disp)
{
    const bool rex_r = dst_reg >= 8;
    const bool rex_b = base_reg >= 8;
    if (rex_b || rex_r) {
        uint8_t rex = 0x40;
        if (rex_r) rex |= 0x04;
        if (rex_b) rex |= 0x01;
        e.u8(rex);
    }
    e.u8(0x0F);
    e.u8(0xB6);

    const uint8_t dst3  = dst_reg & 0x07;
    const uint8_t base3 = base_reg & 0x07;
    const bool needs_sib = (base3 == 4);  // RSP/R12 encode requires SIB
    const bool base_is_rbp = (base3 == 5); // RBP/R13: disp=0 needs disp8

    if (disp == 0 && !base_is_rbp) {
        e.u8(static_cast<uint8_t>((0 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

void emit_xor_r8l_rsp_disp(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);  // REX.R
    } else if (reg >= 4) {
        e.u8(0x40);  // empty REX to force SPL/BPL/SIL/DIL
    }
    e.u8(0x32);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

void emit_xor_rsp_disp_r8l(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);
    } else if (reg >= 4) {
        e.u8(0x40);
    }
    e.u8(0x30);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

void emit_inc_r11(RawEmitter& e) {
    // inc r11 = 49 FF C3
    e.u8(0x49); e.u8(0xFF); e.u8(0xC3);
}

size_t emit_lea_r11_rip_rel32(RawEmitter& e) {
    // lea r11, [rip + rel32]  = 4C 8D 1D rel32
    e.u8(0x4C); e.u8(0x8D); e.u8(0x1D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

size_t emit_lea_reg_rip_rel32(RawEmitter& e, uint8_t reg) {
    const uint8_t rex = (reg >= 8) ? 0x4C : 0x48;
    e.u8(rex);
    e.u8(0x8D);
    // ModRM: mod=00, reg=dst, rm=101 (RIP-relative marker)
    e.u8(static_cast<uint8_t>(((reg & 0x07) << 3) | 0x05));
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

void emit_ud2(RawEmitter& e) { e.u8(0x0F); e.u8(0x0B); }
void emit_ret(RawEmitter& e) { e.u8(0xC3); }
void emit_pushfq(RawEmitter& e) { e.u8(0x9C); }
void emit_popfq(RawEmitter& e) { e.u8(0x9D); }

void emit_push_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x50 + (reg & 0x07));
}

void emit_pop_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x58 + (reg & 0x07));
}

void patch_rel32(ByteBuffer& buf, size_t patch_offset,
                 size_t instruction_end, size_t target_offset)
{
    const auto rel = static_cast<int32_t>(
        static_cast<int64_t>(target_offset) - static_cast<int64_t>(instruction_end));
    std::memcpy(buf.data() + patch_offset, &rel, sizeof(int32_t));
}

void emit_jmp_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0xFF);
    e.u8(static_cast<uint8_t>(0xE0 | (reg & 0x07)));
}

void emit_mov_eax_from_base_rax4(RawEmitter& e, uint8_t base) {
    if (base >= 8) e.u8(0x41);          // REX.B for r8..r15
    e.u8(0x8B);                          // MOV r32, r/m32
    const uint8_t base_low = base & 0x07;
    const uint8_t sib = static_cast<uint8_t>(0x80 | base_low); // scale=x4 index=rax
    if (base_low == 5) {
        // mod=01, reg=000, rm=100 (SIB) → 0x44 + SIB + disp8=0
        e.u8(0x44);
        e.u8(sib);
        e.u8(0x00);
    } else {
        // mod=00, reg=000, rm=100 (SIB) → 0x04 + SIB
        e.u8(0x04);
        e.u8(sib);
    }
}

void emit_add_base_rax(RawEmitter& e, uint8_t base) {
    const uint8_t rex = 0x48 | ((base >= 8) ? 0x01 : 0x00);
    e.u8(rex);
    e.u8(0x01);
    // ModRM: mod=11 reg=000 (rax) rm=base_low
    e.u8(static_cast<uint8_t>(0xC0 | (base & 0x07)));
}

void emit_nop_run(RawEmitter& e, uint8_t size) {
    const auto nop = mx::x86::make_nop(size);
    for (uint8_t b : nop) e.u8(b);
}

void emit_mov_rsp_disp_rax(RawEmitter& e, int32_t disp) {
    e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24);
    e.u32(static_cast<uint32_t>(disp));
}

void emit_mov_eax_rsp_disp(RawEmitter& e, int32_t disp) {
    e.u8(0x8B); e.u8(0x84); e.u8(0x24);
    e.u32(static_cast<uint32_t>(disp));
}

void emit_xor_eax_imm32(RawEmitter& e, uint32_t imm) {
    e.u8(0x35); e.u32(imm);
}

void emit_rol_eax_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0xC1); e.u8(0xC0); e.u8(imm);
}

void emit_ror_eax_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0xC1); e.u8(0xC8); e.u8(imm);
}

uint32_t ror32(uint32_t v, uint32_t n) noexcept {
    n &= 31;
    return (n == 0) ? v : (v >> n) | (v << (32 - n));
}

} // namespace mx::vm::x64
