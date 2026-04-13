/**
 * @file x64_vflags.cpp
 * @brief [BUILDER, x64] vEFLAGS scrambling — variant pickers and emitters.
 *
 * Implementations for `x64_vflags.hpp`. See the header for a description
 * of the scrambling scheme; this file is pure byte emission.
 *
 * Extracted from the legacy `vm_runtime_gen.cpp` monolith during the
 * Phase 2 arch refactor.
 */

#include "mxprotector/protection/vm/x64/x64_vflags.hpp"

#include "mxprotector/protection/vm/x64/x64_emitters.hpp"

namespace mx::vm::x64 {

VflagsStoreV pick_store_variant(Randomizer& rng) {
    return static_cast<VflagsStoreV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsStoreV::kCount) - 1));
}

VflagsPopfqV pick_popfq_variant(Randomizer& rng) {
    return static_cast<VflagsPopfqV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsPopfqV::kCount) - 1));
}

VflagsToEcxV pick_to_ecx_variant(Randomizer& rng) {
    return static_cast<VflagsToEcxV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsToEcxV::kCount) - 1));
}

VflagsInSlotV pick_inslot_variant(Randomizer& rng) {
    return static_cast<VflagsInSlotV>(rng.next_range(0,
        static_cast<uint32_t>(VflagsInSlotV::kCount) - 1));
}

void emit_vflags_store(RawEmitter& e, VflagsStoreV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    switch (variant) {
        case VflagsStoreV::RaxRolFirst: {
            e.u8(0x9C); e.u8(0x58);
            if (n != 0) emit_rol_eax_imm8(e, n);
            if (vflags_key != 0) emit_xor_eax_imm32(e, vflags_key);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsStoreV::RaxXorFirst: {
            const uint32_t k_pre = ror32(vflags_key, n);
            e.u8(0x9C); e.u8(0x58);
            if (vflags_key != 0) emit_xor_eax_imm32(e, k_pre);
            if (n != 0) emit_rol_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsStoreV::InPlace: {
            // pushfq; rol [rsp],n; xor [rsp],k; pop qword [rsp+disp]
            //
            // pop with [rsp+disp] computes the destination address AFTER the
            // rsp increment (Intel SDM), so disp relative to the AFTER-pop rsp
            // is the same as the original rflags_disp.
            e.u8(0x9C);
            if (n != 0) { e.u8(0xC1); e.u8(0x04); e.u8(0x24); e.u8(n); }
            if (vflags_key != 0) {
                e.u8(0x81); e.u8(0x34); e.u8(0x24); e.u32(vflags_key);
            }
            e.u8(0x8F); e.u8(0x84); e.u8(0x24);
            e.u32(static_cast<uint32_t>(rflags_disp));
            return;
        }
        case VflagsStoreV::kCount: break;
    }
}

void emit_vflags_popfq(RawEmitter& e, VflagsPopfqV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    switch (variant) {
        case VflagsPopfqV::RaxXorFirst: {
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (vflags_key != 0) emit_xor_eax_imm32(e, vflags_key);
            if (n != 0) emit_ror_eax_imm8(e, n);
            e.u8(0x50); e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::RaxRorFirst: {
            const uint32_t k_post = ror32(vflags_key, n);
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_ror_eax_imm8(e, n);
            if (vflags_key != 0) emit_xor_eax_imm32(e, k_post);
            e.u8(0x50); e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::InPlace: {
            // push qword [rsp+disp]; xor [rsp],k; ror [rsp],n; popfq
            e.u8(0xFF); e.u8(0xB4); e.u8(0x24);
            e.u32(static_cast<uint32_t>(rflags_disp));
            if (vflags_key != 0) {
                e.u8(0x81); e.u8(0x34); e.u8(0x24); e.u32(vflags_key);
            }
            if (n != 0) { e.u8(0xC1); e.u8(0x0C); e.u8(0x24); e.u8(n); }
            e.u8(0x9D);
            return;
        }
        case VflagsPopfqV::kCount: break;
    }
}

void emit_vflags_inslot_scramble(RawEmitter& e, VflagsInSlotV variant,
                                 uint32_t vflags_key, uint32_t vflags_rol,
                                 int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    const uint32_t k = vflags_key;
    const uint32_t k_pre = ror32(k, n);

    auto emit_xor_mem_imm32 = [&](uint32_t val) {
        // xor dword [rsp + disp], imm32    81 B4 24 disp32 imm32
        e.u8(0x81); e.u8(0xB4); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u32(val);
    };
    auto emit_rol_mem_imm8 = [&](uint8_t amt) {
        // rol dword [rsp + disp], imm8    C1 84 24 disp32 imm8
        e.u8(0xC1); e.u8(0x84); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u8(amt);
    };

    switch (variant) {
        case VflagsInSlotV::RegXorFirst: {
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_rol_eax_imm8(e, n);
            if (k != 0) emit_xor_eax_imm32(e, k);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::RegRorFirst: {
            // xor-then-rol ≡ rol-then-xor-with-rol(k_pre,n)=k
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (k != 0) emit_xor_eax_imm32(e, k_pre);
            if (n != 0) emit_rol_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::MemXorFirst: {
            if (k != 0) emit_xor_mem_imm32(k_pre);
            if (n != 0) emit_rol_mem_imm8(n);
            return;
        }
        case VflagsInSlotV::MemRorFirst: {
            if (n != 0) emit_rol_mem_imm8(n);
            if (k != 0) emit_xor_mem_imm32(k);
            return;
        }
        case VflagsInSlotV::kCount: break;
    }
}

void emit_vflags_inslot_descramble(RawEmitter& e, VflagsInSlotV variant,
                                   uint32_t vflags_key, uint32_t vflags_rol,
                                   int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    const uint32_t k = vflags_key;
    const uint32_t k_post = ror32(k, n);

    auto emit_xor_mem_imm32 = [&](uint32_t val) {
        e.u8(0x81); e.u8(0xB4); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u32(val);
    };
    auto emit_ror_mem_imm8 = [&](uint8_t amt) {
        // ror dword [rsp + disp], imm8    C1 8C 24 disp32 imm8
        e.u8(0xC1); e.u8(0x8C); e.u8(0x24);
        e.u32(static_cast<uint32_t>(rflags_disp));
        e.u8(amt);
    };

    switch (variant) {
        case VflagsInSlotV::RegXorFirst: {
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (k != 0) emit_xor_eax_imm32(e, k);
            if (n != 0) emit_ror_eax_imm8(e, n);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::RegRorFirst: {
            emit_mov_eax_rsp_disp(e, rflags_disp);
            if (n != 0) emit_ror_eax_imm8(e, n);
            if (k != 0) emit_xor_eax_imm32(e, k_post);
            emit_mov_rsp_disp_rax(e, rflags_disp);
            return;
        }
        case VflagsInSlotV::MemXorFirst: {
            if (k != 0) emit_xor_mem_imm32(k);
            if (n != 0) emit_ror_mem_imm8(n);
            return;
        }
        case VflagsInSlotV::MemRorFirst: {
            if (n != 0) emit_ror_mem_imm8(n);
            if (k != 0) emit_xor_mem_imm32(k_post);
            return;
        }
        case VflagsInSlotV::kCount: break;
    }
}

void emit_vflags_to_ecx(RawEmitter& e, VflagsToEcxV variant,
                        uint32_t vflags_key, uint32_t vflags_rol,
                        int32_t rflags_disp)
{
    const uint8_t n = static_cast<uint8_t>(vflags_rol & 0x1F);
    // mov ecx, [rsp + rflags_disp]    8B 8C 24 disp32
    e.u8(0x8B); e.u8(0x8C); e.u8(0x24);
    e.u32(static_cast<uint32_t>(rflags_disp));

    if (variant == VflagsToEcxV::XorFirst) {
        if (vflags_key != 0) {
            // xor ecx, imm32    81 F1 imm32
            e.u8(0x81); e.u8(0xF1); e.u32(vflags_key);
        }
        if (n != 0) {
            // ror ecx, imm8     C1 C9 imm8
            e.u8(0xC1); e.u8(0xC9); e.u8(n);
        }
    } else {
        // RorFirst: ror first, then xor with ror(key, n)
        if (n != 0) { e.u8(0xC1); e.u8(0xC9); e.u8(n); }
        if (vflags_key != 0) {
            const uint32_t k_post = ror32(vflags_key, n);
            e.u8(0x81); e.u8(0xF1); e.u32(k_post);
        }
    }
}

} // namespace mx::vm::x64
