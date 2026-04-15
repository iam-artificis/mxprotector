/**
 * @file stub_self_hash.cpp
 * @brief P6 — stub self-integrity hash + key derivation emitter.
 *
 * See stub_self_hash.hpp for rationale. This file is strictly
 * byte-level x64 emission + a 10-line reference C++ FNV-1a loop.
 */

#include "mxprotector/protection/packer/stub_self_hash.hpp"

namespace mx::packer {

void derive_effective_key_in_place(uint32_t hash, MutableByteView key) noexcept {
    uint32_t state = hash;
    for (auto& b : key) {
        state ^= static_cast<uint32_t>(b);
        state *= kFnv1aPrime;
        b = static_cast<uint8_t>(state & 0xFFu);
    }
}

StubSelfHashEmit emit_stub_self_hash(RawEmitter& e) {
    StubSelfHashEmit out{};
    out.hash_range_start = 0;

    // ----------------------------------------------------------------
    // mov eax, 0x811C9DC5                B8 imm32    (5 bytes)
    //   Initialise the running state with the FNV-1a offset basis.
    // ----------------------------------------------------------------
    e.u8(0xB8);
    e.u32(kFnv1aOffsetBasis);

    // ----------------------------------------------------------------
    // lea rsi, [rip + disp32]            48 8D 35 rel32   (7 bytes)
    //
    // We want rsi = (stub_start + hash_range_start) at runtime. The
    // rip-relative addressing resolves to `rip_after_lea + disp`,
    // where `rip_after_lea = stub_rva + lea_offset + 7`. Setting
    //
    //     disp = -(lea_offset + 7)
    //
    // makes rsi = stub_rva + 0 = the start of the hash range, and
    // the disp is a pure emit-time constant (no runtime patching).
    // ----------------------------------------------------------------
    e.u8(0x48); e.u8(0x8D); e.u8(0x35);
    const size_t disp_slot = e.size();
    out.start_disp32_offset = static_cast<uint32_t>(disp_slot);
    const size_t lea_end = disp_slot + 4;
    const int32_t lea_disp =
        -static_cast<int32_t>(lea_end);
    e.u32(static_cast<uint32_t>(lea_disp));

    // ----------------------------------------------------------------
    // mov ecx, <count>                   B9 imm32    (5 bytes)
    //
    // The loop counter equals the full hash-range byte count. The
    // count isn't known yet because the trailing stub code hasn't
    // been emitted, so we plant a 0 here and the caller patches it
    // via `count_imm32_offset` after stub emission completes.
    // ----------------------------------------------------------------
    e.u8(0xB9);
    out.count_imm32_offset = static_cast<uint32_t>(e.size());
    e.u32(0);

    // ----------------------------------------------------------------
    // mov r8d, 0x01000193                41 B8 imm32 (6 bytes)
    //   Load the FNV-1a prime into r8d. r8 survives the loop body
    //   because nothing in the inner loop touches r8.
    // ----------------------------------------------------------------
    e.u8(0x41); e.u8(0xB8);
    e.u32(kFnv1aPrime);

    // ----------------------------------------------------------------
    // .hash_loop:
    //   movzx edx, byte [rsi]            0F B6 16     (3 bytes)
    //   xor   eax, edx                   31 D0        (2 bytes)
    //   imul  eax, r8d                   41 0F AF C0  (4 bytes)
    //   inc   rsi                        48 FF C6     (3 bytes)
    //   dec   ecx                        FF C9        (2 bytes)
    //   jnz   short .hash_loop           75 rel8      (2 bytes)
    //
    // Loop body is 16 bytes, rel8 is well within range.
    // ----------------------------------------------------------------
    const size_t loop_start = e.size();
    // movzx edx, byte ptr [rsi]
    e.u8(0x0F); e.u8(0xB6); e.u8(0x16);
    // xor eax, edx
    e.u8(0x31); e.u8(0xD0);
    // imul eax, r8d
    e.u8(0x41); e.u8(0x0F); e.u8(0xAF); e.u8(0xC0);
    // inc rsi
    e.u8(0x48); e.u8(0xFF); e.u8(0xC6);
    // dec ecx
    e.u8(0xFF); e.u8(0xC9);
    // jnz short .hash_loop
    e.u8(0x75);
    const size_t jnz_rel8_slot = e.size();
    e.u8(0x00);
    {
        const int32_t jnz_end =
            static_cast<int32_t>(jnz_rel8_slot) + 1;
        const int32_t rel8 =
            static_cast<int32_t>(loop_start) - jnz_end;
        e.buf[jnz_rel8_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    // ----------------------------------------------------------------
    // mov r14d, eax                      41 89 C6    (3 bytes)
    //   Stash the final hash in r14d so the per-layer derivation
    //   loops can read it later. r14 is preserved by the packer
    //   layer loop — it's only clobbered by the reprotect block,
    //   which runs AFTER every layer has already consumed the hash.
    // ----------------------------------------------------------------
    e.u8(0x41); e.u8(0x89); e.u8(0xC6);

    return out;
}

void emit_key_derivation_loop(RawEmitter& e) {
    // ----------------------------------------------------------------
    // mov eax, r14d                      44 89 F0    (3 bytes)
    //   state = hash (restored from r14d).
    // ----------------------------------------------------------------
    e.u8(0x44); e.u8(0x89); e.u8(0xF0);

    // ----------------------------------------------------------------
    // mov rcx, rsi                       48 89 F1    (3 bytes)
    //   rcx = rsi (iterator copy so rsi stays on the key base for
    //   the downstream KSA).
    // ----------------------------------------------------------------
    e.u8(0x48); e.u8(0x89); e.u8(0xF1);

    // ----------------------------------------------------------------
    // mov edx, 32                        BA 20 00 00 00   (5 bytes)
    //   Loop counter = kKeySize bytes. Hard-coded to 32 because the
    //   derivation is only ever called against RC4 keys and
    //   kKeySize is fixed in the packer.
    // ----------------------------------------------------------------
    e.u8(0xBA);
    e.u32(32);

    // ----------------------------------------------------------------
    // mov r8d, 0x01000193                41 B8 imm32 (6 bytes)
    //   FNV-1a prime — same constant as the self-hash loop. r8 is
    //   loaded fresh per derivation rather than carried across
    //   because nothing in the layer loop between the self-hash
    //   exit and the first derivation guarantees r8 is preserved
    //   (the anti-debug probe + mov r15d, edx + lea r8, sbox all
    //   run between).
    // ----------------------------------------------------------------
    e.u8(0x41); e.u8(0xB8);
    e.u32(kFnv1aPrime);

    // ----------------------------------------------------------------
    // .derive_loop:
    //   xor   al, byte [rcx]             32 01       (2 bytes)
    //   imul  eax, r8d                   41 0F AF C0 (4 bytes)
    //   mov   [rcx], al                  88 01       (2 bytes)
    //   inc   rcx                        48 FF C1    (3 bytes)
    //   dec   edx                        FF CA       (2 bytes)
    //   jnz   short .derive_loop         75 rel8     (2 bytes)
    //
    // Loop body is 15 bytes, rel8 is well within range.
    // ----------------------------------------------------------------
    const size_t loop_start = e.size();
    // xor al, byte ptr [rcx]
    e.u8(0x32); e.u8(0x01);
    // imul eax, r8d
    e.u8(0x41); e.u8(0x0F); e.u8(0xAF); e.u8(0xC0);
    // mov [rcx], al
    e.u8(0x88); e.u8(0x01);
    // inc rcx
    e.u8(0x48); e.u8(0xFF); e.u8(0xC1);
    // dec edx
    e.u8(0xFF); e.u8(0xCA);
    // jnz short .derive_loop
    e.u8(0x75);
    const size_t jnz_rel8_slot = e.size();
    e.u8(0x00);
    {
        const int32_t jnz_end =
            static_cast<int32_t>(jnz_rel8_slot) + 1;
        const int32_t rel8 =
            static_cast<int32_t>(loop_start) - jnz_end;
        e.buf[jnz_rel8_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }
}

} // namespace mx::packer
