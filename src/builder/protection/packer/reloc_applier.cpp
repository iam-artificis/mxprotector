/**
 * @file reloc_applier.cpp
 * @brief Post-decrypt base-relocation applier — implementation.
 *
 * See `reloc_applier.hpp` for the big picture and the runtime asm
 * layout. This file is the byte-level encoding; every instruction is
 * hand-assembled and annotated. Tests pin the byte sequence so any
 * regression here surfaces immediately.
 */

#include "mxprotector/protection/packer/reloc_applier.hpp"

#include <cstdint>

namespace mx::packer {

namespace {

// Compute the signed 8-bit displacement from `patch_offset + 1` (the
// byte right after a `jcc rel8`) to `target_offset`, and write it
// into the emitter's buffer at `patch_offset`. Verified to fit into
// int8 at the call site — the applier's forward branches never span
// more than ~80 bytes so rel8 is always enough.
void patch_rel8_forward(RawEmitter& e,
                        uint32_t patch_offset,
                        uint32_t target_offset) noexcept
{
    const int32_t rel = static_cast<int32_t>(target_offset) -
                        static_cast<int32_t>(patch_offset + 1);
    e.buf[patch_offset] =
        static_cast<uint8_t>(static_cast<int8_t>(rel));
}

// Same but for a backward branch — the jmp/jcc is already emitted and
// we just write its rel8 byte in place.
void emit_rel8_backward(RawEmitter& e, uint32_t target_offset) noexcept
{
    const int32_t rel = static_cast<int32_t>(target_offset) -
                        static_cast<int32_t>(e.size() + 1);
    e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel)));
}

} // anonymous namespace

void emit_reloc_applier(RawEmitter&          e,
                        RelocApplierPatches& patches)
{
    patches.applier_begin_offset = static_cast<uint32_t>(e.size());

    // ---------- (1) runtime_base → rax ----------
    //
    //     lea rax, [rip + 0]          48 8D 05 00 00 00 00
    //     sub rax, <imm32>            48 2D xx xx xx xx
    //
    // After the lea, rax = runtime VA of the next instruction. The
    // patcher fills imm32 with `stub_rva + lea_runtime_base_anchor_offset`
    // so the subtraction leaves rax = module's runtime base.
    e.u8(0x48); e.u8(0x8D); e.u8(0x05);
    e.u32(0);
    patches.lea_runtime_base_anchor_offset =
        static_cast<uint32_t>(e.size());
    e.u8(0x48); e.u8(0x2D);
    patches.sub_runtime_base_imm32_at =
        static_cast<uint32_t>(e.size());
    e.u32(0);

    // ---------- (2) delta → r11 ----------
    //
    //     mov rbx, <imm64 preferred_base>   48 BB .. .. .. .. .. .. .. ..
    //     mov r11, rax                      49 89 C3
    //     sub r11, rbx                      49 29 DB
    //     test r11, r11                     4D 85 DB
    //     je   .done                        74 rel8
    e.u8(0x48); e.u8(0xBB);
    patches.preferred_base_imm64_at =
        static_cast<uint32_t>(e.size());
    e.u64(0);

    e.u8(0x49); e.u8(0x89); e.u8(0xC3);
    e.u8(0x49); e.u8(0x29); e.u8(0xDB);
    e.u8(0x4D); e.u8(0x85); e.u8(0xDB);
    e.u8(0x74);
    const uint32_t je_done_patch = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // ---------- (3) reloc-range setup ----------
    //
    //     mov ecx, <imm32 reloc_rva>        B9 xx xx xx xx
    //     add rcx, rax                      48 01 C1
    //     mov edx, <imm32 reloc_size>       BA xx xx xx xx
    //     add rdx, rcx                      48 01 CA
    //
    // rcx points at the first BASE_RELOCATION block; rdx is one past
    // the last byte of the directory. The 32-bit moves zero-extend
    // into rcx/rdx, which is what we want — the directory always
    // lives in the lower 4 GiB of the module.
    e.u8(0xB9);
    patches.reloc_rva_imm32_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    e.u8(0x48); e.u8(0x01); e.u8(0xC1);

    e.u8(0xBA);
    patches.reloc_size_imm32_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    e.u8(0x48); e.u8(0x01); e.u8(0xCA);

    // ---------- (4) block loop ----------
    //
    // .block_loop:
    //     cmp rcx, rdx                  48 39 D1
    //     jae .done                     73 rel8
    //     mov r12d, [rcx]               44 8B 21        ; page RVA
    //     mov r8d,  [rcx + 4]           44 8B 41 04    ; block size
    //     lea r9,   [rcx + r8]          4E 8D 0C 01    ; block end
    //     add rcx,  8                   48 83 C1 08    ; past header
    const uint32_t block_loop = static_cast<uint32_t>(e.size());

    e.u8(0x48); e.u8(0x39); e.u8(0xD1);
    e.u8(0x73);
    const uint32_t jae_done_patch = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x44); e.u8(0x8B); e.u8(0x21);
    e.u8(0x44); e.u8(0x8B); e.u8(0x41); e.u8(0x04);
    e.u8(0x4E); e.u8(0x8D); e.u8(0x0C); e.u8(0x01);
    e.u8(0x48); e.u8(0x83); e.u8(0xC1); e.u8(0x08);

    // ---------- (5) entry loop ----------
    //
    // .entry_loop:
    //     cmp rcx, r9                   4C 39 C9
    //     jae .next_block               73 rel8
    //     movzx r10d, word [rcx]        44 0F B7 11
    //     mov   ebx, r10d               44 89 D3
    //     shr   ebx, 12                 C1 EB 0C
    //     cmp   ebx, 10                 83 FB 0A       ; IMAGE_REL_BASED_DIR64
    //     jne   .skip_entry             75 rel8
    //     and   r10d, 0xFFF             41 81 E2 FF 0F 00 00
    //     lea   rbx, [rax + r12]        4A 8D 1C 20   ; page base = rt_base + page_rva
    //     add   [rbx + r10], r11        4E 01 1C 13   ; apply delta to qword
    // .skip_entry:
    //     add rcx, 2                    48 83 C1 02
    //     jmp .entry_loop               EB rel8
    const uint32_t entry_loop = static_cast<uint32_t>(e.size());

    e.u8(0x4C); e.u8(0x39); e.u8(0xC9);
    e.u8(0x73);
    const uint32_t jae_next_block_patch =
        static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x44); e.u8(0x0F); e.u8(0xB7); e.u8(0x11);
    e.u8(0x44); e.u8(0x89); e.u8(0xD3);
    e.u8(0xC1); e.u8(0xEB); e.u8(0x0C);
    e.u8(0x83); e.u8(0xFB); e.u8(0x0A);
    e.u8(0x75);
    const uint32_t jne_skip_patch = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x41); e.u8(0x81); e.u8(0xE2);
    e.u8(0xFF); e.u8(0x0F); e.u8(0x00); e.u8(0x00);
    e.u8(0x4A); e.u8(0x8D); e.u8(0x1C); e.u8(0x20);
    e.u8(0x4E); e.u8(0x01); e.u8(0x1C); e.u8(0x13);

    const uint32_t skip_entry = static_cast<uint32_t>(e.size());

    e.u8(0x48); e.u8(0x83); e.u8(0xC1); e.u8(0x02);
    e.u8(0xEB);
    emit_rel8_backward(e, entry_loop);

    // ---------- (6) next block ----------
    //
    // .next_block:
    //     mov rcx, r9                   4C 89 C9
    //     jmp .block_loop               EB rel8
    const uint32_t next_block = static_cast<uint32_t>(e.size());

    e.u8(0x4C); e.u8(0x89); e.u8(0xC9);
    e.u8(0xEB);
    emit_rel8_backward(e, block_loop);

    // .done:
    const uint32_t done = static_cast<uint32_t>(e.size());

    // ---------- fix forward branches ----------
    patch_rel8_forward(e, je_done_patch,         done);
    patch_rel8_forward(e, jae_done_patch,        done);
    patch_rel8_forward(e, jae_next_block_patch,  next_block);
    patch_rel8_forward(e, jne_skip_patch,        skip_entry);

    patches.applier_end_offset = static_cast<uint32_t>(e.size());
}

} // namespace mx::packer
