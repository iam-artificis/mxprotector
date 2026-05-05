/**
 * @file string_decryptor_ephemeral.cpp
 * @brief Implementation of `emit_mx_str_get_ephemeral` (S3 variant).
 *
 * @details Extracted from `string_decryptor_codegen.cpp` — the
 *          ephemeral / scratch-ring decryptor that keeps the data
 *          pool ciphertext at rest and copies-then-decrypts into a
 *          fresh ring slot on every call. See
 *          `string_decryptor_codegen.hpp` for the full ABI contract
 *          and the `kEphemeralRing*` constants.
 */

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/protection/string/internal/decryptor_prologue.hpp"

#include <cassert>
#include <cstdint>

namespace mx::string_protect {

EmittedEphemeralDecryptor emit_mx_str_get_ephemeral()
{
    static_assert((kEphemeralRingSlots & (kEphemeralRingSlots - 1)) == 0,
                  "kEphemeralRingSlots must be a power of two");
    static_assert(kEphemeralSlotSize == 256,
                  "kEphemeralSlotSize fixed at 256 for the emitted shl r9d,8");
    static_assert(kEphemeralRingSlots == 16,
                  "kEphemeralRingSlots fixed at 16 for the emitted and r9d,0x0F");
    static_assert(kEphemeralRingHeaderSize == 4,
                  "ring header size must match the disp8 in lea rax,[r8+r9+4]");

    EmittedEphemeralDecryptor out;
    out.code.reserve(kMxStrGetEphemeralSize);
    auto& c = out.code;

    // Bytes 0..30 — shared descriptor-load prologue (emits six
    // instructions and records the two rip-relative disp32 slots).
    const auto pro = detail::emit_mx_str_desc_prologue(c);
    out.desc_table_disp32_offset = pro.desc_table_disp32_offset;
    out.data_base_disp32_offset  = pro.data_base_disp32_offset;

    // [offset 31]
    // add r11, rax                                 (3 bytes)
    // REX.W|B (0x49) + 0x01 + ModRM(11 000 011 = 0xC3)
    //   `add r11, rax` — rax source, r11 dest (result in r11).
    //   r11 = data_base + data_offset = ciphertext_ptr.
    c.push_back(0x49); c.push_back(0x01); c.push_back(0xC3);

    // [offset 34]
    // lea r8, [rip + scratch_ring_disp32]          (7 bytes)
    // REX.W|R (0x4C) + 0x8D + ModRM(00 000 101 = 0x05) + disp32
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x05);
    out.scratch_ring_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // [offset 41]
    // mov r9d, 1                                   (6 bytes)
    // REX.B (0x41) + 0xB9 + imm32=0x00000001
    c.push_back(0x41); c.push_back(0xB9);
    c.push_back(0x01); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // [offset 47]
    // lock xadd dword [r8], r9d                    (5 bytes)
    // LOCK (F0) + REX.R|B (0x45) + 0x0F C1 + ModRM(00 001 000 = 0x08)
    //   Atomic: r9d_new = [r8]; [r8] = [r8] + r9d_old (== 1).
    //   r9d now holds the pre-increment counter value.
    c.push_back(0xF0); c.push_back(0x45); c.push_back(0x0F);
    c.push_back(0xC1); c.push_back(0x08);

    // [offset 52]
    // and r9d, 0x0F                                (4 bytes)
    // REX.B (0x41) + 0x83 + ModRM(11 100 001 = 0xE1, /4) + imm8=0x0F
    //   Reduce the monotonic counter to a slot index mod 16.
    c.push_back(0x41); c.push_back(0x83); c.push_back(0xE1); c.push_back(0x0F);

    // [offset 56]
    // shl r9d, 8                                   (4 bytes)
    // REX.B (0x41) + 0xC1 + ModRM(11 100 001 = 0xE1, /4) + imm8=8
    //   Multiply slot index by kEphemeralSlotSize (256) via shift.
    c.push_back(0x41); c.push_back(0xC1); c.push_back(0xE1); c.push_back(0x08);

    // [offset 60]
    // lea rax, [r8 + r9 + 4]                       (5 bytes)
    // REX.W|X|B (0x4B) + 0x8D + ModRM(01 000 100 = 0x44, SIB follows)
    //   + SIB(00 001 000 = 0x08, scale=1 index=r9 base=r8) + disp8=0x04
    //   rax = r8 + r9 + kEphemeralRingHeaderSize = scratch slot pointer.
    //   This becomes the return value.
    c.push_back(0x4B); c.push_back(0x8D); c.push_back(0x44);
    c.push_back(0x08); c.push_back(0x04);

    // [offset 65]
    // mov r8, rax                                  (3 bytes)
    // REX.W|B (0x49) + 0x89 + ModRM(11 000 000 = 0xC0)
    //   r8 = cursor (advances in the copy loop).
    c.push_back(0x49); c.push_back(0x89); c.push_back(0xC0);

    // [offset 68]
    // test rcx, rcx                                (3 bytes)
    c.push_back(0x48); c.push_back(0x85); c.push_back(0xC9);

    // [offset 71]
    // jz rel8 → .done  (+20 to offset 93)          (2 bytes)
    c.push_back(0x74); c.push_back(0x14);

    // [offset 73] .loop:
    // mov r9b, byte [r11]                          (3 bytes)
    // REX.R|B (0x45) + 0x8A + ModRM(00 001 011 = 0x0B)
    c.push_back(0x45); c.push_back(0x8A); c.push_back(0x0B);

    // [offset 76]
    // xor r9b, dl                                  (3 bytes)
    // REX.B (0x41) + 0x30 + ModRM(11 010 001 = 0xD1)
    //   r9b ^= dl — XOR decrypt one byte in a working register.
    c.push_back(0x41); c.push_back(0x30); c.push_back(0xD1);

    // [offset 79]
    // mov byte [r8], r9b                           (3 bytes)
    // REX.R|B (0x45) + 0x88 + ModRM(00 001 000 = 0x08)
    //   Store the decrypted byte into the scratch slot.
    c.push_back(0x45); c.push_back(0x88); c.push_back(0x08);

    // [offset 82]
    // inc r11                                      (3 bytes)
    c.push_back(0x49); c.push_back(0xFF); c.push_back(0xC3);

    // [offset 85]
    // inc r8                                       (3 bytes)
    c.push_back(0x49); c.push_back(0xFF); c.push_back(0xC0);

    // [offset 88]
    // dec rcx                                      (3 bytes)
    c.push_back(0x48); c.push_back(0xFF); c.push_back(0xC9);

    // [offset 91]
    // jnz rel8 → .loop  (-20 to offset 73)         (2 bytes)
    c.push_back(0x75); c.push_back(0xEC);

    // [offset 93] .done:
    // ret                                          (1 byte)
    c.push_back(asm64::kRet);

    assert(c.size() == kMxStrGetEphemeralSize);
    return out;
}

} // namespace mx::string_protect
