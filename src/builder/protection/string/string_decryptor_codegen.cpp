/**
 * @file string_decryptor_codegen.cpp
 * @brief [BUILDER] Sticky-flag `mx_str_get` decryptor (S2b) +
 *        descriptor packing.
 *
 * Every byte of x64 emitted here was laid out by hand and cross
 * referenced against the unit tests in
 * `tests/unit/string_decryptor_codegen_test.cpp`. If you change a
 * byte, the tests will tell you exactly which invariant broke.
 *
 * The emitter and its sibling variants — `string_decryptor_ephemeral.cpp`
 * (S3) and `string_trampoline_codegen.cpp` — share the 31-byte
 * descriptor-load prologue via the `internal/decryptor_prologue.hpp`
 * header.
 *
 * mx_str_get (S2b — thread-safe variant):
 *
 *   input:  ecx = string_id
 *   output: rax = decrypted plaintext pointer
 *
 *     lea    r10, [rip + desc_table_disp32]   ; r10 = desc_base
 *     lea    r10, [r10 + rcx*8]               ; r10 = desc_entry
 *     mov    eax, [r10]                       ; eax = data_offset
 *     movzx  ecx, word [r10 + 4]              ; ecx = length
 *     movzx  edx, byte [r10 + 6]              ; edx = key
 *     lea    r11, [rip + data_base_disp32]    ; r11 = data_base
 *     add    rax, r11                         ; rax = plaintext_ptr
 *
 *     ; Fast path: already done (flag bit 1 set)?  Plain load — x86
 *     ; gives acquire semantics for ordinary mov, so observing the
 *     ; done bit means the XOR writes that preceded it are visible.
 *     test   byte [r10 + 7], 2
 *     jnz    .done
 *
 *     ; Slow / contended path. We may clobber `al` inside the
 *     ; cmpxchg, so stash the plaintext pointer in r9 and restore
 *     ; it before returning.
 *     mov    r9, rax                         ; r9 = saved plaintext_ptr
 *
 *   .try_claim:
 *     xor    eax, eax                        ; al = 0 (expected)
 *     mov    r8b, 1                          ; r8b = 1 (new — claimed)
 *     lock cmpxchg byte [r10 + 7], r8b
 *     jz     .we_claimed                     ; ZF=1 → we won the claim
 *
 *     ; Lost the race. al now holds the observed flag byte.
 *     cmp    al, 2                           ; already done?
 *     je     .restore_and_done               ; yes → return plaintext
 *     pause                                  ; hint: spin-wait loop
 *     jmp    .try_claim                      ; retry until we see 2
 *
 *   .we_claimed:
 *     mov    r8, r9                          ; cursor = plaintext_ptr
 *     test   rcx, rcx
 *     jz     .mark_done                      ; len == 0 guard
 *   .loop:
 *     xor    byte [r8], dl
 *     inc    r8
 *     dec    rcx
 *     jnz    .loop
 *   .mark_done:
 *     mov    byte [r10 + 7], 2               ; flag = 2 (done)
 *   .restore_and_done:
 *     mov    rax, r9
 *   .done:
 *     ret
 */

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/protection/string/internal/decryptor_prologue.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace mx::string_protect {

// ---------------------------------------------------------------------------
// Descriptor packing
// ---------------------------------------------------------------------------

std::array<uint8_t, kDescriptorSize>
pack_descriptor(const StringDescriptor& d) noexcept
{
    std::array<uint8_t, kDescriptorSize> out{};
    // Little-endian — mirrors the x64 loads inside mx_str_get.
    out[0] = static_cast<uint8_t>(d.data_offset & 0xFF);
    out[1] = static_cast<uint8_t>((d.data_offset >> 8)  & 0xFF);
    out[2] = static_cast<uint8_t>((d.data_offset >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((d.data_offset >> 24) & 0xFF);
    out[4] = static_cast<uint8_t>(d.length & 0xFF);
    out[5] = static_cast<uint8_t>((d.length >> 8) & 0xFF);
    out[6] = d.key;
    out[7] = d.flags;
    return out;
}

// ---------------------------------------------------------------------------
// mx_str_get decryptor (S2b sticky variant)
// ---------------------------------------------------------------------------

EmittedDecryptor emit_mx_str_get()
{
    EmittedDecryptor out;
    out.code.reserve(kMxStrGetSize);
    auto& c = out.code;

    // Bytes 0..30 — shared descriptor-load prologue (emits six
    // instructions and records the two rip-relative disp32 slots).
    const auto pro = detail::emit_mx_str_desc_prologue(c);
    out.desc_table_disp32_offset = pro.desc_table_disp32_offset;
    out.data_base_disp32_offset  = pro.data_base_disp32_offset;

    // [offset 31]
    // add rax, r11                                 (3 bytes)
    // REX.W|R (0x4C) + 0x01 + ModRM(11 011 000 = 0xD8)
    // rax = data_base + data_offset = plaintext_ptr.
    c.push_back(0x4C); c.push_back(0x01); c.push_back(0xD8);

    // Absolute byte offsets inside mx_str_get are tracked in comments
    // below so the rel8 jump distances line up with the assertion
    // suite in `string_decryptor_codegen_test.cpp`.

    // [offset 34]
    // test byte [r10 + 7], 2                       (5 bytes)
    // REX.B + 0xF6 + ModRM(01 000 010 = 0x42) + disp8=7 + imm8=2
    c.push_back(0x41); c.push_back(0xF6); c.push_back(0x42);
    c.push_back(0x07); c.push_back(0x02);

    // [offset 39]
    // jnz rel8 → .done  (+51 to offset 92)         (2 bytes)
    c.push_back(0x75); c.push_back(0x33);

    // [offset 41]
    // mov r9, rax                                  (3 bytes)
    // REX.W|B (0x49) + 0x89 + ModRM(11 000 001 = 0xC1)
    c.push_back(0x49); c.push_back(0x89); c.push_back(0xC1);

    // [offset 44] .try_claim:
    // xor eax, eax                                 (2 bytes)
    c.push_back(0x31); c.push_back(0xC0);

    // [offset 46]
    // mov r8b, 1                                   (3 bytes)
    // REX.B (0x41) + 0xB0 + imm8=1 — `mov rXb, imm8` for r8..r15
    c.push_back(0x41); c.push_back(0xB0); c.push_back(0x01);

    // [offset 49]
    // lock cmpxchg byte [r10 + 7], r8b             (6 bytes)
    // LOCK (F0) + REX.R|B (0x45) + 0x0F B0 +
    //   ModRM(01 000 010 = 0x42) + disp8=7.
    //
    // REX.R selects r8 as the source-reg field, REX.B selects r10
    // as the memory base. After this instruction:
    //   - If the byte was 0: it becomes 1, ZF = 1, al is unchanged
    //     (still 0). We won the claim.
    //   - Otherwise: ZF = 0, al is overwritten with the observed
    //     byte so the caller can test `cmp al, 2`.
    c.push_back(0xF0); c.push_back(0x45); c.push_back(0x0F);
    c.push_back(0xB0); c.push_back(0x42); c.push_back(0x07);

    // [offset 55]
    // jz rel8 → .we_claimed  (+8 to offset 65)     (2 bytes)
    c.push_back(0x74); c.push_back(0x08);

    // [offset 57]
    // cmp al, 2                                    (2 bytes)
    c.push_back(0x3C); c.push_back(0x02);

    // [offset 59]
    // je rel8 → .restore_and_done  (+28 to off 89) (2 bytes)
    c.push_back(0x74); c.push_back(0x1C);

    // [offset 61]
    // pause                                        (2 bytes)
    c.push_back(0xF3); c.push_back(0x90);

    // [offset 63]
    // jmp rel8 → .try_claim  (-21 to offset 44)    (2 bytes)
    c.push_back(0xEB); c.push_back(0xEB);

    // [offset 65] .we_claimed:
    // mov r8, r9                                   (3 bytes)
    // REX.W|R|B (0x4D) + 0x89 + ModRM(11 001 000 = 0xC8)
    c.push_back(0x4D); c.push_back(0x89); c.push_back(0xC8);

    // [offset 68]
    // test rcx, rcx                                (3 bytes)
    c.push_back(0x48); c.push_back(0x85); c.push_back(0xC9);

    // [offset 71]
    // jz rel8 → .mark_done  (+11 to offset 84)     (2 bytes)
    c.push_back(0x74); c.push_back(0x0B);

    // [offset 73] .loop:
    // xor byte [r8], dl                            (3 bytes)
    // REX.B (0x41) + 0x30 + ModRM(00 010 000 = 0x10)
    c.push_back(0x41); c.push_back(0x30); c.push_back(0x10);

    // [offset 76]
    // inc r8                                       (3 bytes)
    // REX.W|B (0x49) + 0xFF + ModRM(11 000 000 = 0xC0)
    c.push_back(0x49); c.push_back(0xFF); c.push_back(0xC0);

    // [offset 79]
    // dec rcx                                      (3 bytes)
    // REX.W (0x48) + 0xFF + ModRM(11 001 001 = 0xC9)
    c.push_back(0x48); c.push_back(0xFF); c.push_back(0xC9);

    // [offset 82]
    // jnz rel8 → .loop  (-11 to offset 73)         (2 bytes)
    c.push_back(0x75); c.push_back(0xF5);

    // [offset 84] .mark_done:
    // mov byte [r10 + 7], 2                        (5 bytes)
    // Plain store: this thread holds the claim bit, so every other
    // thread observing the flag sees `1` and spins in .try_claim.
    // There is no concurrent writer for this byte at this moment.
    c.push_back(0x41); c.push_back(0xC6); c.push_back(0x42);
    c.push_back(0x07); c.push_back(0x02);

    // [offset 89] .restore_and_done:
    // mov rax, r9                                  (3 bytes)
    // REX.W|R (0x4C) + 0x89 + ModRM(11 001 000 = 0xC8)
    c.push_back(0x4C); c.push_back(0x89); c.push_back(0xC8);

    // [offset 92] .done:
    // ret                                          (1 byte)
    c.push_back(asm64::kRet);

    assert(c.size() == kMxStrGetSize);
    return out;
}

} // namespace mx::string_protect
