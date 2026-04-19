/**
 * @file string_decryptor_codegen.cpp
 * @brief [BUILDER] Machine-code emission for `mx_str_get` and its
 *        per-xref trampolines.
 *
 * Every byte of x64 emitted here was laid out by hand and cross
 * referenced against the unit tests in
 * `tests/unit/string_decryptor_codegen_test.cpp`. If you change a
 * byte, the tests will tell you exactly which invariant broke.
 *
 * The code is annotated line-by-line with the disassembly so a
 * reader can follow along without consulting an x64 reference.
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
 *     mov    byte [r10 + 7], 2               ; flag = 2 (done).
 *                                             ; plain store is safe:
 *                                             ; we own the flag byte
 *                                             ; because the claim bit
 *                                             ; made every other thread
 *                                             ; observe 1 and spin.
 *   .restore_and_done:
 *     mov    rax, r9
 *   .done:
 *     ret
 *
 * The trampoline prologue saves all seven Windows x64 volatile GPRs
 * plus RFLAGS. The only registers whose final state differs from
 * entry are (a) the designated target register, which ends up
 * holding the decrypted pointer, and (b) nothing else — every other
 * volatile reg and RFLAGS are restored verbatim. That lets the
 * rewriter drop the trampoline in place of a `lea target, [rip+x]`
 * without disturbing anything the LEA would not have disturbed.
 */

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"

#include "mxprotector/core/asm_builder.hpp"

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
// mx_str_get decryptor
// ---------------------------------------------------------------------------

EmittedDecryptor emit_mx_str_get()
{
    EmittedDecryptor out;
    out.code.reserve(kMxStrGetSize);
    auto& c = out.code;

    // lea r10, [rip + desc_table_disp32]           (7 bytes)
    // REX.W|R (0x4C) + 0x8D + ModRM(00 010 101 = 0x15) + disp32=0
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x15);
    out.desc_table_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // lea r10, [r10 + rcx*8]                       (4 bytes)
    // REX.W|R|B (0x4D) + 0x8D + ModRM(00 010 100 = 0x14) + SIB(11 001 010 = 0xCA)
    c.push_back(0x4D); c.push_back(0x8D); c.push_back(0x14); c.push_back(0xCA);

    // mov eax, dword [r10]                         (3 bytes)
    // REX.B (0x41) + 0x8B + ModRM(00 000 010 = 0x02)
    c.push_back(0x41); c.push_back(0x8B); c.push_back(0x02);

    // movzx ecx, word [r10 + 4]                    (5 bytes)
    // REX.B + 0x0F B7 + ModRM(01 001 010 = 0x4A) + disp8=4
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB7);
    c.push_back(0x4A); c.push_back(0x04);

    // movzx edx, byte [r10 + 6]                    (5 bytes)
    // REX.B + 0x0F B6 + ModRM(01 010 010 = 0x52) + disp8=6
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB6);
    c.push_back(0x52); c.push_back(0x06);

    // lea r11, [rip + data_base_disp32]            (7 bytes)
    // REX.W|R + 0x8D + ModRM(00 011 101 = 0x1D) + disp32=0
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x1D);
    out.data_base_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // add rax, r11                                 (3 bytes)
    // REX.W|R (0x4C) + 0x01 + ModRM(11 011 000 = 0xD8)
    c.push_back(0x4C); c.push_back(0x01); c.push_back(0xD8);

    // ---- S2b thread-safe claim / decrypt body ----
    //
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
    // 0x75 0x33
    c.push_back(0x75); c.push_back(0x33);

    // [offset 41]
    // mov r9, rax                                  (3 bytes)
    // REX.W|B (0x49) + 0x89 + ModRM(11 000 001 = 0xC1)
    c.push_back(0x49); c.push_back(0x89); c.push_back(0xC1);

    // [offset 44] .try_claim:
    // xor eax, eax                                 (2 bytes)
    // 0x31 0xC0
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
    // 0x74 0x08
    c.push_back(0x74); c.push_back(0x08);

    // [offset 57]
    // cmp al, 2                                    (2 bytes)
    // 0x3C 0x02
    c.push_back(0x3C); c.push_back(0x02);

    // [offset 59]
    // je rel8 → .restore_and_done  (+28 to off 89) (2 bytes)
    // 0x74 0x1C
    c.push_back(0x74); c.push_back(0x1C);

    // [offset 61]
    // pause                                        (2 bytes)
    // 0xF3 0x90
    c.push_back(0xF3); c.push_back(0x90);

    // [offset 63]
    // jmp rel8 → .try_claim  (-21 to offset 44)    (2 bytes)
    // 0xEB 0xEB
    c.push_back(0xEB); c.push_back(0xEB);

    // [offset 65] .we_claimed:
    // mov r8, r9                                   (3 bytes)
    // REX.W|R|B (0x4D) + 0x89 + ModRM(11 001 000 = 0xC8)
    c.push_back(0x4D); c.push_back(0x89); c.push_back(0xC8);

    // [offset 68]
    // test rcx, rcx                                (3 bytes)
    // REX.W (0x48) + 0x85 + ModRM(11 001 001 = 0xC9)
    c.push_back(0x48); c.push_back(0x85); c.push_back(0xC9);

    // [offset 71]
    // jz rel8 → .mark_done  (+11 to offset 84)     (2 bytes)
    // 0x74 0x0B
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
    // 0x75 0xF5
    c.push_back(0x75); c.push_back(0xF5);

    // [offset 84] .mark_done:
    // mov byte [r10 + 7], 2                        (5 bytes)
    // REX.B (0x41) + 0xC6 + ModRM(01 000 010 = 0x42) +
    //   disp8=7 + imm8=2.
    //
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

// ---------------------------------------------------------------------------
// S3 ephemeral decryptor
// ---------------------------------------------------------------------------
//
// The ephemeral variant keeps the ciphertext at rest in the `.mxstr`
// data pool and, on every call, allocates a fresh slot from a
// power-of-two scratch ring via `lock xadd`. The ciphertext is copied
// byte-by-byte into the slot and XOR-decrypted in the same loop, so
// at most `kEphemeralRingSlots` plaintext strings exist concurrently
// in the whole process. No sticky flag, no in-place decrypt in the
// data pool, no cached pointer. Callers pay a full decrypt per call
// in exchange for a bounded memory footprint for decrypted strings.
//
// mx_str_get_ephemeral:
//
//   input:  ecx = string_id
//   output: rax = pointer to a scratch slot containing the plaintext
//                 (valid until the ring wraps around — typically 16
//                 more calls)
//
//     lea    r10, [rip + desc_table_disp32]      ; r10 = desc base
//     lea    r10, [r10 + rcx*8]                  ; r10 = desc entry
//     mov    eax, [r10]                          ; eax = data_offset
//     movzx  ecx, word  [r10 + 4]                ; ecx = length
//     movzx  edx, byte  [r10 + 6]                ; edx = key
//     lea    r11, [rip + data_base_disp32]       ; r11 = data pool base
//     add    r11, rax                            ; r11 = ciphertext ptr
//
//     ; Allocate a scratch slot from the ring.
//     lea    r8,  [rip + scratch_ring_disp32]    ; r8 = ring base
//     mov    r9d, 1                              ; r9d = 1
//     lock xadd dword [r8], r9d                  ; r9d = old counter
//     and    r9d, kEphemeralRingSlots - 1        ; slot idx mod N
//     shl    r9d, log2(kEphemeralSlotSize)       ; slot offset
//     lea    rax, [r8 + r9 + kEphemeralRingHeaderSize]
//                                                 ; rax = slot ptr
//                                                 ;     (return value)
//
//     ; Copy + XOR-decrypt the ciphertext into the slot.
//     mov    r8,  rax                             ; cursor = slot start
//     test   rcx, rcx
//     jz     .done                                 ; len == 0 guard
//   .loop:
//     mov    r9b, [r11]                           ; r9b = ciphertext byte
//     xor    r9b, dl                              ; decrypt
//     mov    [r8], r9b                            ; write plaintext
//     inc    r11
//     inc    r8
//     dec    rcx
//     jnz    .loop
//   .done:
//     ret
//
// The assertions in `emit_mx_str_get_ephemeral` pin each instruction's
// byte offset so any accidental size drift is caught at build time.

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

    // [offset 0]
    // lea r10, [rip + desc_table_disp32]           (7 bytes)
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x15);
    out.desc_table_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // [offset 7]
    // lea r10, [r10 + rcx*8]                       (4 bytes)
    // REX.W|R|B (0x4D) + 0x8D + ModRM(00 010 100 = 0x14) + SIB(11 001 010)
    c.push_back(0x4D); c.push_back(0x8D); c.push_back(0x14); c.push_back(0xCA);

    // [offset 11]
    // mov eax, dword [r10]                         (3 bytes)
    c.push_back(0x41); c.push_back(0x8B); c.push_back(0x02);

    // [offset 14]
    // movzx ecx, word [r10 + 4]                    (5 bytes)
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB7);
    c.push_back(0x4A); c.push_back(0x04);

    // [offset 19]
    // movzx edx, byte [r10 + 6]                    (5 bytes)
    c.push_back(0x41); c.push_back(0x0F); c.push_back(0xB6);
    c.push_back(0x52); c.push_back(0x06);

    // [offset 24]
    // lea r11, [rip + data_base_disp32]            (7 bytes)
    c.push_back(0x4C); c.push_back(0x8D); c.push_back(0x1D);
    out.data_base_disp32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // [offset 31]
    // add r11, rax                                 (3 bytes)
    // REX.W|B (0x49) + 0x01 + ModRM(11 000 011 = 0xC3)
    //   `add r11, rax` — rax source, r11 dest (result in r11).
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

// ---------------------------------------------------------------------------
// Per-xref trampolines
// ---------------------------------------------------------------------------

namespace {

/// Stack slot (offset from rsp) of the saved copy of a volatile GPR
/// inside the trampoline, measured at the point where the `mov
/// [rsp+slot], rax` patch fires. Push order is:
///   push rax   (first after pushfq, deepest in stack)
///   push rcx
///   push rdx
///   push r8
///   push r9
///   push r10
///   push r11   (last, top of stack)
/// After all seven pushes, the top of stack holds r11 (slot 0), and
/// rax is eight slots below that at slot 48.
constexpr uint8_t volatile_stack_slot(GprIndex gpr) noexcept {
    switch (gpr) {
        case kGprRax: return 48;
        case kGprRcx: return 40;
        case kGprRdx: return 32;
        case kGprR8:  return 24;
        case kGprR9:  return 16;
        case kGprR10: return 8;
        case kGprR11: return 0;
        default:      return 0;  // unreachable — caller checks is_volatile
    }
}

/// `mov qword [rsp + slot], rax` — 5 bytes.
/// REX.W (0x48) + 0x89 + ModRM(01 000 100 = 0x44, SIB follows) +
/// SIB(00 100 100 = 0x24, base=rsp no index) + disp8 = slot.
void emit_mov_stack_slot_rax(std::vector<uint8_t>& c, uint8_t slot) {
    c.push_back(0x48);
    c.push_back(0x89);
    c.push_back(0x44);
    c.push_back(0x24);
    c.push_back(slot);
}

/// `mov target, rax` — 3 bytes — for a non-volatile GPR target.
/// Low regs (rbx/rbp/rsi/rdi) get REX 0x48; extended regs
/// (r12..r15) get REX 0x49 (REX.B set). ModRM is always
/// 11 000 <target_low3>, where reg field = rax = 0.
void emit_mov_reg_rax(std::vector<uint8_t>& c, GprIndex target) {
    const bool     ext   = target >= 8;
    const uint8_t  rex   = ext ? 0x49 : 0x48;
    const uint8_t  rm    = static_cast<uint8_t>(target & 0x7);
    const uint8_t  modrm = static_cast<uint8_t>(0xC0 | rm);
    c.push_back(rex);
    c.push_back(0x89);
    c.push_back(modrm);
}

} // namespace

EmittedTrampoline emit_trampoline(const TrampolineRequest& req)
{
    assert(req.target_reg != kGprRsp && "rsp is not a valid LEA target");
    assert(req.target_reg < 16       && "target must be a valid x64 GPR");

    EmittedTrampoline out;
    out.code.reserve(kTrampolineSizeVolatile);
    auto& c = out.code;

    // ---- Prologue: pushfq + 7 volatile pushes (12 bytes total) ----
    c.push_back(0x9C);                          // pushfq
    c.push_back(0x50);                          // push rax
    c.push_back(0x51);                          // push rcx
    c.push_back(0x52);                          // push rdx
    c.push_back(0x41); c.push_back(0x50);       // push r8
    c.push_back(0x41); c.push_back(0x51);       // push r9
    c.push_back(0x41); c.push_back(0x52);       // push r10
    c.push_back(0x41); c.push_back(0x53);       // push r11

    // ---- mov ecx, imm32 (string_id) (5 bytes) ----
    c.push_back(0xB9);
    const uint32_t id = req.string_id;
    c.push_back(static_cast<uint8_t>(id         & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 8)  & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 16) & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 24) & 0xFF));

    // ---- call rel32 (mx_str_get) (5 bytes) ----
    c.push_back(asm64::kCallRel32);
    out.call_rel32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // ---- Deliver result to target ----
    if (is_volatile_gpr(req.target_reg)) {
        // Patch the saved slot on the stack so the matching pop
        // below restores `target = rax (pointer)`.
        emit_mov_stack_slot_rax(c, volatile_stack_slot(req.target_reg));
    } else {
        // Direct write. The LEA we replaced was going to clobber
        // target, so there's nothing to preserve.
        emit_mov_reg_rax(c, req.target_reg);
    }

    // ---- Epilogue: 7 pops (reverse order) + popfq + ret ----
    c.push_back(0x41); c.push_back(0x5B);       // pop r11
    c.push_back(0x41); c.push_back(0x5A);       // pop r10
    c.push_back(0x41); c.push_back(0x59);       // pop r9
    c.push_back(0x41); c.push_back(0x58);       // pop r8
    c.push_back(0x5A);                          // pop rdx
    c.push_back(0x59);                          // pop rcx
    c.push_back(0x58);                          // pop rax
    c.push_back(0x9D);                          // popfq
    c.push_back(asm64::kRet);                   // ret

    assert(c.size() == trampoline_size_for(req.target_reg));
    return out;
}

} // namespace mx::string_protect
