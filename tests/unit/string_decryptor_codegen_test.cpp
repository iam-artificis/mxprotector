/**
 * @file string_decryptor_codegen_test.cpp
 * @brief [TESTS] Byte-level unit tests for the S2 mx_str_get
 *        decryptor and its per-xref trampolines.
 *
 * These are brittle on purpose. Every asserted byte corresponds to a
 * specific x64 instruction whose encoding is fixed by the design in
 * `string_decryptor_codegen.cpp`. If a byte drifts, either
 *
 *   (a) a bug snuck into the emitter, in which case the test points
 *       at exactly which instruction broke, or
 *
 *   (b) the design intentionally changed shape, in which case the
 *       patching done by the pass orchestrator must be re-audited
 *       to match, and this file is the place to record the new
 *       invariants.
 *
 * Coverage:
 *   - Descriptor packing mirrors the on-disk layout.
 *   - mx_str_get byte-level shape, size, and the two rip+disp32
 *     patch slots.
 *   - Trampoline byte-level shape for every category we care about:
 *       * volatile rax (slot 48) — target is the return reg itself
 *       * volatile rcx (slot 40) — target is the argument reg
 *       * non-volatile low rbx (REX 0x48)
 *       * non-volatile extended r14 (REX 0x49)
 *   - Trampoline size is uniform within each category.
 *   - `trampoline_size_for` matches the actual emitted size.
 *   - The call-site rel32 patch offset is stable across categories.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"

namespace {

using mx::string_protect::emit_mx_str_get;
using mx::string_protect::emit_trampoline;
using mx::string_protect::EmittedDecryptor;
using mx::string_protect::EmittedTrampoline;
using mx::string_protect::GprIndex;
using mx::string_protect::is_volatile_gpr;
using mx::string_protect::kDescriptorFlagDecrypted;
using mx::string_protect::kDescriptorFlagsField;
using mx::string_protect::kDescriptorKeyField;
using mx::string_protect::kDescriptorLengthField;
using mx::string_protect::kDescriptorOffsetField;
using mx::string_protect::kDescriptorSize;
using mx::string_protect::kGprR10;
using mx::string_protect::kGprR11;
using mx::string_protect::kGprR12;
using mx::string_protect::kGprR13;
using mx::string_protect::kGprR14;
using mx::string_protect::kGprR15;
using mx::string_protect::kGprR8;
using mx::string_protect::kGprR9;
using mx::string_protect::kGprRax;
using mx::string_protect::kGprRbp;
using mx::string_protect::kGprRbx;
using mx::string_protect::kGprRcx;
using mx::string_protect::kGprRdi;
using mx::string_protect::kGprRdx;
using mx::string_protect::kGprRsi;
using mx::string_protect::kMxStrGetSize;
using mx::string_protect::kTrampolineSizeNonVolatile;
using mx::string_protect::kTrampolineSizeVolatile;
using mx::string_protect::pack_descriptor;
using mx::string_protect::StringDescriptor;
using mx::string_protect::trampoline_size_for;
using mx::string_protect::TrampolineRequest;

// Helper: find a byte subsequence `needle` inside `hay`, return
// offset or `hay.size()` if not present.
size_t find_bytes(const std::vector<uint8_t>& hay,
                  std::initializer_list<uint8_t> needle)
{
    const auto it = std::search(hay.begin(), hay.end(),
                                needle.begin(), needle.end());
    return static_cast<size_t>(it - hay.begin());
}

// ---------------------------------------------------------------------------
// Descriptor layout
// ---------------------------------------------------------------------------

TEST(StringDecryptorDescriptor, FieldOffsetsMatchAbi) {
    EXPECT_EQ(kDescriptorSize,         8u);
    EXPECT_EQ(kDescriptorOffsetField,  0u);
    EXPECT_EQ(kDescriptorLengthField,  4u);
    EXPECT_EQ(kDescriptorKeyField,     6u);
    EXPECT_EQ(kDescriptorFlagsField,   7u);
    EXPECT_EQ(kDescriptorFlagDecrypted, 0x01u);
}

TEST(StringDecryptorDescriptor, PackProducesLittleEndianLayout) {
    StringDescriptor d{};
    d.data_offset = 0x11223344;
    d.length      = 0x5566;
    d.key         = 0x77;
    d.flags       = 0x01;

    const auto bytes = pack_descriptor(d);

    ASSERT_EQ(bytes.size(), kDescriptorSize);
    // u32 little-endian
    EXPECT_EQ(bytes[0], 0x44u);
    EXPECT_EQ(bytes[1], 0x33u);
    EXPECT_EQ(bytes[2], 0x22u);
    EXPECT_EQ(bytes[3], 0x11u);
    // u16 little-endian
    EXPECT_EQ(bytes[4], 0x66u);
    EXPECT_EQ(bytes[5], 0x55u);
    // u8 key, flags
    EXPECT_EQ(bytes[6], 0x77u);
    EXPECT_EQ(bytes[7], 0x01u);
}

TEST(StringDecryptorDescriptor, PackZeroDescriptorIsAllZeros) {
    const auto bytes = pack_descriptor({});
    for (auto b : bytes) EXPECT_EQ(b, 0u);
}

// ---------------------------------------------------------------------------
// mx_str_get decryptor byte-level invariants
// ---------------------------------------------------------------------------

TEST(MxStrGet, ExactSize) {
    const auto d = emit_mx_str_get();
    EXPECT_EQ(d.code.size(), kMxStrGetSize);
    // S2b added a lock-cmpxchg claim loop and an rax-preserving stash
    // in r9, bringing the body to 93 bytes. Hard-coded here so any
    // accidental size drift is caught by the test.
    EXPECT_EQ(d.code.size(), 93u);
}

TEST(MxStrGet, StartsWithLeaR10RipRelDescTable) {
    const auto d = emit_mx_str_get();
    ASSERT_GE(d.code.size(), 7u);
    // 4C 8D 15 ?? ?? ?? ??  — lea r10, [rip + disp32]
    EXPECT_EQ(d.code[0], 0x4Cu);
    EXPECT_EQ(d.code[1], 0x8Du);
    EXPECT_EQ(d.code[2], 0x15u);
    EXPECT_EQ(d.desc_table_disp32_offset, 3u);
    // disp32 slot starts zero (to be patched by the orchestrator).
    EXPECT_EQ(d.code[3], 0u);
    EXPECT_EQ(d.code[4], 0u);
    EXPECT_EQ(d.code[5], 0u);
    EXPECT_EQ(d.code[6], 0u);
}

TEST(MxStrGet, HasLeaR10FromR10PlusRcxScaled8) {
    // 4D 8D 14 CA  — lea r10, [r10 + rcx*8]
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x4D, 0x8D, 0x14, 0xCA});
    EXPECT_LT(off, d.code.size()) << "descriptor-index multiplier missing";
    EXPECT_EQ(off, 7u) << "must immediately follow the desc_table lea";
}

TEST(MxStrGet, SecondLeaIsR11RipRelDataBase) {
    const auto d = emit_mx_str_get();
    ASSERT_GE(d.code.size(), 31u);
    // 4C 8D 1D ?? ?? ?? ??  — lea r11, [rip + disp32]
    EXPECT_EQ(d.code[24], 0x4Cu);
    EXPECT_EQ(d.code[25], 0x8Du);
    EXPECT_EQ(d.code[26], 0x1Du);
    EXPECT_EQ(d.data_base_disp32_offset, 27u);
    EXPECT_EQ(d.code[27], 0u);
    EXPECT_EQ(d.code[28], 0u);
    EXPECT_EQ(d.code[29], 0u);
    EXPECT_EQ(d.code[30], 0u);
}

TEST(MxStrGet, ContainsXorByteR8Dl) {
    // 41 30 10  — xor byte [r8], dl  (the actual decrypt step)
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x41, 0x30, 0x10});
    EXPECT_LT(off, d.code.size()) << "xor decrypt instruction missing";
}

TEST(MxStrGet, ContainsFastPathDoneTest) {
    // 41 F6 42 07 02  — test byte [r10+7], 2
    // Acquire-load check on the done bit. Plain mov is acquire on x86
    // so observing bit 1 set implies the decrypted bytes are visible.
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x41, 0xF6, 0x42, 0x07, 0x02});
    EXPECT_LT(off, d.code.size()) << "fast-path done-bit test missing";
}

TEST(MxStrGet, ContainsFinalDoneStore) {
    // 41 C6 42 07 02  — mov byte [r10+7], 2
    // Plain store of the final "done" flag value. Plain store is safe
    // here because the claim bit serializes writes: every other thread
    // observes 1 and spins until this thread switches to 2.
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x41, 0xC6, 0x42, 0x07, 0x02});
    EXPECT_LT(off, d.code.size()) << "final done-store is missing";
}

TEST(MxStrGet, ContainsLockCmpxchgClaim) {
    // F0 45 0F B0 42 07  — lock cmpxchg byte [r10+7], r8b
    //
    // The atomic claim: expected = al (= 0), new = r8b (= 1). On a
    // successful exchange (byte was 0) ZF is set and the winning
    // thread runs the decrypt loop. Every other thread observes a
    // non-zero value, branches on `cmp al, 2`, and either returns
    // (done) or spins on `pause` (still claimed).
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0xF0, 0x45, 0x0F, 0xB0, 0x42, 0x07});
    EXPECT_LT(off, d.code.size()) << "lock cmpxchg claim is missing";
}

TEST(MxStrGet, ContainsPauseSpinHint) {
    // F3 90  — pause. Hints to the CPU that this is a spin-wait loop,
    // reducing power draw and avoiding pipeline-order penalties on
    // the contended path.
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0xF3, 0x90});
    EXPECT_LT(off, d.code.size()) << "pause hint is missing from spin path";
}

TEST(MxStrGet, ContainsStashRaxIntoR9) {
    // 49 89 C1  — mov r9, rax
    // Save the plaintext pointer before cmpxchg clobbers `al` on
    // contended paths, so we can restore `rax` before `ret`.
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x49, 0x89, 0xC1});
    EXPECT_LT(off, d.code.size()) << "rax→r9 stash is missing";
}

TEST(MxStrGet, ContainsRestoreRaxFromR9) {
    // 4C 89 C8  — mov rax, r9
    // Restore the plaintext pointer from the r9 stash. Must appear
    // after the cmpxchg loop and before the final ret.
    const auto d = emit_mx_str_get();
    const auto off = find_bytes(d.code, {0x4C, 0x89, 0xC8});
    EXPECT_LT(off, d.code.size()) << "r9→rax restore is missing";
}

TEST(MxStrGet, EndsWithRet) {
    const auto d = emit_mx_str_get();
    ASSERT_FALSE(d.code.empty());
    EXPECT_EQ(d.code.back(), 0xC3u);
}

TEST(MxStrGet, PatchOffsetsAreDistinctAndInsideCode) {
    const auto d = emit_mx_str_get();
    EXPECT_NE(d.desc_table_disp32_offset, d.data_base_disp32_offset);
    EXPECT_LE(d.desc_table_disp32_offset + 4, d.code.size());
    EXPECT_LE(d.data_base_disp32_offset  + 4, d.code.size());
}

// ---------------------------------------------------------------------------
// S3 ephemeral decryptor byte-level invariants
// ---------------------------------------------------------------------------

TEST(MxStrGetEphemeral, ExactSize) {
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    EXPECT_EQ(d.code.size(), mx::string_protect::kMxStrGetEphemeralSize);
    // Pinned: any codegen drift reshapes the loop and changes the size.
    EXPECT_EQ(d.code.size(), 94u);
}

TEST(MxStrGetEphemeral, PatchOffsetsAreDistinctAndInsideCode) {
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    EXPECT_NE(d.desc_table_disp32_offset,   d.data_base_disp32_offset);
    EXPECT_NE(d.desc_table_disp32_offset,   d.scratch_ring_disp32_offset);
    EXPECT_NE(d.data_base_disp32_offset,    d.scratch_ring_disp32_offset);
    EXPECT_LE(d.desc_table_disp32_offset   + 4, d.code.size());
    EXPECT_LE(d.data_base_disp32_offset    + 4, d.code.size());
    EXPECT_LE(d.scratch_ring_disp32_offset + 4, d.code.size());
    // disp32 slots must be zero-initialised — the pass fills them in
    // post-section-add with the final rel32 values.
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(d.code[d.desc_table_disp32_offset   + i], 0u);
        EXPECT_EQ(d.code[d.data_base_disp32_offset    + i], 0u);
        EXPECT_EQ(d.code[d.scratch_ring_disp32_offset + i], 0u);
    }
}

TEST(MxStrGetEphemeral, StartsWithLeaR10RipRelDescTable) {
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    ASSERT_GE(d.code.size(), 7u);
    EXPECT_EQ(d.code[0], 0x4Cu);
    EXPECT_EQ(d.code[1], 0x8Du);
    EXPECT_EQ(d.code[2], 0x15u);
    EXPECT_EQ(d.desc_table_disp32_offset, 3u);
}

TEST(MxStrGetEphemeral, ContainsLockXaddRingCounter) {
    // F0 45 0F C1 08  — lock xadd dword [r8], r9d
    // The atomic slot allocator: fetches the old counter value into
    // r9d and post-increments the shared counter. The LOCK prefix is
    // required for cross-thread consistency — without it two threads
    // could pick the same slot index and stomp each other's plaintext.
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    const auto off = find_bytes(d.code, {0xF0, 0x45, 0x0F, 0xC1, 0x08});
    EXPECT_LT(off, d.code.size()) << "lock xadd ring allocator missing";
}

TEST(MxStrGetEphemeral, ContainsAndSlotIndexMask) {
    // 41 83 E1 0F  — and r9d, 0x0F   (mask to slot index mod 16)
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    const auto off = find_bytes(d.code, {0x41, 0x83, 0xE1, 0x0F});
    EXPECT_LT(off, d.code.size())
        << "slot-index mask `and r9d, 15` missing";
}

TEST(MxStrGetEphemeral, ContainsShlSlotOffsetByEight) {
    // 41 C1 E1 08  — shl r9d, 8   (multiply slot index by 256)
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    const auto off = find_bytes(d.code, {0x41, 0xC1, 0xE1, 0x08});
    EXPECT_LT(off, d.code.size())
        << "slot-offset shift `shl r9d, 8` missing";
}

TEST(MxStrGetEphemeral, ContainsLeaRaxRingSlot) {
    // 4B 8D 44 08 04  — lea rax, [r8 + r9*1 + 4]
    // rax = ring_base + slot_offset + kEphemeralRingHeaderSize.
    // This is the S3 return value (scratch slot pointer).
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    const auto off = find_bytes(d.code, {0x4B, 0x8D, 0x44, 0x08, 0x04});
    EXPECT_LT(off, d.code.size()) << "lea rax,[r8+r9+4] missing";
}

TEST(MxStrGetEphemeral, ContainsCopyDecryptLoopBody) {
    // 45 8A 0B  — mov r9b, [r11]     ; load ciphertext byte
    // 41 30 D1  — xor r9b, dl        ; decrypt with per-string key
    // 45 88 08  — mov [r8], r9b      ; store plaintext into scratch
    // These three instructions must appear in sequence; the loop
    // increments the source and destination cursors and decrements
    // the length counter around them.
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    const auto off = find_bytes(d.code,
        {0x45, 0x8A, 0x0B, 0x41, 0x30, 0xD1, 0x45, 0x88, 0x08});
    EXPECT_LT(off, d.code.size())
        << "copy+decrypt loop body (mov/xor/mov) missing";
}

TEST(MxStrGetEphemeral, EndsWithRet) {
    const auto d = mx::string_protect::emit_mx_str_get_ephemeral();
    ASSERT_FALSE(d.code.empty());
    EXPECT_EQ(d.code.back(), 0xC3u);
}

TEST(MxStrGetEphemeral, RingHasPowerOfTwoSlots) {
    // The allocator is optimised for a power-of-two ring (uses `and`
    // instead of `imul`/`div`). Pin the invariant so future edits to
    // kEphemeralRingSlots can't silently break the mask.
    using mx::string_protect::kEphemeralRingSlots;
    EXPECT_EQ(kEphemeralRingSlots & (kEphemeralRingSlots - 1), 0u);
}

// ---------------------------------------------------------------------------
// Volatile-class classification
// ---------------------------------------------------------------------------

TEST(VolatileClass, MatchesWindowsX64Abi) {
    // Volatile per Windows x64 ABI: rax, rcx, rdx, r8, r9, r10, r11.
    EXPECT_TRUE(is_volatile_gpr(kGprRax));
    EXPECT_TRUE(is_volatile_gpr(kGprRcx));
    EXPECT_TRUE(is_volatile_gpr(kGprRdx));
    EXPECT_TRUE(is_volatile_gpr(kGprR8));
    EXPECT_TRUE(is_volatile_gpr(kGprR9));
    EXPECT_TRUE(is_volatile_gpr(kGprR10));
    EXPECT_TRUE(is_volatile_gpr(kGprR11));

    // Non-volatile: rbx, rbp, rsi, rdi, r12..r15.
    EXPECT_FALSE(is_volatile_gpr(kGprRbx));
    EXPECT_FALSE(is_volatile_gpr(kGprRbp));
    EXPECT_FALSE(is_volatile_gpr(kGprRsi));
    EXPECT_FALSE(is_volatile_gpr(kGprRdi));
    EXPECT_FALSE(is_volatile_gpr(kGprR12));
    EXPECT_FALSE(is_volatile_gpr(kGprR13));
    EXPECT_FALSE(is_volatile_gpr(kGprR14));
    EXPECT_FALSE(is_volatile_gpr(kGprR15));
}

TEST(TrampolineSize, MatchesCategoryConstants) {
    EXPECT_EQ(trampoline_size_for(kGprRax), kTrampolineSizeVolatile);
    EXPECT_EQ(trampoline_size_for(kGprR11), kTrampolineSizeVolatile);
    EXPECT_EQ(trampoline_size_for(kGprRbx), kTrampolineSizeNonVolatile);
    EXPECT_EQ(trampoline_size_for(kGprR14), kTrampolineSizeNonVolatile);
    EXPECT_EQ(kTrampolineSizeVolatile,    40u);
    EXPECT_EQ(kTrampolineSizeNonVolatile, 38u);
}

// ---------------------------------------------------------------------------
// Trampoline shape — shared prologue
// ---------------------------------------------------------------------------

// Expected prologue: pushfq, push rax, push rcx, push rdx,
// push r8, push r9, push r10, push r11. 12 bytes total.
constexpr std::array<uint8_t, 12> kExpectedPrologue = {
    0x9C,                   // pushfq
    0x50,                   // push rax
    0x51,                   // push rcx
    0x52,                   // push rdx
    0x41, 0x50,             // push r8
    0x41, 0x51,             // push r9
    0x41, 0x52,             // push r10
    0x41, 0x53,             // push r11
};

void expect_prologue(const std::vector<uint8_t>& c) {
    ASSERT_GE(c.size(), kExpectedPrologue.size());
    for (size_t i = 0; i < kExpectedPrologue.size(); ++i) {
        EXPECT_EQ(c[i], kExpectedPrologue[i])
            << "prologue byte " << i << " mismatch";
    }
}

void expect_mov_ecx_imm32_at(const std::vector<uint8_t>& c,
                              size_t off, uint32_t imm)
{
    ASSERT_LE(off + 5, c.size());
    EXPECT_EQ(c[off], 0xB9u);
    EXPECT_EQ(c[off + 1], static_cast<uint8_t>(imm         & 0xFF));
    EXPECT_EQ(c[off + 2], static_cast<uint8_t>((imm >> 8)  & 0xFF));
    EXPECT_EQ(c[off + 3], static_cast<uint8_t>((imm >> 16) & 0xFF));
    EXPECT_EQ(c[off + 4], static_cast<uint8_t>((imm >> 24) & 0xFF));
}

void expect_call_rel32_placeholder_at(const EmittedTrampoline& t, size_t off) {
    ASSERT_LE(off + 5, t.code.size());
    EXPECT_EQ(t.code[off], 0xE8u);
    EXPECT_EQ(t.call_rel32_offset, off + 1);
    for (size_t i = 1; i <= 4; ++i) {
        EXPECT_EQ(t.code[off + i], 0u)
            << "rel32 placeholder byte " << i << " must be zero";
    }
}

void expect_epilogue_tail(const std::vector<uint8_t>& c) {
    // The final 11 bytes: 41 5B (pop r11), 41 5A (pop r10),
    // 41 59 (pop r9), 41 58 (pop r8), 5A (pop rdx), 59 (pop rcx),
    // 58 (pop rax), 9D (popfq), C3 (ret).
    const std::array<uint8_t, 11> tail = {
        0x41, 0x5B,
        0x41, 0x5A,
        0x41, 0x59,
        0x41, 0x58,
        0x5A,
        0x59,
        0x58,
        // popfq + ret follow
    };
    // Last 13 bytes: 11 tail bytes above + popfq (9D) + ret (C3).
    ASSERT_GE(c.size(), tail.size() + 2);
    const size_t base = c.size() - (tail.size() + 2);
    for (size_t i = 0; i < tail.size(); ++i) {
        EXPECT_EQ(c[base + i], tail[i])
            << "epilogue byte " << i << " mismatch";
    }
    EXPECT_EQ(c[c.size() - 2], 0x9Du) << "popfq missing";
    EXPECT_EQ(c[c.size() - 1], 0xC3u) << "ret missing";
}

// ---------------------------------------------------------------------------
// Trampoline — volatile target: rax (slot 48)
// ---------------------------------------------------------------------------

TEST(TrampolineVolatile, RaxTargetUsesSlot48) {
    TrampolineRequest r{};
    r.string_id  = 0xDEADBEEF;
    r.target_reg = kGprRax;

    const auto t = emit_trampoline(r);
    ASSERT_EQ(t.code.size(), kTrampolineSizeVolatile);

    expect_prologue(t.code);
    expect_mov_ecx_imm32_at(t.code, 12, 0xDEADBEEF);
    expect_call_rel32_placeholder_at(t, 17);
    EXPECT_EQ(t.call_rel32_offset, 18u);

    // mov [rsp + 48], rax  ->  48 89 44 24 30
    EXPECT_EQ(t.code[22], 0x48u);
    EXPECT_EQ(t.code[23], 0x89u);
    EXPECT_EQ(t.code[24], 0x44u);
    EXPECT_EQ(t.code[25], 0x24u);
    EXPECT_EQ(t.code[26], 0x30u);

    expect_epilogue_tail(t.code);
}

TEST(TrampolineVolatile, RcxTargetUsesSlot40) {
    TrampolineRequest r{};
    r.string_id  = 0x00000001;
    r.target_reg = kGprRcx;

    const auto t = emit_trampoline(r);
    ASSERT_EQ(t.code.size(), kTrampolineSizeVolatile);

    expect_prologue(t.code);
    expect_mov_ecx_imm32_at(t.code, 12, 0x00000001);
    expect_call_rel32_placeholder_at(t, 17);
    EXPECT_EQ(t.call_rel32_offset, 18u);

    // mov [rsp + 40], rax  ->  48 89 44 24 28
    EXPECT_EQ(t.code[22], 0x48u);
    EXPECT_EQ(t.code[23], 0x89u);
    EXPECT_EQ(t.code[24], 0x44u);
    EXPECT_EQ(t.code[25], 0x24u);
    EXPECT_EQ(t.code[26], 0x28u);

    expect_epilogue_tail(t.code);
}

TEST(TrampolineVolatile, EveryVolatileUsesDistinctSlot) {
    // The slot byte at code[26] is unique per volatile target.
    struct Case { GprIndex reg; uint8_t slot; };
    const Case cases[] = {
        {kGprRax, 48},
        {kGprRcx, 40},
        {kGprRdx, 32},
        {kGprR8,  24},
        {kGprR9,  16},
        {kGprR10, 8},
        {kGprR11, 0},
    };
    for (const auto& tc : cases) {
        TrampolineRequest r{};
        r.string_id  = 0x42;
        r.target_reg = tc.reg;
        const auto t = emit_trampoline(r);
        ASSERT_EQ(t.code.size(), kTrampolineSizeVolatile) << "reg " << +tc.reg;
        // Slot byte is the fifth byte of the mov at offset 22.
        EXPECT_EQ(t.code[22], 0x48u);
        EXPECT_EQ(t.code[23], 0x89u);
        EXPECT_EQ(t.code[24], 0x44u);
        EXPECT_EQ(t.code[25], 0x24u);
        EXPECT_EQ(t.code[26], tc.slot)
            << "wrong slot for gpr " << +tc.reg;
    }
}

// ---------------------------------------------------------------------------
// Trampoline — non-volatile low target: rbx (REX 0x48)
// ---------------------------------------------------------------------------

TEST(TrampolineNonVolatile, RbxTargetUsesDirectMov) {
    TrampolineRequest r{};
    r.string_id  = 0x12345678;
    r.target_reg = kGprRbx;

    const auto t = emit_trampoline(r);
    ASSERT_EQ(t.code.size(), kTrampolineSizeNonVolatile);

    expect_prologue(t.code);
    expect_mov_ecx_imm32_at(t.code, 12, 0x12345678);
    expect_call_rel32_placeholder_at(t, 17);
    EXPECT_EQ(t.call_rel32_offset, 18u);

    // mov rbx, rax  ->  48 89 C3  (3 bytes, no stack slot)
    EXPECT_EQ(t.code[22], 0x48u);
    EXPECT_EQ(t.code[23], 0x89u);
    EXPECT_EQ(t.code[24], 0xC3u);

    expect_epilogue_tail(t.code);
}

TEST(TrampolineNonVolatile, R14TargetUsesExtendedRex) {
    TrampolineRequest r{};
    r.string_id  = 0xCAFEBABE;
    r.target_reg = kGprR14;

    const auto t = emit_trampoline(r);
    ASSERT_EQ(t.code.size(), kTrampolineSizeNonVolatile);

    expect_prologue(t.code);
    expect_mov_ecx_imm32_at(t.code, 12, 0xCAFEBABE);
    expect_call_rel32_placeholder_at(t, 17);
    EXPECT_EQ(t.call_rel32_offset, 18u);

    // mov r14, rax  ->  49 89 C6  (REX.B set, rm low3 = r14 & 7 = 6)
    EXPECT_EQ(t.code[22], 0x49u);
    EXPECT_EQ(t.code[23], 0x89u);
    EXPECT_EQ(t.code[24], 0xC6u);

    expect_epilogue_tail(t.code);
}

TEST(TrampolineNonVolatile, AllLowAndExtendedNonVolatileEncodings) {
    struct Case { GprIndex reg; uint8_t rex; uint8_t modrm; };
    const Case cases[] = {
        // Low non-volatile (REX 0x48, no REX.B).
        {kGprRbx, 0x48, 0xC3},  // rm=3
        {kGprRbp, 0x48, 0xC5},  // rm=5
        {kGprRsi, 0x48, 0xC6},  // rm=6
        {kGprRdi, 0x48, 0xC7},  // rm=7
        // Extended non-volatile (REX 0x49, REX.B set).
        {kGprR12, 0x49, 0xC4},  // rm low3 = 4
        {kGprR13, 0x49, 0xC5},
        {kGprR14, 0x49, 0xC6},
        {kGprR15, 0x49, 0xC7},
    };
    for (const auto& tc : cases) {
        TrampolineRequest r{};
        r.string_id  = 0;
        r.target_reg = tc.reg;
        const auto t = emit_trampoline(r);
        ASSERT_EQ(t.code.size(), kTrampolineSizeNonVolatile)
            << "reg " << +tc.reg;
        EXPECT_EQ(t.code[22], tc.rex)   << "reg " << +tc.reg;
        EXPECT_EQ(t.code[23], 0x89u)    << "reg " << +tc.reg;
        EXPECT_EQ(t.code[24], tc.modrm) << "reg " << +tc.reg;
    }
}

// ---------------------------------------------------------------------------
// Trampoline — uniform invariants across categories
// ---------------------------------------------------------------------------

TEST(TrampolineUniform, CallRel32OffsetIsAlwaysEighteen) {
    // The prologue + mov ecx imm32 + call opcode sum to 18 bytes
    // regardless of target reg; the rel32 itself lives at 18..21.
    for (GprIndex g = 0; g < 16; ++g) {
        if (g == 4) continue;  // rsp is not a valid target
        TrampolineRequest r{};
        r.string_id  = 7;
        r.target_reg = g;
        const auto t = emit_trampoline(r);
        EXPECT_EQ(t.call_rel32_offset, 18u) << "reg " << +g;
        EXPECT_EQ(t.code[17], 0xE8u) << "call opcode missing (reg "
                                     << +g << ")";
    }
}

TEST(TrampolineUniform, VolatileTrampolinesHaveIdenticalShapeExceptSlot) {
    // Every volatile trampoline differs from rax-target only in the
    // single slot byte at offset 26. Everything else — prologue,
    // mov-ecx, call opcode, epilogue — is byte-identical.
    TrampolineRequest base_req{};
    base_req.string_id  = 0xAABBCCDD;
    base_req.target_reg = kGprRax;
    const auto base = emit_trampoline(base_req);

    const GprIndex others[] = {kGprRcx, kGprRdx, kGprR8,
                                kGprR9,  kGprR10, kGprR11};
    for (GprIndex g : others) {
        TrampolineRequest r{};
        r.string_id  = 0xAABBCCDD;
        r.target_reg = g;
        const auto t = emit_trampoline(r);
        ASSERT_EQ(t.code.size(), base.code.size());
        for (size_t i = 0; i < t.code.size(); ++i) {
            if (i == 26) continue;  // the slot byte — expected to differ
            EXPECT_EQ(t.code[i], base.code[i])
                << "byte " << i << " differs for reg " << +g;
        }
    }
}

TEST(TrampolineUniform, StringIdIsBakedIntoMovEcx) {
    // A second request with a different id must differ ONLY in the
    // four imm32 bytes at offsets 13..16 — and nowhere else.
    TrampolineRequest a{}, b{};
    a.string_id = 0x00000000; a.target_reg = kGprRbx;
    b.string_id = 0xFFFFFFFF; b.target_reg = kGprRbx;

    const auto ta = emit_trampoline(a);
    const auto tb = emit_trampoline(b);
    ASSERT_EQ(ta.code.size(), tb.code.size());
    for (size_t i = 0; i < ta.code.size(); ++i) {
        if (i >= 13 && i <= 16) {
            EXPECT_NE(ta.code[i], tb.code[i])
                << "imm32 byte " << i << " should have changed";
        } else {
            EXPECT_EQ(ta.code[i], tb.code[i])
                << "byte " << i << " changed but shouldn't";
        }
    }
}

} // namespace
