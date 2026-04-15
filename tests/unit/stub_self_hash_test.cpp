/**
 * @file stub_self_hash_test.cpp
 * @brief [TESTS] Unit tests for the P6 stub-self-integrity module.
 *
 * Covers:
 *   - `fnv1a_32` is `constexpr`, deterministic, and reproduces the
 *     canonical FNV-1a-32 reference values for the empty input and
 *     a few well-known strings.
 *   - `derive_effective_key_in_place` is deterministic for fixed
 *     hash+key, and the avalanche property holds: a 1-bit change
 *     to the hash flips most of the 32 output bytes.
 *   - `emit_stub_self_hash` produces the documented byte sequence:
 *     `B8 imm32` for the FNV init, `48 8D 35 disp32` for the
 *     rip-relative lea with the emit-time-computed disp, `B9 imm32`
 *     patch slot for the count, `41 B8 imm32` for the prime, loop
 *     body containing the `imul eax, r8d` instruction, and a
 *     `mov r14d, eax` at the end.
 *   - `emit_key_derivation_loop` produces the documented header +
 *     loop body, has the `imul eax, r8d` multiplicative step, and
 *     chains the state correctly.
 *   - Cross-check: running the build-time `derive_effective_key_
 *     in_place` against known inputs is bit-exact and the byte-level
 *     emitter embeds matching FNV-1a prime / offset-basis constants.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"

namespace {

using mx::ByteView;
using mx::MutableByteView;
using mx::RawEmitter;
using mx::packer::derive_effective_key_in_place;
using mx::packer::emit_key_derivation_loop;
using mx::packer::emit_stub_self_hash;
using mx::packer::fnv1a_32;
using mx::packer::kFnv1aOffsetBasis;
using mx::packer::kFnv1aPrime;

[[nodiscard]] uint32_t read_u32_le(const std::vector<uint8_t>& buf, size_t offset) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + offset, sizeof(v));
    return v;
}

[[nodiscard]] int32_t read_i32_le(const std::vector<uint8_t>& buf, size_t offset) {
    int32_t v = 0;
    std::memcpy(&v, buf.data() + offset, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// fnv1a_32 reference correctness
// ---------------------------------------------------------------------------

TEST(StubSelfHash, Fnv1aEmptyInputIsOffsetBasis) {
    // Empty-span case is safe to evaluate in a constant expression
    // because the default-constructed span never touches memory.
    static_assert(fnv1a_32(ByteView{}) == kFnv1aOffsetBasis,
        "FNV-1a of the empty input must equal the offset basis");
    EXPECT_EQ(fnv1a_32(ByteView{}), 0x811C9DC5u);
}

TEST(StubSelfHash, Fnv1aSingleByteMatchesFormula) {
    // Hand-computed: (offset_basis XOR 'a') * prime (32-bit truncated)
    //   offset_basis           = 0x811C9DC5
    //   offset_basis ^ 'a'     = 0x811C9DC5 ^ 0x61 = 0x811C9DA4
    //   (0x811C9DA4 * 0x01000193) & 0xFFFFFFFF = 0xE40C292C
    const uint8_t payload[1] = {'a'};
    EXPECT_EQ(fnv1a_32(ByteView{payload, 1}), 0xE40C292Cu);
}

TEST(StubSelfHash, Fnv1aDistinctInputsProduceDistinctHashes) {
    const uint8_t a[3] = {'a', 'b', 'c'};
    const uint8_t b[3] = {'a', 'b', 'd'};
    const uint8_t c[3] = {'x', 'y', 'z'};
    const uint32_t ha = fnv1a_32(ByteView{a, 3});
    const uint32_t hb = fnv1a_32(ByteView{b, 3});
    const uint32_t hc = fnv1a_32(ByteView{c, 3});
    EXPECT_NE(ha, hb);
    EXPECT_NE(ha, hc);
    EXPECT_NE(hb, hc);
}

TEST(StubSelfHash, Fnv1aOneBitFlipDisturbsHash) {
    // FNV-1a has good avalanche across the multiplicative step.
    // A one-bit flip in any input byte changes enough of the
    // output bits that the raw int values are always different.
    const uint8_t a[4] = {0x00, 0x00, 0x00, 0x00};
    const uint8_t b[4] = {0x00, 0x00, 0x00, 0x01};
    EXPECT_NE(fnv1a_32(ByteView{a, 4}), fnv1a_32(ByteView{b, 4}));
}

// ---------------------------------------------------------------------------
// derive_effective_key_in_place correctness + avalanche
// ---------------------------------------------------------------------------

TEST(StubSelfHash, DeriveIsDeterministic) {
    constexpr uint32_t kHash = 0xDEADBEEFu;
    std::vector<uint8_t> key_a(32, 0xAA);
    std::vector<uint8_t> key_b(32, 0xAA);
    derive_effective_key_in_place(
        kHash, MutableByteView{key_a.data(), key_a.size()});
    derive_effective_key_in_place(
        kHash, MutableByteView{key_b.data(), key_b.size()});
    EXPECT_EQ(key_a, key_b);
}

TEST(StubSelfHash, DeriveMatchesReferenceFnv1aChain) {
    // Hand-unrolled expected first byte:
    //   state = 0xDEADBEEF
    //   state ^= 0xAA       -> 0xDEADBE45
    //   state *= 0x01000193 -> (0xDEADBE45 * 0x01000193) & 0xFFFFFFFF
    constexpr uint32_t kHash = 0xDEADBEEFu;
    constexpr uint8_t kInputByte = 0xAAu;
    const uint32_t step1 = kHash ^ kInputByte;
    const uint32_t step2 = step1 * kFnv1aPrime;
    const uint8_t expected_first_byte = static_cast<uint8_t>(step2 & 0xFFu);

    std::vector<uint8_t> key(32, kInputByte);
    derive_effective_key_in_place(
        kHash, MutableByteView{key.data(), key.size()});
    EXPECT_EQ(key[0], expected_first_byte);
}

TEST(StubSelfHash, DeriveAvalanchesAcrossAllBytes) {
    // A 1-bit flip in the hash should propagate to essentially every
    // output byte thanks to the multiplicative chain. We count how
    // many of the 32 output bytes differ and require "most" of them,
    // allowing a few collisions because 8-bit truncation can hit the
    // same low byte by chance.
    std::vector<uint8_t> base(32, 0x5A);
    std::vector<uint8_t> key_a = base;
    std::vector<uint8_t> key_b = base;

    derive_effective_key_in_place(
        0x00000000u, MutableByteView{key_a.data(), key_a.size()});
    derive_effective_key_in_place(
        0x00000001u, MutableByteView{key_b.data(), key_b.size()});

    int differing = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (key_a[i] != key_b[i]) ++differing;
    }
    EXPECT_GE(differing, 24) << "FNV-1a chain avalanche should flip "
                              << "≥24 of 32 output bytes on a 1-bit "
                              << "hash delta";
}

TEST(StubSelfHash, DeriveAvalanchesAcrossKeyBytes) {
    // Same hash, but a 1-byte change in the base key. The forward
    // chain means byte i's output depends on base_key[0..i], so
    // flipping base_key[0] should ripple to every output byte.
    std::vector<uint8_t> key_a(32, 0x00);
    std::vector<uint8_t> key_b = key_a;
    key_b[0] ^= 0xFF;  // flip byte 0

    derive_effective_key_in_place(
        0x12345678u, MutableByteView{key_a.data(), key_a.size()});
    derive_effective_key_in_place(
        0x12345678u, MutableByteView{key_b.data(), key_b.size()});

    int differing = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (key_a[i] != key_b[i]) ++differing;
    }
    EXPECT_GE(differing, 24) << "FNV-1a chain avalanche should flip "
                              << "≥24 of 32 output bytes on a 1-byte "
                              << "base-key delta at offset 0";
}

// ---------------------------------------------------------------------------
// emit_stub_self_hash byte-pattern assertions
// ---------------------------------------------------------------------------

TEST(StubSelfHash, EmitSelfHashProducesExpectedLayout) {
    RawEmitter e;
    const auto patches = emit_stub_self_hash(e);

    // Total size: header (23) + loop body (16) + trailer (3) = 42 bytes.
    EXPECT_EQ(e.size(), 42u);

    // Header:
    //   [00]    B8              (mov eax, imm32)
    //   [01-04] imm32 = FNV offset basis
    //   [05]    48 8D 35        (lea rsi, [rip + disp32])
    //   [06]    ^
    //   [07]    ^
    //   [08-11] disp32          (= -(lea_end) = -12)
    //   [12]    B9              (mov ecx, imm32)
    //   [13-16] imm32 patch slot (initially 0)
    //   [17-18] 41 B8           (mov r8d, imm32)
    //   [19-22] imm32 = FNV prime
    ASSERT_GE(e.size(), 23u);
    EXPECT_EQ(e.buf[0],  0xB8u);
    EXPECT_EQ(read_u32_le(e.buf, 1), kFnv1aOffsetBasis);

    EXPECT_EQ(e.buf[5],  0x48u);
    EXPECT_EQ(e.buf[6],  0x8Du);
    EXPECT_EQ(e.buf[7],  0x35u);

    // disp32: caller says `hash_range_start = 0` and we baked
    // `disp = -(lea_end) = -(12)`, so runtime resolves to stub offset 0.
    const int32_t disp = read_i32_le(e.buf, 8);
    EXPECT_EQ(disp, -12);
    EXPECT_EQ(patches.start_disp32_offset, 8u);
    EXPECT_EQ(patches.hash_range_start, 0u);

    EXPECT_EQ(e.buf[12], 0xB9u);
    EXPECT_EQ(read_u32_le(e.buf, 13), 0u);  // count starts as placeholder
    EXPECT_EQ(patches.count_imm32_offset, 13u);

    EXPECT_EQ(e.buf[17], 0x41u);
    EXPECT_EQ(e.buf[18], 0xB8u);
    EXPECT_EQ(read_u32_le(e.buf, 19), kFnv1aPrime);
}

TEST(StubSelfHash, EmitSelfHashLoopBodyHasImulAndJnz) {
    RawEmitter e;
    (void)emit_stub_self_hash(e);

    // The loop body lives at offset 23..38 (16 bytes). Inside it we
    // expect:
    //   movzx edx, [rsi]    0F B6 16
    //   xor   eax, edx      31 D0
    //   imul  eax, r8d      41 0F AF C0
    //   inc   rsi           48 FF C6
    //   dec   ecx           FF C9
    //   jnz   rel8          75 rel8
    EXPECT_EQ(e.buf[23], 0x0Fu);
    EXPECT_EQ(e.buf[24], 0xB6u);
    EXPECT_EQ(e.buf[25], 0x16u);

    EXPECT_EQ(e.buf[26], 0x31u);
    EXPECT_EQ(e.buf[27], 0xD0u);

    EXPECT_EQ(e.buf[28], 0x41u);
    EXPECT_EQ(e.buf[29], 0x0Fu);
    EXPECT_EQ(e.buf[30], 0xAFu);
    EXPECT_EQ(e.buf[31], 0xC0u);

    EXPECT_EQ(e.buf[32], 0x48u);
    EXPECT_EQ(e.buf[33], 0xFFu);
    EXPECT_EQ(e.buf[34], 0xC6u);

    EXPECT_EQ(e.buf[35], 0xFFu);
    EXPECT_EQ(e.buf[36], 0xC9u);

    EXPECT_EQ(e.buf[37], 0x75u);
    // rel8: from byte after the jnz (offset 39) back to loop_start (offset 23)
    // delta = 23 - 39 = -16 = 0xF0
    EXPECT_EQ(e.buf[38], 0xF0u);
}

TEST(StubSelfHash, EmitSelfHashTrailerSavesToR14) {
    RawEmitter e;
    (void)emit_stub_self_hash(e);

    // Trailer: `mov r14d, eax` = 41 89 C6 (3 bytes) at offsets 39-41
    EXPECT_EQ(e.buf[39], 0x41u);
    EXPECT_EQ(e.buf[40], 0x89u);
    EXPECT_EQ(e.buf[41], 0xC6u);
}

// ---------------------------------------------------------------------------
// emit_key_derivation_loop byte-pattern assertions
// ---------------------------------------------------------------------------

TEST(StubSelfHash, EmitDerivationLoopHasExpectedLayout) {
    RawEmitter e;
    emit_key_derivation_loop(e);

    // Total size: header (17) + loop body (15) = 32 bytes.
    EXPECT_EQ(e.size(), 32u);

    // Header:
    //   [00-02] 44 89 F0        (mov eax, r14d)
    //   [03-05] 48 89 F1        (mov rcx, rsi)
    //   [06]    BA              (mov edx, imm32)
    //   [07-10] imm32 = 32
    //   [11-12] 41 B8           (mov r8d, imm32)
    //   [13-16] imm32 = FNV prime
    EXPECT_EQ(e.buf[0],  0x44u);
    EXPECT_EQ(e.buf[1],  0x89u);
    EXPECT_EQ(e.buf[2],  0xF0u);

    EXPECT_EQ(e.buf[3],  0x48u);
    EXPECT_EQ(e.buf[4],  0x89u);
    EXPECT_EQ(e.buf[5],  0xF1u);

    EXPECT_EQ(e.buf[6],  0xBAu);
    EXPECT_EQ(read_u32_le(e.buf, 7), 32u);

    EXPECT_EQ(e.buf[11], 0x41u);
    EXPECT_EQ(e.buf[12], 0xB8u);
    EXPECT_EQ(read_u32_le(e.buf, 13), kFnv1aPrime);
}

TEST(StubSelfHash, EmitDerivationLoopBodyHasXorAlAndImul) {
    RawEmitter e;
    emit_key_derivation_loop(e);

    // Loop body at offsets 17..31:
    //   xor al, [rcx]    32 01       (2)
    //   imul eax, r8d    41 0F AF C0 (4)
    //   mov [rcx], al    88 01       (2)
    //   inc rcx          48 FF C1    (3)
    //   dec edx          FF CA       (2)
    //   jnz rel8         75 rel8     (2)
    EXPECT_EQ(e.buf[17], 0x32u); EXPECT_EQ(e.buf[18], 0x01u);
    EXPECT_EQ(e.buf[19], 0x41u); EXPECT_EQ(e.buf[20], 0x0Fu);
    EXPECT_EQ(e.buf[21], 0xAFu); EXPECT_EQ(e.buf[22], 0xC0u);
    EXPECT_EQ(e.buf[23], 0x88u); EXPECT_EQ(e.buf[24], 0x01u);
    EXPECT_EQ(e.buf[25], 0x48u); EXPECT_EQ(e.buf[26], 0xFFu);
    EXPECT_EQ(e.buf[27], 0xC1u);
    EXPECT_EQ(e.buf[28], 0xFFu); EXPECT_EQ(e.buf[29], 0xCAu);
    EXPECT_EQ(e.buf[30], 0x75u);

    // rel8 from byte after jnz (offset 32) back to loop_start (17)
    // delta = 17 - 32 = -15 = 0xF1
    EXPECT_EQ(e.buf[31], 0xF1u);
}

TEST(StubSelfHash, EmitDerivationLoopEmbedsFnv1aPrimeMatchingBuildSide) {
    // Guard against accidental divergence between the build-side
    // FNV-1a constant (`kFnv1aPrime`) and the one the runtime emitter
    // bakes into the `mov r8d, imm32` slot. If they ever disagree,
    // runtime key derivation produces a different result from the
    // build-time `derive_effective_key_in_place` call and every
    // protected binary decrypts to garbage.
    RawEmitter e;
    emit_key_derivation_loop(e);
    EXPECT_EQ(read_u32_le(e.buf, 13), kFnv1aPrime);
}

TEST(StubSelfHash, EmitSelfHashEmbedsFnv1aConstantsMatchingBuildSide) {
    // Same guard for the self-hash loop — it must bake the same
    // offset basis and prime the build-side `fnv1a_32` uses.
    RawEmitter e;
    (void)emit_stub_self_hash(e);
    EXPECT_EQ(read_u32_le(e.buf, 1),  kFnv1aOffsetBasis);
    EXPECT_EQ(read_u32_le(e.buf, 19), kFnv1aPrime);
}

} // namespace
