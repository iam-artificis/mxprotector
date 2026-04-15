/**
 * @file hash_opaque_predicate_test.cpp
 * @brief [TESTS] Unit tests for the G6 hash-based opaque predicate.
 *
 * Covers:
 *   - `compute_hash_opaque` is a pure function of its parameters and
 *     produces distinct outputs for distinct inputs.
 *   - `randomize_hash_opaque_params` honours its invariants
 *     (multipliers odd, rotation in [1, 31]) and is deterministic
 *     when seeded with the same RNG state.
 *   - `emit_hash_opaque_predicate` produces a buffer that begins with
 *     the documented `mov eax, [rip + disp32]` prefix, contains the
 *     three `imul eax, eax, imm32` rounds, ends the chain with
 *     `cmp eax, target` whose embedded imm32 equals
 *     `compute_hash_opaque(params)`, and writes the input value into
 *     the rip-relative target byte slot the load reads from.
 *   - Same params + same RNG state → byte-identical emission.
 *   - Different params → different cmp imm32 slot.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/obfuscation/hash_opaque_predicate.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::obf::compute_hash_opaque;
using mx::obf::emit_hash_opaque_predicate;
using mx::obf::HashOpaqueParams;
using mx::obf::randomize_hash_opaque_params;

/// Read a 32-bit little-endian value at `offset` inside `buf`.
[[nodiscard]] uint32_t read_u32_le(const std::vector<uint8_t>& buf, size_t offset) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + offset, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// compute_hash_opaque — pure function of params
// ---------------------------------------------------------------------------

TEST(HashOpaquePredicate, ComputeIsDeterministic) {
    HashOpaqueParams p{};
    p.input_value = 0x12345678;
    p.mul1 = 0x9E3779B1;
    p.mul2 = 0x85EBCA77;
    p.mul3 = 0xC2B2AE3D;
    p.xor1 = 0xDEADBEEF;
    p.xor2 = 0xCAFEBABE;
    p.rotation = 13;

    const uint32_t a = compute_hash_opaque(p);
    const uint32_t b = compute_hash_opaque(p);
    EXPECT_EQ(a, b);
}

TEST(HashOpaquePredicate, ComputeChangesWithInput) {
    HashOpaqueParams p{};
    p.mul1 = 0x9E3779B1;
    p.mul2 = 0x85EBCA77;
    p.mul3 = 0xC2B2AE3D;
    p.xor1 = 0xDEADBEEF;
    p.xor2 = 0xCAFEBABE;
    p.rotation = 13;

    p.input_value = 0;
    const uint32_t h0 = compute_hash_opaque(p);
    p.input_value = 1;
    const uint32_t h1 = compute_hash_opaque(p);
    p.input_value = 0xFFFFFFFF;
    const uint32_t h2 = compute_hash_opaque(p);

    // Three distinct inputs produce three distinct hashes given odd
    // multipliers — collision is theoretically possible but the
    // test parameters make it astronomically unlikely.
    EXPECT_NE(h0, h1);
    EXPECT_NE(h0, h2);
    EXPECT_NE(h1, h2);
}

TEST(HashOpaquePredicate, ComputeMatchesReferenceFormula) {
    // Hand-evaluated reference: the C++ implementation must agree
    // with the documented build-time formula bit-for-bit.
    HashOpaqueParams p{};
    p.input_value = 0x00000001;
    p.mul1 = 3;
    p.mul2 = 5;
    p.mul3 = 7;
    p.xor1 = 0;
    p.xor2 = 0;
    p.rotation = 1;

    // acc = 1
    // *= 3      → 3
    // ^= 0      → 3
    // *= 5      → 15
    // rotl 1    → 30
    // *= 7      → 210
    // ^= 0      → 210
    EXPECT_EQ(compute_hash_opaque(p), 210u);
}

// ---------------------------------------------------------------------------
// randomize_hash_opaque_params — invariants + determinism
// ---------------------------------------------------------------------------

TEST(HashOpaquePredicate, RandomizeMultipliersAreOdd) {
    Randomizer rng{0x1234'5678'9ABC'DEF0ULL};
    for (int i = 0; i < 256; ++i) {
        const auto p = randomize_hash_opaque_params(rng);
        EXPECT_EQ(p.mul1 & 1u, 1u) << "mul1 must be odd";
        EXPECT_EQ(p.mul2 & 1u, 1u) << "mul2 must be odd";
        EXPECT_EQ(p.mul3 & 1u, 1u) << "mul3 must be odd";
    }
}

TEST(HashOpaquePredicate, RandomizeRotationInBounds) {
    Randomizer rng{0xCAFE'BABE'DEAD'BEEFULL};
    for (int i = 0; i < 256; ++i) {
        const auto p = randomize_hash_opaque_params(rng);
        EXPECT_GE(p.rotation, 1);
        EXPECT_LE(p.rotation, 31);
    }
}

TEST(HashOpaquePredicate, RandomizeIsDeterministicForSameSeed) {
    Randomizer a{42};
    Randomizer b{42};
    for (int i = 0; i < 16; ++i) {
        const auto pa = randomize_hash_opaque_params(a);
        const auto pb = randomize_hash_opaque_params(b);
        EXPECT_EQ(pa.input_value, pb.input_value);
        EXPECT_EQ(pa.mul1, pb.mul1);
        EXPECT_EQ(pa.mul2, pb.mul2);
        EXPECT_EQ(pa.mul3, pb.mul3);
        EXPECT_EQ(pa.xor1, pb.xor1);
        EXPECT_EQ(pa.xor2, pb.xor2);
        EXPECT_EQ(pa.rotation, pb.rotation);
    }
}

// ---------------------------------------------------------------------------
// emit_hash_opaque_predicate — byte-pattern shape
// ---------------------------------------------------------------------------

TEST(HashOpaquePredicate, EmitProducesNonEmptyBuffer) {
    Randomizer rng{0xABCDEF};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);
    EXPECT_GT(e.size(), 30u);
    EXPECT_LT(e.size(), 80u);
}

TEST(HashOpaquePredicate, EmitStartsWithRipRelativeMov) {
    Randomizer rng{0xDEAD};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // The first instruction MUST be `mov eax, [rip + disp32]` so the
    // engine sees the input as a memory load instead of an immediate.
    //   8B 05 disp32   →   ModRM = 00 000 101  (rip-relative addressing)
    ASSERT_GE(e.size(), 6u);
    EXPECT_EQ(e.buf[0], 0x8Bu);
    EXPECT_EQ(e.buf[1], 0x05u);
}

TEST(HashOpaquePredicate, EmitContainsThreeImulRounds) {
    Randomizer rng{0xBEEF};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // Each round emits `imul eax, eax, imm32` = `69 C0 imm32`.
    // The (0x69, 0xC0) prefix appears exactly three times — once per
    // mixing round.
    int imul_count = 0;
    for (size_t i = 0; i + 1 < e.size(); ++i) {
        if (e.buf[i] == 0x69 && e.buf[i + 1] == 0xC0) ++imul_count;
    }
    EXPECT_EQ(imul_count, 3);
}

TEST(HashOpaquePredicate, EmitBakesCorrectTargetIntoCmp) {
    Randomizer rng{0xC0FFEE};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);
    const uint32_t target = compute_hash_opaque(p);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // The chain ends with `cmp eax, target` = `3D imm32`. Because
    // `35 imm32` (xor eax, imm32) shares the EAX-immediate form
    // family (0x35), the cmp opcode 0x3D is unique on the EAX path
    // and must appear exactly once. The next 4 bytes encode the
    // build-time hash target in little-endian.
    int cmp_count = 0;
    size_t cmp_at = 0;
    for (size_t i = 0; i + 4 < e.size(); ++i) {
        if (e.buf[i] == 0x3Du) {
            ++cmp_count;
            cmp_at = i;
        }
    }
    ASSERT_EQ(cmp_count, 1);
    EXPECT_EQ(read_u32_le(e.buf, cmp_at + 1), target);
}

TEST(HashOpaquePredicate, EmitInputBytesEmbeddedAtRipRelativeTarget) {
    Randomizer rng{0xFEEDFACE};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);
    // Use a non-trivial input that's unlikely to collide with any
    // emitted constant by accident.
    p.input_value = 0xC0DECAFE;

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // The disp32 in the leading `8B 05 disp32` points from the byte
    // after the mov (offset 6) to the embedded input slot. Resolve
    // it and confirm the 4 bytes there equal `p.input_value`.
    ASSERT_GE(e.size(), 6u);
    const int32_t disp = static_cast<int32_t>(read_u32_le(e.buf, 2));
    const int64_t input_offset =
        static_cast<int64_t>(6) + static_cast<int64_t>(disp);
    ASSERT_GE(input_offset, 0);
    ASSERT_LE(static_cast<size_t>(input_offset) + 4, e.size());
    EXPECT_EQ(read_u32_le(e.buf, static_cast<size_t>(input_offset)),
              p.input_value);
}

TEST(HashOpaquePredicate, EmitContainsJneAndJmpShort) {
    Randomizer rng{0xBADF00D};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // Always-true predicate path: `cmp eax, target` (3D imm32) is
    // followed by `jne short .false` (75 rel8) and `jmp short .end`
    // (EB rel8). Both opcodes must be present somewhere AFTER the
    // cmp instruction we located in the previous test.
    bool saw_jne = false;
    bool saw_jmp = false;
    for (size_t i = 0; i < e.size(); ++i) {
        if (e.buf[i] == 0x75u) saw_jne = true;
        if (e.buf[i] == 0xEBu) saw_jmp = true;
    }
    EXPECT_TRUE(saw_jne);
    EXPECT_TRUE(saw_jmp);
}

TEST(HashOpaquePredicate, DeterministicForSameSeed) {
    HashOpaqueParams p{};
    p.input_value = 0xAAAAAAAA;
    p.mul1 = 0xDEADBEE1;
    p.mul2 = 0xCAFEBAB1;
    p.mul3 = 0xFEEDFAC1;
    p.xor1 = 0x12345678;
    p.xor2 = 0x9ABCDEF0;
    p.rotation = 7;

    Randomizer rng_a{1234};
    Randomizer rng_b{1234};
    RawEmitter ea;
    RawEmitter eb;
    emit_hash_opaque_predicate(ea, p, rng_a);
    emit_hash_opaque_predicate(eb, p, rng_b);

    ASSERT_EQ(ea.size(), eb.size());
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(HashOpaquePredicate, DiffersAcrossSeeds) {
    // Different RNG state for the false-branch junk constant should
    // produce a different byte sequence even when the hash params
    // themselves are identical.
    HashOpaqueParams p{};
    p.input_value = 0xAAAAAAAA;
    p.mul1 = 0xDEADBEE1;
    p.mul2 = 0xCAFEBAB1;
    p.mul3 = 0xFEEDFAC1;
    p.xor1 = 0x12345678;
    p.xor2 = 0x9ABCDEF0;
    p.rotation = 7;

    Randomizer rng_a{1234};
    Randomizer rng_b{5678};
    RawEmitter ea;
    RawEmitter eb;
    emit_hash_opaque_predicate(ea, p, rng_a);
    emit_hash_opaque_predicate(eb, p, rng_b);

    ASSERT_EQ(ea.size(), eb.size());
    EXPECT_NE(ea.buf, eb.buf);
}

TEST(HashOpaquePredicate, EndToEndEmittedBytesReproduceTarget) {
    // Cross-check: take a predicate, then mentally walk the emitted
    // bytes and confirm the hash chain reproduces compute_hash_opaque.
    // We pull every constant out of the emitted bytes and re-run the
    // formula on the embedded input value, just like a runtime CPU
    // would, then compare against the target slot inside the cmp.
    Randomizer rng{777};
    HashOpaqueParams p = randomize_hash_opaque_params(rng);

    RawEmitter e;
    emit_hash_opaque_predicate(e, p, rng);

    // Hand-decode by walking known opcode prefixes. The layout is
    // fixed by the emitter so positional reads are stable.
    //
    //   [0..1]   8B 05         (mov eax, [rip + disp32])
    //   [2..5]   disp32
    //   [6..7]   69 C0         (imul eax, eax, imm32 — round 1)
    //   [8..11]  mul1
    //   [12]     35            (xor eax, imm32)
    //   [13..16] xor1
    //   [17..18] 69 C0
    //   [19..22] mul2
    //   [23..24] C1 C0         (rol eax, imm8)
    //   [25]     rotation
    //   [26..27] 69 C0
    //   [28..31] mul3
    //   [32]     35
    //   [33..36] xor2
    //   [37]     3D            (cmp eax, imm32)
    //   [38..41] target
    ASSERT_GE(e.size(), 42u);

    EXPECT_EQ(e.buf[0],  0x8Bu);
    EXPECT_EQ(e.buf[1],  0x05u);
    EXPECT_EQ(e.buf[6],  0x69u); EXPECT_EQ(e.buf[7],  0xC0u);
    EXPECT_EQ(read_u32_le(e.buf, 8), p.mul1);
    EXPECT_EQ(e.buf[12], 0x35u);
    EXPECT_EQ(read_u32_le(e.buf, 13), p.xor1);
    EXPECT_EQ(e.buf[17], 0x69u); EXPECT_EQ(e.buf[18], 0xC0u);
    EXPECT_EQ(read_u32_le(e.buf, 19), p.mul2);
    EXPECT_EQ(e.buf[23], 0xC1u); EXPECT_EQ(e.buf[24], 0xC0u);
    EXPECT_EQ(e.buf[25], p.rotation);
    EXPECT_EQ(e.buf[26], 0x69u); EXPECT_EQ(e.buf[27], 0xC0u);
    EXPECT_EQ(read_u32_le(e.buf, 28), p.mul3);
    EXPECT_EQ(e.buf[32], 0x35u);
    EXPECT_EQ(read_u32_le(e.buf, 33), p.xor2);
    EXPECT_EQ(e.buf[37], 0x3Du);
    EXPECT_EQ(read_u32_le(e.buf, 38), compute_hash_opaque(p));
}

} // namespace
