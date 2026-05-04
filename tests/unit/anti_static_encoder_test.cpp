/**
 * @file anti_static_encoder_test.cpp
 * @brief [TESTS] B.4.19 — IndirectCallEncoder + Registry contract.
 *
 * Pins the invariants every encoder must hold:
 *
 *   1. `bytes.size() == stub_size()`.
 *   2. The 5-byte `disp32` slot lives at `disp32_byte_offset` and
 *      decoding `(stub_rva + disp32_offset_after_lea) + disp32`
 *      followed by the encoder's `constant_offset` reaches
 *      `target_rva`.
 *   3. Different `Randomizer` seeds produce different bytes for
 *      the same `(stub_rva, target_rva)` — the encoder is not a
 *      degenerate identity.
 *
 * Plus a registry-level invariant: `pick(rng)` returns one of the
 * registered encoders uniformly.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <string_view>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/anti_static/encoder_registry.hpp"
#include "mxprotector/protection/anti_static/encoders/add_chain4_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/add_offset_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/interleaved_add_sub_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/sub_neg_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/xor_chain4_encoder.hpp"
#include "mxprotector/protection/anti_static/encoders/xor_chain_encoder.hpp"

namespace {

using mx::Randomizer;
using mx::Rva;
using mx::protection::anti_static::AddChain4Encoder;
using mx::protection::anti_static::AddOffsetEncoder;
using mx::protection::anti_static::EncodedStub;
using mx::protection::anti_static::EncoderRegistry;
using mx::protection::anti_static::IIndirectCallEncoder;
using mx::protection::anti_static::InterleavedAddSubEncoder;
using mx::protection::anti_static::SubNegEncoder;
using mx::protection::anti_static::XorChain4Encoder;
using mx::protection::anti_static::XorChainEncoder;

[[nodiscard]] std::int32_t read_disp32(
    const std::vector<std::uint8_t>& bytes, std::uint32_t offset)
{
    std::int32_t v = 0;
    std::memcpy(&v, bytes.data() + offset, sizeof(v));
    return v;
}

/// Common contract: every encoder must satisfy
///
///   target_rva == lea_rip_anchor + disp32 + constant_offset
///
/// where the LEA's RIP-after-anchor is `(stub_rva + disp32_byte_offset + 4)`
/// — `disp32_byte_offset` is the byte offset of the disp32 within
/// the stub, plus 4 for the disp32 size itself.
void verify_chain_resolves(
    const IIndirectCallEncoder& enc,
    Rva                         stub_rva,
    Rva                         target_rva)
{
    Randomizer rng{0xCAFEBABEu};
    const auto stub = enc.emit(stub_rva, target_rva, rng);
    ASSERT_EQ(stub.bytes.size(), enc.stub_size())
        << "encoder " << enc.name() << " produced wrong byte count";

    const std::int32_t disp = read_disp32(stub.bytes, stub.disp32_byte_offset);
    const Rva lea_rip_anchor = static_cast<Rva>(
        stub_rva + stub.disp32_byte_offset + 4);
    const std::int64_t computed =
        static_cast<std::int64_t>(lea_rip_anchor) +
        static_cast<std::int64_t>(disp) +
        static_cast<std::int64_t>(stub.constant_offset);
    EXPECT_EQ(static_cast<Rva>(computed), target_rva)
        << "encoder " << enc.name()
        << ": chain does not resolve to target_rva"
        << " (stub=0x" << std::hex << stub_rva
        << " target=0x" << target_rva
        << " disp=" << std::dec << disp
        << " K=" << stub.constant_offset
        << " lea_anchor=0x" << std::hex << lea_rip_anchor
        << " computed=0x" << computed << ")";
}

// ---------------------------------------------------------------------------
// Per-encoder contract
// ---------------------------------------------------------------------------

TEST(AntiStaticEncoder, AddOffsetResolvesToTarget) {
    AddOffsetEncoder e;
    EXPECT_EQ(e.name(), "add-offset");
    EXPECT_EQ(e.stub_size(), 26u);
    verify_chain_resolves(e, /*stub=*/0x10000, /*target=*/0x12345);
    verify_chain_resolves(e, /*stub=*/0x20000, /*target=*/0x18000);
}

TEST(AntiStaticEncoder, XorChainResolvesToTarget) {
    XorChainEncoder e;
    EXPECT_EQ(e.name(), "xor-chain");
    EXPECT_EQ(e.stub_size(), 39u);
    verify_chain_resolves(e, 0x10000, 0x18000);
    verify_chain_resolves(e, 0x12000, 0x14000);
}

TEST(AntiStaticEncoder, SubNegResolvesToTarget) {
    SubNegEncoder e;
    EXPECT_EQ(e.name(), "sub-neg");
    EXPECT_EQ(e.stub_size(), 32u);
    verify_chain_resolves(e, 0x10000, 0x18000);
    verify_chain_resolves(e, 0x20000, 0x10500);
}

// ---------------------------------------------------------------------------
// Phase C — non-mirrored chain encoders
// ---------------------------------------------------------------------------

TEST(AntiStaticEncoder, AddChain4ResolvesToTarget) {
    AddChain4Encoder e;
    EXPECT_EQ(e.name(), "add-chain-4");
    EXPECT_EQ(e.stub_size(), 37u);
    verify_chain_resolves(e, 0x10000, 0x18000);
    verify_chain_resolves(e, 0x12000, 0x14000);
}

TEST(AntiStaticEncoder, XorChain4ResolvesToTarget) {
    XorChain4Encoder e;
    EXPECT_EQ(e.name(), "xor-chain-4");
    EXPECT_EQ(e.stub_size(), 37u);
    verify_chain_resolves(e, 0x10000, 0x18000);
    verify_chain_resolves(e, 0x20000, 0x10500);
}

TEST(AntiStaticEncoder, InterleavedAddSubResolvesToTarget) {
    InterleavedAddSubEncoder e;
    EXPECT_EQ(e.name(), "interleaved-add-sub");
    EXPECT_EQ(e.stub_size(), 37u);
    verify_chain_resolves(e, 0x10000, 0x18000);
    verify_chain_resolves(e, 0x20000, 0x10500);
}

TEST(AntiStaticEncoder, AddChain4VariesAcrossSeeds) {
    AddChain4Encoder e;
    Randomizer r1{1};
    Randomizer r2{2};
    const auto a = e.emit(0x10000, 0x18000, r1);
    const auto b = e.emit(0x10000, 0x18000, r2);
    EXPECT_NE(a.bytes, b.bytes);
}

TEST(AntiStaticEncoder, AddChain4ConstantsHaveNoVisibleMirror) {
    // Pin the contract: every constant in the chain is independently
    // random — so byte ranges of the four `add` immediates should
    // differ (with overwhelming probability) for almost every seed.
    // This is the OBSERVABLE difference from `AddOffsetEncoder`,
    // whose `add K, sub K` pair embeds the same byte run twice.
    AddChain4Encoder e;
    Randomizer rng{0xDEADBEEFu};
    const auto stub = e.emit(0x10000, 0x18000, rng);
    ASSERT_EQ(stub.bytes.size(), 37u);
    // Add immediates start at offsets 10, 16, 22, 28: 1 (push rax)
    // + 7 (lea) + 2 (`48 05`) = 10 for the first immediate, then
    // +6 per subsequent step.
    auto read_imm = [&](std::size_t off) {
        std::int32_t v = 0;
        std::memcpy(&v, stub.bytes.data() + off, sizeof(v));
        return v;
    };
    const std::int32_t k1 = read_imm(10);
    const std::int32_t k2 = read_imm(16);
    const std::int32_t k3 = read_imm(22);
    const std::int32_t k4 = read_imm(28);

    // Sum to zero mod 2^32 — algebraic identity contract.
    const std::int64_t sum =
        static_cast<std::int64_t>(k1) +
        static_cast<std::int64_t>(k2) +
        static_cast<std::int64_t>(k3) +
        static_cast<std::int64_t>(k4);
    EXPECT_EQ(static_cast<std::int32_t>(sum), 0);

    // None of the constants is the negative of any other (the
    // `add K, sub -K` shortcut a folder might detect). Probability
    // of all six pairs landing on negatives by chance ≈ 6 × 2^-32.
    EXPECT_NE(k1, -k2);
    EXPECT_NE(k1, -k3);
    EXPECT_NE(k1, -k4);
    EXPECT_NE(k2, -k3);
    EXPECT_NE(k2, -k4);
    EXPECT_NE(k3, -k4);
}

// ---------------------------------------------------------------------------
// Variation: different RNG seeds produce different bytes
// ---------------------------------------------------------------------------

TEST(AntiStaticEncoder, AddOffsetVariesAcrossSeeds) {
    AddOffsetEncoder e;
    Randomizer r1{1};
    Randomizer r2{2};
    const auto a = e.emit(0x10000, 0x18000, r1);
    const auto b = e.emit(0x10000, 0x18000, r2);
    EXPECT_NE(a.bytes, b.bytes);
}

// ---------------------------------------------------------------------------
// Registry contract
// ---------------------------------------------------------------------------

TEST(EncoderRegistry, EmptyRegistryReturnsNull) {
    EncoderRegistry r;
    Randomizer rng{0};
    EXPECT_EQ(r.pick(rng), nullptr);
    EXPECT_EQ(r.size(), 0u);
}

TEST(EncoderRegistry, DefaultRegistryHoldsAllShipped) {
    auto r = mx::protection::anti_static::make_default_registry();
    EXPECT_GE(r.size(), 6u);
    EXPECT_NE(r.find("add-offset"),          nullptr);
    EXPECT_NE(r.find("xor-chain"),           nullptr);
    EXPECT_NE(r.find("sub-neg"),             nullptr);
    EXPECT_NE(r.find("add-chain-4"),         nullptr);
    EXPECT_NE(r.find("xor-chain-4"),         nullptr);
    EXPECT_NE(r.find("interleaved-add-sub"), nullptr);
    EXPECT_EQ(r.find("nope"),                nullptr);
}

TEST(EncoderRegistry, PickReturnsRegisteredEncoder) {
    auto r = mx::protection::anti_static::make_default_registry();
    Randomizer rng{0xABCDu};
    std::set<std::string_view> seen;
    for (int i = 0; i < 100; ++i) {
        const auto* e = r.pick(rng);
        ASSERT_NE(e, nullptr);
        seen.insert(e->name());
    }
    // With 3 encoders and 100 picks, all should have appeared at
    // least once (uniform distribution).
    EXPECT_EQ(seen.size(), r.size());
}

} // namespace
