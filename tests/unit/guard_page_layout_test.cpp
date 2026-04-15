/**
 * @file guard_page_layout_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::build_guard_page`.
 *
 * The page builder is a pure function — same inputs yield byte-for-byte
 * identical outputs — so the tests pin down the exact layout contract
 * the runtime-guards VEH dispatcher relies on. The two 5-byte
 * `int3 + tag` windows MUST remain at fixed offsets so Commit 3b's
 * encryption skip-window mechanism can preserve them correctly.
 *
 * Covered behaviours:
 *   * Happy path for a tiny body: size, entry int3+tag, body placement,
 *     exit int3+tag, junk offset, guard_id baked into both tags.
 *   * Determinism: identical body + same seed → identical bytes.
 *   * Different seed: body and both int3+tag windows stable, junk tail
 *     diverges.
 *   * Edge case: body exactly `page_size - 10` fills the page — both
 *     plaintext windows present, zero junk bytes, all fields valid.
 *   * Edge case: body one byte too large → error.
 *   * Edge case: empty body → error.
 *   * Configurable `page_size` override keeps invariants on a small
 *     64-byte page.
 *   * Guard id is encoded as little-endian u32 in BOTH tag windows.
 *   * Two different guard_ids produce distinct tag bytes, same body.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"

namespace {

using mx::ByteBuffer;
using mx::ByteView;
using mx::Randomizer;
using mx::guard::build_guard_page;
using mx::guard::GuardPageLayout;
using mx::guard::kGuardInt3TagSize;
using mx::guard::kGuardPageSize;

/// Read the 4-byte little-endian u32 stored at the tag slot right
/// after an `0xCC` instruction byte.
[[nodiscard]] uint32_t read_tag(const ByteBuffer& buf, uint32_t int3_offset) {
    uint32_t tag = 0;
    std::memcpy(&tag, buf.data() + int3_offset + 1, sizeof(tag));
    return tag;
}

// ---------------------------------------------------------------------------
// Happy path — tiny body on a default 4 KiB page.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, HappyPathTinyBody) {
    const std::vector<uint8_t> body = {
        0x48, 0x89, 0xC1,   // mov rcx, rax
        0x48, 0x01, 0xC8,   // add rax, rcx
        0x48, 0x31, 0xD2,   // xor rdx, rdx
    };
    const uint32_t guard_id = 0x12345678u;

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, guard_id, rng);
    ASSERT_TRUE(result.has_value()) << result.error().format();
    const auto& layout = *result;

    EXPECT_EQ(layout.bytes.size(), kGuardPageSize);

    // Entry int3+tag at offset 0.
    EXPECT_EQ(layout.entry_int3_offset, 0u);
    EXPECT_EQ(layout.bytes[0], 0xCCu);
    EXPECT_EQ(read_tag(layout.bytes, layout.entry_int3_offset), guard_id);

    // Body starts right after the entry tag.
    EXPECT_EQ(layout.body_offset, kGuardInt3TagSize);
    EXPECT_EQ(layout.body_size, body.size());
    for (size_t i = 0; i < body.size(); ++i) {
        EXPECT_EQ(layout.bytes[layout.body_offset + i], body[i])
            << "Body byte mismatch at offset " << i;
    }

    // Exit int3+tag right after the body.
    EXPECT_EQ(layout.exit_int3_offset, layout.body_offset + layout.body_size);
    EXPECT_EQ(layout.bytes[layout.exit_int3_offset], 0xCCu);
    EXPECT_EQ(read_tag(layout.bytes, layout.exit_int3_offset), guard_id);

    // Junk fills the remainder.
    EXPECT_EQ(layout.junk_offset, layout.exit_int3_offset + kGuardInt3TagSize);
    EXPECT_LT(layout.junk_offset, kGuardPageSize);
}

// ---------------------------------------------------------------------------
// Determinism — same body + same seed → bit-identical bytes.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, DeterministicForIdenticalSeeds) {
    const std::vector<uint8_t> body(32, 0x90);  // 32 NOPs

    Randomizer rng_a(0xABCD1234u);
    Randomizer rng_b(0xABCD1234u);

    auto a = build_guard_page(ByteView{body.data(), body.size()}, 7u, rng_a);
    auto b = build_guard_page(ByteView{body.data(), body.size()}, 7u, rng_b);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    EXPECT_EQ(a->bytes, b->bytes) << "Deterministic build must be byte-identical";
}

// ---------------------------------------------------------------------------
// Different seed — body + both int3+tag windows stable, junk tail diverges.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, BodyAndTagsStableAcrossSeedsButJunkDiffers) {
    const std::vector<uint8_t> body = {
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xC3,                           // ret fragment — irrelevant bytes
    };

    Randomizer rng_a(0x11111111u);
    Randomizer rng_b(0x22222222u);

    auto a = build_guard_page(ByteView{body.data(), body.size()}, 3u, rng_a);
    auto b = build_guard_page(ByteView{body.data(), body.size()}, 3u, rng_b);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    // The int3+tag windows and the body are RNG-independent.
    const uint32_t prefix_len = a->junk_offset;
    for (uint32_t i = 0; i < prefix_len; ++i) {
        ASSERT_EQ(a->bytes[i], b->bytes[i])
            << "Deterministic region byte mismatch at offset " << i;
    }

    // Junk tail should mostly differ. With a 4085-byte tail and
    // uniform random bytes we expect ~99% different; require >=80%.
    uint32_t differing = 0;
    for (uint32_t i = a->junk_offset; i < kGuardPageSize; ++i) {
        if (a->bytes[i] != b->bytes[i]) ++differing;
    }
    const uint32_t junk_len = kGuardPageSize - a->junk_offset;
    EXPECT_GT(differing * 5u, junk_len * 4u)
        << "Expected >80% of junk bytes to differ between seeds, got "
        << differing << "/" << junk_len;
}

// ---------------------------------------------------------------------------
// Edge — body exactly `page_size - 10` → zero junk, all fields valid.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, ExactFitBodyHasZeroJunkBytes) {
    const uint32_t kMaxBody = kGuardPageSize - 2 * kGuardInt3TagSize;
    const std::vector<uint8_t> body(kMaxBody, 0xAA);

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, 0xDEADBEEFu, rng);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->entry_int3_offset, 0u);
    EXPECT_EQ(result->body_size, kMaxBody);
    EXPECT_EQ(result->exit_int3_offset, kGuardInt3TagSize + kMaxBody);
    EXPECT_EQ(result->junk_offset, kGuardPageSize);

    EXPECT_EQ(result->bytes[result->entry_int3_offset], 0xCCu);
    EXPECT_EQ(result->bytes[result->exit_int3_offset],  0xCCu);
    EXPECT_EQ(read_tag(result->bytes, result->entry_int3_offset), 0xDEADBEEFu);
    EXPECT_EQ(read_tag(result->bytes, result->exit_int3_offset),  0xDEADBEEFu);
}

// ---------------------------------------------------------------------------
// Edge — body one byte too large.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, BodyTooLargeFails) {
    const std::vector<uint8_t> body(
        kGuardPageSize - 2 * kGuardInt3TagSize + 1, 0xAA);

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, 0u, rng);
    ASSERT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Edge — empty body rejected.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, EmptyBodyFails) {
    Randomizer rng;
    auto result = build_guard_page(ByteView{}, 0u, rng);
    ASSERT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Configurable page size — same invariants on a small 64-byte page.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, CustomPageSizePreservesInvariants) {
    const std::vector<uint8_t> body = {0x48, 0x31, 0xC0};  // xor rax, rax
    constexpr uint32_t kSmallPage = 64;

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, 0xCAFEu, rng, kSmallPage);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->bytes.size(), kSmallPage);
    EXPECT_EQ(result->entry_int3_offset, 0u);
    EXPECT_EQ(result->body_offset, kGuardInt3TagSize);
    EXPECT_EQ(result->body_size, body.size());
    EXPECT_EQ(result->exit_int3_offset, kGuardInt3TagSize + body.size());
    EXPECT_EQ(result->junk_offset,
              kGuardInt3TagSize + body.size() + kGuardInt3TagSize);

    for (size_t i = 0; i < body.size(); ++i) {
        EXPECT_EQ(result->bytes[result->body_offset + i], body[i]);
    }
    EXPECT_EQ(result->bytes[result->entry_int3_offset], 0xCCu);
    EXPECT_EQ(result->bytes[result->exit_int3_offset],  0xCCu);
    EXPECT_EQ(read_tag(result->bytes, result->entry_int3_offset), 0xCAFEu);
    EXPECT_EQ(read_tag(result->bytes, result->exit_int3_offset),  0xCAFEu);
}

// ---------------------------------------------------------------------------
// Different guard_ids produce distinct tag bytes for identical bodies.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, DifferentGuardIdsYieldDifferentTags) {
    const std::vector<uint8_t> body = {0x90, 0x90, 0x90};

    Randomizer rng_a(0x42u);
    Randomizer rng_b(0x42u);

    auto a = build_guard_page(ByteView{body.data(), body.size()}, 1u, rng_a);
    auto b = build_guard_page(ByteView{body.data(), body.size()}, 2u, rng_b);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    EXPECT_NE(read_tag(a->bytes, a->entry_int3_offset),
              read_tag(b->bytes, b->entry_int3_offset));
    EXPECT_NE(read_tag(a->bytes, a->exit_int3_offset),
              read_tag(b->bytes, b->exit_int3_offset));

    // Same guard_id within one page is consistent across entry and exit.
    EXPECT_EQ(read_tag(a->bytes, a->entry_int3_offset),
              read_tag(a->bytes, a->exit_int3_offset));
    EXPECT_EQ(read_tag(b->bytes, b->entry_int3_offset),
              read_tag(b->bytes, b->exit_int3_offset));
}

} // namespace
