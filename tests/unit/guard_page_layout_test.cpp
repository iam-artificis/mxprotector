/**
 * @file guard_page_layout_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::build_guard_page`.
 *
 * The page builder is a pure function — same inputs yield byte-for-byte
 * identical outputs — so the tests pin down the exact layout contract
 * that Commit 2 of the runtime-guards milestone relies on. Future
 * commits will reshape this layout (plaintext int3+tag windows,
 * encrypted tail), and the tests here are the tripwire that warns us
 * about an accidental change before downstream code notices the new
 * offsets.
 *
 * Covered behaviours:
 *   * Happy path for a tiny body: size, body placement, exit-jump
 *     placeholder, junk offset.
 *   * Determinism: identical body + identical seed → identical bytes.
 *   * Different seed: identical body + different seed → identical
 *     body prefix and exit jump, different junk tail.
 *   * Edge case: body exactly `page_size - 5` — zero junk bytes but
 *     still succeeds, all fields valid.
 *   * Edge case: body `page_size - 4` — fails with a clear error
 *     (body + exit jmp would overflow).
 *   * Edge case: empty body fails (nothing to relocate).
 *   * Configurable `page_size` override keeps all invariants intact
 *     on a non-standard small page (useful for tests without
 *     allocating 4 KiB).
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
using mx::guard::kGuardPageSize;

/// Single-byte helper: true iff `buf[offset .. offset+4]` is exactly
/// `E9 00 00 00 00`, which is the placeholder `jmp rel32 0` emitted
/// by `build_guard_page` before `GuardPass::apply_exit_jump` patches
/// the rel32.
[[nodiscard]] bool is_exit_jmp_placeholder(
    const ByteBuffer& buf, uint32_t offset)
{
    if (offset + 5 > buf.size()) return false;
    return buf[offset + 0] == 0xE9u &&
           buf[offset + 1] == 0x00u &&
           buf[offset + 2] == 0x00u &&
           buf[offset + 3] == 0x00u &&
           buf[offset + 4] == 0x00u;
}

// ---------------------------------------------------------------------------
// Happy-path: tiny body on a default 4 KiB page.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, HappyPathTinyBody) {
    const std::vector<uint8_t> body = {
        0x48, 0x89, 0xC1,        // mov rcx, rax
        0x48, 0x01, 0xC8,        // add rax, rcx
        0x48, 0x31, 0xD2,        // xor rdx, rdx
    };

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, rng);
    ASSERT_TRUE(result.has_value()) << result.error().format();
    const auto& layout = *result;

    EXPECT_EQ(layout.bytes.size(), kGuardPageSize);
    EXPECT_EQ(layout.body_offset, 0u);
    EXPECT_EQ(layout.body_size, body.size());

    // Body is placed verbatim at the start of the page.
    for (size_t i = 0; i < body.size(); ++i) {
        EXPECT_EQ(layout.bytes[i], body[i])
            << "Body byte mismatch at offset " << i;
    }

    // Exit jmp rel32 sits right after the body.
    EXPECT_EQ(layout.exit_jmp_offset, body.size());
    EXPECT_TRUE(is_exit_jmp_placeholder(layout.bytes, layout.exit_jmp_offset));

    // Junk fills the remainder.
    EXPECT_EQ(layout.junk_offset, body.size() + 5);
    EXPECT_LT(layout.junk_offset, kGuardPageSize);
}

// ---------------------------------------------------------------------------
// Determinism: same body + same seed → bit-identical pages.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, DeterministicForIdenticalSeeds) {
    const std::vector<uint8_t> body(32, 0x90);  // 32 NOPs

    Randomizer rng_a(0xABCD1234u);
    Randomizer rng_b(0xABCD1234u);

    auto a = build_guard_page(ByteView{body.data(), body.size()}, rng_a);
    auto b = build_guard_page(ByteView{body.data(), body.size()}, rng_b);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    EXPECT_EQ(a->bytes, b->bytes) << "Deterministic build must be byte-identical";
}

// ---------------------------------------------------------------------------
// Different seed: body + exit jmp stay identical, junk tail diverges.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, BodyAndExitStableAcrossSeedsButJunkDiffers) {
    const std::vector<uint8_t> body = {
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xC3,                           // ret  (would-be fragment — irrelevant)
    };

    Randomizer rng_a(0x11111111u);
    Randomizer rng_b(0x22222222u);

    auto a = build_guard_page(ByteView{body.data(), body.size()}, rng_a);
    auto b = build_guard_page(ByteView{body.data(), body.size()}, rng_b);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());

    // Body and exit jmp slots must match regardless of RNG state.
    const uint32_t prefix_len = a->junk_offset;
    for (uint32_t i = 0; i < prefix_len; ++i) {
        ASSERT_EQ(a->bytes[i], b->bytes[i])
            << "Deterministic region mismatch at offset " << i;
    }

    // At least a majority of the junk tail bytes should differ.
    // A random draw of 4085 bytes with a 256-symbol alphabet has a
    // ~0.4% collision per byte, so we expect well over 99% of bytes
    // to differ. We require >= 80% to avoid flakiness on short tails
    // while still detecting an accidental shared-state bug.
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
// Edge case: body fills the page exactly minus the 5-byte exit jump.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, ExactFitBodyHasZeroJunkBytes) {
    const uint32_t kMaxBody = kGuardPageSize - 5;
    const std::vector<uint8_t> body(kMaxBody, 0xAA);

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, rng);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->body_size, kMaxBody);
    EXPECT_EQ(result->exit_jmp_offset, kMaxBody);
    EXPECT_EQ(result->junk_offset, kGuardPageSize);
    EXPECT_TRUE(is_exit_jmp_placeholder(
        result->bytes, result->exit_jmp_offset));
}

// ---------------------------------------------------------------------------
// Edge case: body too large by one byte → error.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, BodyTooLargeFails) {
    const std::vector<uint8_t> body(kGuardPageSize - 4, 0xAA);

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, rng);
    ASSERT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Edge case: empty body rejected.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, EmptyBodyFails) {
    Randomizer rng;
    auto result = build_guard_page(ByteView{}, rng);
    ASSERT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Configurable page size: same invariants on a small 64-byte page.
// ---------------------------------------------------------------------------

TEST(GuardPageLayout, CustomPageSizePreservesInvariants) {
    const std::vector<uint8_t> body = {0x48, 0x31, 0xC0};  // xor rax, rax
    constexpr uint32_t kSmallPage = 64;

    Randomizer rng;
    auto result = build_guard_page(
        ByteView{body.data(), body.size()}, rng, kSmallPage);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->bytes.size(), kSmallPage);
    EXPECT_EQ(result->body_offset, 0u);
    EXPECT_EQ(result->body_size, body.size());
    for (size_t i = 0; i < body.size(); ++i) {
        EXPECT_EQ(result->bytes[i], body[i]);
    }
    EXPECT_EQ(result->exit_jmp_offset, body.size());
    EXPECT_TRUE(is_exit_jmp_placeholder(
        result->bytes, result->exit_jmp_offset));
    EXPECT_EQ(result->junk_offset, body.size() + 5);
}

} // namespace
