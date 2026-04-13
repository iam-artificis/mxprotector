/**
 * @file vm_stack_layout_test.cpp
 * @brief [TESTS] Unit tests for VmStackLayout (G7 — VM stack randomization).
 *
 * Verifies:
 *   - Layout invariants: every native GPR (except RSP) gets a unique slot,
 *     exactly one slot is the junk slot, slot_to_native and native_to_slot
 *     are mutually consistent.
 *   - Determinism: same RNG seed produces identical layouts.
 *   - Variance: different seeds produce different layouts (statistical
 *     distribution check across many seeds).
 *   - Padding: extra_pad_slots stays in [0, kMaxExtraPadSlots] and at least
 *     two distinct values appear across many seeds.
 *   - Computed offsets: rflags_offset, context_size, native_frame_shift
 *     all agree with the documented formulas.
 */

#include <gtest/gtest.h>

#include <array>
#include <set>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"

namespace {

using mx::Randomizer;
using mx::vm::VmStackLayout;

/// Asserts that a layout is internally consistent: native_to_slot and
/// slot_to_native are mutual inverses on the GPR domain, exactly one
/// slot is the junk slot, RSP is unmapped, and the rolling key disp
/// matches `junk_slot * 8`.
void expect_layout_invariants(const VmStackLayout& L) {
    constexpr uint8_t kSlots = VmStackLayout::kSlotCount;
    constexpr uint8_t kJunk  = VmStackLayout::kJunkMarker;

    // Exactly one junk slot, and slot_to_native[junk_slot] == kJunk.
    int junk_count = 0;
    for (uint8_t v = 0; v < kSlots; ++v) {
        if (L.slot_to_native[v] == kJunk) ++junk_count;
    }
    EXPECT_EQ(junk_count, 1);
    ASSERT_LT(L.junk_slot, kSlots);
    EXPECT_EQ(L.slot_to_native[L.junk_slot], kJunk);

    // RSP (native 4) is never mapped to a slot.
    EXPECT_EQ(L.native_to_slot[4], kJunk);

    // For every non-junk slot, its native reg must round-trip.
    std::set<uint8_t> seen_natives;
    for (uint8_t v = 0; v < kSlots; ++v) {
        if (v == L.junk_slot) continue;
        const uint8_t n = L.slot_to_native[v];
        ASSERT_LT(n, kSlots) << "non-junk slot has invalid native reg";
        EXPECT_NE(n, 4) << "RSP must not appear in any non-junk slot";
        EXPECT_EQ(L.native_to_slot[n], v)
            << "native_to_slot/slot_to_native disagree for slot " << int{v};
        EXPECT_TRUE(seen_natives.insert(n).second)
            << "native reg " << int{n} << " is mapped to two slots";
    }

    // Rolling-key disp must match junk_slot * 8.
    EXPECT_EQ(L.rolling_key_disp,
              static_cast<int32_t>(L.junk_slot) * 8);

    // Padding bound.
    EXPECT_LE(L.extra_pad_slots, VmStackLayout::kMaxExtraPadSlots);
}

TEST(VmStackLayout, BuildsValidLayoutForManySeeds) {
    for (uint64_t seed = 1; seed < 200; ++seed) {
        Randomizer rng(seed);
        const auto L = VmStackLayout::make_random(rng);
        SCOPED_TRACE("seed=" + std::to_string(seed));
        expect_layout_invariants(L);
    }
}

TEST(VmStackLayout, DeterministicForSameSeed) {
    Randomizer rng_a(0xDEADBEEFCAFEBABEULL);
    Randomizer rng_b(0xDEADBEEFCAFEBABEULL);
    const auto a = VmStackLayout::make_random(rng_a);
    const auto b = VmStackLayout::make_random(rng_b);

    EXPECT_EQ(a.slot_to_native, b.slot_to_native);
    EXPECT_EQ(a.native_to_slot, b.native_to_slot);
    EXPECT_EQ(a.junk_slot, b.junk_slot);
    EXPECT_EQ(a.rolling_key_disp, b.rolling_key_disp);
    EXPECT_EQ(a.extra_pad_slots, b.extra_pad_slots);
}

TEST(VmStackLayout, DifferentSeedsProduceDifferentLayouts) {
    // Across 100 seeds we must observe more than one distinct (junk_slot,
    // extra_pad_slots, slot_to_native) triple — otherwise the RNG isn't
    // actually being consumed.
    std::set<std::tuple<uint8_t, uint8_t, std::array<uint8_t, 16>>> distinct;
    for (uint64_t seed = 0; seed < 100; ++seed) {
        Randomizer rng(seed * 0x9E3779B97F4A7C15ULL + 1);
        const auto L = VmStackLayout::make_random(rng);
        distinct.emplace(L.junk_slot, L.extra_pad_slots, L.slot_to_native);
    }
    EXPECT_GT(distinct.size(), 50u)
        << "make_random produced too few distinct layouts";
}

TEST(VmStackLayout, ExtraPadSlotsCoversAllValues) {
    // With 7 possible values and 1000 seeds the chance of any one value
    // not appearing is negligible (≈ (6/7)^1000 ≈ 10^-67).
    std::array<int, VmStackLayout::kMaxExtraPadSlots + 1> hits{};
    for (uint64_t seed = 1; seed <= 1000; ++seed) {
        Randomizer rng(seed * 0xBF58476D1CE4E5B9ULL);
        const auto L = VmStackLayout::make_random(rng);
        ASSERT_LE(L.extra_pad_slots, VmStackLayout::kMaxExtraPadSlots);
        hits[L.extra_pad_slots]++;
    }
    for (size_t i = 0; i < hits.size(); ++i) {
        EXPECT_GT(hits[i], 0)
            << "extra_pad_slots == " << i << " never observed";
    }
}

TEST(VmStackLayout, ComputedOffsetsMatchBaselineWhenNoPadding) {
    VmStackLayout L{};
    L.extra_pad_slots = 0;
    EXPECT_EQ(L.pad_area_size(), 0);
    EXPECT_EQ(L.rflags_offset(),     VmStackLayout::kBaseRflagsOffset);
    EXPECT_EQ(L.context_size(),      VmStackLayout::kBaseContextSize);
    EXPECT_EQ(L.native_frame_shift(), VmStackLayout::kBaseNativeShift);
}

TEST(VmStackLayout, ComputedOffsetsScaleWithPadding) {
    for (uint8_t p = 0; p <= VmStackLayout::kMaxExtraPadSlots; ++p) {
        VmStackLayout L{};
        L.extra_pad_slots = p;
        const int32_t pad_bytes = static_cast<int32_t>(p) * 8;
        EXPECT_EQ(L.pad_area_size(),      pad_bytes);
        EXPECT_EQ(L.rflags_offset(),
                  VmStackLayout::kBaseRflagsOffset + pad_bytes);
        EXPECT_EQ(L.context_size(),
                  VmStackLayout::kBaseContextSize + pad_bytes);
        EXPECT_EQ(L.native_frame_shift(),
                  VmStackLayout::kBaseNativeShift + pad_bytes);
    }
}

TEST(VmStackLayout, RollingKeyDispFitsInDisp8) {
    // Rolling key disp == junk_slot * 8, max 15*8 = 120 → fits in i8.
    for (uint64_t seed = 1; seed < 500; ++seed) {
        Randomizer rng(seed);
        const auto L = VmStackLayout::make_random(rng);
        ASSERT_GE(L.rolling_key_disp, 0);
        ASSERT_LE(L.rolling_key_disp, 120);
    }
}

TEST(VmStackLayout, NativeFrameShiftEnvelope) {
    // Even at max padding, the native frame shift stays comfortably
    // within disp32 range used by `lea rsp, [rsp + disp32]`.
    constexpr int32_t kMaxExpected =
        VmStackLayout::kBaseNativeShift +
        VmStackLayout::kMaxExtraPadSlots * 8;
    EXPECT_EQ(kMaxExpected, 168 + 56);
    EXPECT_LT(kMaxExpected, 0x7FFFFFFF);
}

} // namespace
