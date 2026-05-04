/**
 * @file refmap_reference_overlap_filter_test.cpp
 * @brief Tests for `ReferenceOverlapFilter` (B.4.21).
 *
 * Pins the contract documented in
 * `reference_overlap_filter.hpp`:
 *
 *   1. Hard references (any encoding other than `rel`) are kept
 *      verbatim — these are the structurally-decoded slots whose
 *      byte boundaries are authoritative.
 *   2. Soft references (`rel` encoding emitted by `CodeReferenceScanner`)
 *      survive iff their byte range does NOT overlap any hard slot.
 *   3. Soft references emitted by other origins (e.g. structural
 *      walkers that happen to use the `rel` encoding) survive even
 *      when their byte range overlaps a hard slot — they are
 *      authoritative for that slot.
 *   4. Order of surviving references matches input order.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

#include "mxprotector/pe/data_region.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_overlap_filter.hpp"

namespace {

using mx::Rva;
using mx::pe::refmap::OverlapFilterStats;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferenceOverlapFilter;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;

// ---------------------------------------------------------------------------
// Helpers — keep tests focused on intent, not on Reference field plumbing.
// ---------------------------------------------------------------------------

[[nodiscard]] Reference make_soft_rel32(Rva loc, Rva tgt) {
    return Reference{
        .location_rva = loc,
        .target_rva   = tgt,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_branch_or_call,
    };
}

[[nodiscard]] Reference make_soft_riprel32(Rva loc, Rva tgt) {
    return Reference{
        .location_rva = loc,
        .target_rva   = tgt,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_rip_relative,
    };
}

[[nodiscard]] Reference make_jt_xor(Rva loc, Rva tgt) {
    return Reference{
        .location_rva = loc,
        .target_rva   = tgt,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::xor_encoded_signed_delta_imm32,
        .origin       = ReferenceOrigin::obfuscated_jt_entry,
    };
}

[[nodiscard]] Reference make_callpop(Rva loc, Rva tgt) {
    return Reference{
        .location_rva = loc,
        .target_rva   = tgt,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel32_call_pop_anchored,
        .origin       = ReferenceOrigin::vm_call_pop_trampoline,
    };
}

[[nodiscard]] Reference make_pdata_rva(Rva loc, Rva tgt) {
    return Reference{
        .location_rva = loc,
        .target_rva   = tgt,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::pdata_runtime_function,
    };
}

// ---------------------------------------------------------------------------
// Empty / trivial cases
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, EmptyTableReturnsEmpty) {
    ReferenceTable input;
    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 0u);
    EXPECT_EQ(stats.total, 0u);
    EXPECT_EQ(stats.hard_kept, 0u);
    EXPECT_EQ(stats.soft_kept, 0u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

TEST(ReferenceOverlapFilter, OnlySoftRefsAllSurvive) {
    ReferenceTable input;
    input.add(make_soft_rel32(0x1000, 0x2000));
    input.add(make_soft_rel32(0x1010, 0x2010));
    input.add(make_soft_riprel32(0x1020, 0x2020));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 3u);
    EXPECT_EQ(stats.soft_kept, 3u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

TEST(ReferenceOverlapFilter, OnlyHardRefsAllSurvive) {
    ReferenceTable input;
    input.add(make_jt_xor(0x1000, 0x2000));
    input.add(make_callpop(0x1010, 0x2010));
    input.add(make_pdata_rva(0x1020, 0x2020));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 3u);
    EXPECT_EQ(stats.hard_kept, 3u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

// ---------------------------------------------------------------------------
// Overlap drop — the bug B.4.21 fixes
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, SoftRefAtSameRvaAsJtSlotIsDropped) {
    ReferenceTable input;
    input.add(make_soft_rel32(0x1000, 0xDEAD));
    input.add(make_jt_xor(0x1000, 0xCAFE));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 1u);
    EXPECT_EQ(out.slots()[0].encoding,
              ReferenceEncoding::xor_encoded_signed_delta_imm32);
    EXPECT_EQ(stats.hard_kept, 1u);
    EXPECT_EQ(stats.soft_dropped, 1u);
}

TEST(ReferenceOverlapFilter, SoftRefThatStraddlesTwoJtSlotsIsDropped) {
    // JT entries at 0x1000 and 0x1004 (4 bytes each).
    // Soft ref at 0x1002 width 4 → bytes [0x1002, 0x1006), overlaps both.
    ReferenceTable input;
    input.add(make_jt_xor(0x1000, 0xCAFE));
    input.add(make_jt_xor(0x1004, 0xBEEF));
    input.add(make_soft_rel32(0x1002, 0xDEAD));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(stats.soft_dropped, 1u);
}

TEST(ReferenceOverlapFilter, SoftRefAdjacentToHardSlotSurvives) {
    // JT slot at 0x1000-0x1004; soft ref at 0x1004 width 4 starts where
    // the JT ends — half-open ranges do NOT overlap.
    ReferenceTable input;
    input.add(make_jt_xor(0x1000, 0xCAFE));
    input.add(make_soft_rel32(0x1004, 0xDEAD));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

TEST(ReferenceOverlapFilter, SoftRefBeforeHardSlotSurvives) {
    ReferenceTable input;
    input.add(make_soft_rel32(0x0FFC, 0xDEAD));  // ends at 0x1000
    input.add(make_jt_xor(0x1000, 0xCAFE));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

// ---------------------------------------------------------------------------
// Origin gating — only code-scanner-origin soft refs are dropped
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, NonCodeOriginSoftRefAtJtSlotSurvives) {
    // A `rel`-encoded reference whose origin is NOT `code_branch_or_call`
    // / `code_rip_relative` is emitted by a structural walker; it is
    // authoritative even at a hard-slot RVA. (No real scanner emits
    // this combination today; the test pins forward-compatibility.)
    Reference structural_rel{
        .location_rva = 0x1000,
        .target_rva   = 0xDEAD,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::pdata_runtime_function,
    };
    ReferenceTable input;
    input.add(structural_rel);
    input.add(make_jt_xor(0x1000, 0xCAFE));

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(stats.soft_dropped, 0u);
    EXPECT_EQ(stats.soft_kept, 1u);
}

// ---------------------------------------------------------------------------
// Order preservation
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, OrderOfSurvivorsMatchesInputOrder) {
    ReferenceTable input;
    input.add(make_soft_rel32(0x1000, 0xDEAD));      // dropped (overlaps JT@1000)
    input.add(make_jt_xor(0x1000, 0xCAFE));          // kept
    input.add(make_soft_rel32(0x2000, 0xDEAD));      // kept (no overlap)
    input.add(make_callpop(0x3000, 0xBEEF));         // kept
    input.add(make_soft_riprel32(0x3001, 0xDEAD));   // dropped (overlaps callpop)

    auto out = ReferenceOverlapFilter{}.filter(input);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out.slots()[0].encoding,
              ReferenceEncoding::xor_encoded_signed_delta_imm32);
    EXPECT_EQ(out.slots()[1].location_rva, 0x2000u);
    EXPECT_EQ(out.slots()[2].encoding,
              ReferenceEncoding::rel32_call_pop_anchored);
}

// ---------------------------------------------------------------------------
// Data regions — the second source the filter has to police
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, SoftRefInsideDataRegionIsDropped) {
    // Simulate a VM bytecode region at [0x10000, 0x12000). A bogus
    // soft ref at 0x10800 width 4 lands inside.
    ReferenceTable input;
    input.add(make_soft_rel32(0x10800, 0xDEAD));

    mx::pe::DataRegion bytecode{
        .begin_rva = 0x10000,
        .size      = 0x2000,
        .kind      = mx::pe::DataRegionKind::vm_bytecode,
    };
    std::array<mx::pe::DataRegion, 1> regions{bytecode};

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(
        input, std::span{regions}, &stats);
    EXPECT_EQ(out.size(), 0u);
    EXPECT_EQ(stats.soft_dropped_in_data_region, 1u);
    EXPECT_EQ(stats.soft_dropped, 0u);
}

TEST(ReferenceOverlapFilter, SoftRefStraddlingDataRegionEdgeIsDropped) {
    // Soft ref at end-2 of region; bytes [end-2, end+2) — overlaps.
    ReferenceTable input;
    input.add(make_soft_rel32(0x11FFE, 0xDEAD));

    mx::pe::DataRegion bytecode{
        .begin_rva = 0x10000,
        .size      = 0x2000,
        .kind      = mx::pe::DataRegionKind::vm_bytecode,
    };
    std::array<mx::pe::DataRegion, 1> regions{bytecode};

    auto out = ReferenceOverlapFilter{}.filter(input, std::span{regions});
    EXPECT_EQ(out.size(), 0u);
}

TEST(ReferenceOverlapFilter, SoftRefAdjacentToDataRegionSurvives) {
    // Soft ref at end-of-region (half-open). Bytes [end, end+4)
    // do NOT overlap [begin, end).
    ReferenceTable input;
    input.add(make_soft_rel32(0x12000, 0xDEAD));

    mx::pe::DataRegion bytecode{
        .begin_rva = 0x10000,
        .size      = 0x2000,
        .kind      = mx::pe::DataRegionKind::vm_bytecode,
    };
    std::array<mx::pe::DataRegion, 1> regions{bytecode};

    auto out = ReferenceOverlapFilter{}.filter(input, std::span{regions});
    EXPECT_EQ(out.size(), 1u);
}

TEST(ReferenceOverlapFilter, MultipleDataRegionsCoverNonContiguous) {
    // Bytecode A at [0x10000..0x10100), bytecode B at [0x20000..0x20100).
    // Soft refs in each region drop; ref between them survives.
    ReferenceTable input;
    input.add(make_soft_rel32(0x10080, 0xDEAD));   // dropped (in A)
    input.add(make_soft_rel32(0x18000, 0xCAFE));   // kept (between)
    input.add(make_soft_rel32(0x20080, 0xBEEF));   // dropped (in B)

    std::array<mx::pe::DataRegion, 2> regions{
        mx::pe::DataRegion{.begin_rva = 0x10000, .size = 0x100,
                            .kind = mx::pe::DataRegionKind::vm_bytecode},
        mx::pe::DataRegion{.begin_rva = 0x20000, .size = 0x100,
                            .kind = mx::pe::DataRegionKind::vm_handler_table},
    };

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(
        input, std::span{regions}, &stats);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out.slots()[0].location_rva, 0x18000u);
    EXPECT_EQ(stats.soft_dropped_in_data_region, 2u);
}

// ---------------------------------------------------------------------------
// Stress: many JT slots + many code refs, only overlapping ones drop.
// ---------------------------------------------------------------------------

TEST(ReferenceOverlapFilter, ManyJtSlotsManyCodeRefs) {
    // 100 JT slots back-to-back: [0x10000, 0x10000 + 100*4).
    ReferenceTable input;
    for (std::uint32_t i = 0; i < 100; ++i) {
        input.add(make_jt_xor(0x10000 + i * 4, 0x20000 + i));
    }
    // 50 soft refs that overlap (inside the JT region).
    for (std::uint32_t i = 0; i < 50; ++i) {
        input.add(make_soft_rel32(0x10000 + i * 8 + 2, 0xDEAD));
    }
    // 50 soft refs OUTSIDE the JT region.
    for (std::uint32_t i = 0; i < 50; ++i) {
        input.add(make_soft_rel32(0x30000 + i * 8, 0xCAFE));
    }

    OverlapFilterStats stats{};
    auto out = ReferenceOverlapFilter{}.filter(input, /*data_regions=*/{}, &stats);
    EXPECT_EQ(stats.hard_kept, 100u);
    EXPECT_EQ(stats.soft_kept, 50u);
    EXPECT_EQ(stats.soft_dropped, 50u);
    EXPECT_EQ(out.size(), 150u);
}

} // namespace
