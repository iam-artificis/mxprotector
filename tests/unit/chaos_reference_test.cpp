/**
 * @file chaos_reference_test.cpp
 * @brief [TESTS] Chaos B.4.1 — `Reference` + `ReferenceTable` +
 *        `RvaRemapper` data-model contract.
 */

#include <gtest/gtest.h>

#include <vector>

#include "mxprotector/pe/chaos/reference.hpp"
#include "mxprotector/pe/chaos/rva_remapper.hpp"

namespace {

using mx::Rva;
using mx::pe::chaos::origin_name;
using mx::pe::chaos::Reference;
using mx::pe::chaos::ReferenceEncoding;
using mx::pe::chaos::ReferenceOrigin;
using mx::pe::chaos::ReferenceTable;
using mx::pe::chaos::ReferenceWidth;
using mx::pe::chaos::RvaChunk;
using mx::pe::chaos::RvaRemapper;

// ---------------------------------------------------------------------------
// ReferenceTable
// ---------------------------------------------------------------------------

TEST(ReferenceTable, EmptyOnConstruction) {
    ReferenceTable t;
    EXPECT_TRUE(t.empty());
    EXPECT_EQ(t.size(), 0u);
    EXPECT_EQ(t.slots().size(), 0u);
}

TEST(ReferenceTable, AddAppendsInOrder) {
    ReferenceTable t;
    Reference a{0x1000u, 0x2000u, ReferenceWidth::byte4,
                ReferenceEncoding::rel,
                ReferenceOrigin::code_branch_or_call};
    Reference b{0x1010u, 0x2010u, ReferenceWidth::byte4,
                ReferenceEncoding::rel,
                ReferenceOrigin::code_rip_relative};
    Reference c{0x4000u, 0x5000u, ReferenceWidth::byte8,
                ReferenceEncoding::absolute_va,
                ReferenceOrigin::reloc_absolute_va};
    t.add(a);
    t.add(b);
    t.add(c);
    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t.slots()[0], a);
    EXPECT_EQ(t.slots()[1], b);
    EXPECT_EQ(t.slots()[2], c);
}

TEST(ReferenceTable, ReserveDoesNotChangeSize) {
    ReferenceTable t;
    t.reserve(64);
    EXPECT_EQ(t.size(), 0u);
}

TEST(Reference, OriginNameStable) {
    EXPECT_EQ(origin_name(ReferenceOrigin::code_branch_or_call), "code-rel");
    EXPECT_EQ(origin_name(ReferenceOrigin::code_rip_relative),   "code-rip");
    EXPECT_EQ(origin_name(ReferenceOrigin::data_directory_entry), "data-dir");
    EXPECT_EQ(origin_name(ReferenceOrigin::entry_point),         "entry");
    EXPECT_EQ(origin_name(ReferenceOrigin::pdata_runtime_function), "pdata");
    EXPECT_EQ(origin_name(ReferenceOrigin::reloc_absolute_va),   "reloc-va");
}

// ---------------------------------------------------------------------------
// RvaRemapper
// ---------------------------------------------------------------------------

TEST(RvaRemapper, EmptyRemapperPassesThrough) {
    RvaRemapper r;
    ASSERT_TRUE(r.finalize());
    EXPECT_EQ(r.remap(0x1000u), 0x1000u);
    EXPECT_EQ(r.remap(0xFFFFu), 0xFFFFu);
    EXPECT_FALSE(r.is_remapped(0x1000u));
    EXPECT_EQ(r.chunk_count(), 0u);
    EXPECT_EQ(r.total_bytes(), 0u);
}

TEST(RvaRemapper, SingleChunkRemapsInside) {
    // [0x1000, 0x1100) → [0x5000, 0x5100)
    RvaRemapper r;
    r.add_chunk(/*old=*/0x1000u, /*new=*/0x5000u, /*size=*/0x100u);
    ASSERT_TRUE(r.finalize());

    EXPECT_TRUE(r.is_remapped(0x1000u));
    EXPECT_TRUE(r.is_remapped(0x10FFu));
    EXPECT_FALSE(r.is_remapped(0x1100u))
        << "RVA at chunk's exclusive end must NOT be remapped";

    EXPECT_EQ(r.remap(0x1000u), 0x5000u);
    EXPECT_EQ(r.remap(0x1010u), 0x5010u);
    EXPECT_EQ(r.remap(0x10FFu), 0x50FFu);
    EXPECT_EQ(r.remap(0x1100u), 0x1100u) << "outside-chunk → identity";
    EXPECT_EQ(r.remap(0x0FFFu), 0x0FFFu) << "below-chunk → identity";

    EXPECT_EQ(r.chunk_count(), 1u);
    EXPECT_EQ(r.total_bytes(), 0x100u);
}

TEST(RvaRemapper, MultipleChunksDistinctMappings) {
    RvaRemapper r;
    r.add_chunk(0x1000u, 0x9000u, 0x100u);
    r.add_chunk(0x2000u, 0x8000u, 0x200u);
    r.add_chunk(0x3000u, 0x7000u, 0x080u);
    ASSERT_TRUE(r.finalize());

    EXPECT_EQ(r.remap(0x1050u), 0x9050u);
    EXPECT_EQ(r.remap(0x2100u), 0x8100u);
    EXPECT_EQ(r.remap(0x303Fu), 0x703Fu);
    EXPECT_EQ(r.remap(0x4000u), 0x4000u);  // gap → identity
    EXPECT_EQ(r.chunk_count(), 3u);
    EXPECT_EQ(r.total_bytes(), 0x100u + 0x200u + 0x080u);
}

TEST(RvaRemapper, OverlapDetectedByFinalize) {
    RvaRemapper r;
    r.add_chunk(0x1000u, 0x5000u, 0x100u);
    r.add_chunk(0x1080u, 0x6000u, 0x100u);  // overlaps with first
    EXPECT_FALSE(r.finalize());
}

TEST(RvaRemapper, AdjacentChunksAreNotOverlap) {
    RvaRemapper r;
    r.add_chunk(0x1000u, 0x5000u, 0x100u);  // covers [0x1000, 0x1100)
    r.add_chunk(0x1100u, 0x6000u, 0x100u);  // covers [0x1100, 0x1200)
    EXPECT_TRUE(r.finalize());
    EXPECT_EQ(r.remap(0x10FFu), 0x50FFu);
    EXPECT_EQ(r.remap(0x1100u), 0x6000u);
}

TEST(RvaRemapper, IdentityMappingChunkIsAllowed) {
    // A chunk that maps to its old location is a valid "no-op" entry.
    // Useful when the planner wants to register every chunk uniformly
    // even if some happen to land at their original RVA.
    RvaRemapper r;
    r.add_chunk(0x1000u, 0x1000u, 0x40u);
    ASSERT_TRUE(r.finalize());
    EXPECT_EQ(r.remap(0x1010u), 0x1010u);
    EXPECT_TRUE(r.is_remapped(0x1010u));
}

} // namespace
