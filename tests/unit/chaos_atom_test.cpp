/**
 * @file chaos_atom_test.cpp
 * @brief [TESTS] B.4.9.1 — `AtomTable::normalize` contract.
 *
 * Five invariants:
 *   1. Empty table normalises to empty.
 *   2. Single atom normalises to itself.
 *   3. Two non-overlapping atoms keep their distinct ranges, sorted
 *      by start_rva.
 *   4. Two overlapping atoms merge into one covering the union;
 *      first-input origin survives.
 *   5. Adjacent atoms (`A.end_rva == B.start_rva`) merge — the rule
 *      is `B.start_rva < A.end_rva`, so adjacency is NOT a merge
 *      trigger and we test the boundary explicitly.
 */

#include <gtest/gtest.h>

#include "mxprotector/pe/chaos/atom.hpp"

namespace {

using mx::pe::chaos::Atom;
using mx::pe::chaos::AtomOrigin;
using mx::pe::chaos::AtomTable;

// ---------------------------------------------------------------------------
// Empty / single
// ---------------------------------------------------------------------------

TEST(AtomTableNormalize, EmptyTableStaysEmpty) {
    AtomTable t;
    t.normalize();
    EXPECT_EQ(t.size(), 0u);
}

TEST(AtomTableNormalize, SingleAtomSurvives) {
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.normalize();
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      16u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::instruction);
}

TEST(AtomTableNormalize, ZeroSizeAtomDropped) {
    AtomTable t;
    t.add(Atom{0x1000, 0, AtomOrigin::instruction});
    t.add(Atom{0x2000, 4, AtomOrigin::ascii_string});
    t.normalize();
    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x2000u);
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------

TEST(AtomTableNormalize, OutOfOrderInputSorted) {
    AtomTable t;
    t.add(Atom{0x3000, 4, AtomOrigin::ascii_string});
    t.add(Atom{0x1000, 4, AtomOrigin::instruction});
    t.add(Atom{0x2000, 4, AtomOrigin::import_thunk});
    t.normalize();
    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[1].start_rva, 0x2000u);
    EXPECT_EQ(t.atoms()[2].start_rva, 0x3000u);
}

// ---------------------------------------------------------------------------
// Overlap merge
// ---------------------------------------------------------------------------

TEST(AtomTableNormalize, OverlappingAtomsMergeKeepFirstOrigin) {
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.add(Atom{0x1008, 16, AtomOrigin::ascii_string}); // overlaps at 0x1008
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      24u) << "0x1000..0x1018 = 24 B";
    EXPECT_EQ(t.atoms()[0].origin, AtomOrigin::instruction)
        << "first-input origin survives the merge";
}

TEST(AtomTableNormalize, FullyContainedAtomMergedAway) {
    AtomTable t;
    t.add(Atom{0x1000, 32, AtomOrigin::instruction});
    t.add(Atom{0x1010,  4, AtomOrigin::reloc_pointer_slot});
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      32u);
    EXPECT_EQ(t.atoms()[0].origin,    AtomOrigin::instruction);
}

TEST(AtomTableNormalize, ChainOfOverlapsCollapsesToOne) {
    AtomTable t;
    t.add(Atom{0x1000,  8, AtomOrigin::instruction});
    t.add(Atom{0x1004,  8, AtomOrigin::instruction});
    t.add(Atom{0x1008,  8, AtomOrigin::instruction});
    t.add(Atom{0x100C,  8, AtomOrigin::instruction});
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[0].size,      20u) << "0x1000..0x1014";
}

// ---------------------------------------------------------------------------
// Adjacency boundary
// ---------------------------------------------------------------------------

TEST(AtomTableNormalize, AdjacentAtomsStaySeparate) {
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.add(Atom{0x1010, 16, AtomOrigin::ascii_string});
    t.normalize();

    ASSERT_EQ(t.size(), 2u) << "0x1010 == 0x1000 + 16, no overlap";
    EXPECT_EQ(t.atoms()[0].start_rva, 0x1000u);
    EXPECT_EQ(t.atoms()[1].start_rva, 0x1010u);
}

TEST(AtomTableNormalize, OneByteOverlapTriggersMerge) {
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.add(Atom{0x100F, 16, AtomOrigin::ascii_string}); // overlap at last byte
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].size, 31u) << "merged span 0x1000..0x101F";
}

// ---------------------------------------------------------------------------
// Origin name lookup
// ---------------------------------------------------------------------------

TEST(AtomOriginName, AllVariantsHaveDistinctNames) {
    using mx::pe::chaos::atom_origin_name;
    EXPECT_EQ(atom_origin_name(AtomOrigin::pe_header),         "pe-header");
    EXPECT_EQ(atom_origin_name(AtomOrigin::instruction),       "insn");
    EXPECT_EQ(atom_origin_name(AtomOrigin::ascii_string),      "ascii");
    EXPECT_EQ(atom_origin_name(AtomOrigin::import_descriptor), "imp-desc");
    EXPECT_EQ(atom_origin_name(AtomOrigin::tls_directory),     "tls-dir");
    EXPECT_EQ(atom_origin_name(AtomOrigin::resource_data_entry),
                                                                "rsrc-data");
}

// ---------------------------------------------------------------------------
// B.4.10.1 — alignment policy
// ---------------------------------------------------------------------------

TEST(AtomAlignment, MovableOriginsHaveAlignmentOne) {
    using mx::pe::chaos::default_alignment_for;
    EXPECT_EQ(default_alignment_for(AtomOrigin::instruction),           1);
    EXPECT_EQ(default_alignment_for(AtomOrigin::instruction_undecoded), 1);
    EXPECT_EQ(default_alignment_for(AtomOrigin::ascii_string),          1);
    EXPECT_EQ(default_alignment_for(AtomOrigin::import_by_name),        1);
}

TEST(AtomAlignment, PinnedStructuresHaveAlignmentEight) {
    using mx::pe::chaos::default_alignment_for;
    EXPECT_EQ(default_alignment_for(AtomOrigin::tls_directory),        8);
    EXPECT_EQ(default_alignment_for(AtomOrigin::tls_callback_array),   8);
    EXPECT_EQ(default_alignment_for(AtomOrigin::import_thunk),         8);
    EXPECT_EQ(default_alignment_for(AtomOrigin::reloc_pointer_slot),   8);
    EXPECT_EQ(default_alignment_for(AtomOrigin::load_config_directory), 8);
}

TEST(AtomAlignment, IsPinnedReturnsTrueForAlignmentAboveOne) {
    Atom a{0x1000, 8, AtomOrigin::tls_directory, /*alignment=*/8};
    Atom b{0x2000, 8, AtomOrigin::instruction,   /*alignment=*/1};
    EXPECT_TRUE(a.is_pinned());
    EXPECT_FALSE(b.is_pinned());
}

TEST(AtomTableNormalize, OriginPolicyAlignmentApplied) {
    // Source emits atoms without setting alignment — normalize must
    // raise each to the origin's policy default.
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.add(Atom{0x2000,  8, AtomOrigin::tls_directory});
    t.add(Atom{0x3000,  8, AtomOrigin::import_thunk});
    t.normalize();

    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t.atoms()[0].alignment, 1u) << "instruction → movable";
    EXPECT_EQ(t.atoms()[1].alignment, 8u) << "tls_directory → pinned";
    EXPECT_EQ(t.atoms()[2].alignment, 8u) << "import_thunk → pinned";
}

TEST(AtomTableNormalize, MergedAlignmentTakesMaximumOfInputs) {
    // Movable + pinned that overlap → merged atom must stay pinned
    // (alignment = max of inputs after policy floor applied).
    AtomTable t;
    t.add(Atom{0x1000, 16, AtomOrigin::instruction});
    t.add(Atom{0x1008,  8, AtomOrigin::tls_directory});  // overlaps
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_TRUE(t.atoms()[0].is_pinned())
        << "movable + pinned overlap → pinned";
    EXPECT_EQ(t.atoms()[0].alignment, 8u);
}

TEST(AtomTableNormalize, ExplicitAlignmentNotLoweredByPolicyFloor) {
    // Source explicitly raises alignment past the origin's default —
    // normalize() must not lower it.
    AtomTable t;
    Atom big_aligned{0x1000, 16, AtomOrigin::instruction, /*alignment=*/16};
    t.add(big_aligned);
    t.normalize();

    ASSERT_EQ(t.size(), 1u);
    EXPECT_EQ(t.atoms()[0].alignment, 16u);
}

} // namespace
