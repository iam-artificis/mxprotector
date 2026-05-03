/**
 * @file chaos_shuffler_test.cpp
 * @brief [TESTS] B.4.7 — `apply_chunk_shuffle` byte-mover contract.
 */

#include <gtest/gtest.h>

#include <vector>

#include "mxprotector/pe/chaos/chaos_shuffler.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace {

using mx::ByteBuffer;
using mx::Rva;
using mx::pe::chaos::apply_chunk_shuffle;
using mx::pe::refmap::RvaRemapper;

// ---------------------------------------------------------------------------
// Single chunk move
// ---------------------------------------------------------------------------

TEST(ChaosShuffler, SingleChunkMovesBytes) {
    // Buffer at base RVA 0x1000, length 0x100.
    // Chunk 0x1000-0x1010 (16 bytes) → 0x1080.
    ByteBuffer buf(0x100, 0);
    for (std::size_t i = 0; i < 0x10; ++i) buf[i] = 0xAA;

    RvaRemapper r;
    r.add_chunk(/*old=*/0x1000, /*new=*/0x1080, /*size=*/0x10);
    ASSERT_TRUE(r.finalize());

    apply_chunk_shuffle(buf, /*base=*/0x1000, r);

    // Bytes [0x80, 0x90) now hold 0xAA.
    for (std::size_t i = 0x80; i < 0x90; ++i) {
        EXPECT_EQ(buf[i], 0xAA) << "byte " << i << " not moved";
    }
    // Bytes [0, 0x10) — were the chunk's source — are NOT cleared
    // (the shuffler does not zero source bytes; whoever lands there
    // via a swapped chunk overwrites it). With only one chunk, the
    // source bytes stay as 0xAA — this is OK because they're the
    // SAME bytes; nothing got destroyed.
}

// ---------------------------------------------------------------------------
// Two-chunk swap
// ---------------------------------------------------------------------------

TEST(ChaosShuffler, TwoChunkSwap) {
    // Buffer 0x100 bytes at base 0x1000.
    // Chunk A: 0x1000-0x1010 of 0xAA.
    // Chunk B: 0x1080-0x1090 of 0xBB.
    // Swap: A → 0x1080, B → 0x1000.
    ByteBuffer buf(0x100, 0);
    for (std::size_t i = 0;    i < 0x10; ++i) buf[i] = 0xAA;
    for (std::size_t i = 0x80; i < 0x90; ++i) buf[i] = 0xBB;

    RvaRemapper r;
    r.add_chunk(0x1000, 0x1080, 0x10);
    r.add_chunk(0x1080, 0x1000, 0x10);
    ASSERT_TRUE(r.finalize());

    apply_chunk_shuffle(buf, 0x1000, r);

    // After swap, [0, 0x10) holds B's bytes (0xBB), [0x80, 0x90)
    // holds A's bytes (0xAA).
    for (std::size_t i = 0;    i < 0x10; ++i) EXPECT_EQ(buf[i], 0xBB);
    for (std::size_t i = 0x80; i < 0x90; ++i) EXPECT_EQ(buf[i], 0xAA);
}

// ---------------------------------------------------------------------------
// Pinned bytes are untouched
// ---------------------------------------------------------------------------

TEST(ChaosShuffler, PinnedBytesUntouched) {
    // Buffer 0x100. Chunk swap covers only [0..0x10) ↔ [0x80..0x90).
    // Bytes at [0x40..0x50) are pinned (not in remapper).
    ByteBuffer buf(0x100, 0);
    for (std::size_t i = 0;    i < 0x10; ++i) buf[i] = 0xAA;
    for (std::size_t i = 0x40; i < 0x50; ++i) buf[i] = 0xCC;
    for (std::size_t i = 0x80; i < 0x90; ++i) buf[i] = 0xBB;

    RvaRemapper r;
    r.add_chunk(0x1000, 0x1080, 0x10);
    r.add_chunk(0x1080, 0x1000, 0x10);
    ASSERT_TRUE(r.finalize());

    apply_chunk_shuffle(buf, 0x1000, r);

    for (std::size_t i = 0x40; i < 0x50; ++i) {
        EXPECT_EQ(buf[i], 0xCC) << "pinned byte " << i
            << " was modified by the shuffle";
    }
}

// ---------------------------------------------------------------------------
// Empty remapper is no-op
// ---------------------------------------------------------------------------

TEST(ChaosShuffler, EmptyRemapperIsNoOp) {
    ByteBuffer buf(0x40, 0xEE);
    RvaRemapper r;
    ASSERT_TRUE(r.finalize());
    apply_chunk_shuffle(buf, 0x1000, r);
    for (auto b : buf) EXPECT_EQ(b, 0xEE);
}

// ---------------------------------------------------------------------------
// Three-chunk cyclic permutation
// ---------------------------------------------------------------------------

TEST(ChaosShuffler, ThreeChunkCycle) {
    // A → B's slot, B → C's slot, C → A's slot. The snapshot-based
    // implementation must avoid order-dependent overwrites.
    ByteBuffer buf(0x100, 0);
    for (std::size_t i = 0;    i < 0x10; ++i) buf[i] = 0xA1;
    for (std::size_t i = 0x40; i < 0x50; ++i) buf[i] = 0xB2;
    for (std::size_t i = 0x80; i < 0x90; ++i) buf[i] = 0xC3;

    RvaRemapper r;
    r.add_chunk(0x1000, 0x1040, 0x10);  // A → B's old slot
    r.add_chunk(0x1040, 0x1080, 0x10);  // B → C's old slot
    r.add_chunk(0x1080, 0x1000, 0x10);  // C → A's old slot
    ASSERT_TRUE(r.finalize());

    apply_chunk_shuffle(buf, 0x1000, r);

    // After cycle: [0..0x10) is C, [0x40..0x50) is A, [0x80..0x90) is B.
    for (std::size_t i = 0;    i < 0x10; ++i) EXPECT_EQ(buf[i],     0xC3);
    for (std::size_t i = 0x40; i < 0x50; ++i) EXPECT_EQ(buf[i],     0xA1);
    for (std::size_t i = 0x80; i < 0x90; ++i) EXPECT_EQ(buf[i],     0xB2);
}

} // namespace
