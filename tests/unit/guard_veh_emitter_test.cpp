/**
 * @file guard_veh_emitter_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::emit_guard_veh_handler`.
 *
 * Commit 7 adds a per-build random tail of 0..`kGuardVehMaxTailJunk`
 * bytes after the handler's final `ret`, so the handler is no longer
 * byte-identical across emitter invocations with different RNG
 * seeds. The tests still pin down structural invariants — the body
 * is deterministic given a fixed seed, only the tail varies.
 *
 * Covered invariants:
 *   * Size envelope (230 core + 0..8 random tail).
 *   * Prologue pushes rbx/rbp/rsi/rdi.
 *   * ExceptionCode fall-through bailout tail.
 *   * `LOCK XADD` appears twice (entry/exit refcount).
 *   * Decrypt loop's `movzx eax, byte [rsi + r9 + 0x18]` key read.
 *   * HW breakpoint sweep (Dr0 read + Dr1/Dr2/Dr3 ORs + test/jnz).
 *   * 64-byte descriptor stride.
 *   * Patch-slot offsets point at zero placeholders.
 *   * Module-base lea + sub shape.
 *   * Determinism: same seed → bit-identical.
 *   * Polymorphism: two different seeds produce either different
 *     lengths or different trailing bytes.
 *   * Patch offsets are handler-local (not emitter-global).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

namespace {

using mx::ByteBuffer;
using mx::Randomizer;
using mx::RawEmitter;
using mx::guard::emit_guard_veh_handler;
using mx::guard::GuardVehEmit;
using mx::guard::kGuardVehMaxTailJunk;

/// Default seed used everywhere the test only cares about the
/// handler body shape (not its tail polymorphism).
constexpr uint32_t kFixedSeed = 0xC0DEBABEu;

[[nodiscard]] uint32_t read_u32_le(const ByteBuffer& buf, size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + off, sizeof(v));
    return v;
}

[[nodiscard]] size_t find_pattern(
    const ByteBuffer& buf,
    std::initializer_list<uint8_t> pattern)
{
    if (pattern.size() == 0 || pattern.size() > buf.size()) {
        return std::string::npos;
    }
    for (size_t i = 0; i + pattern.size() <= buf.size(); ++i) {
        bool match = true;
        size_t j = 0;
        for (auto b : pattern) {
            if (buf[i + j] != b) { match = false; break; }
            ++j;
        }
        if (match) return i;
    }
    return std::string::npos;
}

[[nodiscard]] int count_pattern(
    const ByteBuffer& buf,
    std::initializer_list<uint8_t> pattern)
{
    if (pattern.size() == 0 || pattern.size() > buf.size()) return 0;
    int count = 0;
    for (size_t i = 0; i + pattern.size() <= buf.size(); ++i) {
        bool match = true;
        size_t j = 0;
        for (auto b : pattern) {
            if (buf[i + j] != b) { match = false; break; }
            ++j;
        }
        if (match) { ++count; i += pattern.size() - 1; }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Total size envelope (230 core + 0..8 polymorphic tail).
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, TotalSizeInExpectedEnvelope) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    // Commit 3b base: 209 bytes. Commit 4 HW bp sweep: +21 → 230.
    // Commit 7 polymorphic tail: +0..kGuardVehMaxTailJunk.
    const size_t base = 288u;
    EXPECT_GE(e.size(), base);
    EXPECT_LE(e.size(), base + kGuardVehMaxTailJunk);
}

// ---------------------------------------------------------------------------
// Prologue saves rbx/rbp/rsi/rdi.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PrologueSavesFourNonvolatiles) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    EXPECT_EQ(e.buf[0], 0x53u);  // push rbx
    EXPECT_EQ(e.buf[1], 0x55u);  // push rbp
    EXPECT_EQ(e.buf[2], 0x56u);  // push rsi
    EXPECT_EQ(e.buf[3], 0x57u);  // push rdi
}

// ---------------------------------------------------------------------------
// Exception-code filter + je-proceed fall-through tail.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, ExceptionCodeFilterFallsThroughToBailout) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    EXPECT_EQ(e.buf[4], 0x48u);
    EXPECT_EQ(e.buf[5], 0x8Bu);
    EXPECT_EQ(e.buf[6], 0x01u);
    EXPECT_EQ(e.buf[7],  0x81u);
    EXPECT_EQ(e.buf[8],  0x38u);
    EXPECT_EQ(e.buf[9],  0x03u);
    EXPECT_EQ(e.buf[10], 0x00u);
    EXPECT_EQ(e.buf[11], 0x00u);
    EXPECT_EQ(e.buf[12], 0x80u);
    EXPECT_EQ(e.buf[13], 0x74u);
    EXPECT_EQ(e.buf[15], 0x31u);
    EXPECT_EQ(e.buf[16], 0xC0u);
    EXPECT_EQ(e.buf[17], 0x5Fu);
    EXPECT_EQ(e.buf[18], 0x5Eu);
    EXPECT_EQ(e.buf[19], 0x5Du);
    EXPECT_EQ(e.buf[20], 0x5Bu);
    EXPECT_EQ(e.buf[21], 0xC3u);
}

// ---------------------------------------------------------------------------
// LOCK XADD appears twice — once for entry count++, once for exit count--.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, LockXaddAppearsTwiceForRefCount) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    const int count = count_pattern(
        e.buf, {0xF0, 0x0F, 0xC1, 0x46, 0x14});
    EXPECT_EQ(count, 2);
}

// ---------------------------------------------------------------------------
// Decrypt body's defining per-guard key read instruction.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DecryptBodyLoopContainsKeyReadPattern) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    const size_t pos = find_pattern(
        e.buf, {0x42, 0x0F, 0xB6, 0x44, 0x0E, 0x18});
    EXPECT_NE(pos, std::string::npos);
}

// ---------------------------------------------------------------------------
// Commit 4: HW breakpoint sweep in entry_match.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, HardwareBreakpointSweepReadsDr0ThroughDr3) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);

    const size_t dr0_read = find_pattern(
        e.buf, {0x48, 0x8B, 0x45, 0x48});
    ASSERT_NE(dr0_read, std::string::npos);

    EXPECT_EQ(e.buf[dr0_read + 4],  0x48u);
    EXPECT_EQ(e.buf[dr0_read + 5],  0x0Bu);
    EXPECT_EQ(e.buf[dr0_read + 6],  0x45u);
    EXPECT_EQ(e.buf[dr0_read + 7],  0x50u);
    EXPECT_EQ(e.buf[dr0_read + 8],  0x48u);
    EXPECT_EQ(e.buf[dr0_read + 9],  0x0Bu);
    EXPECT_EQ(e.buf[dr0_read + 10], 0x45u);
    EXPECT_EQ(e.buf[dr0_read + 11], 0x58u);
    EXPECT_EQ(e.buf[dr0_read + 12], 0x48u);
    EXPECT_EQ(e.buf[dr0_read + 13], 0x0Bu);
    EXPECT_EQ(e.buf[dr0_read + 14], 0x45u);
    EXPECT_EQ(e.buf[dr0_read + 15], 0x60u);
    EXPECT_EQ(e.buf[dr0_read + 16], 0x48u);
    EXPECT_EQ(e.buf[dr0_read + 17], 0x85u);
    EXPECT_EQ(e.buf[dr0_read + 18], 0xC0u);
    EXPECT_EQ(e.buf[dr0_read + 19], 0x75u);
}

// ---------------------------------------------------------------------------
// 64-byte descriptor stride.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, StrideAdvanceMatchesSixtyFourByteDescriptor) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    (void)emit_guard_veh_handler(e, rng);
    const size_t pos = find_pattern(e.buf, {0x48, 0x83, 0xC6, 0x40});
    EXPECT_NE(pos, std::string::npos);
}

// ---------------------------------------------------------------------------
// Patch-slot offsets point at zero placeholders.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PatchSlotsPointAtZeroPlaceholders) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    const auto p = emit_guard_veh_handler(e, rng);

    EXPECT_EQ(read_u32_le(e.buf, p.module_base_sub_imm32_offset), 0u);
    EXPECT_EQ(read_u32_le(e.buf, p.descriptor_table_rel32_offset), 0u);
    EXPECT_EQ(read_u32_le(e.buf, p.descriptor_count_imm32_offset), 0u);

    EXPECT_EQ(p.descriptor_table_rel32_end_offset,
              p.descriptor_table_rel32_offset + 4);
    EXPECT_GT(p.module_base_lea_anchor_offset, 0u);
    EXPECT_GT(p.module_base_sub_imm32_offset,
              p.module_base_lea_anchor_offset);
}

// ---------------------------------------------------------------------------
// Module-base lea/sub shape.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, ModuleBaseLeaAndSubShape) {
    RawEmitter e;
    Randomizer rng(kFixedSeed);
    const auto p = emit_guard_veh_handler(e, rng);
    const uint32_t lea_opcode_offset = p.module_base_lea_anchor_offset - 7;
    EXPECT_EQ(e.buf[lea_opcode_offset + 0], 0x48u);
    EXPECT_EQ(e.buf[lea_opcode_offset + 1], 0x8Du);
    EXPECT_EQ(e.buf[lea_opcode_offset + 2], 0x1Du);
    EXPECT_EQ(read_u32_le(e.buf, lea_opcode_offset + 3), 0u);

    const uint32_t sub_opcode_offset = p.module_base_sub_imm32_offset - 3;
    EXPECT_EQ(e.buf[sub_opcode_offset + 0], 0x48u);
    EXPECT_EQ(e.buf[sub_opcode_offset + 1], 0x81u);
    EXPECT_EQ(e.buf[sub_opcode_offset + 2], 0xEBu);
}

// ---------------------------------------------------------------------------
// Determinism: same seed → bit-identical handler bytes.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, DeterministicForIdenticalSeeds) {
    RawEmitter a, b;
    Randomizer rng_a(kFixedSeed);
    Randomizer rng_b(kFixedSeed);
    (void)emit_guard_veh_handler(a, rng_a);
    (void)emit_guard_veh_handler(b, rng_b);
    EXPECT_EQ(a.buf, b.buf);
}

// ---------------------------------------------------------------------------
// Commit 7: polymorphism — two different seeds MUST produce either
// different lengths or different trailing bytes (or both). The
// deterministic core body [0..230) stays identical for every seed
// because no RNG is consumed there; all variance comes from the
// tail.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PolymorphicTailVariesAcrossSeeds) {
    constexpr size_t kAttempts = 16;
    RawEmitter baseline;
    Randomizer baseline_rng(1u);
    (void)emit_guard_veh_handler(baseline, baseline_rng);

    bool found_different = false;
    for (size_t seed = 2; seed <= kAttempts + 2 && !found_different; ++seed) {
        RawEmitter other;
        Randomizer other_rng(static_cast<uint32_t>(seed));
        (void)emit_guard_veh_handler(other, other_rng);
        if (other.size() != baseline.size() || other.buf != baseline.buf) {
            found_different = true;
        }
    }

    EXPECT_TRUE(found_different)
        << "Expected at least one seed in 2.." << (kAttempts + 2)
        << " to produce a different handler from seed 1 — polymorphic "
           "tail is not contributing any per-build variance";
}

TEST(GuardVehEmitter, DeterministicCoreRegardlessOfSeed) {
    // The first 230 bytes of the handler (up to the final `ret`)
    // are seed-independent. Only the tail bytes vary.
    RawEmitter a, b;
    Randomizer rng_a(123u);
    Randomizer rng_b(456u);
    (void)emit_guard_veh_handler(a, rng_a);
    (void)emit_guard_veh_handler(b, rng_b);

    const size_t core = 288u;
    ASSERT_GE(a.size(), core);
    ASSERT_GE(b.size(), core);
    for (size_t i = 0; i < core; ++i) {
        ASSERT_EQ(a.buf[i], b.buf[i])
            << "Core handler byte " << i << " differs across seeds";
    }
}

// ---------------------------------------------------------------------------
// Patch offsets are relative to handler start, not emitter start.
// ---------------------------------------------------------------------------

TEST(GuardVehEmitter, PatchOffsetsAreRelativeToHandlerStart) {
    RawEmitter a;
    Randomizer rng_a(kFixedSeed);
    const auto pa = emit_guard_veh_handler(a, rng_a);

    RawEmitter b;
    b.buf.resize(100, 0xCCu);
    Randomizer rng_b(kFixedSeed);
    const auto pb = emit_guard_veh_handler(b, rng_b);

    EXPECT_EQ(pa.module_base_sub_imm32_offset,
              pb.module_base_sub_imm32_offset);
    EXPECT_EQ(pa.module_base_lea_anchor_offset,
              pb.module_base_lea_anchor_offset);
    EXPECT_EQ(pa.descriptor_table_rel32_offset,
              pb.descriptor_table_rel32_offset);
    EXPECT_EQ(pa.descriptor_table_rel32_end_offset,
              pb.descriptor_table_rel32_end_offset);
    EXPECT_EQ(pa.descriptor_count_imm32_offset,
              pb.descriptor_count_imm32_offset);
}

} // namespace
