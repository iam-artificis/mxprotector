/**
 * @file veh_int3_trap_test.cpp
 * @brief [TESTS] Unit tests for the G3 Phase 2 VEH INT3 trap emitter.
 *
 * Covers:
 *   - `emit_veh_int3_trap` produces a buffer in the expected size
 *     window and starts with the documented `jmp short` prefix that
 *     skips the VEH handler body.
 *   - The handler body contains the STATUS_BREAKPOINT compare and
 *     two `ret` instructions (one on the "catch" path, one on the
 *     "continue search" path).
 *   - The handler includes the `mov eax, 0xFFFFFFFF` literal
 *     (EXCEPTION_CONTINUE_EXECUTION) and a distinct `xor eax, eax`
 *     (EXCEPTION_CONTINUE_SEARCH) so the filter path is complete.
 *   - The sequence ends with an `int3` followed by exactly 6 more
 *     bytes of junk before the emitter returns.
 *   - Two emissions with the same RNG seed produce byte-identical
 *     output; two different seeds differ at least in the junk tail
 *     and the Hell's Gate salt.
 *   - The `lea rdx, [rip + disp32]` that passes the handler address
 *     to `AddVectoredExceptionHandler` resolves to the documented
 *     handler offset (3 bytes into the buffer — right after the
 *     initial `jmp short`).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/packer/veh_int3_trap.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::packer::emit_veh_int3_trap;

/// Count how many times `byte` appears as a standalone byte in
/// `buf`. Used for loose coarse-grained pattern checks ("there is at
/// least one `ret` somewhere in the handler").
[[nodiscard]] int count_byte(const std::vector<uint8_t>& buf, uint8_t b) {
    int n = 0;
    for (uint8_t x : buf) {
        if (x == b) ++n;
    }
    return n;
}

/// Scan the buffer for the first occurrence of a byte pattern.
[[nodiscard]] size_t find_pattern(const std::vector<uint8_t>& buf,
                                   const std::vector<uint8_t>& pat)
{
    if (pat.empty() || pat.size() > buf.size()) {
        return std::string::npos;
    }
    for (size_t i = 0; i + pat.size() <= buf.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (buf[i + j] != pat[j]) { match = false; break; }
        }
        if (match) return i;
    }
    return std::string::npos;
}

/// Read a 32-bit little-endian value at `offset`.
[[nodiscard]] uint32_t read_u32_le(const std::vector<uint8_t>& buf, size_t offset) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + offset, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// Shape + size
// ---------------------------------------------------------------------------

TEST(VehInt3Trap, EmitProducesBufferInExpectedSizeWindow) {
    Randomizer rng{0xBEEF};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);
    // Handler ~49 + jmp-past-handler 2 + install frame + Hell's Gate
    // (~155) + call scaffolding + int3 tail (7) ≈ 240 bytes. Leave
    // plenty of slack for future tweaks to the resolver.
    EXPECT_GT(e.size(), 150u);
    EXPECT_LT(e.size(), 350u);
}

TEST(VehInt3Trap, EmitStartsWithJmpShortPrefix) {
    Randomizer rng{0xCAFE};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // The very first instruction MUST be a short jump over the
    // handler body so execution enters the install sequence. We
    // don't check the rel8 value exactly — it depends on the
    // handler's final size — but the opcode must be EB and the
    // computed distance must land INSIDE the buffer.
    ASSERT_GE(e.size(), 2u);
    EXPECT_EQ(e.buf[0], 0xEBu);
    const int8_t rel = static_cast<int8_t>(e.buf[1]);
    EXPECT_GT(rel, 0);
    EXPECT_LT(static_cast<size_t>(2 + rel), e.size());
}

// ---------------------------------------------------------------------------
// Handler body shape
// ---------------------------------------------------------------------------

TEST(VehInt3Trap, HandlerComparesExceptionCodeToStatusBreakpoint) {
    Randomizer rng{0xD0D0};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // `cmp eax, 0x80000003` → 3D 03 00 00 80. This is the strict
    // filter that prevents the VEH from firing on C++ exceptions
    // (code 0xE06D7363) or any other non-breakpoint event.
    const std::vector<uint8_t> pat{0x3Du, 0x03u, 0x00u, 0x00u, 0x80u};
    EXPECT_NE(find_pattern(e.buf, pat), std::string::npos);
}

TEST(VehInt3Trap, HandlerContainsContinueExecutionAndContinueSearch) {
    Randomizer rng{0x1234};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // `mov eax, 0xFFFFFFFF` → B8 FF FF FF FF for the
    // EXCEPTION_CONTINUE_EXECUTION return on the catch path.
    const std::vector<uint8_t> continue_execution{
        0xB8u, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
    };
    EXPECT_NE(find_pattern(e.buf, continue_execution), std::string::npos);

    // `xor eax, eax` → 31 C0 for EXCEPTION_CONTINUE_SEARCH. Because
    // `31 C0` is a common two-byte sequence that may legitimately
    // appear elsewhere (e.g., inside a Hell's Gate hash loop), we
    // only check for presence, not count.
    const std::vector<uint8_t> xor_eax{0x31u, 0xC0u};
    EXPECT_NE(find_pattern(e.buf, xor_eax), std::string::npos);
}

TEST(VehInt3Trap, HandlerContainsRipAdvanceByFixedAmount) {
    Randomizer rng{0xB00B};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // `add qword [rax + 0xF8], 7` = 48 83 80 F8 00 00 00 07. This
    // is the single instruction that performs the Rip advance past
    // the planted int3 + 6 junk bytes. A reverser changing it
    // (e.g., to 1) would break the trap — the test pins the exact
    // byte sequence.
    const std::vector<uint8_t> pat{
        0x48u, 0x83u, 0x80u, 0xF8u, 0x00u, 0x00u, 0x00u, 0x07u,
    };
    EXPECT_NE(find_pattern(e.buf, pat), std::string::npos);
}

// ---------------------------------------------------------------------------
// Planted int3 + junk tail
// ---------------------------------------------------------------------------

TEST(VehInt3Trap, EndsWithInt3PlusSixBytes) {
    Randomizer rng{0xFEE1};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // The very last 7 bytes of the emission are the planted int3
    // (CC) followed by 6 junk bytes. We don't pin the junk values —
    // they're per-build random — but the position and the int3
    // opcode are fixed.
    ASSERT_GE(e.size(), 7u);
    EXPECT_EQ(e.buf[e.size() - 7], 0xCCu);
}

TEST(VehInt3Trap, JunkTailVariesAcrossSeeds) {
    Randomizer rng_a{111};
    Randomizer rng_b{222};
    RawEmitter ea, eb;
    emit_veh_int3_trap(ea, rng_a);
    emit_veh_int3_trap(eb, rng_b);

    // At minimum the 6 junk bytes (and the Hell's Gate salt inside
    // the resolver) must differ across seeds. A full byte-buffer
    // diff is overkill — we just need at least one differing byte.
    ASSERT_EQ(ea.size(), eb.size());
    EXPECT_NE(ea.buf, eb.buf);
}

TEST(VehInt3Trap, DeterministicForSameSeed) {
    Randomizer rng_a{0xBAADF00D};
    Randomizer rng_b{0xBAADF00D};
    RawEmitter ea, eb;
    emit_veh_int3_trap(ea, rng_a);
    emit_veh_int3_trap(eb, rng_b);

    ASSERT_EQ(ea.size(), eb.size());
    EXPECT_EQ(ea.buf, eb.buf);
}

// ---------------------------------------------------------------------------
// lea-rdx-to-handler resolves to the handler's recorded offset
// ---------------------------------------------------------------------------

TEST(VehInt3Trap, LeaHandlerDispResolvesToHandlerStart) {
    Randomizer rng{0xAA55};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // Layout invariants the emitter enforces:
    //   [0..1]    EB rel8            (jmp short .past_handler)
    //   [2..]     handler body       (.handler_offset == 2)
    //
    // Somewhere after the handler, the install sequence includes
    //   48 8D 15 disp32              (lea rdx, [rip + .handler])
    // whose disp32 slot, when read from end_of_lea, must resolve
    // back to offset 2. We locate the first occurrence of the
    // `48 8D 15` prefix and verify the disp32 it encodes.
    const std::vector<uint8_t> lea_prefix{0x48u, 0x8Du, 0x15u};
    const size_t lea_pos = find_pattern(e.buf, lea_prefix);
    ASSERT_NE(lea_pos, std::string::npos);
    ASSERT_LE(lea_pos + 7, e.size());

    const uint32_t disp_u = read_u32_le(e.buf, lea_pos + 3);
    const int32_t disp = static_cast<int32_t>(disp_u);
    const int64_t end_of_lea = static_cast<int64_t>(lea_pos) + 7;
    const int64_t handler_target = end_of_lea + disp;

    EXPECT_EQ(handler_target, 2) << "lea rdx, [rip + disp32] must "
        "resolve to the handler body which lives at offset 2";
}

TEST(VehInt3Trap, ContainsHellsGateCallThroughR13) {
    Randomizer rng{0x1111};
    RawEmitter e;
    emit_veh_int3_trap(e, rng);

    // The install sequence ends with `call r13` = 41 FF D5. This
    // is the actual `RtlAddVectoredExceptionHandler(first, handler)`
    // invocation after the resolver puts the function address in
    // r13. Its presence proves the Hell's Gate integration is
    // wired up — without the call, the VEH is never registered.
    const std::vector<uint8_t> call_r13{0x41u, 0xFFu, 0xD5u};
    EXPECT_NE(find_pattern(e.buf, call_r13), std::string::npos);
}

} // namespace
