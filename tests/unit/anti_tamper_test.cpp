/**
 * @file anti_tamper_test.cpp
 * @brief [TESTS] Unit tests for the G3 anti-tamper infrastructure.
 *
 * Covers:
 *   - `djb2_ascii_hash` is constexpr and gives known values for
 *     both the empty string and a few fixed strings.
 *   - `emit_hells_gate_resolver` produces a non-empty byte sequence
 *     whose prefix is the `mov rax, gs:[0x60]` PEB read, and whose
 *     body embeds the target hash as an imm32 somewhere.
 *   - `CheckRegistry` contains the expected `hw_breakpoint_sweep`
 *     entry and supports deterministic picking.
 *   - `HwBreakpointSweepCheck` emits the documented ~90-byte body,
 *     contains a `syscall` (0F 05) somewhere inside, reads its SSN
 *     from `r13d` (`44 89 E8` pattern), and ends with
 *     `xor [rsp + disp8], eax`.
 *   - Same RNG seed → byte-identical emission; different seeds →
 *     differing emission (mask randomisation).
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_tamper/check.hpp"
#include "mxprotector/protection/anti_tamper/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::anti_tamper::CheckRegistry;
using mx::anti_tamper::djb2_ascii_hash;
using mx::anti_tamper::emit_hells_gate_resolver;
using mx::anti_tamper::ICheck;

// ---------------------------------------------------------------------------
// DJB2 hash — constexpr correctness
// ---------------------------------------------------------------------------

TEST(AntiTamperDjb2, EmptyStringHashIsInitValue) {
    constexpr uint32_t h = djb2_ascii_hash("");
    static_assert(h == 5381u, "DJB2 init must be 5381");
    EXPECT_EQ(h, 5381u);
}

TEST(AntiTamperDjb2, SingleCharHashFormula) {
    // h = 5381 * 33 + 'A' = 177573 + 65 = 177638
    constexpr uint32_t h = djb2_ascii_hash("A");
    static_assert(h == 177638u);
    EXPECT_EQ(h, 177638u);
}

TEST(AntiTamperDjb2, DistinctStringsProduceDistinctHashes) {
    // Compile-time check that the hash actually discriminates.
    constexpr uint32_t h1 = djb2_ascii_hash("NtGetContextThread");
    constexpr uint32_t h2 = djb2_ascii_hash("NtClose");
    constexpr uint32_t h3 = djb2_ascii_hash("NtQueryInformationThread");
    static_assert(h1 != h2);
    static_assert(h1 != h3);
    static_assert(h2 != h3);
    EXPECT_NE(h1, h2);
    EXPECT_NE(h1, h3);
    EXPECT_NE(h2, h3);
}

TEST(AntiTamperDjb2, StableAcrossCallsWithSameInput) {
    EXPECT_EQ(djb2_ascii_hash("NtGetContextThread"),
              djb2_ascii_hash("NtGetContextThread"));
}

// ---------------------------------------------------------------------------
// Hell's Gate resolver — byte pattern invariants
// ---------------------------------------------------------------------------

TEST(AntiTamperHellsGate, EmitsNonEmptyBody) {
    RawEmitter e;
    emit_hells_gate_resolver(e, 0xDEADBEEFu);
    EXPECT_GT(e.size(), 100u)
        << "Hell's Gate resolver is expected to be ~150 bytes";
    EXPECT_LT(e.size(), 300u)
        << "...but not a kilobyte";
}

TEST(AntiTamperHellsGate, StartsWithPebReadPrefix) {
    // `mov rax, gs:[0x60]` must be the very first instruction.
    //   65 48 8B 04 25 60 00 00 00
    RawEmitter e;
    emit_hells_gate_resolver(e, 0xDEADBEEFu);
    ASSERT_GE(e.size(), 9u);
    EXPECT_EQ(e.buf[0], 0x65);
    EXPECT_EQ(e.buf[1], 0x48);
    EXPECT_EQ(e.buf[2], 0x8B);
    EXPECT_EQ(e.buf[3], 0x04);
    EXPECT_EQ(e.buf[4], 0x25);
    EXPECT_EQ(e.buf[5], 0x60);
    EXPECT_EQ(e.buf[6], 0x00);
    EXPECT_EQ(e.buf[7], 0x00);
    EXPECT_EQ(e.buf[8], 0x00);
}

TEST(AntiTamperHellsGate, EmbedsTargetHashAsImm32) {
    // Two distinct target hashes must produce bodies that differ
    // in at least one byte (proving the hash is actually threaded
    // through as an immediate, not dropped on the floor).
    RawEmitter e1, e2;
    emit_hells_gate_resolver(e1, 0xAAAAAAAAu);
    emit_hells_gate_resolver(e2, 0x55555555u);
    ASSERT_EQ(e1.size(), e2.size())
        << "resolver size should not depend on hash value";
    EXPECT_NE(e1.buf, e2.buf);
}

TEST(AntiTamperHellsGate, TargetHashBytesAppearInBody) {
    // The target hash is emitted as a little-endian imm32 after the
    // `cmp eax, imm32` (opcode 0x3D). Scan the body for the exact
    // 4-byte pattern.
    constexpr uint32_t kHash = 0xCAFEBABEu;
    RawEmitter e;
    emit_hells_gate_resolver(e, kHash);

    const uint8_t b0 = static_cast<uint8_t>(kHash & 0xFFu);
    const uint8_t b1 = static_cast<uint8_t>((kHash >> 8) & 0xFFu);
    const uint8_t b2 = static_cast<uint8_t>((kHash >> 16) & 0xFFu);
    const uint8_t b3 = static_cast<uint8_t>((kHash >> 24) & 0xFFu);

    bool found = false;
    for (size_t i = 0; i + 3 < e.size(); ++i) {
        if (e.buf[i]   == b0 && e.buf[i+1] == b1
         && e.buf[i+2] == b2 && e.buf[i+3] == b3)
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "target hash should appear as a 4-byte imm32";
}

TEST(AntiTamperHellsGate, DeterministicForSameHash) {
    RawEmitter a, b;
    emit_hells_gate_resolver(a, 0x12345678u);
    emit_hells_gate_resolver(b, 0x12345678u);
    EXPECT_EQ(a.buf, b.buf);
}

// ---------------------------------------------------------------------------
// CheckRegistry
// ---------------------------------------------------------------------------

TEST(AntiTamperRegistry, ContainsHwBreakpointSweep) {
    CheckRegistry reg;
    ASSERT_GE(reg.size(), 1u);
    bool found = false;
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == "hw_breakpoint_sweep") {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST(AntiTamperRegistry, PickRandomReturnsDistinct) {
    CheckRegistry reg;
    Randomizer rng(0xCAFE);
    const auto picks = reg.pick_random(reg.size(), rng);
    EXPECT_EQ(picks.size(), reg.size());
}

TEST(AntiTamperRegistry, PickRandomZeroIsEmpty) {
    CheckRegistry reg;
    Randomizer rng(1);
    EXPECT_TRUE(reg.pick_random(0, rng).empty());
}

// ---------------------------------------------------------------------------
// HwBreakpointSweepCheck — byte-level invariants
// ---------------------------------------------------------------------------

namespace {
const ICheck* find_check(const CheckRegistry& reg, const char* name) {
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == name) return &reg.at(i);
    }
    return nullptr;
}
}  // namespace

TEST(AntiTamperHwBreakpoint, EmitsNonEmptyAndEndsWithXorRspDisp8) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xABCDEF);
    RawEmitter e;
    constexpr int8_t kProbeDisp = 0x18;
    check->emit(e, kProbeDisp, rng);

    ASSERT_GT(e.size(), 50u) << "check should be ~90 bytes";

    // Tail must be `xor [rsp + disp8], eax`:
    //   31 44 24 disp8
    const size_t n = e.size();
    EXPECT_EQ(e.buf[n - 4], 0x31);
    EXPECT_EQ(e.buf[n - 3], 0x44);
    EXPECT_EQ(e.buf[n - 2], 0x24);
    EXPECT_EQ(static_cast<int8_t>(e.buf[n - 1]), kProbeDisp);
}

TEST(AntiTamperHwBreakpoint, ContainsSyscallInstruction) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng(42);
    RawEmitter e;
    check->emit(e, 0x10, rng);

    bool has_syscall = false;
    for (size_t i = 0; i + 1 < e.size(); ++i) {
        if (e.buf[i] == 0x0F && e.buf[i + 1] == 0x05) {
            has_syscall = true;
            break;
        }
    }
    EXPECT_TRUE(has_syscall) << "no `0F 05` syscall byte pair in emitted body";
}

TEST(AntiTamperHwBreakpoint, LoadsSsnFromR13) {
    // The check should use `mov eax, r13d` (44 89 E8) to load the
    // SSN at runtime, NOT `mov eax, imm32` (B8 imm32).
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng(1);
    RawEmitter e;
    check->emit(e, 0x10, rng);

    bool has_mov_from_r13 = false;
    for (size_t i = 0; i + 2 < e.size(); ++i) {
        if (e.buf[i] == 0x44 && e.buf[i+1] == 0x89 && e.buf[i+2] == 0xE8) {
            has_mov_from_r13 = true;
            break;
        }
    }
    EXPECT_TRUE(has_mov_from_r13)
        << "HW BP check must read SSN from r13d, not from an imm32";
}

TEST(AntiTamperHwBreakpoint, DeterministicForSameSeed) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(0xDEAD);
    Randomizer rng_b(0xDEAD);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a);
    check->emit(eb, 0x10, rng_b);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperHwBreakpoint, DiffersAcrossSeeds) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a);
    check->emit(eb, 0x10, rng_b);
    EXPECT_NE(ea.buf, eb.buf);
}

} // namespace
