/**
 * @file anti_emulation_check_test.cpp
 * @brief [TESTS] Unit tests for anti-emulation check infrastructure.
 *
 * Covers:
 *   - CheckRegistry contains every expected built-in technique, addressed
 *     by name (decoupled from registration order).
 *   - pick_random honours the requested count, returns distinct items,
 *     clamps to registry size, and is deterministic for the same RNG seed.
 *   - Every check emits a non-empty byte sequence whose tail matches the
 *     contract: `xor [rsp + disp8], <reg>` with the caller-supplied disp.
 *   - Per-build mask randomisation actually consumes the RNG: two
 *     different seeds must produce different byte sequences for the
 *     same check.
 *   - Same seed is fully deterministic.
 *
 * The tests do not execute the emitted machine code — that's the job of
 * the end-to-end stress builds. They validate the structural invariants
 * a future technique author would otherwise have to re-discover by
 * staring at hex dumps.
 */

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_emulation/check.hpp"
#include "mxprotector/protection/anti_emulation/check_registry.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::anti_emulation::CheckRegistry;
using mx::anti_emulation::ICheck;

/// Names of every check that MUST live in the default registry. Matches
/// `CheckRegistry::CheckRegistry()` in check_registry.cpp; adding a new
/// technique should add a name here AND register it there.
const std::vector<std::string_view>& expected_check_names() {
    static const std::vector<std::string_view> names = {
        "rdtsc_zero_delta",
        "rdtsc_huge_delta",
        "eflags_reserved_bit",
    };
    return names;
}

/// Locate a check inside the registry by its `name()`. Returns nullptr
/// if missing.
const ICheck* find_check(const CheckRegistry& reg, std::string_view name) {
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == name) return &reg.at(i);
    }
    return nullptr;
}

/// Verifies that `bytes` ends with a `xor [rsp + disp8], <reg>` instruction.
/// Encoding: `[REX?] 31 modrm 24 disp8` where modrm.mod==01 and rm==100 (SIB)
/// and the SIB is `0x24` (scale=0, index=100=none, base=100=rsp).
///
/// We accept both:
///   * No REX:   31 4? 24 disp8     (eax/ecx/edx/ebx as src reg)
///   * With REX: 44 31 4? 24 disp8  (r8d..r15d as src reg)
::testing::AssertionResult ends_with_xor_rsp_disp8(
    const std::vector<uint8_t>& bytes, int8_t expected_disp)
{
    if (bytes.size() < 4) {
        return ::testing::AssertionFailure() << "buffer too short ("
                                             << bytes.size() << ")";
    }

    const size_t n = bytes.size();
    // Disp8 is the last byte.
    const auto actual_disp = static_cast<int8_t>(bytes[n - 1]);
    if (actual_disp != expected_disp) {
        return ::testing::AssertionFailure()
            << "disp8 mismatch: expected " << int{expected_disp}
            << ", got " << int{actual_disp};
    }
    // SIB byte (rsp base) is at n-2.
    if (bytes[n - 2] != 0x24) {
        return ::testing::AssertionFailure()
            << "expected SIB=0x24 at byte n-2, got 0x"
            << std::hex << int{bytes[n - 2]};
    }
    // ModR/M at n-3: mod=01, rm=100, reg = src register (any 0..7)
    // → top two bits == 01, bottom three bits == 100.
    const uint8_t modrm = bytes[n - 3];
    if ((modrm & 0xC7) != 0x44) {
        return ::testing::AssertionFailure()
            << "expected ModRM mod=01 rm=100 (mask 0x44), got 0x"
            << std::hex << int{modrm};
    }
    // Opcode XOR r/m32, r32 = 0x31, at n-4.
    if (bytes[n - 4] != 0x31) {
        return ::testing::AssertionFailure()
            << "expected XOR opcode 0x31 at byte n-4, got 0x"
            << std::hex << int{bytes[n - 4]};
    }
    return ::testing::AssertionSuccess();
}

std::vector<uint8_t> emit_check(const ICheck& chk, int32_t disp,
                                 uint64_t seed) {
    Randomizer rng(seed);
    RawEmitter e;
    chk.emit(e, disp, rng);
    return e.buf;
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

TEST(AntiEmulationRegistry, ContainsAllExpectedChecks) {
    CheckRegistry reg;
    EXPECT_EQ(reg.size(), expected_check_names().size())
        << "registry size diverged from expected_check_names() — "
           "did you add a check without updating the test list?";
    for (auto name : expected_check_names()) {
        EXPECT_NE(find_check(reg, name), nullptr)
            << "missing check: " << name;
    }
}

TEST(AntiEmulationRegistry, PickRandomReturnsDistinctChecks) {
    CheckRegistry reg;
    Randomizer rng(0xCAFEBABE12345678ULL);
    const auto picks = reg.pick_random(reg.size(), rng);
    ASSERT_EQ(picks.size(), reg.size());

    std::set<const ICheck*> seen;
    for (const auto* chk : picks) {
        ASSERT_NE(chk, nullptr);
        EXPECT_TRUE(seen.insert(chk).second)
            << "pick_random returned duplicate: " << chk->name();
    }
}

TEST(AntiEmulationRegistry, PickRandomClampsToRegistrySize) {
    CheckRegistry reg;
    Randomizer rng(42);
    const auto picks = reg.pick_random(reg.size() + 99, rng);
    EXPECT_EQ(picks.size(), reg.size());
}

TEST(AntiEmulationRegistry, PickRandomZeroReturnsEmpty) {
    CheckRegistry reg;
    Randomizer rng(7);
    EXPECT_TRUE(reg.pick_random(0, rng).empty());
}

TEST(AntiEmulationRegistry, PickRandomDeterministicForSameSeed) {
    CheckRegistry reg;
    Randomizer rng_a(0xDEADBEEF);
    Randomizer rng_b(0xDEADBEEF);
    const auto a = reg.pick_random(reg.size(), rng_a);
    const auto b = reg.pick_random(reg.size(), rng_b);
    ASSERT_EQ(a.size(), b.size());
    for (size_t i = 0; i < a.size(); ++i) {
        EXPECT_STREQ(a[i]->name(), b[i]->name()) << "i=" << i;
    }
}

TEST(AntiEmulationRegistry, PickRandomDifferentSeedsDifferOften) {
    // Across many seed pairs, the picked-name sequence should differ
    // most of the time. (Identical sequences happen rarely by chance.)
    CheckRegistry reg;
    int diffs = 0;
    for (uint64_t seed = 1; seed <= 50; ++seed) {
        Randomizer rng_a(seed * 0x9E3779B97F4A7C15ULL);
        Randomizer rng_b(seed * 0xBF58476D1CE4E5B9ULL + 1);
        const auto a = reg.pick_random(reg.size(), rng_a);
        const auto b = reg.pick_random(reg.size(), rng_b);
        ASSERT_EQ(a.size(), b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::string_view{a[i]->name()} != b[i]->name()) {
                ++diffs;
                break;
            }
        }
    }
    EXPECT_GT(diffs, 30) << "pick_random looks too deterministic across seeds";
}

// ---------------------------------------------------------------------------
// Per-check structural tests — each named check must:
//   * emit a non-empty buffer;
//   * end with `xor [rsp + disp8], <reg>` matching the requested disp;
//   * differ across two distinct seeds (random mask consumed);
//   * be byte-identical for the same seed (determinism).
//
// One parameterised TEST_F would be cleaner but the registry doesn't
// expose iteration in the header — keep it simple with a single
// fixture-driven TEST that walks every check.
// ---------------------------------------------------------------------------

TEST(AntiEmulationCheck, EveryCheckEndsWithXorRspDisp8) {
    CheckRegistry reg;
    constexpr int8_t kProbeDisp = 0x18;  // arbitrary in-range disp8
    for (size_t i = 0; i < reg.size(); ++i) {
        const auto& chk = reg.at(i);
        const auto bytes = emit_check(chk, kProbeDisp, /*seed=*/12345);
        SCOPED_TRACE(chk.name());
        EXPECT_GE(bytes.size(), 8u);
        EXPECT_TRUE(ends_with_xor_rsp_disp8(bytes, kProbeDisp));
    }
}

TEST(AntiEmulationCheck, EveryCheckIsDeterministicForSameSeed) {
    CheckRegistry reg;
    for (size_t i = 0; i < reg.size(); ++i) {
        const auto& chk = reg.at(i);
        const auto a = emit_check(chk, 0x10, /*seed=*/0xABCD);
        const auto b = emit_check(chk, 0x10, /*seed=*/0xABCD);
        SCOPED_TRACE(chk.name());
        EXPECT_EQ(a, b);
    }
}

TEST(AntiEmulationCheck, EveryCheckVariesWithSeed) {
    // Two seeds must give two different byte sequences for the same
    // check — proves the randomiser is actually consumed (mask, etc.).
    CheckRegistry reg;
    for (size_t i = 0; i < reg.size(); ++i) {
        const auto& chk = reg.at(i);
        const auto a = emit_check(chk, 0x20, /*seed=*/1);
        const auto b = emit_check(chk, 0x20, /*seed=*/2);
        SCOPED_TRACE(chk.name());
        EXPECT_NE(a, b);
    }
}

TEST(AntiEmulationCheck, DispIsThreadedThrough) {
    // Different disp8 values must produce different last-byte patterns
    // across every check.
    CheckRegistry reg;
    for (size_t i = 0; i < reg.size(); ++i) {
        const auto& chk = reg.at(i);
        SCOPED_TRACE(chk.name());
        const auto a = emit_check(chk, 0x10, /*seed=*/9999);
        const auto b = emit_check(chk, 0x70, /*seed=*/9999);
        ASSERT_EQ(a.size(), b.size());
        ASSERT_GE(a.size(), 1u);
        EXPECT_EQ(a.back(), 0x10);
        EXPECT_EQ(b.back(), 0x70);
    }
}

TEST(AntiEmulationCheck, NewFlagCheckIsRegistered) {
    // Sanity: the new EFLAGS reserved-bit-1 probe is wired up.
    // (AC flag fidelity was tried and rejected — see the giant comment
    // in check_registry.cpp explaining why setting EFLAGS.AC=1 in user
    // mode crashes Windows binaries via the alignment-check trap.)
    CheckRegistry reg;
    EXPECT_NE(find_check(reg, "eflags_reserved_bit"), nullptr);
    EXPECT_EQ(find_check(reg, "ac_flag_fidelity"), nullptr)
        << "AC check is unsafe on Windows x64 — must NOT be re-registered";
}

} // namespace
