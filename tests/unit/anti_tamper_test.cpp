/**
 * @file anti_tamper_test.cpp
 * @brief [TESTS] Unit tests for the G3 anti-tamper infrastructure.
 *
 * Covers:
 *   - SyscallResolver returns a non-zero SSN for NtGetContextThread on
 *     a Windows builder host. (Sanity test that the resolver actually
 *     finds the function and validates the prologue bytes.)
 *   - SyscallResolver returns 0 for an unknown / non-existent function.
 *   - SyscallResolver returns 0 for nullptr.
 *   - CheckRegistry contains the expected hw_breakpoint_sweep check
 *     when running on Windows. (Skipped on non-Windows builders.)
 *   - HwBreakpointSweepCheck emits a non-empty byte sequence whose
 *     tail matches the `xor [rsp+disp8], eax` final write into the
 *     key slot.
 *   - Two emissions with different RNG seeds produce different bytes
 *     (proving the corruption mask is randomised per build).
 *   - Two emissions with the same seed are byte-identical.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_tamper/check.hpp"
#include "mxprotector/protection/anti_tamper/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/syscall_resolver.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::anti_tamper::CheckRegistry;
using mx::anti_tamper::ICheck;
using mx::anti_tamper::SyscallResolver;

// ---------------------------------------------------------------------------
// SyscallResolver
// ---------------------------------------------------------------------------

#if defined(_WIN32)
TEST(AntiTamperSyscallResolver, ResolvesNtGetContextThread) {
    SyscallResolver r;
    const uint32_t ssn = r.resolve("NtGetContextThread");
    EXPECT_NE(ssn, 0u)
        << "SyscallResolver could not extract SSN for NtGetContextThread — "
           "either the builder host has a hooked NTDLL or the prologue "
           "format has changed";
    // SSNs are small positive integers, well under 0x10000.
    EXPECT_LT(ssn, 0x1000u)
        << "SSN looks suspiciously large: 0x" << std::hex << ssn;
}
#endif

TEST(AntiTamperSyscallResolver, ReturnsZeroForUnknownFunction) {
    SyscallResolver r;
    EXPECT_EQ(r.resolve("ThisFunctionDoesNotExistInNtdll12345"), 0u);
}

TEST(AntiTamperSyscallResolver, ReturnsZeroForNullName) {
    SyscallResolver r;
    EXPECT_EQ(r.resolve(nullptr), 0u);
}

// ---------------------------------------------------------------------------
// CheckRegistry
// ---------------------------------------------------------------------------

#if defined(_WIN32)
TEST(AntiTamperRegistry, ContainsHwBreakpointSweep) {
    CheckRegistry reg;
    ASSERT_GE(reg.size(), 1u)
        << "Registry should contain at least the HW breakpoint sweep check";
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
#endif

// ---------------------------------------------------------------------------
// HwBreakpointSweepCheck — byte-level invariants
// ---------------------------------------------------------------------------

#if defined(_WIN32)
TEST(AntiTamperHwBreakpoint, EmitsNonEmptyAndEndsWithXorRspDisp8) {
    CheckRegistry reg;
    ASSERT_GE(reg.size(), 1u);

    // Find hw_breakpoint_sweep by name (don't depend on registration order).
    const ICheck* check = nullptr;
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == "hw_breakpoint_sweep") {
            check = &reg.at(i);
            break;
        }
    }
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xABCDEF);
    RawEmitter e;
    constexpr int8_t kProbeDisp = 0x18;
    check->emit(e, kProbeDisp, rng);

    ASSERT_GT(e.size(), 50u)
        << "HW breakpoint sweep should be ~90 bytes, got " << e.size();

    // Tail must be `xor [rsp + disp8], eax`:
    //   31 44 24 disp8
    const size_t n = e.size();
    EXPECT_EQ(e.buf[n - 4], 0x31);  // XOR r/m32, r32
    // ModRM: mod=01, reg=000(eax), rm=100(SIB) → 0x44
    EXPECT_EQ(e.buf[n - 3], 0x44);
    // SIB: scale=00, index=100(none), base=100(rsp) → 0x24
    EXPECT_EQ(e.buf[n - 2], 0x24);
    // disp8 (signed)
    EXPECT_EQ(static_cast<int8_t>(e.buf[n - 1]), kProbeDisp);
}

TEST(AntiTamperHwBreakpoint, ContainsSyscallInstruction) {
    CheckRegistry reg;
    const ICheck* check = nullptr;
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == "hw_breakpoint_sweep") {
            check = &reg.at(i);
            break;
        }
    }
    ASSERT_NE(check, nullptr);

    Randomizer rng(42);
    RawEmitter e;
    check->emit(e, 0x10, rng);

    // The emitted body must contain `0F 05` (syscall) somewhere.
    bool has_syscall = false;
    for (size_t i = 0; i + 1 < e.size(); ++i) {
        if (e.buf[i] == 0x0F && e.buf[i + 1] == 0x05) {
            has_syscall = true;
            break;
        }
    }
    EXPECT_TRUE(has_syscall) << "no `0F 05` syscall byte pair in emitted body";
}

TEST(AntiTamperHwBreakpoint, DeterministicForSameSeed) {
    CheckRegistry reg;
    const ICheck* check = nullptr;
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == "hw_breakpoint_sweep") {
            check = &reg.at(i);
            break;
        }
    }
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(0xDEAD);
    Randomizer rng_b(0xDEAD);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a);
    check->emit(eb, 0x10, rng_b);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperHwBreakpoint, DiffersAcrossSeeds) {
    // Different seeds → different corruption mask → different bytes.
    CheckRegistry reg;
    const ICheck* check = nullptr;
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == "hw_breakpoint_sweep") {
            check = &reg.at(i);
            break;
        }
    }
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a);
    check->emit(eb, 0x10, rng_b);
    EXPECT_NE(ea.buf, eb.buf);
}
#endif

} // namespace
