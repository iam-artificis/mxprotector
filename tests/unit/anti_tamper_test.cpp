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
#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"

namespace {

using mx::Randomizer;
using mx::RawEmitter;
using mx::anti_tamper::CheckContext;
using mx::anti_tamper::CheckRegistry;
using mx::anti_tamper::djb2_ascii_hash;
using mx::anti_tamper::emit_hells_gate_resolver;
using mx::anti_tamper::ICheck;

/// Default context used by tests that don't care about entry_offset.
/// Self-CRC testing supplies its own with a non-zero offset.
const CheckContext kEmptyContext{};

/// Look up a check by its `name()` — keeps tests independent of the
/// registry's iteration order.
const ICheck* find_check(const CheckRegistry& reg, const char* name) {
    for (size_t i = 0; i < reg.size(); ++i) {
        if (std::string_view{reg.at(i).name()} == name) return &reg.at(i);
    }
    return nullptr;
}

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

TEST(AntiTamperRegistry, ContainsAllExpectedChecks) {
    CheckRegistry reg;
    EXPECT_EQ(reg.size(), 4u);

    bool has_hw_bp = false;
    bool has_import_hook = false;
    bool has_self_crc = false;
    bool has_page_prot = false;
    for (size_t i = 0; i < reg.size(); ++i) {
        const std::string_view n{reg.at(i).name()};
        if (n == "hw_breakpoint_sweep")  has_hw_bp = true;
        if (n == "import_hook_detect")   has_import_hook = true;
        if (n == "self_crc")             has_self_crc = true;
        if (n == "page_protection")      has_page_prot = true;
    }
    EXPECT_TRUE(has_hw_bp);
    EXPECT_TRUE(has_import_hook);
    EXPECT_TRUE(has_self_crc);
    EXPECT_TRUE(has_page_prot);
}

TEST(AntiTamperRegistry, RequiredSyscallHashPerCheck) {
    // Each check must declare whether it needs a syscall-resolver
    // emission in front of it. HW BP + Page Protection → non-zero
    // hash; Import Hook + Self-CRC → 0.
    CheckRegistry reg;
    const ICheck* hw_bp      = find_check(reg, "hw_breakpoint_sweep");
    const ICheck* import_hk  = find_check(reg, "import_hook_detect");
    const ICheck* self_crc   = find_check(reg, "self_crc");
    const ICheck* page_prot  = find_check(reg, "page_protection");
    ASSERT_NE(hw_bp, nullptr);
    ASSERT_NE(import_hk, nullptr);
    ASSERT_NE(self_crc, nullptr);
    ASSERT_NE(page_prot, nullptr);

    // Syscall-needing checks advertise a non-null name.
    ASSERT_NE(hw_bp->required_syscall_name(), nullptr);
    EXPECT_STREQ(hw_bp->required_syscall_name(), "NtGetContextThread");

    ASSERT_NE(page_prot->required_syscall_name(), nullptr);
    EXPECT_STREQ(page_prot->required_syscall_name(), "NtQueryVirtualMemory");

    // User-mode checks don't need a resolver.
    EXPECT_EQ(import_hk->required_syscall_name(), nullptr);
    EXPECT_EQ(self_crc->required_syscall_name(), nullptr);
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

TEST(AntiTamperHwBreakpoint, EmitsNonEmptyAndEndsWithXorRspDisp8) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xABCDEF);
    RawEmitter e;
    constexpr int8_t kProbeDisp = 0x18;
    check->emit(e, kProbeDisp, rng, kEmptyContext);

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
    check->emit(e, 0x10, rng, kEmptyContext);

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
    check->emit(e, 0x10, rng, kEmptyContext);

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
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperHwBreakpoint, DiffersAcrossSeeds) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "hw_breakpoint_sweep");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_NE(ea.buf, eb.buf);
}

// ---------------------------------------------------------------------------
// PageProtectionCheck — byte-level invariants
// ---------------------------------------------------------------------------

TEST(AntiTamperPageProtection, EmitsNonEmptyAndEndsWithXorRspDisp8) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xC0FFEE);
    RawEmitter e;
    constexpr int8_t kProbeDisp = 0x28;
    check->emit(e, kProbeDisp, rng, kEmptyContext);

    ASSERT_GT(e.size(), 50u) << "check should be ~85 bytes";

    // Tail must be `xor [rsp + disp8], eax`: 31 44 24 disp8
    const size_t n = e.size();
    EXPECT_EQ(e.buf[n - 4], 0x31);
    EXPECT_EQ(e.buf[n - 3], 0x44);
    EXPECT_EQ(e.buf[n - 2], 0x24);
    EXPECT_EQ(static_cast<int8_t>(e.buf[n - 1]), kProbeDisp);
}

TEST(AntiTamperPageProtection, ContainsSyscallInstruction) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng(11);
    RawEmitter e;
    check->emit(e, 0x10, rng, kEmptyContext);

    bool has_syscall = false;
    for (size_t i = 0; i + 1 < e.size(); ++i) {
        if (e.buf[i] == 0x0F && e.buf[i + 1] == 0x05) {
            has_syscall = true;
            break;
        }
    }
    EXPECT_TRUE(has_syscall) << "no `0F 05` syscall byte pair in emitted body";
}

TEST(AntiTamperPageProtection, LoadsSsnFromR13) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng(1);
    RawEmitter e;
    check->emit(e, 0x10, rng, kEmptyContext);

    bool has_mov_from_r13 = false;
    for (size_t i = 0; i + 2 < e.size(); ++i) {
        if (e.buf[i] == 0x44 && e.buf[i+1] == 0x89 && e.buf[i+2] == 0xE8) {
            has_mov_from_r13 = true;
            break;
        }
    }
    EXPECT_TRUE(has_mov_from_r13)
        << "page protection check must read SSN from r13d";
}

TEST(AntiTamperPageProtection, MasksWriteBitsWithCC) {
    // The check must mask MBI.Protect with 0xCC (PAGE_READWRITE |
    // PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY).
    // That's emitted as `and eax, 0xCC` → 25 CC 00 00 00.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng(5);
    RawEmitter e;
    check->emit(e, 0x10, rng, kEmptyContext);

    bool has_and_cc = false;
    for (size_t i = 0; i + 4 < e.size(); ++i) {
        if (e.buf[i]   == 0x25 && e.buf[i+1] == 0xCC
         && e.buf[i+2] == 0x00 && e.buf[i+3] == 0x00
         && e.buf[i+4] == 0x00)
        {
            has_and_cc = true;
            break;
        }
    }
    EXPECT_TRUE(has_and_cc)
        << "expected `and eax, 0xCC` (25 CC 00 00 00) in emitted body";
}

TEST(AntiTamperPageProtection, DeterministicForSameSeed) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(0xBEEF);
    Randomizer rng_b(0xBEEF);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperPageProtection, DiffersAcrossSeeds) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "page_protection");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_NE(ea.buf, eb.buf);
}

// ---------------------------------------------------------------------------
// ImportHookDetectCheck
// ---------------------------------------------------------------------------

TEST(AntiTamperImportHook, EmitsNonEmptyAndStartsWithPebRead) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "import_hook_detect");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xFEED);
    RawEmitter e;
    check->emit(e, 0x20, rng, kEmptyContext);

    ASSERT_GT(e.size(), 100u) << "import hook check should be ~150 bytes";

    // Must start with `mov rax, gs:[0x60]` (65 48 8B 04 25 60 00 00 00).
    ASSERT_GE(e.size(), 9u);
    EXPECT_EQ(e.buf[0], 0x65);
    EXPECT_EQ(e.buf[1], 0x48);
    EXPECT_EQ(e.buf[2], 0x8B);
    EXPECT_EQ(e.buf[3], 0x04);
    EXPECT_EQ(e.buf[4], 0x25);
    EXPECT_EQ(e.buf[5], 0x60);
}

TEST(AntiTamperImportHook, ContainsPrologueLiteral) {
    // The check must contain the expected syscall prologue
    // literal `4C 8B D1 B8` as bytes inside a `cmp dword [rdi], imm32`.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "import_hook_detect");
    ASSERT_NE(check, nullptr);

    Randomizer rng(1);
    RawEmitter e;
    check->emit(e, 0x10, rng, kEmptyContext);

    bool has_prologue_lit = false;
    for (size_t i = 0; i + 3 < e.size(); ++i) {
        if (e.buf[i]   == 0x4C && e.buf[i+1] == 0x8B
         && e.buf[i+2] == 0xD1 && e.buf[i+3] == 0xB8)
        {
            has_prologue_lit = true;
            break;
        }
    }
    EXPECT_TRUE(has_prologue_lit)
        << "expected 4C 8B D1 B8 syscall-stub prologue literal in check body";
}

TEST(AntiTamperImportHook, EndsWithXorRspDisp8) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "import_hook_detect");
    ASSERT_NE(check, nullptr);

    Randomizer rng(7);
    RawEmitter e;
    constexpr int8_t kProbeDisp = 0x30;
    check->emit(e, kProbeDisp, rng, kEmptyContext);

    const size_t n = e.size();
    EXPECT_EQ(e.buf[n - 4], 0x31);
    EXPECT_EQ(e.buf[n - 3], 0x44);
    EXPECT_EQ(e.buf[n - 2], 0x24);
    EXPECT_EQ(static_cast<int8_t>(e.buf[n - 1]), kProbeDisp);
}

TEST(AntiTamperImportHook, DeterministicForSameSeed) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "import_hook_detect");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(0x1234);
    Randomizer rng_b(0x1234);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperImportHook, DiffersAcrossSeeds) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "import_hook_detect");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(2);
    RawEmitter ea, eb;
    check->emit(ea, 0x10, rng_a, kEmptyContext);
    check->emit(eb, 0x10, rng_b, kEmptyContext);
    EXPECT_NE(ea.buf, eb.buf);
}

// ---------------------------------------------------------------------------
// SelfCrcCheck
// ---------------------------------------------------------------------------

/// Helper: pre-fill the emitter with N pseudo-random bytes (simulating
/// a partially-emitted entry stub), then run the Self-CRC check on top.
/// Returns the position at which the check started emitting.
size_t prefill_and_emit_self_crc(RawEmitter& e, const ICheck* check,
                                  size_t prefix_bytes,
                                  int32_t key_disp,
                                  Randomizer& rng)
{
    // Fill prefix with a fixed pattern so the expected CRC is stable
    // across test runs.
    for (size_t i = 0; i < prefix_bytes; ++i) {
        e.u8(static_cast<uint8_t>((i * 31u + 7u) & 0xFFu));
    }
    const size_t check_start = e.size();
    const CheckContext ctx{/*entry_offset=*/0};  // whole buffer counts
    check->emit(e, key_disp, rng, ctx);
    return check_start;
}

TEST(AntiTamperSelfCrc, EmitsRoughlyExpectedSize) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xBABE);
    RawEmitter e;
    const size_t start = prefill_and_emit_self_crc(e, check, 64, 0x10, rng);
    const size_t check_bytes = e.size() - start;
    EXPECT_GE(check_bytes, 40u);
    EXPECT_LE(check_bytes, 80u);
}

TEST(AntiTamperSelfCrc, ContainsHardwareCrc32Opcode) {
    // The check uses the SSE4.2 `crc32 eax, byte [rsi]` instruction,
    // encoded as F2 0F 38 F0 06.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng(0xBABE);
    RawEmitter e;
    prefill_and_emit_self_crc(e, check, 64, 0x10, rng);

    bool has_crc32 = false;
    for (size_t i = 0; i + 4 < e.size(); ++i) {
        if (e.buf[i]   == 0xF2 && e.buf[i+1] == 0x0F
         && e.buf[i+2] == 0x38 && e.buf[i+3] == 0xF0
         && e.buf[i+4] == 0x06)
        {
            has_crc32 = true;
            break;
        }
    }
    EXPECT_TRUE(has_crc32) << "expected F2 0F 38 F0 06 (crc32 eax, [rsi])";
}

TEST(AntiTamperSelfCrc, ContainsNegativeLeaRel32) {
    // The check starts with `lea rsi, [rip + rel32]` where rel32 is
    // negative (points backwards at the entry-stub start). Verify the
    // instruction is there and its rel32 has the sign bit set.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng(1);
    RawEmitter e;
    const size_t start = prefill_and_emit_self_crc(e, check, 64, 0x10, rng);

    // The check's first 3 bytes should be 48 8D 35 (lea rsi, [rip+...]),
    // followed by a 32-bit rel32.
    ASSERT_GE(e.size() - start, 7u);
    EXPECT_EQ(e.buf[start + 0], 0x48);
    EXPECT_EQ(e.buf[start + 1], 0x8D);
    EXPECT_EQ(e.buf[start + 2], 0x35);
    // Read rel32 little-endian
    const uint32_t rel32 =
         static_cast<uint32_t>(e.buf[start + 3])
      | (static_cast<uint32_t>(e.buf[start + 4]) << 8)
      | (static_cast<uint32_t>(e.buf[start + 5]) << 16)
      | (static_cast<uint32_t>(e.buf[start + 6]) << 24);
    const int32_t rel32s = static_cast<int32_t>(rel32);
    EXPECT_LT(rel32s, 0)
        << "rel32 should point backwards at the entry-stub start";
}

TEST(AntiTamperSelfCrc, DegradesSafelyOnEmptyRange) {
    // If entry_offset == current position, the check has nothing to
    // CRC and must degrade to a safe no-op (eax = 0, xor into slot).
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng(1);
    RawEmitter e;
    const CheckContext ctx{/*entry_offset=*/0};
    check->emit(e, 0x10, rng, ctx);

    // Very short body (just xor eax,eax + xor [rsp+disp], eax = 6 bytes).
    EXPECT_LT(e.size(), 16u);
    // Final instruction must still be the key-slot XOR.
    ASSERT_GE(e.size(), 4u);
    const size_t n = e.size();
    EXPECT_EQ(e.buf[n - 4], 0x31);
    EXPECT_EQ(e.buf[n - 3], 0x44);
    EXPECT_EQ(e.buf[n - 2], 0x24);
}

TEST(AntiTamperSelfCrc, DeterministicForSameSeedAndPrefix) {
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(0xDEAD);
    Randomizer rng_b(0xDEAD);
    RawEmitter ea, eb;
    prefill_and_emit_self_crc(ea, check, 64, 0x10, rng_a);
    prefill_and_emit_self_crc(eb, check, 64, 0x10, rng_b);
    EXPECT_EQ(ea.buf, eb.buf);
}

TEST(AntiTamperSelfCrc, DifferentPrefixProducesDifferentExpectedCrc) {
    // Two checks emitted over two different prefixes must have
    // different `cmp eax, imm32` operands AFTER finalization —
    // the expected CRC is deferred until `finalize_self_crc_patches`
    // runs, so tests must invoke it explicitly (the X64 backend
    // does so at the end of its patch pass).
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    Randomizer rng_a(1);
    Randomizer rng_b(1);

    // Two different prefixes of the same length.
    RawEmitter ea, eb;
    for (size_t i = 0; i < 64; ++i) ea.u8(static_cast<uint8_t>(i));
    for (size_t i = 0; i < 64; ++i) eb.u8(static_cast<uint8_t>(0xFF - i));

    std::vector<mx::anti_tamper::SelfCrcPatchRecord> patches_a, patches_b;
    CheckContext ctx_a{};
    ctx_a.entry_offset     = 0;
    ctx_a.self_crc_patches = &patches_a;
    CheckContext ctx_b{};
    ctx_b.entry_offset     = 0;
    ctx_b.self_crc_patches = &patches_b;
    check->emit(ea, 0x10, rng_a, ctx_a);
    check->emit(eb, 0x10, rng_b, ctx_b);

    // Both checks should have recorded one patch record each.
    ASSERT_EQ(patches_a.size(), 1u);
    ASSERT_EQ(patches_b.size(), 1u);

    // Finalise both. This writes the CRC over the prefix bytes
    // into the placeholder imm32 position inside the check body.
    mx::anti_tamper::finalize_self_crc_patches(ea, patches_a);
    mx::anti_tamper::finalize_self_crc_patches(eb, patches_b);

    // Now the check bodies must differ in the 4 bytes at the
    // placeholder position.
    ASSERT_EQ(patches_a[0].placeholder_offset, patches_b[0].placeholder_offset);
    const size_t off = patches_a[0].placeholder_offset;
    const uint32_t crc_a =
         static_cast<uint32_t>(ea.buf[off])
      | (static_cast<uint32_t>(ea.buf[off+1]) << 8)
      | (static_cast<uint32_t>(ea.buf[off+2]) << 16)
      | (static_cast<uint32_t>(ea.buf[off+3]) << 24);
    const uint32_t crc_b =
         static_cast<uint32_t>(eb.buf[off])
      | (static_cast<uint32_t>(eb.buf[off+1]) << 8)
      | (static_cast<uint32_t>(eb.buf[off+2]) << 16)
      | (static_cast<uint32_t>(eb.buf[off+3]) << 24);
    EXPECT_NE(crc_a, crc_b)
        << "different prefixes should produce different finalised CRCs";
}

// ---------------------------------------------------------------------------
// Self-CRC behaviour tests — simulate clean + tampered buffers and verify
// the finalised check body would detect the tamper at runtime.
//
// These are build-time logical tests, not in-process execution of the
// emitted bytes (which would require VirtualAlloc + unsafe rsp
// manipulation + SEH). They instead verify the invariant that makes
// the runtime detection work: the baked imm32 in the check body
// corresponds exactly to `crc32c_sw(unchanged_prefix)`, which means:
//
//   * In a clean environment, the runtime loop computes the same
//     value, the `cmp` branch takes the clean path, key untouched.
//   * After ANY one-byte tamper in the prefix, the runtime loop
//     computes a different value, the `cmp` branch falls through,
//     the corruption mask is ORed into the key slot, the binary
//     crashes on the next VM dispatch.
// ---------------------------------------------------------------------------

TEST(AntiTamperSelfCrcBehavior, CleanBufferMatchesBakedCrc) {
    // Emit a check over a known prefix, finalize, then verify the
    // baked imm32 equals `crc32c_sw(prefix)`. This is the invariant
    // the runtime loop relies on — if it holds, a clean runtime run
    // will see eax == expected and take the no-op path.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    RawEmitter e;
    constexpr size_t kPrefixLen = 48;
    for (size_t i = 0; i < kPrefixLen; ++i) {
        e.u8(static_cast<uint8_t>((i * 13u + 5u) & 0xFFu));
    }

    std::vector<mx::anti_tamper::SelfCrcPatchRecord> patches;
    CheckContext ctx{};
    ctx.entry_offset     = 0;
    ctx.self_crc_patches = &patches;

    Randomizer rng(0xAABB);
    check->emit(e, 0x10, rng, ctx);

    ASSERT_EQ(patches.size(), 1u);
    mx::anti_tamper::finalize_self_crc_patches(e, patches);

    // Compute the expected CRC the same way the runtime loop would:
    // CRC32C over the first `kPrefixLen` bytes of the buffer.
    const uint32_t runtime_would_compute =
        mx::anti_tamper::crc32c_sw(e.buf.data(), kPrefixLen);

    // Read the imm32 baked at the placeholder.
    const size_t off = patches[0].placeholder_offset;
    const uint32_t baked =
         static_cast<uint32_t>(e.buf[off])
      | (static_cast<uint32_t>(e.buf[off+1]) << 8)
      | (static_cast<uint32_t>(e.buf[off+2]) << 16)
      | (static_cast<uint32_t>(e.buf[off+3]) << 24);

    EXPECT_EQ(baked, runtime_would_compute)
        << "baked imm32 must match what the runtime loop will compute";
}

TEST(AntiTamperSelfCrcBehavior, OneByteTamperInvalidatesCrc) {
    // After finalization, flip one byte in the prefix (simulating an
    // attacker patching the entry-stub code at runtime) and verify
    // the baked imm32 NO LONGER matches `crc32c_sw(tampered_prefix)`.
    // At runtime, this mismatch is exactly what drives the branch
    // that corrupts the key slot.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    RawEmitter e;
    constexpr size_t kPrefixLen = 48;
    for (size_t i = 0; i < kPrefixLen; ++i) {
        e.u8(static_cast<uint8_t>((i * 13u + 5u) & 0xFFu));
    }

    std::vector<mx::anti_tamper::SelfCrcPatchRecord> patches;
    CheckContext ctx{};
    ctx.entry_offset     = 0;
    ctx.self_crc_patches = &patches;

    Randomizer rng(0xCCDD);
    check->emit(e, 0x10, rng, ctx);
    mx::anti_tamper::finalize_self_crc_patches(e, patches);

    // Snapshot the baked CRC.
    const size_t off = patches[0].placeholder_offset;
    const uint32_t baked =
         static_cast<uint32_t>(e.buf[off])
      | (static_cast<uint32_t>(e.buf[off+1]) << 8)
      | (static_cast<uint32_t>(e.buf[off+2]) << 16)
      | (static_cast<uint32_t>(e.buf[off+3]) << 24);

    // Now simulate a runtime tamper: flip byte 10 of the prefix.
    // Do NOT re-finalize — the point is to show that the PRE-TAMPER
    // baked value disagrees with the POST-TAMPER buffer contents,
    // which is exactly what the runtime check catches.
    e.buf[10] ^= 0x01;

    // Compute what the runtime loop would see over the tampered
    // prefix.
    const uint32_t tampered_crc =
        mx::anti_tamper::crc32c_sw(e.buf.data(), kPrefixLen);

    EXPECT_NE(baked, tampered_crc)
        << "a one-byte tamper must invalidate the baked CRC — this "
           "mismatch is what drives runtime key corruption";
}

TEST(AntiTamperSelfCrcBehavior, TamperIsDetectedForEveryByte) {
    // Stronger version: verify every single byte of the prefix
    // contributes to the CRC, so tampering ANYWHERE triggers
    // detection. Iterates each byte, flips it, and confirms the
    // baked CRC never matches the tampered computation.
    CheckRegistry reg;
    const ICheck* check = find_check(reg, "self_crc");
    ASSERT_NE(check, nullptr);

    RawEmitter e;
    constexpr size_t kPrefixLen = 32;
    for (size_t i = 0; i < kPrefixLen; ++i) {
        e.u8(static_cast<uint8_t>(i * 7u + 1u));
    }

    std::vector<mx::anti_tamper::SelfCrcPatchRecord> patches;
    CheckContext ctx{};
    ctx.entry_offset     = 0;
    ctx.self_crc_patches = &patches;

    Randomizer rng(0xEEFF);
    check->emit(e, 0x10, rng, ctx);
    mx::anti_tamper::finalize_self_crc_patches(e, patches);

    const size_t off = patches[0].placeholder_offset;
    const uint32_t baked =
         static_cast<uint32_t>(e.buf[off])
      | (static_cast<uint32_t>(e.buf[off+1]) << 8)
      | (static_cast<uint32_t>(e.buf[off+2]) << 16)
      | (static_cast<uint32_t>(e.buf[off+3]) << 24);

    // Make a working copy of the prefix so each iteration can
    // mutate and restore without affecting the next.
    std::vector<uint8_t> prefix(e.buf.begin(), e.buf.begin() + kPrefixLen);

    int false_clean = 0;
    for (size_t i = 0; i < kPrefixLen; ++i) {
        const uint8_t original = prefix[i];
        prefix[i] ^= 0xFF;  // flip all bits of the byte
        const uint32_t tampered =
            mx::anti_tamper::crc32c_sw(prefix.data(), kPrefixLen);
        if (tampered == baked) ++false_clean;
        prefix[i] = original;
    }
    EXPECT_EQ(false_clean, 0)
        << false_clean << " byte positions did NOT change the CRC — "
           "a real attacker flipping one of them would bypass detection";
}

TEST(AntiTamperSelfCrc, FinalizePatchesUpdatesImm32) {
    // Smoke test the finalize function directly: construct a
    // contrived patch record and verify finalize writes the
    // expected CRC.
    RawEmitter e;
    // Prefix of 10 bytes + 4-byte placeholder.
    for (size_t i = 0; i < 10; ++i) e.u8(static_cast<uint8_t>(i));
    const size_t placeholder_off = e.size();
    e.u32(0xFFFFFFFFu);  // non-zero placeholder so we can see it change

    mx::anti_tamper::SelfCrcPatchRecord rec{};
    rec.placeholder_offset = placeholder_off;
    rec.range_start        = 0;
    rec.length             = 10;

    std::vector<mx::anti_tamper::SelfCrcPatchRecord> patches = {rec};
    mx::anti_tamper::finalize_self_crc_patches(e, patches);

    // Recompute the expected CRC using the same helper and compare.
    const uint32_t expected =
        mx::anti_tamper::crc32c_sw(e.buf.data(), 10);
    const uint32_t written =
         static_cast<uint32_t>(e.buf[placeholder_off])
      | (static_cast<uint32_t>(e.buf[placeholder_off+1]) << 8)
      | (static_cast<uint32_t>(e.buf[placeholder_off+2]) << 16)
      | (static_cast<uint32_t>(e.buf[placeholder_off+3]) << 24);
    EXPECT_EQ(written, expected);
    EXPECT_NE(written, 0xFFFFFFFFu);
}

} // namespace
