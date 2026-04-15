/**
 * @file guard_tls_installer_test.cpp
 * @brief [TESTS] Unit tests for `mx::guard::emit_guard_tls_installer`.
 *
 * The TLS installer wraps a Hell's Gate resolver block whose exact
 * bytes vary slightly per build (salted DJB2 hash bakes into the
 * scan loop), so the tests focus on:
 *
 *   * Deterministic output for an identical RNG seed.
 *   * The static prefix (`cmp edx, 1; jne ...; sub rsp, 0x28`) and
 *     static suffix (`mov ecx, 1; lea rdx; call r13; add rsp, 0x28;
 *     xor eax, eax; ret`) match their expected bytes.
 *   * The returned patch-slot offsets point at a 4-byte zero
 *     placeholder — the rel32 the caller back-patches with the
 *     VEH handler's relative offset.
 *   * Overall size is in a sensible range (prefix + Hell's Gate
 *     resolver + suffix ≈ 150-300 bytes).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_tls_installer.hpp"

namespace {

using mx::ByteBuffer;
using mx::Randomizer;
using mx::RawEmitter;
using mx::guard::emit_guard_tls_installer;
using mx::guard::GuardTlsInstallerEmit;

[[nodiscard]] uint32_t read_u32_le(const ByteBuffer& buf, size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, buf.data() + off, sizeof(v));
    return v;
}

// ---------------------------------------------------------------------------
// Static prefix: cmp edx, 1; jne rel8; sub rsp, 0x28
// ---------------------------------------------------------------------------

TEST(GuardTlsInstaller, PrefixMatchesReasonCheckAndFrameSetup) {
    RawEmitter e;
    Randomizer rng(0x12345678u);
    (void)emit_guard_tls_installer(e, rng);

    // cmp edx, 1             83 FA 01        @0..2
    EXPECT_EQ(e.buf[0], 0x83u);
    EXPECT_EQ(e.buf[1], 0xFAu);
    EXPECT_EQ(e.buf[2], 0x01u);

    // jne rel8               75 ??           @3..4
    EXPECT_EQ(e.buf[3], 0x75u);

    // sub rsp, 0x28          48 83 EC 28     @5..8
    EXPECT_EQ(e.buf[5], 0x48u);
    EXPECT_EQ(e.buf[6], 0x83u);
    EXPECT_EQ(e.buf[7], 0xECu);
    EXPECT_EQ(e.buf[8], 0x28u);
}

// ---------------------------------------------------------------------------
// Deterministic output for an identical RNG seed
// ---------------------------------------------------------------------------

TEST(GuardTlsInstaller, DeterministicForIdenticalSeeds) {
    RawEmitter a, b;
    Randomizer rng_a(0xDEADBEEFu);
    Randomizer rng_b(0xDEADBEEFu);

    auto pa = emit_guard_tls_installer(a, rng_a);
    auto pb = emit_guard_tls_installer(b, rng_b);

    EXPECT_EQ(a.buf, b.buf);
    EXPECT_EQ(pa.handler_rel32_offset, pb.handler_rel32_offset);
    EXPECT_EQ(pa.handler_rel32_end_offset, pb.handler_rel32_end_offset);
}

// ---------------------------------------------------------------------------
// Different seeds → Hell's Gate body diverges but the static prefix
// and suffix stay the same.
// ---------------------------------------------------------------------------

TEST(GuardTlsInstaller, DifferentSeedsDivergeInResolverOnly) {
    RawEmitter a, b;
    Randomizer rng_a(1u);
    Randomizer rng_b(2u);
    (void)emit_guard_tls_installer(a, rng_a);
    (void)emit_guard_tls_installer(b, rng_b);

    ASSERT_EQ(a.size(), b.size())
        << "The same static prefix/suffix around the Hell's Gate "
           "block keeps the total size seed-independent";

    // Prefix bytes must match.
    for (size_t i = 0; i < 9; ++i) {
        EXPECT_EQ(a.buf[i], b.buf[i])
            << "Prefix byte mismatch at offset " << i;
    }

    // Somewhere between prefix and suffix, the Hell's Gate block
    // differs — otherwise the salted hash isn't actually influencing
    // emission.
    bool found_difference = false;
    for (size_t i = 9; i + 20 < a.size(); ++i) {
        if (a.buf[i] != b.buf[i]) {
            found_difference = true;
            break;
        }
    }
    EXPECT_TRUE(found_difference)
        << "Expected Hell's Gate block to vary across seeds";
}

// ---------------------------------------------------------------------------
// Suffix check: mov ecx, 1; lea rdx; call r13; add rsp 0x28; xor eax; ret
// ---------------------------------------------------------------------------

TEST(GuardTlsInstaller, SuffixShapeMatchesAddVehCall) {
    RawEmitter e;
    Randomizer rng(0x42u);
    const auto p = emit_guard_tls_installer(e, rng);

    // The `lea rdx, [rip + rel32]` rel32 starts at
    // `p.handler_rel32_offset`. We can work outward from there:
    //
    //   mov ecx, 1             B9 01 00 00 00   (5 bytes) before
    //   48 8D 15                                (3 bytes) opcode
    //   <rel32 placeholder>                     (4 bytes)
    //   41 FF D5               call r13         (3 bytes) after
    //   48 83 C4 28            add rsp, 0x28    (4 bytes)
    //   31 C0                  xor eax, eax     (2 bytes)
    //   C3                     ret              (1 byte)
    //
    // handler_rel32_offset points at the 4-byte rel32, so the
    // opcode bytes precede it at `offset - 3`, and the mov ecx
    // precedes THAT at `offset - 8`.
    const uint32_t rel32_off = p.handler_rel32_offset;
    ASSERT_GE(rel32_off, 8u);

    // mov ecx, 1 — 5 bytes ending at rel32_off - 3
    EXPECT_EQ(e.buf[rel32_off - 8], 0xB9u);
    EXPECT_EQ(e.buf[rel32_off - 7], 0x01u);
    EXPECT_EQ(e.buf[rel32_off - 6], 0x00u);
    EXPECT_EQ(e.buf[rel32_off - 5], 0x00u);
    EXPECT_EQ(e.buf[rel32_off - 4], 0x00u);

    // lea rdx, [rip + rel32] opcode — 3 bytes right before the rel32
    EXPECT_EQ(e.buf[rel32_off - 3], 0x48u);
    EXPECT_EQ(e.buf[rel32_off - 2], 0x8Du);
    EXPECT_EQ(e.buf[rel32_off - 1], 0x15u);

    // rel32 slot is zero-initialised (caller back-patches).
    EXPECT_EQ(read_u32_le(e.buf, rel32_off), 0u);
    EXPECT_EQ(p.handler_rel32_end_offset, rel32_off + 4);

    // call r13 — 3 bytes immediately after the rel32 slot.
    EXPECT_EQ(e.buf[rel32_off + 4], 0x41u);
    EXPECT_EQ(e.buf[rel32_off + 5], 0xFFu);
    EXPECT_EQ(e.buf[rel32_off + 6], 0xD5u);

    // add rsp, 0x28 — 4 bytes after call r13.
    EXPECT_EQ(e.buf[rel32_off + 7],  0x48u);
    EXPECT_EQ(e.buf[rel32_off + 8],  0x83u);
    EXPECT_EQ(e.buf[rel32_off + 9],  0xC4u);
    EXPECT_EQ(e.buf[rel32_off + 10], 0x28u);

    // xor eax, eax; ret — final 3 bytes.
    EXPECT_EQ(e.buf[rel32_off + 11], 0x31u);
    EXPECT_EQ(e.buf[rel32_off + 12], 0xC0u);
    EXPECT_EQ(e.buf[rel32_off + 13], 0xC3u);
}

// ---------------------------------------------------------------------------
// Overall size is in the expected envelope.
// ---------------------------------------------------------------------------

TEST(GuardTlsInstaller, SizeInReasonableRange) {
    RawEmitter e;
    Randomizer rng(0xAAAAAAAAu);
    (void)emit_guard_tls_installer(e, rng);
    // Prefix (9) + Hell's Gate (~155) + suffix (~17) ≈ 180 bytes.
    // We allow a generous 150..350 window so minor Hell's Gate
    // tweaks don't break the test unintentionally.
    EXPECT_GE(e.size(), 150u);
    EXPECT_LE(e.size(), 350u);
}

} // namespace
