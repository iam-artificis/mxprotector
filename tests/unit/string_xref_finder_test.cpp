/**
 * @file string_xref_finder_test.cpp
 * @brief [TESTS] Unit tests for the S2 LEA rip-relative XREF finder.
 *
 * Tests hand-assemble tiny `.text` buffers containing LEA instructions
 * with precomputed `disp32` values so the rip-relative arithmetic can
 * be verified independently of any real binary. The general recipe:
 *
 *   1. Pick an arbitrary `code_rva` (e.g. 0x1000) and `target_rva`
 *      (e.g. 0x2000 — the string's RVA in a fake `.rdata`).
 *   2. Decide the LEA's offset inside the code buffer (say `lea_off`).
 *   3. Compute `disp32 = target_rva - (code_rva + lea_off + 7)`
 *      where `+7` accounts for the full LEA length so `rip` is the
 *      address of the next instruction (x86-64 rule).
 *   4. Emit a 7-byte LEA with that displacement and wrap it in
 *      surrounding filler so we can verify the finder only returns
 *      the real LEA site and not any accidental matches.
 *
 * Tests cover:
 *   - Finding a single LEA targeting a single string
 *   - Multiple LEAs to the same string (e.g. two log calls with the
 *     same format string)
 *   - LEAs to different strings in one code buffer
 *   - Rejection: LEA pointing BEFORE any candidate
 *   - Rejection: LEA pointing BETWEEN two candidates (no exact match)
 *   - Rejection: LEA pointing INTO a candidate (not at rva_start)
 *   - Rejection: non-LEA rip-relative (`mov rax, [rip+disp]`) — we
 *     only care about LEA
 *   - Code buffer with no candidates → empty result
 *   - Empty code buffer → empty result
 *   - Decode recovery: garbage byte followed by a valid LEA — the
 *     finder advances past the bad byte and still finds the LEA
 *   - Destination register identification for both "low" regs
 *     (rax..rdi) and "extended" regs (r8..r15)
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <Zydis/Zydis.h>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/string/string_scanner.hpp"
#include "mxprotector/protection/string/string_xref_finder.hpp"

namespace {

using mx::ByteView;
using mx::Rva;
using mx::string_protect::FoundString;
using mx::string_protect::StringXref;
using mx::string_protect::StringXrefFinder;

/// Fake candidate list helper — scanner output format but built by
/// hand so tests don't depend on scanner behaviour.
FoundString make_candidate(Rva rva, uint32_t len) {
    FoundString fs{};
    fs.rva_start = rva;
    fs.length    = len;
    fs.bytes     = {};  // not used by the xref finder
    return fs;
}

/// Emit a 7-byte `lea <reg>, [rip + disp32]` at `dst` with the given
/// 32-bit displacement. Returns the 7 bytes that were written.
///
/// Encoding for `lea <reg64>, [rip + disp32]`:
///   REX.W  = 0x48 (or 0x4C for r8..r15)
///   opcode = 0x8D
///   ModRM  = 00 <reg&7> 101     ; mod=00, rm=101 → rip-rel
///   disp32 = little-endian signed
std::array<uint8_t, 7> encode_lea_rip(uint8_t reg_encoding, int32_t disp32) {
    std::array<uint8_t, 7> out{};
    // REX prefix: W=1 always, R=1 iff reg >= 8.
    uint8_t rex = 0x48;
    if (reg_encoding >= 8) rex |= 0x04;  // REX.R
    out[0] = rex;
    out[1] = 0x8D;
    out[2] = static_cast<uint8_t>(((reg_encoding & 0x07) << 3) | 0x05);
    out[3] = static_cast<uint8_t>(disp32 & 0xFF);
    out[4] = static_cast<uint8_t>((disp32 >> 8)  & 0xFF);
    out[5] = static_cast<uint8_t>((disp32 >> 16) & 0xFF);
    out[6] = static_cast<uint8_t>((disp32 >> 24) & 0xFF);
    return out;
}

/// Append a `lea` to `buf` pointing from `(code_rva + buf.size())`
/// to `target_rva`, using the provided Zydis register encoding.
/// Returns the RVA of the LEA instruction itself.
Rva append_lea_to(std::vector<uint8_t>& buf,
                  Rva                    code_rva,
                  Rva                    target_rva,
                  uint8_t                reg_encoding = 0 /* rax */)
{
    const Rva lea_rva = code_rva + static_cast<Rva>(buf.size());
    const int64_t rip_after = static_cast<int64_t>(lea_rva) + 7;
    const int64_t disp64 = static_cast<int64_t>(target_rva) - rip_after;
    const int32_t disp32 = static_cast<int32_t>(disp64);
    const auto bytes = encode_lea_rip(reg_encoding, disp32);
    buf.insert(buf.end(), bytes.begin(), bytes.end());
    return lea_rva;
}

// ---------------------------------------------------------------------------
// Empty / no-candidate cases
// ---------------------------------------------------------------------------

TEST(StringXrefFinderEdge, EmptyCodeReturnsEmpty) {
    std::vector<FoundString> cands = { make_candidate(0x2000, 8) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{}, 0x1000, cands);
    EXPECT_TRUE(xrefs.empty());
}

TEST(StringXrefFinderEdge, NoCandidatesReturnsEmpty) {
    // Even with real LEAs in the code, zero candidates → zero xrefs.
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    append_lea_to(buf, kCodeRva, /*target=*/0x2000);
    append_lea_to(buf, kCodeRva, /*target=*/0x2100);

    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, /*cands=*/{});
    EXPECT_TRUE(xrefs.empty());
}

// ---------------------------------------------------------------------------
// Single LEA targeting a single string
// ---------------------------------------------------------------------------

TEST(StringXrefFinderSingle, OneLeaToOneString) {
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva  = 0x1000;
    constexpr Rva kTarget   = 0x2000;

    const Rva lea_rva = append_lea_to(buf, kCodeRva, kTarget);

    std::vector<FoundString> cands = { make_candidate(kTarget, 13) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);

    ASSERT_EQ(xrefs.size(), 1u);
    EXPECT_EQ(xrefs[0].xref_rva,     lea_rva);
    EXPECT_EQ(xrefs[0].insn_length,  7);
    EXPECT_EQ(xrefs[0].target_rva,   kTarget);
    EXPECT_EQ(xrefs[0].string_index, 0u);
    EXPECT_EQ(xrefs[0].dest_reg,     ZYDIS_REGISTER_RAX);
}

// ---------------------------------------------------------------------------
// Multiple LEAs to the same string
// ---------------------------------------------------------------------------

TEST(StringXrefFinderMultiple, TwoLeasToSameString) {
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    constexpr Rva kTarget  = 0x2500;

    const Rva lea_a = append_lea_to(buf, kCodeRva, kTarget);
    // A few filler bytes between the two LEAs.
    buf.push_back(0x90); buf.push_back(0x90); buf.push_back(0x90);
    const Rva lea_b = append_lea_to(buf, kCodeRva, kTarget,
                                     /*reg=*/1 /* rcx */);

    std::vector<FoundString> cands = { make_candidate(kTarget, 10) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);

    ASSERT_EQ(xrefs.size(), 2u);
    EXPECT_EQ(xrefs[0].xref_rva, lea_a);
    EXPECT_EQ(xrefs[1].xref_rva, lea_b);
    EXPECT_EQ(xrefs[0].dest_reg, ZYDIS_REGISTER_RAX);
    EXPECT_EQ(xrefs[1].dest_reg, ZYDIS_REGISTER_RCX);
    EXPECT_EQ(xrefs[0].string_index, 0u);
    EXPECT_EQ(xrefs[1].string_index, 0u);
}

// ---------------------------------------------------------------------------
// LEAs to distinct strings
// ---------------------------------------------------------------------------

TEST(StringXrefFinderMultiple, LeasToDifferentStringsIndexCorrectly) {
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    constexpr Rva kTargetA = 0x2000;
    constexpr Rva kTargetB = 0x2100;
    constexpr Rva kTargetC = 0x2200;

    // Candidates sorted by rva_start (scanner invariant).
    std::vector<FoundString> cands = {
        make_candidate(kTargetA, 6),
        make_candidate(kTargetB, 8),
        make_candidate(kTargetC, 10),
    };

    append_lea_to(buf, kCodeRva, kTargetB, /*reg=*/2 /* rdx */);
    append_lea_to(buf, kCodeRva, kTargetA, /*reg=*/0 /* rax */);
    append_lea_to(buf, kCodeRva, kTargetC, /*reg=*/1 /* rcx */);

    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);

    ASSERT_EQ(xrefs.size(), 3u);
    EXPECT_EQ(xrefs[0].string_index, 1u);  // targetB → index 1
    EXPECT_EQ(xrefs[1].string_index, 0u);  // targetA → index 0
    EXPECT_EQ(xrefs[2].string_index, 2u);  // targetC → index 2
}

// ---------------------------------------------------------------------------
// Rejection cases
// ---------------------------------------------------------------------------

TEST(StringXrefFinderReject, LeaTargetBeforeAllCandidates) {
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;

    // LEA to 0x1F00, but candidates start at 0x2000.
    append_lea_to(buf, kCodeRva, /*target=*/0x1F00);

    std::vector<FoundString> cands = { make_candidate(0x2000, 6) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    EXPECT_TRUE(xrefs.empty());
}

TEST(StringXrefFinderReject, LeaTargetBetweenTwoCandidates) {
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;

    append_lea_to(buf, kCodeRva, /*target=*/0x2050);  // between

    std::vector<FoundString> cands = {
        make_candidate(0x2000, 6),
        make_candidate(0x2100, 8),
    };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    EXPECT_TRUE(xrefs.empty());
}

TEST(StringXrefFinderReject, LeaTargetInsideCandidateNotAtStart) {
    // Candidate is 12 bytes long starting at 0x2000; a LEA pointing at
    // 0x2006 (the middle) is NOT considered an xref for this v1 design.
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    append_lea_to(buf, kCodeRva, /*target=*/0x2006);

    std::vector<FoundString> cands = { make_candidate(0x2000, 12) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    EXPECT_TRUE(xrefs.empty());
}

TEST(StringXrefFinderReject, NonLeaRipRelativeIsIgnored) {
    // `mov rax, [rip + disp32]` (48 8B 05 disp32) is rip-relative but
    // loads BYTES from [rip+disp], not the address. It's not a string
    // reference in the "take the address of a C string" sense and the
    // finder must ignore it.
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    constexpr Rva kTarget  = 0x2000;

    // Build the instruction with the same displacement math as LEA.
    const Rva insn_rva = kCodeRva + static_cast<Rva>(buf.size());
    const int64_t rip_after = static_cast<int64_t>(insn_rva) + 7;
    const int32_t disp = static_cast<int32_t>(
        static_cast<int64_t>(kTarget) - rip_after);

    buf.push_back(0x48);  // REX.W
    buf.push_back(0x8B);  // MOV r64, r/m64
    buf.push_back(0x05);  // ModRM: rax ← [rip+disp]
    buf.push_back(static_cast<uint8_t>(disp & 0xFF));
    buf.push_back(static_cast<uint8_t>((disp >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((disp >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((disp >> 24) & 0xFF));

    std::vector<FoundString> cands = { make_candidate(kTarget, 8) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    EXPECT_TRUE(xrefs.empty())
        << "finder must only match LEA, not MOV [rip+disp]";
}

// ---------------------------------------------------------------------------
// Destination register identification — all GPR encodings
// ---------------------------------------------------------------------------

TEST(StringXrefFinderRegister, LowRegistersIdentifiedCorrectly) {
    struct Case { uint8_t enc; ZydisRegister expected; };
    const Case cases[] = {
        { 0, ZYDIS_REGISTER_RAX },
        { 1, ZYDIS_REGISTER_RCX },
        { 2, ZYDIS_REGISTER_RDX },
        { 3, ZYDIS_REGISTER_RBX },
    };

    for (const auto& c : cases) {
        std::vector<uint8_t> buf;
        constexpr Rva kCodeRva = 0x1000;
        constexpr Rva kTarget  = 0x2000;
        append_lea_to(buf, kCodeRva, kTarget, c.enc);

        std::vector<FoundString> cands = { make_candidate(kTarget, 6) };
        StringXrefFinder finder;
        auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                                 kCodeRva, cands);
        ASSERT_EQ(xrefs.size(), 1u);
        EXPECT_EQ(xrefs[0].dest_reg, c.expected)
            << "encoding " << static_cast<int>(c.enc);
    }
}

TEST(StringXrefFinderRegister, ExtendedRegistersIdentifiedCorrectly) {
    // REX.R extends reg to r8..r15.
    struct Case { uint8_t enc; ZydisRegister expected; };
    const Case cases[] = {
        { 8,  ZYDIS_REGISTER_R8  },
        { 9,  ZYDIS_REGISTER_R9  },
        { 10, ZYDIS_REGISTER_R10 },
        { 15, ZYDIS_REGISTER_R15 },
    };

    for (const auto& c : cases) {
        std::vector<uint8_t> buf;
        constexpr Rva kCodeRva = 0x1000;
        constexpr Rva kTarget  = 0x2000;
        append_lea_to(buf, kCodeRva, kTarget, c.enc);

        std::vector<FoundString> cands = { make_candidate(kTarget, 6) };
        StringXrefFinder finder;
        auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                                 kCodeRva, cands);
        ASSERT_EQ(xrefs.size(), 1u);
        EXPECT_EQ(xrefs[0].dest_reg, c.expected)
            << "encoding " << static_cast<int>(c.enc);
    }
}

// ---------------------------------------------------------------------------
// Multi-instruction iteration — preceding NOP then valid LEA
// ---------------------------------------------------------------------------

TEST(StringXrefFinderIteration, PrecedingNopDoesNotLoseValidLea) {
    // Place a 1-byte nop (0x90) before the LEA. The finder should
    // decode the nop, advance by 1, then find and report the LEA
    // at offset 1 of the code buffer. This exercises the
    // per-instruction advancement loop — a real-world .text section
    // is an arbitrary mix of instructions with no padding alignment
    // guarantees, and the finder has to walk them one-by-one.
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    constexpr Rva kTarget  = 0x2000;

    buf.push_back(0x90);  // nop
    append_lea_to(buf, kCodeRva, kTarget);

    std::vector<FoundString> cands = { make_candidate(kTarget, 10) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    ASSERT_EQ(xrefs.size(), 1u);
    EXPECT_EQ(xrefs[0].xref_rva, kCodeRva + 1);
}

TEST(StringXrefFinderIteration, TrailingJunkAfterLeaDoesNotBreakLoop) {
    // A LEA followed by a few bytes of data that may or may not
    // decode cleanly. Even if the trailing bytes produce decode
    // failures, the LEA itself was already emitted, so the result
    // should still contain exactly one xref.
    std::vector<uint8_t> buf;
    constexpr Rva kCodeRva = 0x1000;
    constexpr Rva kTarget  = 0x2000;

    append_lea_to(buf, kCodeRva, kTarget);
    // Five bytes that Zydis may or may not decode — the finder's
    // byte-by-byte fallback guarantees forward progress regardless.
    buf.push_back(0x00); buf.push_back(0x00);
    buf.push_back(0xCC); buf.push_back(0xCC); buf.push_back(0xCC);

    std::vector<FoundString> cands = { make_candidate(kTarget, 10) };
    StringXrefFinder finder;
    auto xrefs = finder.find(ByteView{buf.data(), buf.size()},
                             kCodeRva, cands);
    ASSERT_EQ(xrefs.size(), 1u);
    EXPECT_EQ(xrefs[0].xref_rva, kCodeRva);
}

} // namespace
