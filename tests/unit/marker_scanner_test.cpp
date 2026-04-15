/**
 * @file marker_scanner_test.cpp
 * @brief [TESTS] Unit tests for MarkerScanner — with focus on the newly
 *        added `MX_GUARD_BEGIN`/`MX_GUARD_END` pair (Commit 1 of the
 *        runtime-guards milestone).
 *
 * Covers:
 *   * Round-trip for every marker kind: a hand-crafted `mov rax, imm64`
 *     byte sequence feeds into a minimal `PeImage` and `find_markers`
 *     returns exactly the expected `MarkedRegion`.
 *   * `GUARD_BEGIN`/`GUARD_END` round-trip end-to-end: this is the new
 *     behaviour; if the scanner's type-byte bound check, `is_begin_marker`
 *     set, `matching_end_type` mapping, or `marker_type_name` switch
 *     forget to include the guard pair, one of the tests below fails.
 *   * Mixed markers in one section: a `VM_BEGIN/END` region and a
 *     `GUARD_BEGIN/END` region coexist and are both returned, ordered by
 *     `start_rva`.
 *   * Orphan `GUARD_BEGIN` (no matching end) → error.
 *   * Orphan `GUARD_END` (no preceding begin) → error.
 *   * Zero-size guard region (begin immediately followed by end, no body
 *     bytes between them) → error with `region_too_small`.
 *   * Non-code section is ignored — the scanner only walks code sections
 *     (see the `is_code()` filter inside `MarkerScanner::find_markers`).
 *
 * The tests deliberately construct a minimal `PeImage` by hand (default
 * constructor + `set_sections`) and drive `find_markers` through its
 * public surface. They do NOT touch the private `scan_section` helper;
 * keeping the test surface aligned with the public API means future
 * refactors of the scanner internals do not invalidate these tests.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "mxprotector/analysis/marker_scanner.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace {

using mx::ByteBuffer;
using mx::MarkedRegion;
using mx::MarkerType;
using mx::PeImage;
using mx::Rva;
using mx::analysis::MarkerScanner;
using mx::pe::SectionInfo;

// ---------------------------------------------------------------------------
// Helpers for building test fixtures by hand.
// ---------------------------------------------------------------------------

/// Full 8-byte magic for a marker: `"MX_PROT" + type byte` packed as a
/// 64-bit little-endian word. Must match
/// `mx::sdk::make_marker_constant` bit-for-bit.
[[nodiscard]] constexpr uint64_t marker_magic(uint8_t type_byte) noexcept {
    return 0x00544F52505F584DULL | (static_cast<uint64_t>(type_byte) << 56);
}

/// Append a single marker construct (`mov rax, imm64` with the magic
/// constant) to `buf`. Returns the offset of the opcode byte (REX prefix)
/// so the caller can assert that the scanner reports this exact RVA.
///
/// The scanner considers the marker to consist of just this 10-byte
/// instruction when no trailing `mov [rsp|rbp+disp], ...` stores follow,
/// which is always the case in these hand-crafted fixtures.
[[nodiscard]] uint32_t emit_marker(ByteBuffer& buf, MarkerType type) {
    const uint32_t insn_offset = static_cast<uint32_t>(buf.size());
    // REX.W + MOV r64, imm64 — `mov rax, imm64` = `48 B8 <imm64-le>`.
    buf.push_back(0x48);
    buf.push_back(0xB8);
    const uint64_t magic = marker_magic(static_cast<uint8_t>(type));
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<uint8_t>((magic >> (8 * i)) & 0xFFu));
    }
    return insn_offset;
}

/// Append `count` 0x90 NOP bytes to `buf`. NOP terminates the scanner's
/// trailing `mov [rsp|rbp+disp], ...` absorb loop on the first decoded
/// instruction, so the reported `total_size` stays at exactly 10 bytes
/// (the size of the `mov rax, imm64` alone).
void emit_nop_padding(ByteBuffer& buf, size_t count) {
    for (size_t i = 0; i < count; ++i) buf.push_back(0x90);
}

/// Wrap a byte buffer in a fresh `PeImage` with a single code section
/// at `section_rva`. The rest of the image is left at defaults — the
/// scanner only looks at `sections()` entries with `is_code() == true`.
[[nodiscard]] PeImage make_image_with_code_section(
    ByteBuffer section_bytes, Rva section_rva = 0x1000)
{
    PeImage image;
    SectionInfo sec;
    sec.name            = ".text";
    sec.virtual_address = section_rva;
    sec.virtual_size    = static_cast<uint32_t>(section_bytes.size());
    sec.raw_size        = static_cast<uint32_t>(section_bytes.size());
    sec.raw_offset      = 0;
    // IMAGE_SCN_CNT_CODE (0x00000020) | IMAGE_SCN_MEM_EXECUTE (0x20000000)
    // | IMAGE_SCN_MEM_READ (0x40000000). The scanner only checks the
    // `IMAGE_SCN_CNT_CODE` bit via `SectionInfo::is_code()`.
    sec.characteristics = 0x60000020u;
    sec.data            = std::move(section_bytes);
    image.sections().push_back(std::move(sec));
    return image;
}

// ---------------------------------------------------------------------------
// Happy-path tests for existing markers — regression coverage to catch
// accidental breakage when we extend the scanner for new marker kinds.
// ---------------------------------------------------------------------------

TEST(MarkerScanner, FindsSingleVmRegion) {
    constexpr Rva kSectionRva = 0x1000;
    ByteBuffer bytes;
    const uint32_t begin_off = emit_marker(bytes, MarkerType::vm_begin);
    emit_nop_padding(bytes, 16);                              // body
    const uint32_t end_off   = emit_marker(bytes, MarkerType::vm_end);
    emit_nop_padding(bytes, 4);

    auto image = make_image_with_code_section(std::move(bytes), kSectionRva);
    auto result = MarkerScanner::find_markers(image);
    ASSERT_TRUE(result.has_value()) << result.error().format();

    const auto& regions = *result;
    ASSERT_EQ(regions.size(), 1u);
    EXPECT_EQ(regions[0].type, MarkerType::vm_begin);
    EXPECT_EQ(regions[0].start_rva, kSectionRva + begin_off + 10u);
    EXPECT_EQ(regions[0].end_rva,   kSectionRva + end_off);
    EXPECT_EQ(regions[0].begin_marker_size, 10u);
    EXPECT_EQ(regions[0].end_marker_size,   10u);
}

// ---------------------------------------------------------------------------
// Core new behaviour: GUARD_BEGIN / GUARD_END pair is recognised.
// ---------------------------------------------------------------------------

TEST(MarkerScanner, FindsGuardRegionRoundTrip) {
    constexpr Rva kSectionRva = 0x2000;
    ByteBuffer bytes;
    const uint32_t begin_off = emit_marker(bytes, MarkerType::guard_begin);
    emit_nop_padding(bytes, 24);                              // body
    const uint32_t end_off   = emit_marker(bytes, MarkerType::guard_end);
    emit_nop_padding(bytes, 4);

    auto image = make_image_with_code_section(std::move(bytes), kSectionRva);
    auto result = MarkerScanner::find_markers(image);
    ASSERT_TRUE(result.has_value()) << result.error().format();

    const auto& regions = *result;
    ASSERT_EQ(regions.size(), 1u);
    EXPECT_EQ(regions[0].type, MarkerType::guard_begin);
    EXPECT_EQ(regions[0].start_rva, kSectionRva + begin_off + 10u);
    EXPECT_EQ(regions[0].end_rva,   kSectionRva + end_off);
    EXPECT_EQ(regions[0].end_rva - regions[0].start_rva, 24u);
    EXPECT_EQ(regions[0].begin_marker_size, 10u);
    EXPECT_EQ(regions[0].end_marker_size,   10u);
    EXPECT_EQ(regions[0].section_index, 0u);
}

TEST(MarkerScanner, MixedVmAndGuardInOneSectionCoexistAndAreOrdered) {
    // Layout: [VM_BEGIN][body_vm][VM_END][pad][GUARD_BEGIN][body_g][GUARD_END]
    constexpr Rva kSectionRva = 0x3000;
    ByteBuffer bytes;
    const uint32_t vm_begin_off    = emit_marker(bytes, MarkerType::vm_begin);
    emit_nop_padding(bytes, 8);
    const uint32_t vm_end_off      = emit_marker(bytes, MarkerType::vm_end);
    emit_nop_padding(bytes, 16);
    const uint32_t guard_begin_off = emit_marker(bytes, MarkerType::guard_begin);
    emit_nop_padding(bytes, 12);
    const uint32_t guard_end_off   = emit_marker(bytes, MarkerType::guard_end);
    emit_nop_padding(bytes, 4);

    auto image = make_image_with_code_section(std::move(bytes), kSectionRva);
    auto result = MarkerScanner::find_markers(image);
    ASSERT_TRUE(result.has_value()) << result.error().format();

    const auto& regions = *result;
    ASSERT_EQ(regions.size(), 2u);
    // regions are ordered by start_rva — VM comes before GUARD.
    EXPECT_EQ(regions[0].type, MarkerType::vm_begin);
    EXPECT_EQ(regions[0].start_rva, kSectionRva + vm_begin_off + 10u);
    EXPECT_EQ(regions[0].end_rva,   kSectionRva + vm_end_off);

    EXPECT_EQ(regions[1].type, MarkerType::guard_begin);
    EXPECT_EQ(regions[1].start_rva, kSectionRva + guard_begin_off + 10u);
    EXPECT_EQ(regions[1].end_rva,   kSectionRva + guard_end_off);
}

// ---------------------------------------------------------------------------
// Pairing error paths — orphans and zero-size regions.
// ---------------------------------------------------------------------------

TEST(MarkerScanner, OrphanGuardBeginIsReported) {
    ByteBuffer bytes;
    emit_marker(bytes, MarkerType::guard_begin);
    emit_nop_padding(bytes, 16);
    // Deliberately no matching GUARD_END.

    auto image = make_image_with_code_section(std::move(bytes));
    auto result = MarkerScanner::find_markers(image);
    ASSERT_FALSE(result.has_value());
    const auto& msg = result.error().message();
    EXPECT_NE(msg.find("GUARD_BEGIN"), std::string::npos)
        << "Error should name the orphaned GUARD_BEGIN: " << msg;
}

TEST(MarkerScanner, OrphanGuardEndIsReported) {
    ByteBuffer bytes;
    emit_nop_padding(bytes, 4);
    emit_marker(bytes, MarkerType::guard_end);
    emit_nop_padding(bytes, 4);

    auto image = make_image_with_code_section(std::move(bytes));
    auto result = MarkerScanner::find_markers(image);
    ASSERT_FALSE(result.has_value());
    const auto& msg = result.error().message();
    EXPECT_NE(msg.find("GUARD_END"), std::string::npos)
        << "Error should name the orphan GUARD_END: " << msg;
}

TEST(MarkerScanner, ZeroSizeGuardRegionIsRejected) {
    // GUARD_BEGIN immediately followed by GUARD_END — no body bytes.
    // The scanner's `validate_and_pair` flags this as `region_too_small`.
    ByteBuffer bytes;
    emit_marker(bytes, MarkerType::guard_begin);
    emit_marker(bytes, MarkerType::guard_end);

    auto image = make_image_with_code_section(std::move(bytes));
    auto result = MarkerScanner::find_markers(image);
    ASSERT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// Non-code sections are skipped even if they happen to contain bytes that
// look like a valid marker. This guards against false positives on
// `.rdata` constants that share the magic prefix.
// ---------------------------------------------------------------------------

TEST(MarkerScanner, IgnoresNonCodeSectionsContainingMarkerBytes) {
    ByteBuffer bytes;
    emit_marker(bytes, MarkerType::guard_begin);
    emit_nop_padding(bytes, 16);
    emit_marker(bytes, MarkerType::guard_end);
    emit_nop_padding(bytes, 4);

    PeImage image;
    SectionInfo sec;
    sec.name            = ".rdata";
    sec.virtual_address = 0x4000;
    sec.virtual_size    = static_cast<uint32_t>(bytes.size());
    sec.raw_size        = static_cast<uint32_t>(bytes.size());
    sec.raw_offset      = 0;
    // IMAGE_SCN_MEM_READ only — no IMAGE_SCN_CNT_CODE bit set.
    sec.characteristics = 0x40000040u;
    sec.data            = std::move(bytes);
    image.sections().push_back(std::move(sec));

    auto result = MarkerScanner::find_markers(image);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty())
        << "Markers in non-code sections must not be reported";
}

// ---------------------------------------------------------------------------
// Static helpers (is_begin_marker / matching_end_type / marker_type_name)
// are in the public header as protected-via-friend — we can't call them
// directly. Instead we exercise them INDIRECTLY via happy-path pairing:
// if `is_begin_marker(guard_begin)` returned false, the orphan test above
// would instead report "GUARD_END without begin"; if `matching_end_type`
// mapped `guard_begin` to itself, the happy-path test would fail because
// `GUARD_END` wouldn't be considered a match.
//
// This indirection is intentional — it couples the tests to OBSERVED
// behaviour, not to implementation-detail helpers.
// ---------------------------------------------------------------------------

} // namespace
