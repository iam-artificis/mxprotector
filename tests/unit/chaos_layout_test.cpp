/**
 * @file chaos_layout_test.cpp
 * @brief [TESTS] `ChaosLayout` policy contract.
 *
 * Pins the B.1 invariants — `resolve()` always returns RWX / mixed,
 * `finalize()` stamps every existing section's characteristics with
 * the chaos bits while preserving any unrelated bits the section
 * already had.
 */

#include <gtest/gtest.h>

#include <vector>

#include "mxprotector/pe/layout/chaos_layout.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::SectionManager;
using mx::pe::ChaosLayout;
using mx::pe::SectionContentType;
using mx::pe::SectionIntent;
using mx::pe::SectionPermissions;

[[nodiscard]] PeImage make_empty_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);
    return img;
}

constexpr std::uint32_t kRwxMixedMask =
    mx::pe::IMAGE_SCN_CNT_CODE
    | mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
    | mx::pe::IMAGE_SCN_MEM_READ
    | mx::pe::IMAGE_SCN_MEM_WRITE
    | mx::pe::IMAGE_SCN_MEM_EXECUTE;

// ---------------------------------------------------------------------------
// resolve()
// ---------------------------------------------------------------------------

TEST(ChaosLayout, ResolveOverridesEverythingToRwxMixed) {
    ChaosLayout policy;

    auto rx_resolved = policy.resolve(
        ".text",
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    EXPECT_EQ(rx_resolved.content, SectionContentType::mixed_code_data);
    EXPECT_EQ(rx_resolved.perms,   SectionPermissions::rwx);

    auto ro_resolved = policy.resolve(
        ".rdata",
        SectionIntent{SectionContentType::data, SectionPermissions::r});
    EXPECT_EQ(ro_resolved.content, SectionContentType::mixed_code_data);
    EXPECT_EQ(ro_resolved.perms,   SectionPermissions::rwx);

    auto rw_resolved = policy.resolve(
        ".data",
        SectionIntent{SectionContentType::data, SectionPermissions::rw});
    EXPECT_EQ(rw_resolved.content, SectionContentType::mixed_code_data);
    EXPECT_EQ(rw_resolved.perms,   SectionPermissions::rwx);
}

TEST(ChaosLayout, ResolveIgnoresSectionName) {
    // Independent of name — chaos doesn't special-case any section.
    ChaosLayout policy;
    auto a = policy.resolve(
        ".guard",
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    auto b = policy.resolve(
        ".mxguard",
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    EXPECT_EQ(a, b);
}

// ---------------------------------------------------------------------------
// finalize()
// ---------------------------------------------------------------------------

TEST(ChaosLayout, FinalizeStampsEverySectionWithRwxMixed) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto data1 = std::vector<std::uint8_t>(0x40, 0x90);
    auto idx1 = mgr.add_section(
        ".text",
        mx::ByteView{data1.data(), data1.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    ASSERT_TRUE(idx1.has_value());

    const auto data2 = std::vector<std::uint8_t>(0x40, 0xAA);
    auto idx2 = mgr.add_section(
        ".rdata",
        mx::ByteView{data2.data(), data2.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx2.has_value());

    ChaosLayout policy;
    auto status = policy.finalize(img);
    ASSERT_TRUE(status.has_value());

    for (const auto& sec : img.sections()) {
        EXPECT_TRUE((sec.characteristics & kRwxMixedMask) == kRwxMixedMask)
            << "section '" << sec.name
            << "' should have all chaos bits set";
    }
}

TEST(ChaosLayout, FinalizePreservesUnrelatedCharacteristicsBits) {
    // `IMAGE_SCN_MEM_DISCARDABLE` is not part of the chaos bit-set;
    // `finalize` must not clear it.
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    constexpr std::uint32_t kPlainRx =
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE;
    constexpr std::uint32_t kDiscardable =
        kPlainRx | mx::pe::IMAGE_SCN_MEM_DISCARDABLE;

    const auto data = std::vector<std::uint8_t>(0x40, 0x90);
    auto idx = mgr.add_section(
        ".init",
        mx::ByteView{data.data(), data.size()},
        kDiscardable);
    ASSERT_TRUE(idx.has_value());

    ChaosLayout policy;
    auto status = policy.finalize(img);
    ASSERT_TRUE(status.has_value());

    const auto& sec = img.sections()[*idx];
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_DISCARDABLE)
        << "DISCARDABLE bit must survive finalize";
    EXPECT_TRUE((sec.characteristics & kRwxMixedMask) == kRwxMixedMask)
        << "chaos bits must still be present alongside DISCARDABLE";
}

TEST(ChaosLayout, NameIsChaos) {
    ChaosLayout policy;
    EXPECT_EQ(policy.name(), "chaos");
}

// ---------------------------------------------------------------------------
// finalize() — section merge
// ---------------------------------------------------------------------------

TEST(ChaosLayout, FinalizeCollapsesMultipleSectionsIntoOne) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto text_data = std::vector<std::uint8_t>(0x40, 0xAA);
    auto idx_text = mgr.add_section(
        ".text", mx::ByteView{text_data.data(), text_data.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    ASSERT_TRUE(idx_text.has_value());

    const auto rdata_data = std::vector<std::uint8_t>(0x40, 0xBB);
    auto idx_rdata = mgr.add_section(
        ".rdata", mx::ByteView{rdata_data.data(), rdata_data.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx_rdata.has_value());

    const auto text_va  = img.sections()[0].virtual_address;
    const auto rdata_va = img.sections()[1].virtual_address;
    const auto rdata_vsize = img.sections()[1].virtual_size;
    const auto expected_first_va = std::min(text_va, rdata_va);
    const auto expected_total = static_cast<std::uint32_t>(
        rdata_va + rdata_vsize - expected_first_va);

    ChaosLayout policy;
    auto status = policy.finalize(img);
    ASSERT_TRUE(status.has_value());

    ASSERT_EQ(img.sections().size(), 1u);
    const auto& merged = img.sections()[0];
    EXPECT_EQ(merged.name, ".mxchaos");
    EXPECT_EQ(merged.virtual_address, expected_first_va);
    EXPECT_EQ(merged.virtual_size, expected_total);

    // Original .text bytes preserved at their original offset
    // (= virtual_address - merged.virtual_address).
    const auto text_off = text_va - merged.virtual_address;
    for (std::size_t i = 0; i < text_data.size(); ++i) {
        EXPECT_EQ(merged.data[text_off + i], text_data[i])
            << ".text byte " << i << " corrupted by merge";
    }
    const auto rdata_off = rdata_va - merged.virtual_address;
    for (std::size_t i = 0; i < rdata_data.size(); ++i) {
        EXPECT_EQ(merged.data[rdata_off + i], rdata_data[i])
            << ".rdata byte " << i << " corrupted by merge";
    }
}

TEST(ChaosLayout, FinalizeFillsInterSectionGapsWith0xCC) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto text_data = std::vector<std::uint8_t>(0x40, 0xAA);
    auto idx_text = mgr.add_section(
        ".text", mx::ByteView{text_data.data(), text_data.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_EXECUTE);
    ASSERT_TRUE(idx_text.has_value());

    const auto rdata_data = std::vector<std::uint8_t>(0x40, 0xBB);
    auto idx_rdata = mgr.add_section(
        ".rdata", mx::ByteView{rdata_data.data(), rdata_data.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx_rdata.has_value());

    const auto text_va    = img.sections()[0].virtual_address;
    const auto text_vsize = img.sections()[0].virtual_size;
    const auto rdata_va   = img.sections()[1].virtual_address;

    ChaosLayout policy;
    ASSERT_TRUE(policy.finalize(img).has_value());

    // Gap is the bytes between (.text end) and (.rdata start) inside
    // the merged buffer. There must be at least one — section
    // alignment of 0x1000 vs `.text` virtual_size of 0x40 leaves a
    // ≥ 0xFC0-byte gap.
    const auto& merged = img.sections()[0];
    const auto gap_start = (text_va + text_vsize) - merged.virtual_address;
    const auto gap_end   = rdata_va - merged.virtual_address;
    ASSERT_LT(gap_start, gap_end);
    for (std::size_t i = gap_start; i < gap_end; ++i) {
        EXPECT_EQ(merged.data[i], 0xCCu)
            << "gap byte at offset " << i
            << " was not the chaos fill (0xCC)";
    }
}

TEST(ChaosLayout, FinalizeUpdatesNumberOfSectionsTo1) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto data1 = std::vector<std::uint8_t>(0x40, 0x90);
    const auto data2 = std::vector<std::uint8_t>(0x40, 0xAA);
    auto idx1 = mgr.add_section(
        ".a", mx::ByteView{data1.data(), data1.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    auto idx2 = mgr.add_section(
        ".b", mx::ByteView{data2.data(), data2.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx1.has_value());
    ASSERT_TRUE(idx2.has_value());

    std::uint16_t before_count = 0;
    std::visit([&](const auto& nt) {
        before_count = nt.FileHeader.NumberOfSections;
    }, img.nt_headers());
    EXPECT_EQ(before_count, 2u);

    ChaosLayout policy;
    ASSERT_TRUE(policy.finalize(img).has_value());

    std::uint16_t after_count = 0;
    std::visit([&](const auto& nt) {
        after_count = nt.FileHeader.NumberOfSections;
    }, img.nt_headers());
    EXPECT_EQ(after_count, 1u);
}

TEST(ChaosLayout, FinalizeIsNoOpForSingleSectionImage) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto data = std::vector<std::uint8_t>(0x40, 0x90);
    auto idx = mgr.add_section(
        ".only", mx::ByteView{data.data(), data.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx.has_value());

    const auto name_before = img.sections()[0].name;
    const auto va_before   = img.sections()[0].virtual_address;

    ChaosLayout policy;
    ASSERT_TRUE(policy.finalize(img).has_value());

    // Single-section image is already merged by definition — name
    // and VA stay as the original section, only characteristics
    // pick up the chaos bits.
    ASSERT_EQ(img.sections().size(), 1u);
    EXPECT_EQ(img.sections()[0].name, name_before);
    EXPECT_EQ(img.sections()[0].virtual_address, va_before);
}

TEST(ChaosLayout, FinalizeMergedSectionHasComputedRawFields) {
    // The merged section must carry valid `raw_offset` /
    // `raw_size` so `PeBuilder` does not produce a section table
    // pointing at zero-offset data.
    PeImage img = make_empty_image();
    SectionManager mgr{img};

    const auto data1 = std::vector<std::uint8_t>(0x40, 0x90);
    const auto data2 = std::vector<std::uint8_t>(0x40, 0xAA);
    (void)mgr.add_section(
        ".a", mx::ByteView{data1.data(), data1.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    (void)mgr.add_section(
        ".b", mx::ByteView{data2.data(), data2.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);

    ChaosLayout policy;
    ASSERT_TRUE(policy.finalize(img).has_value());

    const auto& merged = img.sections()[0];
    EXPECT_GT(merged.raw_offset, 0u);
    EXPECT_GT(merged.raw_size, 0u);
    EXPECT_EQ(merged.raw_size % img.file_alignment(), 0u);
    EXPECT_EQ(merged.raw_offset % img.file_alignment(), 0u);
    EXPECT_GE(merged.raw_size, merged.data.size());
}

} // namespace
