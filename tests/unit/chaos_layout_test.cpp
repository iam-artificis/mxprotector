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

} // namespace
