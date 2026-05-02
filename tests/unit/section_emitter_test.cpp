/**
 * @file section_emitter_test.cpp
 * @brief [TESTS] `SectionEmitter` facade contract.
 *
 * The emitter is the single seam every pass goes through to add or
 * grow a section. These tests pin three invariants:
 *
 *   1. `append_section` produces an `IMAGE_SCN_*` mask consistent
 *      with the resolved (policy + intent) pair.
 *   2. `append_to_section` grows an existing section by exactly
 *      `bytes.size()` bytes, preserves the prior contents, and
 *      writes the new bytes at the end. The returned offset matches
 *      the pre-grow size.
 *   3. `allocate_overflow_section` returns a coherent
 *      `(section_index, base_rva)` pair where the section actually
 *      contains the supplied bytes at offset 0.
 *
 * A custom test-double policy (`AlwaysRwxLayout`) is used to verify
 * that the policy seam is honoured — `append_section` must respect
 * the override regardless of what the pass requested.
 */

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "mxprotector/pe/layout/standard_layout.hpp"
#include "mxprotector/pe/layout_policy.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::SectionManager;
using mx::pe::ILayoutPolicy;
using mx::pe::OverflowAllocation;
using mx::pe::SectionContentType;
using mx::pe::SectionEmitter;
using mx::pe::SectionIntent;
using mx::pe::SectionPermissions;
using mx::pe::StandardLayout;

/// Test double — flips every intent to RWX. Used to verify the
/// policy seam without depending on the (future) `ChaosLayout`.
class AlwaysRwxLayout final : public ILayoutPolicy {
public:
    [[nodiscard]] SectionIntent resolve(
        std::string_view, SectionIntent requested) const noexcept override
    {
        return {requested.content, SectionPermissions::rwx};
    }
    [[nodiscard]] mx::MxStatus finalize(PeImage&) const override { return {}; }
    [[nodiscard]] std::string_view name() const noexcept override {
        return "test-rwx";
    }
};

/// Build an empty image with a sane file_alignment so
/// SectionManager::add_section can recompute layout cleanly.
[[nodiscard]] PeImage make_empty_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    return img;
}

[[nodiscard]] std::vector<std::uint8_t> bytes(std::initializer_list<std::uint8_t> v) {
    return std::vector<std::uint8_t>{v};
}

// ---------------------------------------------------------------------------
// append_section
// ---------------------------------------------------------------------------

TEST(SectionEmitter, AppendSectionForwardsPolicyResolvedCharacteristics) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto data = bytes({0x90, 0xCC, 0x90});
    const auto idx = emit.append_section(
        ".test1",
        mx::ByteView{data.data(), data.size()},
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    ASSERT_TRUE(idx.has_value());
    EXPECT_EQ(*idx, 0u);

    const auto& sec = img.sections()[*idx];
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_CNT_CODE);
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_EXECUTE);
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_READ);
    EXPECT_FALSE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_WRITE);
}

TEST(SectionEmitter, AppendSectionHonoursPolicyOverride) {
    // The pass asks for RX; the policy rewrites to RWX. Emitter must
    // honour the policy.
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    AlwaysRwxLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto data = bytes({0x90});
    const auto idx = emit.append_section(
        ".over",
        mx::ByteView{data.data(), data.size()},
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    ASSERT_TRUE(idx.has_value());

    const auto& sec = img.sections()[*idx];
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_WRITE)
        << "policy override must add MEM_WRITE";
    EXPECT_TRUE(sec.characteristics & mx::pe::IMAGE_SCN_MEM_EXECUTE);
}

// ---------------------------------------------------------------------------
// append_to_section
// ---------------------------------------------------------------------------

TEST(SectionEmitter, AppendToSectionGrowsByExactSize) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto initial = bytes({0xAA, 0xBB});
    auto idx = emit.append_section(
        ".grow", mx::ByteView{initial.data(), initial.size()},
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    ASSERT_TRUE(idx.has_value());

    const auto more = bytes({0xCC, 0xDD, 0xEE});
    auto offset = emit.append_to_section(
        ".grow", mx::ByteView{more.data(), more.size()});
    ASSERT_TRUE(offset.has_value());
    EXPECT_EQ(*offset, 2u) << "offset must equal pre-grow size";

    const auto& sec = img.sections()[*idx];
    ASSERT_EQ(sec.data.size(), 5u);
    EXPECT_EQ(sec.data[0], 0xAAu);
    EXPECT_EQ(sec.data[1], 0xBBu);
    EXPECT_EQ(sec.data[2], 0xCCu);
    EXPECT_EQ(sec.data[3], 0xDDu);
    EXPECT_EQ(sec.data[4], 0xEEu);
}

TEST(SectionEmitter, AppendToSectionEmptyInputIsNoOp) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto initial = bytes({0x42});
    auto idx = emit.append_section(
        ".noop", mx::ByteView{initial.data(), initial.size()},
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    ASSERT_TRUE(idx.has_value());

    auto off = emit.append_to_section(".noop", mx::ByteView{});
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(*off, 1u);
    EXPECT_EQ(img.sections()[*idx].data.size(), 1u);
}

TEST(SectionEmitter, AppendToSectionUnknownNameFails) {
    PeImage img = make_empty_image();
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto data = bytes({0x90});
    auto off = emit.append_to_section(
        ".does_not_exist", mx::ByteView{data.data(), data.size()});
    EXPECT_FALSE(off.has_value());
}

// ---------------------------------------------------------------------------
// allocate_overflow_section
// ---------------------------------------------------------------------------

TEST(SectionEmitter, AllocateOverflowReturnsIndexAndRva) {
    PeImage img = make_empty_image();
    img.set_image_base(0x140000000ULL);
    SectionManager mgr{img};
    StandardLayout policy;
    SectionEmitter emit{mgr, policy};

    const auto payload = bytes({0xC3, 0xC3, 0xC3});
    auto alloc = emit.allocate_overflow_section(
        ".spill", mx::ByteView{payload.data(), payload.size()},
        SectionIntent{SectionContentType::code, SectionPermissions::rx});
    ASSERT_TRUE(alloc.has_value());
    EXPECT_EQ(alloc->section_index, 0u);
    EXPECT_GT(alloc->base_rva, 0u);

    const auto& sec = img.sections()[alloc->section_index];
    EXPECT_EQ(sec.virtual_address, alloc->base_rva);
    ASSERT_EQ(sec.data.size(), 3u);
    EXPECT_EQ(sec.data[0], 0xC3u);
    EXPECT_EQ(sec.data[1], 0xC3u);
    EXPECT_EQ(sec.data[2], 0xC3u);
}

} // namespace
