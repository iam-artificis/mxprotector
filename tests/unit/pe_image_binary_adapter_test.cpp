/**
 * @file pe_image_binary_adapter_test.cpp
 * @brief Unit tests for `pe::PeImageBinaryAdapter`.
 *
 * @details Verifies the format-agnostic `target::IBinaryImage` view
 *          over a `mx::PeImage`:
 *            * basic accessors (target, image_base, entry point,
 *              is_64bit) forward correctly;
 *            * `sections()` produces a `SectionView` per stored
 *              `SectionInfo`, with the right name / RVA / sizes /
 *              flag translation;
 *            * `find_section()` returns the right view by name and
 *              fails with `section_not_found` for absent names;
 *            * `add_section(name, data, flags)` builds a
 *              `SectionInfo` with the right characteristics and
 *              forwards to `PeImage::add_section`;
 *            * `patch_section_bytes()` rewrites the right bytes in
 *              place and refuses out-of-range patches.
 */

#include <gtest/gtest.h>

#include <cstring>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_image_binary_adapter.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/target/target_info.hpp"

using namespace mx;
using namespace mx::pe;
using namespace mx::target;

namespace {

PeImage make_dummy_image() {
    PeImage img;
    img.set_architecture(Architecture::x64);
    img.set_image_base(0x140000000ULL);
    img.set_entry_point_rva(0x1000);

    SectionInfo text;
    text.name            = ".text";
    text.virtual_address = 0x1000;
    text.virtual_size    = 0x100;
    text.raw_size        = 0x100;
    text.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    text.data.assign(0x100, 0xAA);

    SectionInfo data;
    data.name            = ".data";
    data.virtual_address = 0x2000;
    data.virtual_size    = 0x100;
    data.raw_size        = 0x100;
    data.characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    data.data.assign(0x100, 0xBB);

    img.set_sections({std::move(text), std::move(data)});

    pe::IMAGE_NT_HEADERS64 nt{};
    nt.FileHeader.NumberOfSections = 2;
    img.set_nt_headers(nt);
    return img;
}

} // namespace

TEST(PeImageBinaryAdapterTest, BasicAccessorsForwardToPeImage) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    EXPECT_EQ(adapter.image_base(), 0x140000000ULL);
    EXPECT_EQ(adapter.entry_point_rva(), 0x1000u);
    EXPECT_TRUE(adapter.is_64bit());

    const auto t = adapter.target();
    EXPECT_TRUE(t.is_windows());
    EXPECT_TRUE(t.is_pe());
    EXPECT_TRUE(t.is_x64());
}

TEST(PeImageBinaryAdapterTest, SetEntryPointRvaForwards) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    adapter.set_entry_point_rva(0x4242);
    EXPECT_EQ(img.entry_point_rva(), 0x4242u);
}

TEST(PeImageBinaryAdapterTest, SectionsProducesViewPerSection) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    const auto views = adapter.sections();
    ASSERT_EQ(views.size(), 2u);

    EXPECT_EQ(views[0].name, ".text");
    EXPECT_EQ(views[0].rva,  0x1000u);
    EXPECT_TRUE(has_flag(views[0].flags, SectionFlags::read));
    EXPECT_TRUE(has_flag(views[0].flags, SectionFlags::execute));
    EXPECT_FALSE(has_flag(views[0].flags, SectionFlags::write));

    EXPECT_EQ(views[1].name, ".data");
    EXPECT_EQ(views[1].rva,  0x2000u);
    EXPECT_TRUE(has_flag(views[1].flags, SectionFlags::read));
    EXPECT_TRUE(has_flag(views[1].flags, SectionFlags::write));
    EXPECT_FALSE(has_flag(views[1].flags, SectionFlags::execute));
}

TEST(PeImageBinaryAdapterTest, FindSectionByNameSuccess) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    auto v = adapter.find_section(".data");
    ASSERT_TRUE(v);
    EXPECT_EQ(v->name, ".data");
    EXPECT_EQ(v->rva,  0x2000u);
}

TEST(PeImageBinaryAdapterTest, FindSectionMissingReturnsError) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    auto v = adapter.find_section(".nonexistent");
    EXPECT_FALSE(v);
    if (!v) {
        EXPECT_EQ(v.error().code(), static_cast<uint16_t>(PeErrorCode::section_not_found));
    }
}

TEST(PeImageBinaryAdapterTest, AddSectionWithExecuteFlagsBuildsCodeSection) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    const std::array<uint8_t, 4> bytes = {0x90, 0x90, 0x90, 0xC3};  // nop nop nop ret
    auto idx = adapter.add_section(".mxnew", ByteView{bytes.data(), bytes.size()},
                                   SectionFlags::read | SectionFlags::execute);
    ASSERT_TRUE(idx);
    EXPECT_EQ(*idx, 2u);
    ASSERT_EQ(img.sections().size(), 3u);

    const auto& sec = img.sections()[2];
    EXPECT_EQ(sec.name, ".mxnew");
    EXPECT_TRUE(sec.is_code());
    EXPECT_TRUE(sec.is_executable());
}

TEST(PeImageBinaryAdapterTest, PatchSectionBytesOverwritesInPlace) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    const std::array<uint8_t, 4> patch = {0x11, 0x22, 0x33, 0x44};
    auto status = adapter.patch_section_bytes(0, /*offset=*/8,
                                              ByteView{patch.data(), patch.size()});
    ASSERT_TRUE(status);

    const auto& text = img.sections()[0];
    EXPECT_EQ(text.data[8],  0x11);
    EXPECT_EQ(text.data[9],  0x22);
    EXPECT_EQ(text.data[10], 0x33);
    EXPECT_EQ(text.data[11], 0x44);
    EXPECT_EQ(text.data[12], 0xAA);  // unchanged sentinel
}

TEST(PeImageBinaryAdapterTest, PatchOutOfRangeReturnsError) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    const std::array<uint8_t, 4> patch = {0, 0, 0, 0};
    auto status = adapter.patch_section_bytes(
        /*section_index=*/0,
        /*offset=*/0xFE,
        ByteView{patch.data(), patch.size()});
    EXPECT_FALSE(status);
}

TEST(PeImageBinaryAdapterTest, PatchInvalidSectionIndexReturnsError) {
    PeImage img = make_dummy_image();
    PeImageBinaryAdapter adapter(img, TargetInfo::windows_pe_x64());

    const std::array<uint8_t, 1> patch = {0};
    auto status = adapter.patch_section_bytes(
        /*section_index=*/999,
        /*offset=*/0,
        ByteView{patch.data(), patch.size()});
    EXPECT_FALSE(status);
}
