/**
 * @file refmap_reference_patcher_test.cpp
 * @brief [TESTS] B.4.6 — `ReferencePatcher` contract.
 *
 * Five invariants:
 *   1. `rva` references write the raw new target as a `byte4` value.
 *   2. `rel` references write `new_target - (new_location + width)`.
 *   3. `absolute_va` references write `image_base + new_target` as 8 bytes.
 *   4. Header-located references reach `nt_headers` not `section.data`.
 *   5. Unresolvable locations (bad RVA, OOB) increment `skipped` but
 *      do not abort the run.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::PatchStats;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferencePatcher;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;
using mx::pe::refmap::RvaRemapper;

constexpr std::uint64_t kImageBase     = 0x140000000ULL;
constexpr std::uint32_t kLfanew        = 0x100;
constexpr std::uint32_t kSizeOfHeaders = 0x400;

[[nodiscard]] PeImage make_pe32plus_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(kImageBase);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = static_cast<std::int32_t>(kLfanew);
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                          = 0x00004550;
    nt.FileHeader.Machine                 = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader    = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic               = 0x20B;
    nt.OptionalHeader.SizeOfHeaders       = kSizeOfHeaders;
    nt.OptionalHeader.NumberOfRvaAndSizes = mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt_of(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

[[nodiscard]] std::int32_t read_le_i32(
    const PeImage& img, Rva rva)
{
    for (const auto& s : img.sections()) {
        if (rva < s.virtual_address ||
            rva >= s.virtual_address + s.virtual_size) continue;
        const auto off = rva - s.virtual_address;
        std::int32_t v = 0;
        std::memcpy(&v, s.data.data() + off, sizeof(v));
        return v;
    }
    return 0;
}

[[nodiscard]] std::uint32_t read_le_u32(
    const PeImage& img, Rva rva)
{
    for (const auto& s : img.sections()) {
        if (rva < s.virtual_address ||
            rva >= s.virtual_address + s.virtual_size) continue;
        const auto off = rva - s.virtual_address;
        std::uint32_t v = 0;
        std::memcpy(&v, s.data.data() + off, sizeof(v));
        return v;
    }
    return 0;
}

[[nodiscard]] std::uint64_t read_le_u64(
    const PeImage& img, Rva rva)
{
    for (const auto& s : img.sections()) {
        if (rva < s.virtual_address ||
            rva >= s.virtual_address + s.virtual_size) continue;
        const auto off = rva - s.virtual_address;
        std::uint64_t v = 0;
        std::memcpy(&v, s.data.data() + off, sizeof(v));
        return v;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// rva encoding
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, RvaEncodingWritesRawTarget) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{std::vector<std::uint8_t>(0x100, 0).data(), 0x100},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx.has_value());
    const Rva text_va = img.sections()[*idx].virtual_address;

    ReferenceTable t;
    t.add(Reference{
        .location_rva = text_va + 0x10,
        .target_rva   = 0x5000,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::data_directory_entry,
    });

    RvaRemapper remapper;
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.total,          1u);
    EXPECT_EQ(stats.patched,        1u);
    EXPECT_EQ(stats.section_writes, 1u);

    EXPECT_EQ(read_le_u32(img, text_va + 0x10), 0x5000u);
}

// ---------------------------------------------------------------------------
// rel encoding
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, Rel32EncodingWritesDisplacement) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{std::vector<std::uint8_t>(0x100, 0).data(), 0x100},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    const Rva text_va = img.sections()[*idx].virtual_address;

    // Slot at text_va + 0x10, target at 0x5000.
    // rel32 = 0x5000 - (text_va + 0x10 + 4)
    ReferenceTable t;
    t.add(Reference{
        .location_rva = text_va + 0x10,
        .target_rva   = 0x5000,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_branch_or_call,
    });

    RvaRemapper remapper;
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.patched, 1u);

    const std::int32_t expected = static_cast<std::int32_t>(0x5000) -
        static_cast<std::int32_t>(text_va + 0x10 + 4);
    EXPECT_EQ(read_le_i32(img, text_va + 0x10), expected);
}

// ---------------------------------------------------------------------------
// absolute_va encoding
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, AbsoluteVaWritesImageBasePlusTarget) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".rdata",
        mx::ByteView{std::vector<std::uint8_t>(0x100, 0).data(), 0x100},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    const Rva rdata_va = img.sections()[*idx].virtual_address;

    ReferenceTable t;
    t.add(Reference{
        .location_rva = rdata_va + 0x20,
        .target_rva   = 0x3000,
        .width        = ReferenceWidth::byte8,
        .encoding     = ReferenceEncoding::absolute_va,
        .origin       = ReferenceOrigin::reloc_absolute_va,
    });

    RvaRemapper remapper;
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.patched, 1u);

    EXPECT_EQ(read_le_u64(img, rdata_va + 0x20),
              kImageBase + 0x3000u);
}

// ---------------------------------------------------------------------------
// Header writes
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, EntryPointSlotInHeadersIsRewritten) {
    PeImage img = make_pe32plus_image();
    nt_of(img).OptionalHeader.AddressOfEntryPoint = 0x1234;

    const Rva entry_slot = kLfanew +
        offsetof(mx::pe::IMAGE_NT_HEADERS64, OptionalHeader) +
        offsetof(mx::pe::IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);

    ReferenceTable t;
    t.add(Reference{
        .location_rva = entry_slot,
        .target_rva   = 0xABCD,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::entry_point,
    });

    RvaRemapper remapper;
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.patched,        1u);
    EXPECT_EQ(stats.header_writes,  1u);
    EXPECT_EQ(stats.section_writes, 0u);

    EXPECT_EQ(nt_of(img).OptionalHeader.AddressOfEntryPoint, 0xABCDu);
}

// ---------------------------------------------------------------------------
// Remap applied to BOTH location and target
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, RemapTranslatesLocationAndTarget) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};
    // .text long enough to host both the source AND post-remap location.
    auto idx = mgr.add_section(
        ".text",
        mx::ByteView{std::vector<std::uint8_t>(0x800, 0).data(), 0x800},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    const Rva text_va = img.sections()[*idx].virtual_address;

    // Reference at OLD location text_va+0x100 → OLD target text_va+0x500.
    const Rva old_loc    = text_va + 0x100;
    const Rva old_target = text_va + 0x500;
    ReferenceTable t;
    t.add(Reference{
        .location_rva = old_loc,
        .target_rva   = old_target,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_branch_or_call,
    });

    // Remap: location moves to text_va+0x300; target moves to text_va+0x700.
    RvaRemapper remapper;
    remapper.add_chunk(old_loc,    text_va + 0x300, 0x40);
    remapper.add_chunk(old_target, text_va + 0x700, 0x40);
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.patched, 1u);

    // The slot was written at the NEW location (text_va+0x300), encoding
    // the NEW target (text_va+0x700).
    const Rva new_loc    = text_va + 0x300;
    const Rva new_target = text_va + 0x700;
    const std::int32_t expected = static_cast<std::int32_t>(new_target) -
        static_cast<std::int32_t>(new_loc + 4);
    EXPECT_EQ(read_le_i32(img, new_loc), expected);

    // The OLD location is left as its original zero (not touched).
    EXPECT_EQ(read_le_i32(img, old_loc), 0);
}

// ---------------------------------------------------------------------------
// Skipped on bad location
// ---------------------------------------------------------------------------

TEST(ReferencePatcher, UnreachableLocationIsSkipped) {
    PeImage img = make_pe32plus_image();
    // No sections — every section-style write fails.

    ReferenceTable t;
    t.add(Reference{
        .location_rva = 0x9999,  // outside every range
        .target_rva   = 0x5000,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::code_branch_or_call,
    });

    RvaRemapper remapper;
    ASSERT_TRUE(remapper.finalize());

    ReferencePatcher p;
    auto stats = p.apply(img, t, remapper);
    EXPECT_EQ(stats.total,    1u);
    EXPECT_EQ(stats.patched,  0u);
    EXPECT_EQ(stats.skipped,  1u);
}

} // namespace
