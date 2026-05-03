/**
 * @file chaos_structure_reference_scanner_test.cpp
 * @brief [TESTS] B.4.3 — `StructureReferenceScanner` contract.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/reference.hpp"
#include "mxprotector/pe/chaos/structure_reference_scanner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::chaos::Reference;
using mx::pe::chaos::ReferenceEncoding;
using mx::pe::chaos::ReferenceOrigin;
using mx::pe::chaos::ReferenceTable;
using mx::pe::chaos::ReferenceWidth;
using mx::pe::chaos::StructureReferenceScanner;

constexpr std::uint32_t kLfanew = 0x100;

[[nodiscard]] PeImage make_pe32plus_image() {
    PeImage img;
    img.set_architecture(mx::Architecture::x64);
    img.set_file_alignment(0x200);
    img.set_section_alignment(0x1000);
    img.set_image_base(0x140000000ULL);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_lfanew = static_cast<std::int32_t>(kLfanew);
    img.set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                            = 0x00004550;
    nt.FileHeader.Machine                   = 0x8664;
    nt.FileHeader.NumberOfSections          = 0;
    nt.FileHeader.SizeOfOptionalHeader      = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic                 = 0x20B;
    nt.OptionalHeader.AddressOfEntryPoint   = 0;  // populated per test
    nt.OptionalHeader.NumberOfRvaAndSizes   = mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

constexpr Rva kOptHdrRva = kLfanew +
    offsetof(mx::pe::IMAGE_NT_HEADERS64, OptionalHeader);
constexpr Rva kEntryPointSlotRva = kOptHdrRva +
    offsetof(mx::pe::IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);
constexpr Rva kDataDirSlotRva = kOptHdrRva +
    offsetof(mx::pe::IMAGE_OPTIONAL_HEADER64, DataDirectory);

// ---------------------------------------------------------------------------
// AddressOfEntryPoint
// ---------------------------------------------------------------------------

TEST(StructureReferenceScanner, EntryPointEmittedWhenNonZero) {
    PeImage img = make_pe32plus_image();
    nt(img).OptionalHeader.AddressOfEntryPoint = 0x1234;

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    bool found_entry = false;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::entry_point) {
            found_entry = true;
            EXPECT_EQ(r.location_rva, kEntryPointSlotRva);
            EXPECT_EQ(r.target_rva,   0x1234u);
            EXPECT_EQ(r.width,        ReferenceWidth::byte4);
            EXPECT_EQ(r.encoding,     ReferenceEncoding::rva);
        }
    }
    EXPECT_TRUE(found_entry);
}

TEST(StructureReferenceScanner, EntryPointSkippedWhenZero) {
    PeImage img = make_pe32plus_image();
    // entry_point already 0 from default ctor.

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    for (const auto& r : t.slots()) {
        EXPECT_NE(r.origin, ReferenceOrigin::entry_point)
            << "zero entry point must not emit a reference";
    }
}

// ---------------------------------------------------------------------------
// DataDirectory entries
// ---------------------------------------------------------------------------

TEST(StructureReferenceScanner, DataDirectoryEntriesEmittedForNonEmpty) {
    PeImage img = make_pe32plus_image();
    nt(img).OptionalHeader.DataDirectory[1].VirtualAddress = 0x2000;
    nt(img).OptionalHeader.DataDirectory[1].Size           = 0x40;
    nt(img).OptionalHeader.DataDirectory[5].VirtualAddress = 0x3000;
    nt(img).OptionalHeader.DataDirectory[5].Size           = 0x10;
    // entries 0, 2-4, 6-15 stay zero.

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    int dir_count = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::data_directory_entry) ++dir_count;
    }
    EXPECT_EQ(dir_count, 2);

    bool found_1 = false, found_5 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::data_directory_entry) continue;
        if (r.location_rva == kDataDirSlotRva +
            1 * sizeof(mx::pe::IMAGE_DATA_DIRECTORY))
        {
            EXPECT_EQ(r.target_rva, 0x2000u);
            found_1 = true;
        }
        if (r.location_rva == kDataDirSlotRva +
            5 * sizeof(mx::pe::IMAGE_DATA_DIRECTORY))
        {
            EXPECT_EQ(r.target_rva, 0x3000u);
            found_5 = true;
        }
    }
    EXPECT_TRUE(found_1);
    EXPECT_TRUE(found_5);
}

TEST(StructureReferenceScanner, DataDirectoryRespectsNumberOfRvaAndSizes) {
    PeImage img = make_pe32plus_image();
    nt(img).OptionalHeader.NumberOfRvaAndSizes = 4;
    // Entry 5 is past the limit; should be skipped.
    nt(img).OptionalHeader.DataDirectory[5].VirtualAddress = 0x3000;

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::data_directory_entry) continue;
        EXPECT_LT(r.location_rva, kDataDirSlotRva +
            4 * sizeof(mx::pe::IMAGE_DATA_DIRECTORY))
            << "entry past NumberOfRvaAndSizes must not be emitted";
    }
}

// ---------------------------------------------------------------------------
// .pdata
// ---------------------------------------------------------------------------

TEST(StructureReferenceScanner, PdataEntriesEmitThreeReferencesEach) {
    PeImage img = make_pe32plus_image();

    // Build a section that holds .pdata starting at RVA 0x1000.
    // Two RUNTIME_FUNCTION entries:
    //   #0: begin=0x2000, end=0x2050, unwind=0x4000.
    //   #1: begin=0x2100, end=0x2120, unwind=0x4100.
    std::vector<std::uint8_t> pdata_bytes;
    auto append_u32 = [&](std::uint32_t v) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
        pdata_bytes.insert(pdata_bytes.end(), p, p + 4);
    };
    append_u32(0x2000); append_u32(0x2050); append_u32(0x4000);
    append_u32(0x2100); append_u32(0x2120); append_u32(0x4100);

    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".pdata",
        mx::ByteView{pdata_bytes.data(), pdata_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx.has_value());
    const Rva pdata_rva = img.sections()[*idx].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdata_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size =
            static_cast<std::uint32_t>(pdata_bytes.size());

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    int pdata_count = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::pdata_runtime_function) ++pdata_count;
    }
    EXPECT_EQ(pdata_count, 6) << "2 entries × 3 RVA fields each";

    // Entry #1's BeginAddress slot lives at pdata_rva + 12, target = 0x2100.
    bool found = false;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::pdata_runtime_function &&
            r.location_rva == pdata_rva + 12)
        {
            EXPECT_EQ(r.target_rva, 0x2100u);
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST(StructureReferenceScanner, ZeroFieldInPdataEntryIsSkipped) {
    PeImage img = make_pe32plus_image();

    // One entry with begin=0x2000, end=0, unwind=0x4000.
    std::vector<std::uint8_t> pdata_bytes(12, 0);
    std::uint32_t begin = 0x2000, unwind = 0x4000;
    std::memcpy(pdata_bytes.data() + 0, &begin,  4);
    // bytes [4..8] stay zero (end = 0)
    std::memcpy(pdata_bytes.data() + 8, &unwind, 4);

    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".pdata",
        mx::ByteView{pdata_bytes.data(), pdata_bytes.size()},
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    ASSERT_TRUE(idx.has_value());
    const Rva pdata_rva = img.sections()[*idx].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdata_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 12;

    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);

    int pdata_count = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::pdata_runtime_function) ++pdata_count;
    }
    EXPECT_EQ(pdata_count, 2)
        << "EndAddress=0 should be skipped — only BeginAddress + UnwindInfoAddress emit";
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

TEST(StructureReferenceScanner, Pe32ImageIsNoOp) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    StructureReferenceScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
