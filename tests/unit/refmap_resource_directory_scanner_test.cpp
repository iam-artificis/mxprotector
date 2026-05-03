/**
 * @file refmap_resource_directory_scanner_test.cpp
 * @brief [TESTS] B.4.8.6 — `ResourceDirectoryScanner` contract.
 *
 * Five invariants:
 *   1. PE32 / empty RESOURCE directory → no-op.
 *   2. Each leaf IMAGE_RESOURCE_DATA_ENTRY emits one byte4/rva/
 *      resource_data_entry ref pointing at the `OffsetToData` slot.
 *   3. Subdirectory entries are not emitted (they are .rsrc-relative
 *      offsets, not RVAs).
 *   4. Multi-level trees walked correctly (Type → Lang → Data).
 *   5. Out-of-section / depth-overflow / zero OffsetToData are
 *      skipped quietly.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/resource_directory_scanner.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;
using mx::pe::refmap::ResourceDirectoryScanner;

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
    nt.Signature                          = 0x00004550;
    nt.FileHeader.Machine                 = 0x8664;
    nt.FileHeader.SizeOfOptionalHeader    = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic               = 0x20B;
    nt.OptionalHeader.NumberOfRvaAndSizes =
        mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt_of(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

template <typename T>
void write_le(std::vector<std::uint8_t>& out, std::size_t off, T value) {
    if (off + sizeof(T) > out.size()) out.resize(off + sizeof(T), 0);
    std::memcpy(out.data() + off, &value, sizeof(T));
}

[[nodiscard]] Rva add_section(
    PeImage&                         img,
    std::string_view                 name,
    const std::vector<std::uint8_t>& bytes)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        std::string(name),
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    return img.sections()[*idx].virtual_address;
}

[[nodiscard]] int count_origin(
    const ReferenceTable& t, ReferenceOrigin o)
{
    int n = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == o) ++n;
    }
    return n;
}

constexpr std::uint32_t kSubdirFlag = 0x80000000u;

// ---------------------------------------------------------------------------
// No-op
// ---------------------------------------------------------------------------

TEST(ResourceDirectoryScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ResourceDirectoryScanner, NoOpWhenResourceDirEmpty) {
    PeImage img = make_pe32plus_image();
    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single-level tree with one data entry
// ---------------------------------------------------------------------------

TEST(ResourceDirectoryScanner, SingleDataEntryEmitsRef) {
    PeImage img = make_pe32plus_image();

    // Layout in .rsrc:
    //   off 0..15 : root directory header (1 named entry, 0 id)
    //   off 16..23: one entry — Name=0x80000000|name_off,
    //               OffsetToData=24 (data entry leaf)
    //   off 24..39: data entry { OffsetToData=0x4000, Size=64,
    //                            CodePage=0, Reserved=0 }
    std::vector<std::uint8_t> bytes(64, 0);
    // Header: NumberOfNamedEntries=0, NumberOfIdEntries=1
    write_le<std::uint16_t>(bytes, 12, 0);
    write_le<std::uint16_t>(bytes, 14, 1);
    // Entry: Name=42 (ID), OffsetToData=24 (no subdir flag)
    write_le<std::uint32_t>(bytes, 16, 42);
    write_le<std::uint32_t>(bytes, 20, 24);
    // Data entry at off 24
    write_le<std::uint32_t>(bytes, 24, 0x4000);
    write_le<std::uint32_t>(bytes, 28, 64);

    const Rva sec_rva = add_section(img, ".rsrc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
            static_cast<std::uint32_t>(bytes.size());

    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::resource_data_entry), 1);

    bool found = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::resource_data_entry) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        EXPECT_EQ(r.target_rva, 0x4000u);
        EXPECT_EQ(r.location_rva, sec_rva + 24);
        found = true;
    }
    EXPECT_TRUE(found);
}

// ---------------------------------------------------------------------------
// Two-level tree
// ---------------------------------------------------------------------------

TEST(ResourceDirectoryScanner, TwoLevelTreeEmitsLeafRefs) {
    PeImage img = make_pe32plus_image();

    // Layout:
    //   off 0..15 : root (Type) — 1 id entry → subdir at off 24
    //   off 16..23: entry: id=10, OffsetToData=0x80000000|24
    //   off 24..39: subdir (Lang) header — 2 id entries
    //   off 40..47: entry: id=1, OffsetToData=56  (leaf)
    //   off 48..55: entry: id=2, OffsetToData=72  (leaf)
    //   off 56..71: data entry { 0x5000, Size=10 }
    //   off 72..87: data entry { 0x6000, Size=20 }
    std::vector<std::uint8_t> bytes(96, 0);
    write_le<std::uint16_t>(bytes, 12, 0);
    write_le<std::uint16_t>(bytes, 14, 1);
    write_le<std::uint32_t>(bytes, 16, 10);
    write_le<std::uint32_t>(bytes, 20, kSubdirFlag | 24);
    // Subdir header
    write_le<std::uint16_t>(bytes, 24+12, 0);
    write_le<std::uint16_t>(bytes, 24+14, 2);
    // Subdir entries
    write_le<std::uint32_t>(bytes, 40, 1);
    write_le<std::uint32_t>(bytes, 44, 56);
    write_le<std::uint32_t>(bytes, 48, 2);
    write_le<std::uint32_t>(bytes, 52, 72);
    // Data entries
    write_le<std::uint32_t>(bytes, 56, 0x5000);
    write_le<std::uint32_t>(bytes, 60, 10);
    write_le<std::uint32_t>(bytes, 72, 0x6000);
    write_le<std::uint32_t>(bytes, 76, 20);

    const Rva sec_rva = add_section(img, ".rsrc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
            static_cast<std::uint32_t>(bytes.size());

    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::resource_data_entry), 2);

    bool saw_5000 = false, saw_6000 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::resource_data_entry) continue;
        if (r.target_rva == 0x5000u) saw_5000 = true;
        if (r.target_rva == 0x6000u) saw_6000 = true;
    }
    EXPECT_TRUE(saw_5000);
    EXPECT_TRUE(saw_6000);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

TEST(ResourceDirectoryScanner, ZeroOffsetToDataIsSkipped) {
    PeImage img = make_pe32plus_image();

    // Single-level with one entry pointing to a zero-OffsetToData
    // data entry — ref must NOT emit.
    std::vector<std::uint8_t> bytes(64, 0);
    write_le<std::uint16_t>(bytes, 14, 1);
    write_le<std::uint32_t>(bytes, 16, 1);
    write_le<std::uint32_t>(bytes, 20, 24);
    // Data entry at 24 with OffsetToData = 0.

    const Rva sec_rva = add_section(img, ".rsrc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size =
            static_cast<std::uint32_t>(bytes.size());

    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(count_origin(t, ReferenceOrigin::resource_data_entry), 0);
}

TEST(ResourceDirectoryScanner, OutOfSectionDataEntryIsSkipped) {
    PeImage img = make_pe32plus_image();

    // Entry's OffsetToData points way past the end of .rsrc — the
    // walker must skip without crashing.
    std::vector<std::uint8_t> bytes(64, 0);
    write_le<std::uint16_t>(bytes, 14, 1);
    write_le<std::uint32_t>(bytes, 16, 1);
    write_le<std::uint32_t>(bytes, 20, 1024);     // OOB inside section

    const Rva sec_rva = add_section(img, ".rsrc", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 64;

    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ResourceDirectoryScanner, OutOfSectionRsrcDirectoryIsNoOp) {
    PeImage img = make_pe32plus_image();

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0xFFFF0000u;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 64;

    ResourceDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
