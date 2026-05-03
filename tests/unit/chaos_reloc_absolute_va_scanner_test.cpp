/**
 * @file chaos_reloc_absolute_va_scanner_test.cpp
 * @brief [TESTS] B.4.4 — `RelocAbsoluteVaScanner` contract.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "mxprotector/pe/chaos/reference.hpp"
#include "mxprotector/pe/chaos/reloc_absolute_va_scanner.hpp"
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
using mx::pe::chaos::RelocAbsoluteVaScanner;

constexpr std::uint64_t kImageBase = 0x140000000ULL;
constexpr std::uint32_t kLfanew    = 0x100;

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
    nt.OptionalHeader.NumberOfRvaAndSizes = mx::pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    img.set_nt_headers(nt);
    return img;
}

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

/// Append a `u32` at the back of `out` (little-endian).
void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

/// Append a `u16` at the back of `out` (little-endian).
void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

/// Append a `u64` at the back of `out` (little-endian).
void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

// ---------------------------------------------------------------------------
// Empty / missing .reloc → no-op
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, MissingDirectoryNoOp) {
    PeImage img = make_pe32plus_image();
    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single block, single DIR64 entry
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, SingleDir64EntryEmitsReference) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    // Section A — holds the absolute VA at RVA 0x1004.
    std::vector<std::uint8_t> sec_a(0x40, 0);
    const std::uint64_t stored_va = kImageBase + 0x2050;
    std::memcpy(sec_a.data() + 4, &stored_va, sizeof(stored_va));
    auto idx_a = mgr.add_section(
        ".text",
        mx::ByteView{sec_a.data(), sec_a.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx_a.has_value());
    const Rva sec_a_va = img.sections()[*idx_a].virtual_address;

    // Section B — holds the .reloc directory.
    // One block: page=sec_a_va, size=8+2=10, entry: DIR64 at offset 4.
    std::vector<std::uint8_t> reloc_bytes;
    append_u32(reloc_bytes, sec_a_va);   // VirtualAddress
    append_u32(reloc_bytes, 10);          // SizeOfBlock
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_DIR64 << 12) | 4));

    auto idx_r = mgr.add_section(
        ".reloc",
        mx::ByteView{reloc_bytes.data(), reloc_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ |
        mx::pe::IMAGE_SCN_MEM_DISCARDABLE);
    ASSERT_TRUE(idx_r.has_value());
    const Rva reloc_rva = img.sections()[*idx_r].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size =
            static_cast<std::uint32_t>(reloc_bytes.size());

    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);

    ASSERT_EQ(t.size(), 1u);
    const auto& r = t.slots()[0];
    EXPECT_EQ(r.location_rva, sec_a_va + 4);
    EXPECT_EQ(r.target_rva,   0x2050u);
    EXPECT_EQ(r.width,        ReferenceWidth::byte8);
    EXPECT_EQ(r.encoding,     ReferenceEncoding::absolute_va);
    EXPECT_EQ(r.origin,       ReferenceOrigin::reloc_absolute_va);
}

// ---------------------------------------------------------------------------
// IMAGE_REL_BASED_ABSOLUTE entries are skipped (alignment padding)
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, AbsoluteEntriesAreSkipped) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    // Section A.
    std::vector<std::uint8_t> sec_a(0x20, 0);
    const std::uint64_t stored_va = kImageBase + 0x500;
    std::memcpy(sec_a.data() + 0, &stored_va, sizeof(stored_va));
    auto idx_a = mgr.add_section(
        ".text",
        mx::ByteView{sec_a.data(), sec_a.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    ASSERT_TRUE(idx_a.has_value());
    const Rva sec_a_va = img.sections()[*idx_a].virtual_address;

    // Block with two entries: one DIR64, one ABSOLUTE (padding).
    std::vector<std::uint8_t> reloc_bytes;
    append_u32(reloc_bytes, sec_a_va);
    append_u32(reloc_bytes, 12);
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_DIR64 << 12) | 0));
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_ABSOLUTE << 12) | 0));

    auto idx_r = mgr.add_section(
        ".reloc", mx::ByteView{reloc_bytes.data(), reloc_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    ASSERT_TRUE(idx_r.has_value());
    const Rva reloc_rva = img.sections()[*idx_r].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 12;

    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(t.size(), 1u) << "DIR64 emitted; ABSOLUTE skipped";
    EXPECT_EQ(t.slots()[0].target_rva, 0x500u);
}

// ---------------------------------------------------------------------------
// Multiple blocks
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, MultipleBlocksAccumulate) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    // Two pages, each with a stored VA.
    std::vector<std::uint8_t> sec_a(0x20, 0);
    const std::uint64_t va_at_0 = kImageBase + 0x1234;
    std::memcpy(sec_a.data(), &va_at_0, sizeof(va_at_0));
    auto idx_a = mgr.add_section(
        ".text", mx::ByteView{sec_a.data(), sec_a.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    const Rva page_a = img.sections()[*idx_a].virtual_address;

    std::vector<std::uint8_t> sec_b(0x20, 0);
    const std::uint64_t va_at_b = kImageBase + 0x5678;
    std::memcpy(sec_b.data(), &va_at_b, sizeof(va_at_b));
    auto idx_b = mgr.add_section(
        ".data", mx::ByteView{sec_b.data(), sec_b.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    const Rva page_b = img.sections()[*idx_b].virtual_address;

    // Two blocks back-to-back.
    std::vector<std::uint8_t> reloc_bytes;
    // Block 1: page_a + DIR64 entry at offset 0.
    append_u32(reloc_bytes, page_a);
    append_u32(reloc_bytes, 10);
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_DIR64 << 12) | 0));
    // Block 2: page_b + DIR64 entry at offset 0.
    append_u32(reloc_bytes, page_b);
    append_u32(reloc_bytes, 10);
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_DIR64 << 12) | 0));

    auto idx_r = mgr.add_section(
        ".reloc", mx::ByteView{reloc_bytes.data(), reloc_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    const Rva reloc_rva = img.sections()[*idx_r].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size =
            static_cast<std::uint32_t>(reloc_bytes.size());

    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);

    ASSERT_EQ(t.size(), 2u);
    bool found_1234 = false, found_5678 = false;
    for (const auto& r : t.slots()) {
        if (r.target_rva == 0x1234u) found_1234 = true;
        if (r.target_rva == 0x5678u) found_5678 = true;
    }
    EXPECT_TRUE(found_1234);
    EXPECT_TRUE(found_5678);
}

// ---------------------------------------------------------------------------
// VA below image_base is skipped
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, SubBaseVaIsSkipped) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    std::vector<std::uint8_t> sec_a(0x20, 0);
    const std::uint64_t bogus_va = kImageBase - 1;  // below base
    std::memcpy(sec_a.data(), &bogus_va, sizeof(bogus_va));
    auto idx_a = mgr.add_section(
        ".text", mx::ByteView{sec_a.data(), sec_a.size()},
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_READ);
    const Rva page_a = img.sections()[*idx_a].virtual_address;

    std::vector<std::uint8_t> reloc_bytes;
    append_u32(reloc_bytes, page_a);
    append_u32(reloc_bytes, 10);
    append_u16(reloc_bytes,
        static_cast<std::uint16_t>((mx::pe::IMAGE_REL_BASED_DIR64 << 12) | 0));

    auto idx_r = mgr.add_section(
        ".reloc", mx::ByteView{reloc_bytes.data(), reloc_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    const Rva reloc_rva = img.sections()[*idx_r].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 10;

    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(t.size(), 0u) << "VA < image_base must be skipped";
}

// ---------------------------------------------------------------------------
// Malformed block size terminates walking cleanly
// ---------------------------------------------------------------------------

TEST(RelocAbsoluteVaScanner, MalformedBlockSizeTerminates) {
    PeImage img = make_pe32plus_image();
    SectionManager mgr{img};

    std::vector<std::uint8_t> reloc_bytes;
    append_u32(reloc_bytes, 0x1000);  // page
    append_u32(reloc_bytes, 4);       // BlockSize < 8 — malformed

    auto idx_r = mgr.add_section(
        ".reloc", mx::ByteView{reloc_bytes.data(), reloc_bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA);
    const Rva reloc_rva = img.sections()[*idx_r].virtual_address;

    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 8;

    RelocAbsoluteVaScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(t.size(), 0u);
    // (Did not loop forever — that's the property under test.)
}

} // namespace
