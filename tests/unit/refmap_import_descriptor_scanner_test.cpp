/**
 * @file refmap_import_descriptor_scanner_test.cpp
 * @brief [TESTS] B.4.8.1 — `ImportDescriptorScanner` contract.
 *
 * Five invariants:
 *   1. Each descriptor emits one rva-typed reference per non-zero
 *      Name / OriginalFirstThunk / FirstThunk slot.
 *   2. Each non-ordinal thunk entry emits one rva-typed reference
 *      pointing at its IMAGE_IMPORT_BY_NAME RVA.
 *   3. Ordinal thunk entries (top bit set) are skipped.
 *   4. The walker stops cleanly at the null descriptor terminator.
 *   5. PE32 images are no-ops; empty IMPORT directories are no-ops.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::ImportDescriptorScanner;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;

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

/// Append `value` little-endian to a byte vector.
template <typename T>
void append_le(std::vector<std::uint8_t>& out, T value) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

/// Pack one IMAGE_IMPORT_DESCRIPTOR (20 bytes).
void append_descriptor(
    std::vector<std::uint8_t>& out,
    std::uint32_t              oft,
    std::uint32_t              tds,
    std::uint32_t              fwd,
    std::uint32_t              name,
    std::uint32_t              ft)
{
    append_le<std::uint32_t>(out, oft);
    append_le<std::uint32_t>(out, tds);
    append_le<std::uint32_t>(out, fwd);
    append_le<std::uint32_t>(out, name);
    append_le<std::uint32_t>(out, ft);
}

/// Add a section with the given bytes; return its base RVA.
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

/// Count refs of one origin in the table.
[[nodiscard]] int count_origin(
    const ReferenceTable& t, ReferenceOrigin o)
{
    int n = 0;
    for (const auto& r : t.slots()) {
        if (r.origin == o) ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Empty / disabled cases
// ---------------------------------------------------------------------------

TEST(ImportDescriptorScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ImportDescriptorScanner, NoOpWhenImportDirEmpty) {
    PeImage img = make_pe32plus_image();
    // DataDirectory[IMPORT] left at default {0,0}.

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single descriptor — descriptor field references
// ---------------------------------------------------------------------------

TEST(ImportDescriptorScanner, SingleDescriptorEmitsThreeFieldRefs) {
    PeImage img = make_pe32plus_image();

    // Descriptor references for {OFT=0x2000, Name=0x3000, FT=0x4000};
    // followed by the null terminator.
    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes,
        /*oft=*/0x2000, /*tds=*/0, /*fwd=*/0,
        /*name=*/0x3000, /*ft=*/0x4000);
    append_descriptor(bytes, 0, 0, 0, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_descriptor), 3);

    bool found_oft = false, found_name = false, found_ft = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::import_descriptor) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.location_rva == sec_rva +  0) {
            EXPECT_EQ(r.target_rva, 0x2000u);
            found_oft = true;
        } else if (r.location_rva == sec_rva + 12) {
            EXPECT_EQ(r.target_rva, 0x3000u);
            found_name = true;
        } else if (r.location_rva == sec_rva + 16) {
            EXPECT_EQ(r.target_rva, 0x4000u);
            found_ft = true;
        }
    }
    EXPECT_TRUE(found_oft);
    EXPECT_TRUE(found_name);
    EXPECT_TRUE(found_ft);
}

TEST(ImportDescriptorScanner, ZeroFieldsWithinDescriptorAreSkipped) {
    PeImage img = make_pe32plus_image();

    // Descriptor with OFT=0 (some compilers omit INT for bound imports).
    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes,
        /*oft=*/0, /*tds=*/0, /*fwd=*/0,
        /*name=*/0x3000, /*ft=*/0x4000);
    append_descriptor(bytes, 0, 0, 0, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_descriptor), 2)
        << "OFT=0 must not emit a reference";
}

// ---------------------------------------------------------------------------
// Multi-descriptor — null terminator
// ---------------------------------------------------------------------------

TEST(ImportDescriptorScanner, MultiDescriptorStopsAtTerminator) {
    PeImage img = make_pe32plus_image();

    // Three descriptors + terminator. Each has all three fields set
    // so we expect 9 import_descriptor refs total.
    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes, 0x2000, 0, 0, 0x3000, 0x4000);
    append_descriptor(bytes, 0x2100, 0, 0, 0x3100, 0x4100);
    append_descriptor(bytes, 0x2200, 0, 0, 0x3200, 0x4200);
    append_descriptor(bytes, 0,      0, 0, 0,      0);
    // Trailing garbage that must be ignored.
    append_descriptor(bytes, 0xDEAD, 0, 0, 0xBEEF, 0xCAFE);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_descriptor), 9)
        << "exactly 3 descriptors × 3 fields, terminator stops the walk";

    // Sanity: 0xDEAD/0xBEEF/0xCAFE never reach the table.
    for (const auto& r : t.slots()) {
        EXPECT_NE(r.target_rva, 0xDEADu);
        EXPECT_NE(r.target_rva, 0xBEEFu);
        EXPECT_NE(r.target_rva, 0xCAFEu);
    }
}

// ---------------------------------------------------------------------------
// Thunk array walk
// ---------------------------------------------------------------------------

TEST(ImportDescriptorScanner, ThunkArrayEmitsRefsForByNameEntries) {
    PeImage img = make_pe32plus_image();

    // Layout (single section, RVA = sec_rva):
    //   off 0:  desc[0]  (OFT=sec+0x40, Name=0, FT=sec+0x40)
    //   off 20: desc[null terminator]
    //   off 40: thunk[0] = 0x5000  (RVA of IMAGE_IMPORT_BY_NAME)
    //   off 48: thunk[1] = 0x5050
    //   off 56: thunk[2] = 0  (terminator)
    std::vector<std::uint8_t> bytes;

    // Reserve room first; we'll patch in concrete RVAs after we
    // know the section's base.
    append_descriptor(bytes, 0, 0, 0, 0, 0);  // desc[0] placeholder
    append_descriptor(bytes, 0, 0, 0, 0, 0);  // desc null terminator
    // Thunk array follows at offset 40.
    append_le<std::uint64_t>(bytes, 0x5000);
    append_le<std::uint64_t>(bytes, 0x5050);
    append_le<std::uint64_t>(bytes, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint32_t thunk_array_rva = sec_rva + 40;

    // Patch desc[0] OFT and FT to point at the thunk array.
    auto patch_u32 = [&](std::uint32_t off, std::uint32_t v) {
        auto& sec_data = img.sections()[0].data;
        std::memcpy(sec_data.data() + off, &v, sizeof(v));
    };
    patch_u32( 0, thunk_array_rva); // OFT
    patch_u32(16, thunk_array_rva); // FT

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // OFT and FT both walk the same thunk array → 2 entries × 2 walks
    // = 4 thunk refs total.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_thunk), 4);

    bool saw_5000 = false, saw_5050 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::import_thunk) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.target_rva == 0x5000u) saw_5000 = true;
        if (r.target_rva == 0x5050u) saw_5050 = true;
    }
    EXPECT_TRUE(saw_5000);
    EXPECT_TRUE(saw_5050);
}

TEST(ImportDescriptorScanner, OrdinalThunkEntriesAreSkipped) {
    PeImage img = make_pe32plus_image();

    // Single descriptor pointing at a thunk array of one ordinal +
    // one by-name + null terminator.
    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes, 0, 0, 0, 0, 0);  // placeholder
    append_descriptor(bytes, 0, 0, 0, 0, 0);  // null
    // thunk[0] = ordinal (top bit set + ordinal #42)
    append_le<std::uint64_t>(bytes,
        mx::pe::IMAGE_ORDINAL_FLAG64 | 42ULL);
    // thunk[1] = by-name (RVA 0x5000)
    append_le<std::uint64_t>(bytes, 0x5000);
    // thunk[2] = terminator
    append_le<std::uint64_t>(bytes, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint32_t thunk_array_rva = sec_rva + 40;

    auto patch_u32 = [&](std::uint32_t off, std::uint32_t v) {
        auto& sec_data = img.sections()[0].data;
        std::memcpy(sec_data.data() + off, &v, sizeof(v));
    };
    patch_u32( 0, thunk_array_rva);
    patch_u32(16, thunk_array_rva);

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // Ordinal thunk skipped; OFT + FT both walk → 2 by-name refs total.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_thunk), 2);
    for (const auto& r : t.slots()) {
        if (r.origin == ReferenceOrigin::import_thunk) {
            EXPECT_EQ(r.target_rva, 0x5000u)
                << "only the by-name thunk emits a reference";
        }
    }
}

// ---------------------------------------------------------------------------
// Truncated / out-of-section robustness
// ---------------------------------------------------------------------------

TEST(ImportDescriptorScanner, TruncatedDescriptorTableStopsCleanly) {
    PeImage img = make_pe32plus_image();

    // Only 10 bytes of section data — well under the 20-byte
    // descriptor size. The walker must exit without crashing.
    std::vector<std::uint8_t> bytes(10, 0);
    const Rva sec_rva = add_section(img, ".rdata", bytes);

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 10;

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ImportDescriptorScanner, OutOfSectionThunkArrayIsSkippedQuietly) {
    PeImage img = make_pe32plus_image();

    // Descriptor whose OFT/FT point past the end of any section —
    // the thunk walker must skip without emitting refs.
    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes, 0xFFFF0000u, 0, 0, 0, 0xFFFF1000u);
    append_descriptor(bytes, 0, 0, 0, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_descriptor), 2)
        << "descriptor refs still emitted (OFT and FT non-zero)";
    EXPECT_EQ(count_origin(t, ReferenceOrigin::import_thunk), 0)
        << "thunk arrays are out-of-section, no thunk refs";
}

} // namespace
