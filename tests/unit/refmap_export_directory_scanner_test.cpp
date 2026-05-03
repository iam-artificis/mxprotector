/**
 * @file refmap_export_directory_scanner_test.cpp
 * @brief [TESTS] B.4.8.2 — `ExportDirectoryScanner` contract.
 *
 * Five invariants:
 *   1. The four pointer slots (Name / AddressOf{Functions,Names,
 *      NameOrdinals}) emit one rva-typed reference each when non-zero.
 *   2. EAT entries emit one rva-typed export_function_rva ref each.
 *   3. Name pointer entries emit one rva-typed export_name_rva ref each.
 *   4. Zero entries are skipped (no spurious refs).
 *   5. PE32 / empty directory / out-of-section directory → no-op.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/export_directory_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::ExportDirectoryScanner;
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

template <typename T>
void append_le(std::vector<std::uint8_t>& out, T value) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

/// Pack an IMAGE_EXPORT_DIRECTORY (40 bytes) at the end of `out`.
void append_export_directory(
    std::vector<std::uint8_t>& out,
    std::uint32_t              name_rva,
    std::uint32_t              num_functions,
    std::uint32_t              num_names,
    std::uint32_t              addr_functions,
    std::uint32_t              addr_names,
    std::uint32_t              addr_name_ordinals)
{
    append_le<std::uint32_t>(out, 0);                  //  0 Characteristics
    append_le<std::uint32_t>(out, 0);                  //  4 TimeDateStamp
    append_le<std::uint16_t>(out, 0);                  //  8 MajorVersion
    append_le<std::uint16_t>(out, 0);                  // 10 MinorVersion
    append_le<std::uint32_t>(out, name_rva);           // 12 Name
    append_le<std::uint32_t>(out, 1);                  // 16 Base
    append_le<std::uint32_t>(out, num_functions);      // 20
    append_le<std::uint32_t>(out, num_names);          // 24
    append_le<std::uint32_t>(out, addr_functions);     // 28
    append_le<std::uint32_t>(out, addr_names);         // 32
    append_le<std::uint32_t>(out, addr_name_ordinals); // 36
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

// ---------------------------------------------------------------------------
// No-op cases
// ---------------------------------------------------------------------------

TEST(ExportDirectoryScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ExportDirectoryScanner, NoOpWhenExportDirEmpty) {
    PeImage img = make_pe32plus_image();
    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Directory pointer slots
// ---------------------------------------------------------------------------

TEST(ExportDirectoryScanner, DirectoryPointerSlotsEmittedWhenNonZero) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_export_directory(bytes,
        /*name=*/0x2000,
        /*nfunc=*/0,    // no entries — pointer slots only
        /*nname=*/0,
        /*addr_fn=*/0x3000,
        /*addr_nm=*/0x3100,
        /*addr_no=*/0x3200);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_directory), 4);

    bool name_ok = false, fn_ok = false, nm_ok = false, no_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::export_directory) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.location_rva == sec_rva + 12) {
            EXPECT_EQ(r.target_rva, 0x2000u);
            name_ok = true;
        } else if (r.location_rva == sec_rva + 28) {
            EXPECT_EQ(r.target_rva, 0x3000u);
            fn_ok = true;
        } else if (r.location_rva == sec_rva + 32) {
            EXPECT_EQ(r.target_rva, 0x3100u);
            nm_ok = true;
        } else if (r.location_rva == sec_rva + 36) {
            EXPECT_EQ(r.target_rva, 0x3200u);
            no_ok = true;
        }
    }
    EXPECT_TRUE(name_ok);
    EXPECT_TRUE(fn_ok);
    EXPECT_TRUE(nm_ok);
    EXPECT_TRUE(no_ok);
}

TEST(ExportDirectoryScanner, ZeroPointerSlotsAreSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_export_directory(bytes,
        /*name=*/0,        // zero — must NOT emit
        /*nfunc=*/0,
        /*nname=*/0,
        /*addr_fn=*/0,     // zero
        /*addr_nm=*/0x3100,
        /*addr_no=*/0);    // zero

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // Only AddressOfNames is non-zero.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_directory), 1);
}

// ---------------------------------------------------------------------------
// EAT and name table walks
// ---------------------------------------------------------------------------

TEST(ExportDirectoryScanner, EatEntriesEmitFunctionRefs) {
    PeImage img = make_pe32plus_image();

    // Layout (single section):
    //   off 0..39 : IMAGE_EXPORT_DIRECTORY
    //   off 40..51: EAT — 3 × 4-byte RVAs (0x4000, 0x4050, 0)
    //   off 52..  : trailer
    std::vector<std::uint8_t> bytes;
    append_export_directory(bytes, 0, /*nfunc=*/3, 0, 0, 0, 0);
    append_le<std::uint32_t>(bytes, 0x4000);
    append_le<std::uint32_t>(bytes, 0x4050);
    append_le<std::uint32_t>(bytes, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);

    // Patch AddressOfFunctions in the directory header (offset 28)
    // to point at the EAT (sec_rva + 40).
    const std::uint32_t eat_rva = sec_rva + 40;
    std::memcpy(img.sections()[0].data.data() + 28, &eat_rva,
                sizeof(eat_rva));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // 2 non-zero EAT entries. The zero entry is skipped.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_function_rva), 2);

    bool saw_4000 = false, saw_4050 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::export_function_rva) continue;
        if (r.target_rva == 0x4000u) saw_4000 = true;
        if (r.target_rva == 0x4050u) saw_4050 = true;
    }
    EXPECT_TRUE(saw_4000);
    EXPECT_TRUE(saw_4050);
}

TEST(ExportDirectoryScanner, NameTableEntriesEmitNameRefs) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_export_directory(bytes, 0, 0, /*nname=*/2, 0, 0, 0);
    // Name pointer table at offset 40.
    append_le<std::uint32_t>(bytes, 0x5000);
    append_le<std::uint32_t>(bytes, 0x5050);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint32_t name_table_rva = sec_rva + 40;
    std::memcpy(img.sections()[0].data.data() + 32, &name_table_rva,
                sizeof(name_table_rva));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_name_rva), 2);
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

TEST(ExportDirectoryScanner, TruncatedDirectoryStopsCleanly) {
    PeImage img = make_pe32plus_image();

    // 20 bytes — well under IMAGE_EXPORT_DIRECTORY's 40 bytes.
    std::vector<std::uint8_t> bytes(20, 0);
    const Rva sec_rva = add_section(img, ".rdata", bytes);

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 20;

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(ExportDirectoryScanner, OutOfSectionEatPointerIsIgnored) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // EAT pointer points way past any section — must skip silently.
    append_export_directory(bytes,
        0, /*nfunc=*/2, 0,
        /*addr_fn=*/0xFFFFF000u, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    ExportDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // AddressOfFunctions slot itself emits a reference (it's in
    // the dir's body, which IS in section), but the EAT walk skips.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_function_rva), 0);
    EXPECT_EQ(count_origin(t, ReferenceOrigin::export_directory), 1)
        << "only AddressOfFunctions slot is non-zero in this image";
}

} // namespace
