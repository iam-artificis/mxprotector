/**
 * @file refmap_delay_import_descriptor_scanner_test.cpp
 * @brief [TESTS] B.4.8.3 — `DelayImportDescriptorScanner` contract.
 *
 * Six invariants:
 *   1. PE32 image / empty directory → no-op.
 *   2. Each descriptor with `RvaBased=1` emits refs for its non-zero
 *      RVA fields (DllName, ModuleHandle, IAT, INT, BIAT, UnloadInfo).
 *   3. Each non-ordinal thunk in INT/IAT emits one thunk ref.
 *   4. Ordinal thunks are skipped.
 *   5. Descriptors with `RvaBased=0` are skipped silently (legacy VA).
 *   6. The walker stops cleanly at the all-zero terminator.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/delay_import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::DelayImportDescriptorScanner;
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

/// Pack one IMAGE_DELAYLOAD_DESCRIPTOR (32 bytes).
void append_descriptor(
    std::vector<std::uint8_t>& out,
    std::uint32_t              attributes,
    std::uint32_t              dll_name,
    std::uint32_t              module_handle,
    std::uint32_t              iat,
    std::uint32_t              int_,
    std::uint32_t              biat,
    std::uint32_t              unload,
    std::uint32_t              tds = 0)
{
    append_le<std::uint32_t>(out, attributes);
    append_le<std::uint32_t>(out, dll_name);
    append_le<std::uint32_t>(out, module_handle);
    append_le<std::uint32_t>(out, iat);
    append_le<std::uint32_t>(out, int_);
    append_le<std::uint32_t>(out, biat);
    append_le<std::uint32_t>(out, unload);
    append_le<std::uint32_t>(out, tds);
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
// No-op
// ---------------------------------------------------------------------------

TEST(DelayImportDescriptorScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(DelayImportDescriptorScanner, NoOpWhenDirectoryEmpty) {
    PeImage img = make_pe32plus_image();
    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Single descriptor
// ---------------------------------------------------------------------------

TEST(DelayImportDescriptorScanner, SingleDescriptorEmitsAllNonZeroFieldRefs) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes,
        /*attr=*/1,
        /*dll=*/0x2000,
        /*module=*/0x2010,
        /*iat=*/0x3000,
        /*int=*/0x3100,
        /*biat=*/0x3200,
        /*unload=*/0x3300);
    append_descriptor(bytes, 0, 0, 0, 0, 0, 0, 0);  // terminator

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::delay_import_descriptor), 6);

    bool dll_ok = false, mod_ok = false, iat_ok = false,
         int_ok = false, biat_ok = false, unl_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::delay_import_descriptor) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.target_rva == 0x2000u) dll_ok  = true;
        if (r.target_rva == 0x2010u) mod_ok  = true;
        if (r.target_rva == 0x3000u) iat_ok  = true;
        if (r.target_rva == 0x3100u) int_ok  = true;
        if (r.target_rva == 0x3200u) biat_ok = true;
        if (r.target_rva == 0x3300u) unl_ok  = true;
    }
    EXPECT_TRUE(dll_ok);
    EXPECT_TRUE(mod_ok);
    EXPECT_TRUE(iat_ok);
    EXPECT_TRUE(int_ok);
    EXPECT_TRUE(biat_ok);
    EXPECT_TRUE(unl_ok);
}

TEST(DelayImportDescriptorScanner, ZeroFieldsAreSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes,
        /*attr=*/1,
        /*dll=*/0x2000,
        /*module=*/0,        // zero
        /*iat=*/0x3000,
        /*int=*/0,           // zero
        /*biat=*/0,          // zero (often the case)
        /*unload=*/0);       // zero (often the case)
    append_descriptor(bytes, 0, 0, 0, 0, 0, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::delay_import_descriptor), 2)
        << "only DllNameRVA + IAT non-zero";
}

// ---------------------------------------------------------------------------
// Legacy VA-based skip
// ---------------------------------------------------------------------------

TEST(DelayImportDescriptorScanner, RvaBasedZeroDescriptorIsSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes,
        /*attr=*/0,           // RvaBased clear
        /*dll=*/0x2000, /*module=*/0x2010,
        /*iat=*/0x3000, /*int=*/0x3100,
        /*biat=*/0x3200, /*unload=*/0x3300);
    append_descriptor(bytes, 0, 0, 0, 0, 0, 0, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::delay_import_descriptor), 0);
}

// ---------------------------------------------------------------------------
// Thunk array walks
// ---------------------------------------------------------------------------

TEST(DelayImportDescriptorScanner, ThunkArraysWalkedAndOrdinalsSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // descriptor[0] placeholder (filled below).
    append_descriptor(bytes, 0, 0, 0, 0, 0, 0, 0);
    // terminator.
    append_descriptor(bytes, 0, 0, 0, 0, 0, 0, 0);

    // Thunk arrays start at offset 64 (= 2 × 32).
    // INT: 1 ordinal + 1 by-name + null
    append_le<std::uint64_t>(bytes,
        mx::pe::IMAGE_ORDINAL_FLAG64 | 99ULL);   // off 64
    append_le<std::uint64_t>(bytes, 0x5000);     // off 72
    append_le<std::uint64_t>(bytes, 0);          // off 80 (null)
    // IAT: 2 by-name + null (at off 88)
    append_le<std::uint64_t>(bytes, 0x6000);     // off 88
    append_le<std::uint64_t>(bytes, 0x6050);     // off 96
    append_le<std::uint64_t>(bytes, 0);          // off 104

    const Rva sec_rva = add_section(img, ".rdata", bytes);

    auto patch_u32 = [&](std::uint32_t off, std::uint32_t v) {
        std::memcpy(img.sections()[0].data.data() + off, &v, sizeof(v));
    };
    // Build descriptor[0]: attr=1, IAT=sec+88, INT=sec+64.
    patch_u32(0,  1);                 // Attributes
    patch_u32(12, sec_rva + 88);      // ImportAddressTableRVA
    patch_u32(16, sec_rva + 64);      // ImportNameTableRVA

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // INT contributes 1 by-name (0x5000); IAT contributes 2 (0x6000, 0x6050).
    EXPECT_EQ(count_origin(t, ReferenceOrigin::delay_import_thunk), 3);

    bool saw_5000 = false, saw_6000 = false, saw_6050 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::delay_import_thunk) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.target_rva == 0x5000u) saw_5000 = true;
        if (r.target_rva == 0x6000u) saw_6000 = true;
        if (r.target_rva == 0x6050u) saw_6050 = true;
    }
    EXPECT_TRUE(saw_5000);
    EXPECT_TRUE(saw_6000);
    EXPECT_TRUE(saw_6050);
}

// ---------------------------------------------------------------------------
// Multi-descriptor + truncation
// ---------------------------------------------------------------------------

TEST(DelayImportDescriptorScanner, TerminatorStopsTheWalk) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_descriptor(bytes, 1, 0x2000, 0, 0x3000, 0, 0, 0);  // 1 desc
    append_descriptor(bytes, 1, 0x2010, 0, 0x3010, 0, 0, 0);  // 2nd desc
    append_descriptor(bytes, 0, 0,      0, 0,      0, 0, 0);  // null
    append_descriptor(bytes, 1, 0xDEAD, 0, 0xBEEF, 0, 0, 0);  // garbage

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size =
            static_cast<std::uint32_t>(bytes.size());

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // 2 descriptors × 2 fields each = 4.
    EXPECT_EQ(count_origin(t, ReferenceOrigin::delay_import_descriptor), 4);
    for (const auto& r : t.slots()) {
        EXPECT_NE(r.target_rva, 0xDEADu);
        EXPECT_NE(r.target_rva, 0xBEEFu);
    }
}

TEST(DelayImportDescriptorScanner, TruncatedDescriptorTableStopsCleanly) {
    PeImage img = make_pe32plus_image();
    std::vector<std::uint8_t> bytes(20, 0);  // < 32-byte descriptor

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 20;

    DelayImportDescriptorScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
