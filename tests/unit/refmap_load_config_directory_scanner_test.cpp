/**
 * @file refmap_load_config_directory_scanner_test.cpp
 * @brief [TESTS] B.4.8.5 — `LoadConfigDirectoryScanner` contract.
 *
 * Six invariants:
 *   1. PE32 / empty directory → no-op.
 *   2. Each non-zero VA pointer slot inside LOAD_CONFIG that fits
 *      under the reported `Size` emits one byte8/absolute_va/
 *      load_config_directory ref.
 *   3. Slots whose offset is past `Size` are skipped.
 *   4. CFG / IAT-taken / longjmp / EH-cont / SEH function tables
 *      emit one byte4/rva/load_config_table_entry ref per non-zero
 *      record.
 *   5. CFG-class table stride is `4 + ((GuardFlags >> 28) & 0xF)`;
 *      EH-cont and SEH use plain 4-byte stride.
 *   6. Truncated / out-of-section table → walk truncates safely.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/load_config_directory_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::LoadConfigDirectoryScanner;
using mx::pe::refmap::Reference;
using mx::pe::refmap::ReferenceEncoding;
using mx::pe::refmap::ReferenceOrigin;
using mx::pe::refmap::ReferenceTable;
using mx::pe::refmap::ReferenceWidth;

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

// ---------------------------------------------------------------------------
// No-op
// ---------------------------------------------------------------------------

TEST(LoadConfigDirectoryScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(LoadConfigDirectoryScanner, NoOpWhenLoadConfigEmpty) {
    PeImage img = make_pe32plus_image();
    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// VA slot tests
// ---------------------------------------------------------------------------

TEST(LoadConfigDirectoryScanner, SecurityCookieAndCfgPointersEmitted) {
    PeImage img = make_pe32plus_image();

    // Build a 320-byte LOAD_CONFIG block (covers all known slots
    // through GuardMemcpyFunctionPointer). We populate just three
    // slots; the rest stay zero and must NOT emit refs.
    std::vector<std::uint8_t> bytes(320, 0);
    write_le<std::uint32_t>(bytes,  0, 320);                      // Size
    write_le<std::uint64_t>(bytes, 88, kImageBase + 0x4000);      // SecurityCookie
    write_le<std::uint64_t>(bytes,112, kImageBase + 0x4100);      // CFCheckFP
    write_le<std::uint64_t>(bytes,128, kImageBase + 0x5000);      // CFFunctionTable

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_directory), 3);

    bool sec_ok = false, cfp_ok = false, ctab_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::load_config_directory) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte8);
        EXPECT_EQ(r.encoding, ReferenceEncoding::absolute_va);
        if (r.location_rva == sec_rva +  88) {
            EXPECT_EQ(r.target_rva, 0x4000u); sec_ok  = true;
        } else if (r.location_rva == sec_rva + 112) {
            EXPECT_EQ(r.target_rva, 0x4100u); cfp_ok  = true;
        } else if (r.location_rva == sec_rva + 128) {
            EXPECT_EQ(r.target_rva, 0x5000u); ctab_ok = true;
        }
    }
    EXPECT_TRUE(sec_ok);
    EXPECT_TRUE(cfp_ok);
    EXPECT_TRUE(ctab_ok);
}

TEST(LoadConfigDirectoryScanner, SlotsPastSizeAreSkipped) {
    PeImage img = make_pe32plus_image();

    // 96 bytes: covers SecurityCookie (88..96) but stops short of
    // GuardCFCheckFunctionPointer (112..120). The CF slot must NOT
    // emit even though we wrote a value into it.
    std::vector<std::uint8_t> bytes(320, 0);
    write_le<std::uint32_t>(bytes,  0, 96);
    write_le<std::uint64_t>(bytes, 88, kImageBase + 0x4000);
    write_le<std::uint64_t>(bytes,112, kImageBase + 0x4100);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 96;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    // Only SecurityCookie should appear (88+8=96, fits exactly).
    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_directory), 1);
    for (const auto& r : t.slots()) {
        EXPECT_NE(r.location_rva, sec_rva + 112)
            << "CFCheckFP slot is past reported Size";
    }
}

TEST(LoadConfigDirectoryScanner, BelowImageBaseSlotIsSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes(320, 0);
    write_le<std::uint32_t>(bytes,  0, 320);
    write_le<std::uint64_t>(bytes, 88, 0xCAFE);                // below base
    write_le<std::uint64_t>(bytes,112, kImageBase + 0x4100);   // valid

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_directory), 1);
}

// ---------------------------------------------------------------------------
// Function-table tests
// ---------------------------------------------------------------------------

TEST(LoadConfigDirectoryScanner, CfgFunctionTableEntriesEmitted) {
    PeImage img = make_pe32plus_image();

    // 320-byte LOAD_CONFIG, with the CFG fid table inline at off 320.
    // GuardFlags = 0 → stride = 4 (no metadata). 3 entries:
    // 0x6000, 0x6100, 0 (skip).
    std::vector<std::uint8_t> bytes(320 + 12, 0);
    write_le<std::uint32_t>(bytes,   0, 320);
    write_le<std::uint64_t>(bytes, 128, 0);                    // patch below
    write_le<std::uint64_t>(bytes, 136, 3);                    // count
    write_le<std::uint32_t>(bytes, 144, 0);                    // GuardFlags
    write_le<std::uint32_t>(bytes, 320,    0x6000);
    write_le<std::uint32_t>(bytes, 320+4,  0x6100);
    write_le<std::uint32_t>(bytes, 320+8,  0);                 // null entry

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint64_t cfg_va = kImageBase + sec_rva + 320;
    std::memcpy(img.sections()[0].data.data() + 128, &cfg_va, sizeof(cfg_va));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_table_entry), 2)
        << "two non-zero CFG entries; the null third is skipped";

    bool saw_6000 = false, saw_6100 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::load_config_table_entry) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte4);
        EXPECT_EQ(r.encoding, ReferenceEncoding::rva);
        if (r.target_rva == 0x6000u) saw_6000 = true;
        if (r.target_rva == 0x6100u) saw_6100 = true;
    }
    EXPECT_TRUE(saw_6000);
    EXPECT_TRUE(saw_6100);
}

TEST(LoadConfigDirectoryScanner, CfgStrideIncludesMetadataBytes) {
    PeImage img = make_pe32plus_image();

    // GuardFlags bits 28..31 = 0x1 → stride = 4 + 1 = 5 bytes.
    // 2 entries × 5 bytes = 10 bytes total inline at off 320.
    std::vector<std::uint8_t> bytes(320 + 10, 0);
    write_le<std::uint32_t>(bytes,   0, 320);
    write_le<std::uint64_t>(bytes, 136, 2);                    // count
    write_le<std::uint32_t>(bytes, 144, 0x10000000);           // flags=stride+1
    write_le<std::uint32_t>(bytes, 320,    0x6000);
    bytes[320 + 4] = 0xCC;                                     // metadata byte
    write_le<std::uint32_t>(bytes, 320+5,  0x6100);
    bytes[320 + 9] = 0xAA;                                     // metadata byte

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint64_t cfg_va = kImageBase + sec_rva + 320;
    std::memcpy(img.sections()[0].data.data() + 128, &cfg_va, sizeof(cfg_va));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_table_entry), 2);

    bool e0_ok = false, e1_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::load_config_table_entry) continue;
        if (r.location_rva == sec_rva + 320)     { e0_ok = (r.target_rva == 0x6000u); }
        if (r.location_rva == sec_rva + 320 + 5) { e1_ok = (r.target_rva == 0x6100u); }
    }
    EXPECT_TRUE(e0_ok);
    EXPECT_TRUE(e1_ok);
}

TEST(LoadConfigDirectoryScanner, EhContinuationTableUsesPlainFourByteStride) {
    PeImage img = make_pe32plus_image();

    // EH-cont entries are pure 4-byte RVAs regardless of GuardFlags.
    std::vector<std::uint8_t> bytes(320 + 8, 0);
    write_le<std::uint32_t>(bytes,   0, 320);
    write_le<std::uint64_t>(bytes, 264, 0);                    // patched
    write_le<std::uint64_t>(bytes, 272, 2);                    // count
    write_le<std::uint32_t>(bytes, 144, 0x20000000);           // flags=stride+2
    write_le<std::uint32_t>(bytes, 320,   0x7000);
    write_le<std::uint32_t>(bytes, 324,   0x7100);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    const std::uint64_t eh_va = kImageBase + sec_rva + 320;
    std::memcpy(img.sections()[0].data.data() + 264, &eh_va, sizeof(eh_va));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_table_entry), 2);
    bool e0_ok = false, e1_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::load_config_table_entry) continue;
        if (r.location_rva == sec_rva + 320) e0_ok = (r.target_rva == 0x7000u);
        if (r.location_rva == sec_rva + 324) e1_ok = (r.target_rva == 0x7100u);
    }
    EXPECT_TRUE(e0_ok);
    EXPECT_TRUE(e1_ok);
}

TEST(LoadConfigDirectoryScanner, OutOfSectionTablePointerIgnored) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes(320, 0);
    write_le<std::uint32_t>(bytes,   0, 320);
    write_le<std::uint64_t>(bytes, 128, kImageBase + 0xFFFF0000u); // OOB
    write_le<std::uint64_t>(bytes, 136, 100);                       // count

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 320;

    LoadConfigDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_table_entry), 0);
    // The directory's CFG-table pointer slot itself still emits
    // a ref (it's inside the LOAD_CONFIG bytes, which are in section).
    EXPECT_EQ(count_origin(t, ReferenceOrigin::load_config_directory), 1);
}

} // namespace
