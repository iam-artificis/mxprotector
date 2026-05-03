/**
 * @file refmap_tls_directory_scanner_test.cpp
 * @brief [TESTS] B.4.8.4 — `TlsDirectoryScanner` contract.
 *
 * Five invariants:
 *   1. PE32 / empty TLS directory → no-op.
 *   2. Each non-zero VA-bearing slot of IMAGE_TLS_DIRECTORY64 emits
 *      one byte8/absolute_va/tls_directory reference whose
 *      `target_rva = stored_va - image_base`.
 *   3. Each non-zero entry in the callback array emits one
 *      byte8/absolute_va/tls_callback reference.
 *   4. VAs below `image_base` are skipped (would underflow).
 *   5. The callback walk stops at the first null terminator or OOB.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/tls_directory_scanner.hpp"
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
using mx::pe::refmap::TlsDirectoryScanner;

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
void append_le(std::vector<std::uint8_t>& out, T value) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
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

TEST(TlsDirectoryScanner, NoOpOnPe32) {
    PeImage img;
    img.set_architecture(mx::Architecture::x86);
    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

TEST(TlsDirectoryScanner, NoOpWhenTlsDirEmpty) {
    PeImage img = make_pe32plus_image();
    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

// ---------------------------------------------------------------------------
// Directory VA-bearing slots
// ---------------------------------------------------------------------------

TEST(TlsDirectoryScanner, FourSlotsEmitWhenAllSet) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // IMAGE_TLS_DIRECTORY64 — 40 bytes (PE32+).
    append_le<std::uint64_t>(bytes, kImageBase + 0x2000);  // Start
    append_le<std::uint64_t>(bytes, kImageBase + 0x2050);  // End
    append_le<std::uint64_t>(bytes, kImageBase + 0x2100);  // AddressOfIndex
    append_le<std::uint64_t>(bytes, kImageBase + 0x2200);  // AddressOfCallBacks
    append_le<std::uint32_t>(bytes, 0);                    // SizeOfZeroFill
    append_le<std::uint32_t>(bytes, 0);                    // Characteristics
    // The callback array right after at offset 40 — empty (just null).
    append_le<std::uint64_t>(bytes, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);

    // Patch AddressOfCallBacks to point at the inline array (sec+40).
    const std::uint64_t cb_va = kImageBase + sec_rva + 40;
    std::memcpy(img.sections()[0].data.data() + 24, &cb_va, sizeof(cb_va));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].Size =
            static_cast<std::uint32_t>(bytes.size());

    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::tls_directory), 4);

    bool start_ok = false, end_ok = false, idx_ok = false, cb_ok = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::tls_directory) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte8);
        EXPECT_EQ(r.encoding, ReferenceEncoding::absolute_va);
        if (r.location_rva == sec_rva +  0) {
            EXPECT_EQ(r.target_rva, 0x2000u);  start_ok = true;
        } else if (r.location_rva == sec_rva +  8) {
            EXPECT_EQ(r.target_rva, 0x2050u);  end_ok   = true;
        } else if (r.location_rva == sec_rva + 16) {
            EXPECT_EQ(r.target_rva, 0x2100u);  idx_ok   = true;
        } else if (r.location_rva == sec_rva + 24) {
            // The pointer slot — its target is the callback array's RVA.
            EXPECT_EQ(r.target_rva, sec_rva + 40);
            cb_ok = true;
        }
    }
    EXPECT_TRUE(start_ok);
    EXPECT_TRUE(end_ok);
    EXPECT_TRUE(idx_ok);
    EXPECT_TRUE(cb_ok);
}

TEST(TlsDirectoryScanner, BelowImageBaseSlotIsSkipped) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    append_le<std::uint64_t>(bytes, kImageBase + 0x2000);  // valid
    append_le<std::uint64_t>(bytes, 0x100);                // below base
    append_le<std::uint64_t>(bytes, 0);                    // zero
    append_le<std::uint64_t>(bytes, 0);                    // zero
    append_le<std::uint32_t>(bytes, 0);
    append_le<std::uint32_t>(bytes, 0);

    const Rva sec_rva = add_section(img, ".rdata", bytes);
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].Size =
            static_cast<std::uint32_t>(bytes.size());

    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::tls_directory), 1)
        << "only the valid VA emits; below-base slot skipped";
}

// ---------------------------------------------------------------------------
// Callback array walk
// ---------------------------------------------------------------------------

TEST(TlsDirectoryScanner, CallbackArrayEmitsRefsAndStopsAtNull) {
    PeImage img = make_pe32plus_image();

    std::vector<std::uint8_t> bytes;
    // TLS dir with only AddressOfCallBacks set (others zero).
    append_le<std::uint64_t>(bytes, 0);                       // Start
    append_le<std::uint64_t>(bytes, 0);                       // End
    append_le<std::uint64_t>(bytes, 0);                       // Index
    append_le<std::uint64_t>(bytes, 0);                       // CallBacks (patch)
    append_le<std::uint32_t>(bytes, 0);
    append_le<std::uint32_t>(bytes, 0);
    // Callback array at off 40: 3 callbacks + null + garbage.
    append_le<std::uint64_t>(bytes, kImageBase + 0x4000);     // off 40
    append_le<std::uint64_t>(bytes, kImageBase + 0x4050);     // off 48
    append_le<std::uint64_t>(bytes, kImageBase + 0x4100);     // off 56
    append_le<std::uint64_t>(bytes, 0);                       // off 64 (null)
    append_le<std::uint64_t>(bytes, kImageBase + 0xDEAD);     // off 72 (garbage)

    const Rva sec_rva = add_section(img, ".rdata", bytes);

    // Patch AddressOfCallBacks (off 24) to sec+40.
    const std::uint64_t cb_va = kImageBase + sec_rva + 40;
    std::memcpy(img.sections()[0].data.data() + 24, &cb_va, sizeof(cb_va));

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = sec_rva;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].Size =
            static_cast<std::uint32_t>(bytes.size());

    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);

    EXPECT_EQ(count_origin(t, ReferenceOrigin::tls_callback), 3)
        << "three callbacks before null; garbage past null ignored";

    bool saw_4000 = false, saw_4050 = false, saw_4100 = false;
    for (const auto& r : t.slots()) {
        if (r.origin != ReferenceOrigin::tls_callback) continue;
        EXPECT_EQ(r.width,    ReferenceWidth::byte8);
        EXPECT_EQ(r.encoding, ReferenceEncoding::absolute_va);
        if (r.target_rva == 0x4000u) saw_4000 = true;
        if (r.target_rva == 0x4050u) saw_4050 = true;
        if (r.target_rva == 0x4100u) saw_4100 = true;
        EXPECT_NE(r.target_rva, 0xDEADu);
    }
    EXPECT_TRUE(saw_4000);
    EXPECT_TRUE(saw_4050);
    EXPECT_TRUE(saw_4100);
}

TEST(TlsDirectoryScanner, OutOfSectionDirectoryIsNoOp) {
    PeImage img = make_pe32plus_image();

    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0xFFFF0000u;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_TLS].Size = 40;

    TlsDirectoryScanner s;
    ReferenceTable t;
    s.scan(img, t);
    EXPECT_EQ(t.size(), 0u);
}

} // namespace
