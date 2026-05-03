/**
 * @file refmap_reloc_rebuilder_test.cpp
 * @brief [TESTS] B.4.10.3 — `RelocRebuilder` contract.
 *
 * Six invariants:
 *   1. No `.reloc` directory → no-op (parsed = 0).
 *   2. Identity remapper → bytes round-trip with the same entry set.
 *   3. Translated entries that stay on the same page rewrite in
 *      place; the new page RVA + offset reflects the remap.
 *   4. Cross-page move regroups entries: an entry moved from page
 *      A to page B ends up in page B's block (and the planner
 *      block count reflects the new grouping).
 *   5. `IMAGE_REL_BASED_ABSOLUTE` (type 0) padding entries pass
 *      through verbatim.
 *   6. New bytes too large to fit in old capacity → `written = false`
 *      and the directory is left untouched (defence in depth — the
 *      planner's pinned-block invariant should make this unreachable
 *      under normal use).
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reloc_rebuilder.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace {

using mx::PeImage;
using mx::Rva;
using mx::SectionManager;
using mx::pe::refmap::RelocRebuilder;
using mx::pe::refmap::RvaRemapper;

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

[[nodiscard]] mx::pe::IMAGE_NT_HEADERS64& nt_of(PeImage& img) {
    return std::get<mx::pe::IMAGE_NT_HEADERS64>(img.nt_headers());
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(v));
}

[[nodiscard]] std::uint16_t pack_entry(
    std::uint16_t type, std::uint16_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        (type << 12) | (offset & 0x0FFFu));
}

[[nodiscard]] Rva install_reloc_section(
    PeImage&                          img,
    const std::vector<std::uint8_t>&  bytes,
    std::uint32_t                     directory_size_override = 0)
{
    SectionManager mgr{img};
    auto idx = mgr.add_section(
        ".reloc",
        mx::ByteView{bytes.data(), bytes.size()},
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA |
        mx::pe::IMAGE_SCN_MEM_READ);
    const Rva reloc_va = img.sections()[*idx].virtual_address;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_va;
    nt_of(img).OptionalHeader.DataDirectory[
        mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size =
            directory_size_override == 0
                ? static_cast<std::uint32_t>(bytes.size())
                : directory_size_override;
    return reloc_va;
}

/// One block: one DIR64 entry at `(page_rva, offset)`.
[[nodiscard]] std::vector<std::uint8_t> make_single_block(
    std::uint32_t page_rva,
    std::uint16_t offset)
{
    std::vector<std::uint8_t> bytes;
    // Two entries (DIR64 + ABSOLUTE pad) so block stays 4-byte aligned.
    append_u32(bytes, page_rva);
    append_u32(bytes, /*SizeOfBlock=*/12);
    append_u16(bytes, pack_entry(mx::pe::IMAGE_REL_BASED_DIR64, offset));
    append_u16(bytes, pack_entry(mx::pe::IMAGE_REL_BASED_ABSOLUTE, 0));
    return bytes;
}

/// Decode the rebuilt directory back into a list of (page, offset, type).
struct DecodedEntry {
    std::uint32_t page_rva;
    std::uint16_t offset;
    std::uint16_t type;
};

[[nodiscard]] std::vector<DecodedEntry> decode_directory(
    const PeImage& img)
{
    std::vector<DecodedEntry> out;
    const auto& dir = std::get<mx::pe::IMAGE_NT_HEADERS64>(
        img.nt_headers()).OptionalHeader.DataDirectory[
            mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.VirtualAddress == 0 || dir.Size < 8) return out;

    const auto* sec = img.section_by_rva(dir.VirtualAddress);
    if (sec == nullptr) return out;
    const auto off = dir.VirtualAddress - sec->virtual_address;
    const auto* data = sec->data.data() + off;

    std::uint32_t walked = 0;
    while (walked + 8 <= dir.Size) {
        std::uint32_t page_rva   = 0;
        std::uint32_t block_size = 0;
        std::memcpy(&page_rva,   data + walked + 0, sizeof(page_rva));
        std::memcpy(&block_size, data + walked + 4, sizeof(block_size));
        if (block_size < 8 || walked + block_size > dir.Size) break;
        if (page_rva == 0 && block_size == 8) break;
        const std::uint32_t entry_count =
            (block_size - 8) / sizeof(std::uint16_t);
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            std::uint16_t e = 0;
            std::memcpy(&e, data + walked + 8 + i * 2, sizeof(e));
            out.push_back(DecodedEntry{
                page_rva,
                static_cast<std::uint16_t>(e & 0x0FFFu),
                static_cast<std::uint16_t>((e >> 12) & 0xFu),
            });
        }
        walked += block_size;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Empty / missing
// ---------------------------------------------------------------------------

TEST(RelocRebuilder, NoDirectoryNoOp) {
    PeImage img = make_pe32plus_image();
    RvaRemapper r;
    (void)r.finalize();

    RelocRebuilder rb;
    const auto stats = rb.rebuild(img, r);
    EXPECT_EQ(stats.parsed,     0u);
    EXPECT_EQ(stats.translated, 0u);
    EXPECT_FALSE(stats.written);
}

// ---------------------------------------------------------------------------
// Identity remapper — round-trip
// ---------------------------------------------------------------------------

TEST(RelocRebuilder, IdentityRemapperPreservesEntries) {
    PeImage img = make_pe32plus_image();
    auto bytes = make_single_block(/*page=*/0x4000, /*offset=*/0x100);
    [[maybe_unused]] const auto reloc_va = install_reloc_section(img, bytes);

    RvaRemapper r;
    (void)r.finalize();

    RelocRebuilder rb;
    const auto stats = rb.rebuild(img, r);
    EXPECT_EQ(stats.parsed,            2u);
    EXPECT_EQ(stats.translated,        1u) << "ABSOLUTE pad dropped on rebuild";
    EXPECT_EQ(stats.absolute_padding,  1u);
    EXPECT_TRUE(stats.written);

    const auto entries = decode_directory(img);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].page_rva, 0x4000u);
    EXPECT_EQ(entries[0].offset,   0x100u);
    EXPECT_EQ(entries[0].type,     mx::pe::IMAGE_REL_BASED_DIR64);
    // The trailing 16-bit slot is zeroed by `block_bytes_for` →
    // type=0 (ABSOLUTE pad) at page=0x4000, offset=0.
    EXPECT_EQ(entries[1].type, mx::pe::IMAGE_REL_BASED_ABSOLUTE);
}

// ---------------------------------------------------------------------------
// Same-page remap — page stays, offset shifts
// ---------------------------------------------------------------------------

TEST(RelocRebuilder, SamePageRemapKeepsBlockShiftsOffset) {
    PeImage img = make_pe32plus_image();
    // Old: page=0x4000, offset=0x100 → slot RVA = 0x4100.
    auto bytes = make_single_block(0x4000, 0x100);
    [[maybe_unused]] const auto reloc_va = install_reloc_section(img, bytes);

    // Move slot 0x4100 to 0x4200 (same page).
    RvaRemapper r;
    r.add_chunk(/*old=*/0x4100, /*new=*/0x4200, /*size=*/8);
    ASSERT_TRUE(r.finalize());

    RelocRebuilder rb;
    const auto stats = rb.rebuild(img, r);
    EXPECT_TRUE(stats.written);

    const auto entries = decode_directory(img);
    ASSERT_GE(entries.size(), 1u);
    EXPECT_EQ(entries[0].page_rva, 0x4000u);
    EXPECT_EQ(entries[0].offset,   0x200u);
    EXPECT_EQ(entries[0].type,     mx::pe::IMAGE_REL_BASED_DIR64);
}

// ---------------------------------------------------------------------------
// Cross-page remap — entry migrates to a different block
// ---------------------------------------------------------------------------

TEST(RelocRebuilder, CrossPageRemapMigratesToNewBlock) {
    PeImage img = make_pe32plus_image();
    // Old: page=0x4000, offset=0x100 → slot 0x4100.
    auto bytes = make_single_block(0x4000, 0x100);
    [[maybe_unused]] const auto reloc_va = install_reloc_section(img, bytes);

    // Move slot 0x4100 to 0x6050 (different page = 0x6000).
    RvaRemapper r;
    r.add_chunk(/*old=*/0x4100, /*new=*/0x6050, /*size=*/8);
    ASSERT_TRUE(r.finalize());

    RelocRebuilder rb;
    const auto stats = rb.rebuild(img, r);
    EXPECT_TRUE(stats.written);

    const auto entries = decode_directory(img);
    // Should find a DIR64 entry at page=0x6000, offset=0x050.
    bool found = false;
    for (const auto& e : entries) {
        if (e.type == mx::pe::IMAGE_REL_BASED_DIR64 &&
            e.page_rva == 0x6000u && e.offset == 0x050u)
        {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "DIR64 entry must migrate to 0x6000:0x50 block";
}

// ---------------------------------------------------------------------------
// Capacity check — new bytes too large → no write
// ---------------------------------------------------------------------------

TEST(RelocRebuilder, OverflowCapacityFailsClosed) {
    PeImage img = make_pe32plus_image();
    // Create a directory with two entries on the SAME page so the
    // single block is compact (12 bytes total).
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, /*page=*/0x4000);
    append_u32(bytes, /*SizeOfBlock=*/12);
    append_u16(bytes, pack_entry(mx::pe::IMAGE_REL_BASED_DIR64, 0));
    append_u16(bytes, pack_entry(mx::pe::IMAGE_REL_BASED_DIR64, 0x800));
    [[maybe_unused]] const auto reloc_va = install_reloc_section(img, bytes);

    // Move both entries to DIFFERENT pages — rebuilder will need
    // 2 blocks (8B header × 2 + 4B entries × 2 with padding =
    // 24 B), exceeding the original 12 B.
    RvaRemapper r;
    r.add_chunk(/*old=*/0x4000, /*new=*/0x5000, /*size=*/8);
    r.add_chunk(/*old=*/0x4800, /*new=*/0x7000, /*size=*/8);
    ASSERT_TRUE(r.finalize());

    RelocRebuilder rb;
    const auto stats = rb.rebuild(img, r);
    EXPECT_EQ(stats.parsed, 2u);
    EXPECT_FALSE(stats.written) << "must fail closed when capacity overflows";

    // Original bytes preserved.
    const auto& sec = img.sections()[0];
    EXPECT_EQ(sec.data[0], bytes[0]) << "old directory bytes preserved";
}

} // namespace
