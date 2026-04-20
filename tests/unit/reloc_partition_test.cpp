/**
 * @file reloc_partition_test.cpp
 * @brief [TESTS] `partition_encrypted_relocs` correctness.
 *
 * Constructs a minimal `PeImage` with two sections — a synthetic
 * "encrypted code" section at RVA 0x1000 and a "data" section at
 * RVA 0x3000 — plus a hand-built `.reloc` directory containing
 * blocks targeting both. Each test calls `partition_encrypted_relocs`
 * and pins the expected partition outcome:
 *
 *   - Block at page_rva inside the encrypted section: copied
 *     verbatim into the stub-private blob and every non-ABSOLUTE
 *     entry in the visible `.reloc` is rewritten to type 0
 *     (ABSOLUTE) while keeping its 12-bit page offset.
 *   - Block at page_rva in the non-encrypted section: stays
 *     untouched in the visible `.reloc`; not copied.
 *   - ABSOLUTE entries (already padding) are not promoted into
 *     the stub-private blob — the applier walks live entries
 *     only.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/packer_stub_patcher.hpp"
#include "mxprotector/protection/packer/reloc_partition.hpp"

namespace {

using mx::ByteBuffer;
using mx::ByteView;
using mx::PeImage;
using mx::packer::partition_encrypted_relocs;
using mx::packer::RelocPartitionResult;
using mx::packer::TargetSection;

// --------------------------------------------------------------------
// Test fixture helpers
// --------------------------------------------------------------------

/// Append a serialized IMAGE_BASE_RELOCATION block to `out`.
/// Entries are 16-bit values: top 4 bits = type, low 12 bits =
/// offset within page. Pads to 4-byte alignment with a single
/// IMAGE_REL_BASED_ABSOLUTE entry when the entry count is odd.
void append_block(ByteBuffer& out,
                  uint32_t page_rva,
                  std::initializer_list<uint16_t> entries)
{
    const uint32_t entry_bytes = static_cast<uint32_t>(entries.size() * 2);
    const bool needs_pad = (entries.size() % 2) != 0;
    const uint32_t pad_bytes = needs_pad ? 2u : 0u;
    const uint32_t block_size = 8 + entry_bytes + pad_bytes;

    mx::pe::IMAGE_BASE_RELOCATION hdr{};
    hdr.VirtualAddress = page_rva;
    hdr.SizeOfBlock    = block_size;
    const auto* h = reinterpret_cast<const uint8_t*>(&hdr);
    out.insert(out.end(), h, h + sizeof(hdr));

    for (uint16_t e : entries) {
        out.push_back(static_cast<uint8_t>(e & 0xFF));
        out.push_back(static_cast<uint8_t>((e >> 8) & 0xFF));
    }
    if (needs_pad) {
        out.push_back(0);
        out.push_back(0);
    }
}

/// Encode an `IMAGE_REL_BASED_DIR64` entry pointing at `offset`
/// inside its page.
constexpr uint16_t dir64(uint16_t offset) {
    return static_cast<uint16_t>(
        (mx::pe::IMAGE_REL_BASED_DIR64 << 12) | (offset & 0x0FFF));
}

/// Encode an `IMAGE_REL_BASED_ABSOLUTE` (padding) entry.
constexpr uint16_t absent(uint16_t offset = 0) {
    return static_cast<uint16_t>(offset & 0x0FFF);
}

/// Build a `PeImage` with a `.text` section at RVA 0x1000 (size
/// 0x2000), a `.data` section at RVA 0x3000 (size 0x1000), and a
/// `.reloc` section at RVA 0x4000 carrying `reloc_data`. The
/// DataDirectory[BASERELOC] entry is set to `{0x4000, reloc_data.size()}`.
std::unique_ptr<PeImage> make_image_with_reloc(const ByteBuffer& reloc_data)
{
    auto img = std::make_unique<PeImage>();
    img->set_architecture(mx::Architecture::x64);
    img->set_pe_type(mx::PeType::executable);
    img->set_image_base(static_cast<mx::Va>(0x140000000ULL));
    img->set_file_alignment(0x200);
    img->set_section_alignment(0x1000);

    mx::pe::IMAGE_DOS_HEADER dos{};
    dos.e_magic  = mx::pe::IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    img->set_dos_header(dos);

    mx::pe::IMAGE_NT_HEADERS64 nt{};
    nt.Signature                       = mx::pe::IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine              = mx::pe::IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections     = 0;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(mx::pe::IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics      = mx::pe::IMAGE_FILE_EXECUTABLE_IMAGE;
    nt.OptionalHeader.Magic            = mx::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase        = 0x140000000ULL;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment    = 0x200;
    nt.OptionalHeader.NumberOfRvaAndSizes = 16;
    nt.OptionalHeader.DataDirectory[mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC]
        .VirtualAddress = 0x4000;
    nt.OptionalHeader.DataDirectory[mx::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC]
        .Size           = static_cast<uint32_t>(reloc_data.size());
    img->set_nt_headers(nt);

    mx::pe::SectionInfo text{};
    text.name            = ".text";
    text.virtual_address = 0x1000;
    text.virtual_size    = 0x2000;
    text.raw_size        = 0x2000;
    text.characteristics =
        mx::pe::IMAGE_SCN_CNT_CODE | mx::pe::IMAGE_SCN_MEM_EXECUTE
        | mx::pe::IMAGE_SCN_MEM_READ;
    text.data.resize(0x2000, 0);
    auto add1 = img->add_section(std::move(text));
    EXPECT_TRUE(add1.has_value());

    mx::pe::SectionInfo data{};
    data.name            = ".data";
    data.virtual_address = 0x3000;
    data.virtual_size    = 0x1000;
    data.raw_size        = 0x1000;
    data.characteristics =
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
        | mx::pe::IMAGE_SCN_MEM_READ | mx::pe::IMAGE_SCN_MEM_WRITE;
    data.data.resize(0x1000, 0);
    auto add2 = img->add_section(std::move(data));
    EXPECT_TRUE(add2.has_value());

    mx::pe::SectionInfo reloc{};
    reloc.name            = ".reloc";
    reloc.virtual_address = 0x4000;
    reloc.virtual_size    = static_cast<uint32_t>(reloc_data.size());
    reloc.raw_size        = static_cast<uint32_t>(reloc_data.size());
    reloc.characteristics =
        mx::pe::IMAGE_SCN_CNT_INITIALIZED_DATA
        | mx::pe::IMAGE_SCN_MEM_DISCARDABLE
        | mx::pe::IMAGE_SCN_MEM_READ;
    reloc.data = reloc_data;
    auto add3 = img->add_section(std::move(reloc));
    EXPECT_TRUE(add3.has_value());

    return img;
}

/// Read the on-disk type bits of the entry at byte offset
/// `entry_offset` within the `.reloc` section data.
uint16_t read_type_at(const PeImage& img, size_t entry_offset)
{
    for (const auto& sec : img.sections()) {
        if (sec.name == ".reloc") {
            uint16_t raw = 0;
            std::memcpy(&raw, sec.data.data() + entry_offset, sizeof(raw));
            return static_cast<uint16_t>((raw >> 12) & 0x0F);
        }
    }
    return 0xFFFF;  // sentinel — section not found
}

uint16_t read_offset_at(const PeImage& img, size_t entry_offset)
{
    for (const auto& sec : img.sections()) {
        if (sec.name == ".reloc") {
            uint16_t raw = 0;
            std::memcpy(&raw, sec.data.data() + entry_offset, sizeof(raw));
            return static_cast<uint16_t>(raw & 0x0FFF);
        }
    }
    return 0xFFFF;
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

TEST(RelocPartition, EmptyDirectoryReturnsEmptyResult) {
    auto img = make_image_with_reloc({});
    // Force directory size back to 0 — the helper would have set it to
    // 0 already since reloc_data is empty.
    std::array<TargetSection, 1> tgts{TargetSection{0x1000, 0x2000}};
    auto result = partition_encrypted_relocs(*img, tgts);
    EXPECT_EQ(result.stub_private_blob.size(), 0u);
    EXPECT_EQ(result.stub_private_entry_count, 0u);
    EXPECT_EQ(result.visible_entry_count,      0u);
    EXPECT_EQ(result.neutralised_block_count,  0u);
}

TEST(RelocPartition, AllNonEncryptedEntriesStayVisible) {
    ByteBuffer reloc;
    // One block at page 0x3000 (.data), two entries.
    append_block(reloc, 0x3000, {dir64(0x10), dir64(0x18)});
    auto img = make_image_with_reloc(reloc);

    std::array<TargetSection, 1> tgts{TargetSection{0x1000, 0x2000}};
    auto result = partition_encrypted_relocs(*img, tgts);

    EXPECT_TRUE(result.stub_private_blob.empty());
    EXPECT_EQ(result.stub_private_entry_count, 0u);
    EXPECT_EQ(result.visible_entry_count,      2u);
    EXPECT_EQ(result.neutralised_block_count,  0u);

    // .reloc bytes unchanged: both entries still type DIR64 (10).
    // Block layout: [0..7] header, [8..9] entry0, [10..11] entry1.
    EXPECT_EQ(read_type_at(*img, 8),  mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ(read_type_at(*img, 10), mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ(read_offset_at(*img, 8),  0x10);
    EXPECT_EQ(read_offset_at(*img, 10), 0x18);
}

TEST(RelocPartition, AllEncryptedEntriesMovedAndNeutralised) {
    ByteBuffer reloc;
    // One block at page 0x1000 (.text), three entries.
    append_block(reloc, 0x1000,
                 {dir64(0x100), dir64(0x200), dir64(0x300)});
    auto img = make_image_with_reloc(reloc);

    std::array<TargetSection, 1> tgts{TargetSection{0x1000, 0x2000}};
    auto result = partition_encrypted_relocs(*img, tgts);

    EXPECT_EQ(result.stub_private_entry_count, 3u);
    EXPECT_EQ(result.visible_entry_count,      0u);
    EXPECT_EQ(result.neutralised_block_count,  1u);

    // Stub-private blob: header + 3 entries + 1 padding (odd count).
    // Block size = 8 + 3*2 + 2 = 16.
    EXPECT_EQ(result.stub_private_blob.size(), 16u);
    // Header at the start: VirtualAddress = 0x1000, SizeOfBlock = 16.
    mx::pe::IMAGE_BASE_RELOCATION hdr{};
    std::memcpy(&hdr, result.stub_private_blob.data(), sizeof(hdr));
    EXPECT_EQ(hdr.VirtualAddress, 0x1000u);
    EXPECT_EQ(hdr.SizeOfBlock,    16u);
    // Three live entries inside the blob, all original types kept.
    auto blob_entry = [&](size_t idx) -> uint16_t {
        uint16_t v = 0;
        std::memcpy(&v, result.stub_private_blob.data() + 8 + idx * 2,
                    sizeof(v));
        return v;
    };
    EXPECT_EQ((blob_entry(0) >> 12) & 0x0F, mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ((blob_entry(1) >> 12) & 0x0F, mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ((blob_entry(2) >> 12) & 0x0F, mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ(blob_entry(0) & 0x0FFF, 0x100u);
    EXPECT_EQ(blob_entry(1) & 0x0FFF, 0x200u);
    EXPECT_EQ(blob_entry(2) & 0x0FFF, 0x300u);

    // Visible .reloc: every live entry rewritten to ABSOLUTE (type 0)
    // with offset preserved.
    EXPECT_EQ(read_type_at(*img, 8),  mx::pe::IMAGE_REL_BASED_ABSOLUTE);
    EXPECT_EQ(read_type_at(*img, 10), mx::pe::IMAGE_REL_BASED_ABSOLUTE);
    EXPECT_EQ(read_type_at(*img, 12), mx::pe::IMAGE_REL_BASED_ABSOLUTE);
    EXPECT_EQ(read_offset_at(*img, 8),  0x100);
    EXPECT_EQ(read_offset_at(*img, 10), 0x200);
    EXPECT_EQ(read_offset_at(*img, 12), 0x300);
}

TEST(RelocPartition, MixedBlocksSplitByTargetSection) {
    ByteBuffer reloc;
    // .text block (encrypted): 2 entries.
    append_block(reloc, 0x1000, {dir64(0x40), dir64(0x80)});
    // .data block (non-encrypted): 2 entries.
    append_block(reloc, 0x3000, {dir64(0xA0), dir64(0xB0)});
    // .text page 2 (encrypted): 1 entry.
    append_block(reloc, 0x2000, {dir64(0x10)});
    auto img = make_image_with_reloc(reloc);

    std::array<TargetSection, 1> tgts{TargetSection{0x1000, 0x2000}};
    auto result = partition_encrypted_relocs(*img, tgts);

    // Encrypted: 3 entries (block[0]'s 2 + block[2]'s 1).
    // Non-encrypted: 2 entries (block[1]'s 2).
    // Two blocks neutralised (block[0] and block[2]).
    EXPECT_EQ(result.stub_private_entry_count, 3u);
    EXPECT_EQ(result.visible_entry_count,      2u);
    EXPECT_EQ(result.neutralised_block_count,  2u);

    // The two encrypted blocks landed in stub-private. Block layout
    // inside the blob:
    //   block A: 8 (hdr) + 2*2 (entries) = 12 bytes (even count → no pad)
    //   block C: 8 (hdr) + 1*2 (entry)   + 2 (pad) = 12 bytes
    //   total: 24
    EXPECT_EQ(result.stub_private_blob.size(), 24u);

    mx::pe::IMAGE_BASE_RELOCATION blob_a{};
    std::memcpy(&blob_a, result.stub_private_blob.data(), sizeof(blob_a));
    EXPECT_EQ(blob_a.VirtualAddress, 0x1000u);
    EXPECT_EQ(blob_a.SizeOfBlock,    12u);

    mx::pe::IMAGE_BASE_RELOCATION blob_c{};
    std::memcpy(&blob_c, result.stub_private_blob.data() + 12,
                sizeof(blob_c));
    EXPECT_EQ(blob_c.VirtualAddress, 0x2000u);
    EXPECT_EQ(blob_c.SizeOfBlock,    12u);

    // Source bytes:
    //   block[0] (page 0x1000) at offset [0..11]:
    //     entries at [8..9] and [10..11] → both neutralised.
    //   block[1] (page 0x3000) at offset [12..23]:
    //     entries at [20..21] and [22..23] → unchanged.
    //   block[2] (page 0x2000) at offset [24..35]:
    //     entry at [32..33] → neutralised.
    EXPECT_EQ(read_type_at(*img, 8),  mx::pe::IMAGE_REL_BASED_ABSOLUTE);
    EXPECT_EQ(read_type_at(*img, 10), mx::pe::IMAGE_REL_BASED_ABSOLUTE);
    EXPECT_EQ(read_type_at(*img, 20), mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ(read_type_at(*img, 22), mx::pe::IMAGE_REL_BASED_DIR64);
    EXPECT_EQ(read_type_at(*img, 32), mx::pe::IMAGE_REL_BASED_ABSOLUTE);
}

TEST(RelocPartition, AbsoluteEntriesNotPromotedToBlob) {
    ByteBuffer reloc;
    // Encrypted-section block with one DIR64 + two ABSOLUTE padding
    // entries.
    append_block(reloc, 0x1000,
                 {dir64(0x40), absent(0), absent(0)});
    auto img = make_image_with_reloc(reloc);

    std::array<TargetSection, 1> tgts{TargetSection{0x1000, 0x2000}};
    auto result = partition_encrypted_relocs(*img, tgts);

    EXPECT_EQ(result.stub_private_entry_count, 1u);
    EXPECT_EQ(result.visible_entry_count,      0u);
    EXPECT_EQ(result.neutralised_block_count,  1u);

    // Stub-private block: hdr (8) + 1 entry (2) + 1 pad (2) = 12.
    EXPECT_EQ(result.stub_private_blob.size(), 12u);
}

TEST(RelocPartition, MultipleEncryptedSectionsHandledTogether) {
    ByteBuffer reloc;
    append_block(reloc, 0x1000, {dir64(0x10)});  // .text
    append_block(reloc, 0x3000, {dir64(0x20)});  // .data
    append_block(reloc, 0x5000, {dir64(0x30)});  // additional encrypted
    auto img = make_image_with_reloc(reloc);

    // .text + a synthetic second encrypted section at 0x5000.
    std::array<TargetSection, 2> tgts{
        TargetSection{0x1000, 0x2000},
        TargetSection{0x5000, 0x1000},
    };
    auto result = partition_encrypted_relocs(*img, tgts);

    // 0x1000 and 0x5000 are encrypted → 2 entries moved.
    // 0x3000 stays visible → 1 entry remains.
    EXPECT_EQ(result.stub_private_entry_count, 2u);
    EXPECT_EQ(result.visible_entry_count,      1u);
    EXPECT_EQ(result.neutralised_block_count,  2u);
}

} // namespace
