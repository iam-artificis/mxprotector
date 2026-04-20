/**
 * @file reloc_partition.cpp
 * @brief Build-time partitioning of `.reloc` — implementation.
 *
 * See `reloc_partition.hpp` for the rationale and the algorithm
 * outline. This file is the byte-level walker.
 */

#include "mxprotector/protection/packer/reloc_partition.hpp"

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

#include <cstring>
#include <variant>

namespace mx::packer {

namespace {

constexpr uint32_t kPageSize = 0x1000;

constexpr uint32_t align_up(uint32_t n, uint32_t alignment) noexcept {
    return (n + alignment - 1) & ~(alignment - 1);
}

/**
 * @brief Does `[page_rva, page_rva + 0x1000)` overlap any of the
 *        encrypted sections' `[rva, rva + size)` ranges?
 */
[[nodiscard]] bool block_targets_encrypted_section(
    uint32_t page_rva,
    std::span<const TargetSection> encrypted_sections) noexcept
{
    for (const auto& sec : encrypted_sections) {
        const uint32_t sec_end = sec.rva + sec.size;
        if (page_rva + kPageSize > sec.rva && page_rva < sec_end) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Locate the section whose virtual coverage contains `rva`.
 *
 * Prefers `virtual_size` aligned up to the image's section
 * alignment; falls back to `data.size()` when `virtual_size` is
 * zero (some tooling emits zero-sized virtual size for all-data
 * sections). Returns nullptr on no match.
 */
[[nodiscard]] pe::SectionInfo* find_section_containing(PeImage& image,
                                                    Rva rva) noexcept
{
    const uint32_t align = image.section_alignment();
    for (auto& sec : image.sections()) {
        const uint32_t vsize =
            sec.virtual_size > 0
                ? sec.virtual_size
                : static_cast<uint32_t>(sec.data.size());
        const uint32_t sec_end =
            sec.virtual_address + align_up(vsize, align);
        if (rva >= sec.virtual_address && rva < sec_end) {
            return &sec;
        }
    }
    return nullptr;
}

/**
 * @brief Read the BASERELOC directory `{VirtualAddress, Size}` out
 *        of the image's NT headers. Zero-fill both on any failure
 *        path (missing directory slot, truncated headers).
 */
struct BaseRelocDir {
    Rva      rva  = 0;
    uint32_t size = 0;
};

[[nodiscard]] BaseRelocDir read_base_reloc_directory(const PeImage& image)
{
    BaseRelocDir out{};
    std::visit([&](const auto& nt) {
        if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC <
            nt.OptionalHeader.NumberOfRvaAndSizes)
        {
            const auto& entry = nt.OptionalHeader
                .DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC];
            out.rva  = entry.VirtualAddress;
            out.size = entry.Size;
        }
    }, image.nt_headers());
    return out;
}

/**
 * @brief Emit a single stub-private `IMAGE_BASE_RELOCATION` block.
 *
 * `source_entries_base` points at the first 16-bit entry of the
 * source block. `num_entries` is the count of 16-bit slots there.
 * The source entries are read twice by the caller — once here to
 * filter ABSOLUTE padding and copy the live ones into the new
 * block, and once in the caller to neutralise them in place. The
 * two passes are kept separate so the neutralisation step sees
 * only entries that were actually relevant (non-ABSOLUTE).
 *
 * Returns the number of non-ABSOLUTE entries copied. The caller
 * must still neutralise the source entries after this returns.
 */
[[nodiscard]] uint32_t build_stub_private_block(
    ByteBuffer&     out_blob,
    uint32_t        page_rva,
    const uint8_t*  source_entries_base,
    uint32_t        num_entries)
{
    const size_t block_start = out_blob.size();
    // Reserve slot for the header; we patch SizeOfBlock at the end.
    out_blob.resize(block_start + sizeof(pe::IMAGE_BASE_RELOCATION));

    uint32_t copied = 0;
    for (uint32_t i = 0; i < num_entries; ++i) {
        uint16_t raw = 0;
        std::memcpy(&raw, source_entries_base + i * sizeof(uint16_t),
                    sizeof(raw));
        const uint16_t type = (raw >> 12) & 0x0F;
        if (type == pe::IMAGE_REL_BASED_ABSOLUTE) {
            continue; // Skip padding — the stub applier only runs
                      // over live entries.
        }
        out_blob.push_back(static_cast<uint8_t>(raw & 0xFF));
        out_blob.push_back(static_cast<uint8_t>((raw >> 8) & 0xFF));
        ++copied;
    }

    if (copied == 0) {
        // Undo the header reservation — block is empty, don't emit.
        out_blob.resize(block_start);
        return 0;
    }

    // 4-byte alignment for the next block: pad with a single
    // ABSOLUTE entry (type 0, offset 0) when the copied entry
    // count is odd.
    if ((copied % 2u) != 0u) {
        out_blob.push_back(0);
        out_blob.push_back(0);
    }

    // Finalise the header at block_start.
    pe::IMAGE_BASE_RELOCATION hdr{};
    hdr.VirtualAddress = page_rva;
    hdr.SizeOfBlock    = static_cast<uint32_t>(out_blob.size() - block_start);
    std::memcpy(out_blob.data() + block_start, &hdr, sizeof(hdr));

    return copied;
}

/**
 * @brief Rewrite every non-ABSOLUTE entry in the source block to
 *        `IMAGE_REL_BASED_ABSOLUTE` (type 0), keeping the original
 *        offset bits. The mapper skips absolute entries as padding,
 *        and the byte count stays the same so
 *        `DataDirectory[BASERELOC].Size` does not need updating.
 */
void neutralise_block_entries_in_place(
    uint8_t*  entries_base,
    uint32_t  num_entries) noexcept
{
    for (uint32_t i = 0; i < num_entries; ++i) {
        uint16_t raw = 0;
        std::memcpy(&raw, entries_base + i * sizeof(uint16_t), sizeof(raw));
        const uint16_t type = (raw >> 12) & 0x0F;
        if (type == pe::IMAGE_REL_BASED_ABSOLUTE) continue;
        const uint16_t neutralised = static_cast<uint16_t>(raw & 0x0FFFu);
        std::memcpy(entries_base + i * sizeof(uint16_t), &neutralised,
                    sizeof(neutralised));
    }
}

/**
 * @brief Count non-ABSOLUTE entries in a block (diagnostic).
 */
[[nodiscard]] uint32_t count_live_entries(
    const uint8_t* entries_base,
    uint32_t       num_entries) noexcept
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < num_entries; ++i) {
        uint16_t raw = 0;
        std::memcpy(&raw, entries_base + i * sizeof(uint16_t), sizeof(raw));
        const uint16_t type = (raw >> 12) & 0x0F;
        if (type != pe::IMAGE_REL_BASED_ABSOLUTE) ++n;
    }
    return n;
}

} // anonymous namespace

RelocPartitionResult partition_encrypted_relocs(
    PeImage&                         image,
    std::span<const TargetSection>   encrypted_sections)
{
    RelocPartitionResult result;

    const BaseRelocDir dir = read_base_reloc_directory(image);
    if (dir.rva == 0 || dir.size == 0) {
        // Image has no relocations — nothing to partition.
        return result;
    }

    pe::SectionInfo* reloc_sec = find_section_containing(image, dir.rva);
    if (reloc_sec == nullptr) {
        // Directory points outside any section — the image is
        // malformed. Fail safe: return empty; the caller's applier
        // will be patched with {rva=0, size=0} and do nothing.
        return result;
    }

    const uint32_t dir_offset_in_sec = dir.rva - reloc_sec->virtual_address;
    if (dir_offset_in_sec + dir.size > reloc_sec->data.size()) {
        // Directory extends past the section's raw data. Fail safe.
        return result;
    }

    uint8_t* const base = reloc_sec->data.data() + dir_offset_in_sec;

    // Walk blocks.
    size_t pos = 0;
    while (pos + sizeof(pe::IMAGE_BASE_RELOCATION) <= dir.size) {
        pe::IMAGE_BASE_RELOCATION hdr{};
        std::memcpy(&hdr, base + pos, sizeof(hdr));

        if (hdr.SizeOfBlock == 0) {
            break; // Null terminator per PE spec — stop.
        }
        if (hdr.SizeOfBlock < sizeof(hdr) ||
            pos + hdr.SizeOfBlock > dir.size)
        {
            // Malformed — leave the rest of the directory alone and
            // stop. Any corruption would likely have been flagged by
            // the parser already; we bail defensively.
            break;
        }

        const uint32_t block_size  = hdr.SizeOfBlock;
        const uint32_t entries_sz  = block_size
            - static_cast<uint32_t>(sizeof(hdr));
        const uint32_t num_entries = entries_sz / sizeof(uint16_t);
        uint8_t* const entries_base = base + pos + sizeof(hdr);
        const uint32_t page_rva    = hdr.VirtualAddress;

        if (block_targets_encrypted_section(page_rva, encrypted_sections)) {
            // Copy live entries to stub-private, then neutralise
            // them in the visible .reloc. Order matters — copy
            // first (reads original types), neutralise second
            // (writes type = 0).
            const uint32_t copied = build_stub_private_block(
                result.stub_private_blob, page_rva,
                entries_base, num_entries);
            result.stub_private_entry_count += copied;

            if (copied > 0) {
                neutralise_block_entries_in_place(entries_base,
                                                   num_entries);
                ++result.neutralised_block_count;
            }
        } else {
            result.visible_entry_count +=
                count_live_entries(entries_base, num_entries);
        }

        pos += block_size;
    }

    return result;
}

} // namespace mx::packer
