/**
 * @file reloc_rebuilder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/reloc_rebuilder.hpp"

#include <algorithm>
#include <cstring>
#include <span>
#include <variant>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx::pe::refmap {

namespace {

/// `IMAGE_BASE_RELOCATION` header size: 4-byte page RVA + 4-byte size.
constexpr std::uint32_t kBlockHeaderSize = 8;

/// `.reloc` page is 4 KiB.
constexpr std::uint32_t kPageSize = 0x1000;
constexpr std::uint32_t kPageMask = kPageSize - 1;

/// One translated reloc entry: where the slot lives and what type
/// of relocation it is.
struct ParsedEntry {
    Rva           slot_rva;
    std::uint16_t type;
};

/// `.reloc` directory location inside the image headers.
struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_reloc_directory(const PeImage& image) noexcept {
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_BASERELOC];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

/// Locate the `.reloc` bytes inside the image's section list. The
/// chaos planner keeps the directory in the unified section; this
/// helper handles both the unified-section and pre-merge-multisection
/// case.
struct DirSlice {
    std::uint8_t* data;
    std::size_t   size;
};

[[nodiscard]] DirSlice locate_directory_bytes(
    PeImage&           image,
    const DirLocation& loc)
{
    if (loc.rva == 0 || loc.size == 0) return {nullptr, 0};
    for (auto& sec : image.sections()) {
        const Rva sec_end = sec.virtual_address + sec.virtual_size;
        if (loc.rva < sec.virtual_address || loc.rva >= sec_end) continue;
        const auto off = loc.rva - sec.virtual_address;
        if (off + loc.size > sec.data.size()) return {nullptr, 0};
        return {sec.data.data() + off, static_cast<std::size_t>(loc.size)};
    }
    return {nullptr, 0};
}

/// Parse one `.reloc` block at `data` (size `≥ kBlockHeaderSize`).
/// Appends every entry (including `IMAGE_REL_BASED_ABSOLUTE` padding)
/// to `out`. Returns block_size on success, 0 on malformed.
[[nodiscard]] std::uint32_t parse_one_block(
    const std::uint8_t*       data,
    std::uint32_t             remaining,
    std::vector<ParsedEntry>& out)
{
    std::uint32_t page_rva   = 0;
    std::uint32_t block_size = 0;
    std::memcpy(&page_rva,   data + 0, sizeof(page_rva));
    std::memcpy(&block_size, data + 4, sizeof(block_size));

    if (block_size < kBlockHeaderSize || block_size > remaining) {
        return 0;
    }
    if (page_rva == 0 && block_size == kBlockHeaderSize) {
        return 0;
    }

    const std::uint32_t entry_count =
        (block_size - kBlockHeaderSize) / sizeof(std::uint16_t);
    const auto* entries = data + kBlockHeaderSize;

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint16_t entry = 0;
        std::memcpy(&entry, entries + i * sizeof(std::uint16_t),
                    sizeof(entry));
        const std::uint16_t type   = (entry >> 12) & 0xFu;
        const std::uint16_t offset = entry & 0xFFFu;
        out.push_back(ParsedEntry{
            .slot_rva = static_cast<Rva>(page_rva + offset),
            .type     = type,
        });
    }
    return block_size;
}

/// Walk the entire `.reloc` directory and collect every entry.
[[nodiscard]] std::vector<ParsedEntry> parse_directory(
    const std::uint8_t* dir, std::uint32_t dir_size)
{
    std::vector<ParsedEntry> out;
    if (dir == nullptr || dir_size < kBlockHeaderSize) return out;
    out.reserve(dir_size / sizeof(std::uint16_t));

    std::uint32_t walked = 0;
    while (walked + kBlockHeaderSize <= dir_size) {
        const auto consumed = parse_one_block(
            dir + walked, dir_size - walked, out);
        if (consumed == 0) break;
        walked += consumed;
    }
    return out;
}

/// Translate every entry's slot RVA through `remapper`. Type stays.
///
/// `IMAGE_REL_BASED_ABSOLUTE` (type 0) entries exist only to pad
/// each block's entry count to a multiple of 2 so that block-to-
/// block alignment stays at 4 bytes. They do not point at a slot,
/// so we drop them here — `emit_one_block` re-pads on its own as
/// part of the byte-stream emission.
[[nodiscard]] std::vector<ParsedEntry> translate_entries(
    std::span<const ParsedEntry> in,
    const RvaRemapper&           remapper)
{
    std::vector<ParsedEntry> out;
    out.reserve(in.size());
    for (const auto& e : in) {
        if (e.type == pe::IMAGE_REL_BASED_ABSOLUTE) continue;
        const Rva new_slot = remapper.remap(e.slot_rva);
        out.push_back(ParsedEntry{
            .slot_rva = new_slot,
            .type     = e.type,
        });
    }
    return out;
}

/// Sort entries by their (page_rva, offset) so we can group by page.
void sort_by_page_and_offset(std::vector<ParsedEntry>& entries) noexcept {
    std::sort(entries.begin(), entries.end(),
              [](const ParsedEntry& a, const ParsedEntry& b) noexcept {
                  return a.slot_rva < b.slot_rva;
              });
}

/// Bytes required to encode one block of `entry_count` entries
/// (rounded up to even count for 4-byte alignment of the next block).
[[nodiscard]] constexpr std::uint32_t block_bytes_for(
    std::uint32_t entry_count) noexcept
{
    const std::uint32_t padded = entry_count + (entry_count & 1u);
    return kBlockHeaderSize + padded * sizeof(std::uint16_t);
}

/// Emit one block's bytes into `out`.
void emit_one_block(
    std::uint32_t                page_rva,
    std::span<const ParsedEntry> entries,
    std::vector<std::uint8_t>&   out)
{
    const std::uint32_t bytes = block_bytes_for(
        static_cast<std::uint32_t>(entries.size()));
    const std::size_t   start = out.size();
    out.resize(start + bytes, 0);

    std::memcpy(out.data() + start + 0, &page_rva, sizeof(page_rva));
    std::memcpy(out.data() + start + 4, &bytes,    sizeof(bytes));

    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto offset = static_cast<std::uint16_t>(
            entries[i].slot_rva & kPageMask);
        const auto encoded = static_cast<std::uint16_t>(
            (entries[i].type << 12) | (offset & 0xFFFu));
        std::memcpy(out.data() + start + kBlockHeaderSize +
                    i * sizeof(std::uint16_t),
                    &encoded, sizeof(encoded));
    }
    // Trailing pad slot (if any) was zeroed by `resize` above —
    // type 0 = `IMAGE_REL_BASED_ABSOLUTE`, ignored by the loader.
}

/// Group sorted entries by their 4 KiB page and emit each group as
/// one `IMAGE_BASE_RELOCATION` block. Entries' types are encoded
/// verbatim (so `IMAGE_REL_BASED_ABSOLUTE` padding stays where it
/// was in the same block).
[[nodiscard]] std::vector<std::uint8_t> emit_blocks(
    const std::vector<ParsedEntry>& sorted)
{
    std::vector<std::uint8_t> out;
    if (sorted.empty()) return out;
    out.reserve(sorted.size() * 2 + 64);

    std::size_t i = 0;
    while (i < sorted.size()) {
        const std::uint32_t page_rva = sorted[i].slot_rva & ~kPageMask;
        std::size_t j = i + 1;
        while (j < sorted.size() &&
               (sorted[j].slot_rva & ~kPageMask) == page_rva)
        {
            ++j;
        }
        emit_one_block(page_rva,
                       std::span<const ParsedEntry>(
                           sorted.data() + i, j - i),
                       out);
        i = j;
    }
    return out;
}

} // anonymous namespace

RelocRebuildStats RelocRebuilder::rebuild(
    PeImage&           image,
    const RvaRemapper& remapper) const
{
    RelocRebuildStats stats;

    const auto loc = find_reloc_directory(image);
    if (loc.rva == 0 || loc.size < kBlockHeaderSize) return stats;

    const auto slice = locate_directory_bytes(image, loc);
    if (slice.data == nullptr) return stats;

    auto entries = parse_directory(slice.data,
                                   static_cast<std::uint32_t>(slice.size));
    if (entries.empty()) return stats;
    stats.parsed = static_cast<std::uint32_t>(entries.size());
    for (const auto& e : entries) {
        if (e.type == pe::IMAGE_REL_BASED_ABSOLUTE) ++stats.absolute_padding;
    }

    auto translated = translate_entries(entries, remapper);
    sort_by_page_and_offset(translated);

    const auto new_bytes = emit_blocks(translated);
    if (new_bytes.size() > slice.size) {
        // Doesn't fit in the old directory's capacity — fail closed.
        return stats;
    }

    std::memcpy(slice.data, new_bytes.data(), new_bytes.size());
    if (new_bytes.size() < slice.size) {
        std::memset(slice.data + new_bytes.size(), 0,
                    slice.size - new_bytes.size());
    }
    stats.translated = static_cast<std::uint32_t>(translated.size());
    stats.written = true;
    return stats;
}

} // namespace mx::pe::refmap
