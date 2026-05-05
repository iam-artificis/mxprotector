/**
 * @file reloc_absolute_va_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/reloc_absolute_va_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// Each `.reloc` block opens with two 32-bit fields (`VirtualAddress`,
/// `SizeOfBlock`) followed by `(SizeOfBlock - 8) / 2` 16-bit entries.
constexpr std::uint32_t kBlockHeaderSize = 8;

/// Locate the `.reloc` directory's RVA and size in PE32+ headers.
struct RelocLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] RelocLocation find_reloc_directory(const PeImage& image) noexcept {
    RelocLocation result{0, 0};
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

/// Read a `byte8` absolute VA from `image` at `slot_rva` and convert
/// it to an RVA. Returns `nullopt` when the slot's bytes are not
/// fully inside any section, or when the read VA is below
/// `image_base` (a malformed entry that would underflow the RVA).
[[nodiscard]] std::optional<Rva> read_target_rva(
    const PeImage& image,
    Rva            slot_rva)
{
    const auto* sec = image.section_by_rva(slot_rva);
    if (sec == nullptr) return std::nullopt;

    const auto slot_off = slot_rva - sec->virtual_address;
    if (slot_off + sizeof(std::uint64_t) > sec->data.size()) {
        return std::nullopt;
    }

    std::uint64_t va_value = 0;
    std::memcpy(&va_value, sec->data.data() + slot_off, sizeof(va_value));

    const std::uint64_t image_base = image.image_base();
    if (va_value < image_base) return std::nullopt;

    return static_cast<Rva>(va_value - image_base);
}

/// Append one DIR64 reference to the table. Caller has already
/// validated slot bounds and computed `target_rva`.
void emit_dir64_reference(
    Rva             slot_rva,
    Rva             target_rva,
    ReferenceTable& table)
{
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte8,
        .encoding     = ReferenceEncoding::absolute_va,
        .origin       = ReferenceOrigin::reloc_absolute_va,
    });
}

/// Parse a single `.reloc` block at `block_data` (size guaranteed
/// `>= kBlockHeaderSize`). Each `IMAGE_REL_BASED_DIR64` entry maps
/// to one Reference; other types are skipped.
///
/// @return `block_size` consumed; `0` when the block is malformed
///         and the walker should stop.
[[nodiscard]] std::uint32_t parse_reloc_block(
    const PeImage&         image,
    const std::uint8_t*    block_data,
    std::uint32_t          remaining_bytes,
    ReferenceTable&        table)
{
    std::uint32_t page_rva    = 0;
    std::uint32_t block_size  = 0;
    std::memcpy(&page_rva,   block_data + 0, sizeof(page_rva));
    std::memcpy(&block_size, block_data + 4, sizeof(block_size));

    if (block_size < kBlockHeaderSize || block_size > remaining_bytes) {
        return 0;
    }
    if (page_rva == 0 && block_size == kBlockHeaderSize) {
        // A trailing zero header is a valid terminator some toolchains
        // emit; treat as end-of-directory.
        return 0;
    }

    const std::uint32_t entry_count =
        (block_size - kBlockHeaderSize) / sizeof(std::uint16_t);
    const auto* entries = block_data + kBlockHeaderSize;

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint16_t entry = 0;
        std::memcpy(&entry, entries + i * sizeof(std::uint16_t),
                    sizeof(entry));
        const std::uint16_t type   = (entry >> 12) & 0xF;
        const std::uint16_t offset = entry & 0xFFF;

        if (type != pe::IMAGE_REL_BASED_DIR64) continue;

        const Rva slot_rva = page_rva + offset;
        if (auto target = read_target_rva(image, slot_rva); target) {
            emit_dir64_reference(slot_rva, *target, table);
        }
    }

    return block_size;
}

} // anonymous namespace

void RelocAbsoluteVaScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_reloc_directory(image);
    if (loc.rva == 0 || loc.size < kBlockHeaderSize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const std::uint32_t off_in_section = loc.rva - sec->virtual_address;
    if (off_in_section + loc.size > sec->data.size()) return;

    const std::uint8_t* directory = sec->data.data() + off_in_section;
    std::uint32_t walked = 0;

    while (walked + kBlockHeaderSize <= loc.size) {
        const std::uint32_t consumed = parse_reloc_block(
            image,
            directory + walked,
            loc.size - walked,
            table);
        if (consumed == 0) break;
        walked += consumed;
    }
}

} // namespace mx::pe::refmap
