/**
 * @file reloc_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/reloc_atom_source.hpp"

#include <cstring>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// `.reloc` block header: 4-byte page RVA + 4-byte block size.
constexpr std::uint32_t kBlockHeaderSize = 8;

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_reloc_directory(
    const PeImage& image) noexcept
{
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

/// Walk the directory and call `on_block(block_rva, block_size,
/// block_data)` for each well-formed block. Stops on a malformed
/// block.
template <typename Fn>
void walk_reloc_blocks(
    const PeImage& image,
    Fn             on_block)
{
    if (!image.is_64bit()) return;
    const auto loc = find_reloc_directory(image);
    if (loc.rva == 0 || loc.size < kBlockHeaderSize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const auto off_in_section = loc.rva - sec->virtual_address;
    if (off_in_section + loc.size > sec->data.size()) return;

    const std::uint8_t* directory = sec->data.data() + off_in_section;
    std::uint32_t walked = 0;

    while (walked + kBlockHeaderSize <= loc.size) {
        std::uint32_t page_rva   = 0;
        std::uint32_t block_size = 0;
        std::memcpy(&page_rva,   directory + walked + 0,
                    sizeof(page_rva));
        std::memcpy(&block_size, directory + walked + 4,
                    sizeof(block_size));

        if (block_size < kBlockHeaderSize ||
            walked + block_size > loc.size)
        {
            break;
        }
        if (page_rva == 0 && block_size == kBlockHeaderSize) break;

        const Rva block_rva = static_cast<Rva>(loc.rva + walked);
        on_block(block_rva, page_rva, block_size,
                 directory + walked);

        walked += block_size;
    }
}

} // anonymous namespace

void RelocBlockAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    walk_reloc_blocks(image,
        [&](Rva block_rva, std::uint32_t /*page_rva*/,
            std::uint32_t block_size,
            const std::uint8_t* /*data*/)
    {
        out.add(Atom{
            .start_rva = block_rva,
            .size      = block_size,
            .origin    = AtomOrigin::reloc_block,
        });
    });
}

void RelocPointerAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    walk_reloc_blocks(image,
        [&](Rva /*block_rva*/, std::uint32_t page_rva,
            std::uint32_t block_size,
            const std::uint8_t* data)
    {
        const std::uint32_t entry_count =
            (block_size - kBlockHeaderSize) / sizeof(std::uint16_t);
        const auto* entries = data + kBlockHeaderSize;
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            std::uint16_t entry = 0;
            std::memcpy(&entry, entries + i * sizeof(std::uint16_t),
                        sizeof(entry));
            const std::uint16_t type   = (entry >> 12) & 0xF;
            const std::uint16_t offset = entry & 0xFFF;
            if (type != pe::IMAGE_REL_BASED_DIR64) continue;
            out.add(Atom{
                .start_rva = static_cast<Rva>(page_rva + offset),
                .size      = sizeof(std::uint64_t),
                .origin    = AtomOrigin::reloc_pointer_slot,
            });
        }
    });
}

} // namespace mx::pe::chaos
