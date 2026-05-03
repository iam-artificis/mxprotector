/**
 * @file resource_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/resource_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kDirHeaderSize  =
    sizeof(pe::IMAGE_RESOURCE_DIRECTORY);
constexpr std::uint32_t kDirEntrySize   =
    sizeof(pe::IMAGE_RESOURCE_DIRECTORY_ENTRY);
constexpr std::uint32_t kDataEntrySize  =
    sizeof(pe::IMAGE_RESOURCE_DATA_ENTRY);
constexpr std::uint32_t kMaxDepth = 8;

[[nodiscard]] Rva find_resource_directory_rva(
    const PeImage& image) noexcept
{
    Rva result = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_RESOURCE <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                result = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
            }
        }
    }, image.nt_headers());
    return result;
}

void walk_directory(
    const pe::SectionInfo& sec,
    Rva                    rsrc_base_rva,
    std::uint32_t          rsrc_base_off,
    std::uint32_t          dir_off_in_rsrc,
    std::uint32_t          depth,
    AtomTable&             out)
{
    if (depth >= kMaxDepth) return;
    const std::uint32_t hdr_off = rsrc_base_off + dir_off_in_rsrc;
    if (hdr_off + kDirHeaderSize > sec.data.size()) return;

    pe::IMAGE_RESOURCE_DIRECTORY hdr{};
    std::memcpy(&hdr, sec.data.data() + hdr_off, kDirHeaderSize);

    const std::uint32_t entry_count =
        static_cast<std::uint32_t>(hdr.NumberOfNamedEntries) +
        static_cast<std::uint32_t>(hdr.NumberOfIdEntries);
    const std::uint32_t node_size =
        kDirHeaderSize + entry_count * kDirEntrySize;
    if (hdr_off + node_size > sec.data.size()) return;

    // Emit the node atom (header + entries).
    out.add(Atom{
        .start_rva = static_cast<Rva>(rsrc_base_rva + dir_off_in_rsrc),
        .size      = node_size,
        .origin    = AtomOrigin::resource_directory_node,
    });

    // Recurse into children.
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        const std::uint32_t entry_off =
            hdr_off + kDirHeaderSize + i * kDirEntrySize;
        pe::IMAGE_RESOURCE_DIRECTORY_ENTRY entry{};
        std::memcpy(&entry,
                    sec.data.data() + entry_off, kDirEntrySize);
        const std::uint32_t off = entry.OffsetToData &
            ~pe::IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG;
        const bool is_subdir = (entry.OffsetToData &
            pe::IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG) != 0;

        if (is_subdir) {
            walk_directory(sec, rsrc_base_rva, rsrc_base_off,
                           off, depth + 1, out);
        } else {
            // Data leaf: emit a 16-byte atom.
            const std::uint32_t leaf_off = rsrc_base_off + off;
            if (leaf_off + kDataEntrySize > sec.data.size()) continue;
            out.add(Atom{
                .start_rva = static_cast<Rva>(rsrc_base_rva + off),
                .size      = kDataEntrySize,
                .origin    = AtomOrigin::resource_data_entry,
            });
        }
    }
}

} // anonymous namespace

void ResourceAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const Rva dir_rva = find_resource_directory_rva(image);
    if (dir_rva == 0) return;

    const auto* sec = image.section_by_rva(dir_rva);
    if (sec == nullptr) return;

    const std::uint32_t rsrc_base_off = dir_rva - sec->virtual_address;
    walk_directory(*sec, dir_rva, rsrc_base_off,
                   /*dir_off_in_rsrc=*/0,
                   /*depth=*/0, out);
}

} // namespace mx::pe::chaos
