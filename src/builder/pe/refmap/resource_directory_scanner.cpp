/**
 * @file resource_directory_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/resource_directory_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

constexpr std::uint32_t kDirHeaderSize  =
    sizeof(pe::IMAGE_RESOURCE_DIRECTORY);
constexpr std::uint32_t kDirEntrySize   =
    sizeof(pe::IMAGE_RESOURCE_DIRECTORY_ENTRY);
constexpr std::uint32_t kDataEntrySize  =
    sizeof(pe::IMAGE_RESOURCE_DATA_ENTRY);

/// Cap on tree depth. Real PE practice rarely goes past 3 levels;
/// 8 leaves headroom and aborts a malformed cycle.
constexpr std::uint32_t kMaxRecursionDepth = 8;

/// Offset of `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` from the start
/// of the data-entry struct. Hand-encoded for layout stability.
constexpr std::uint32_t kOffDataEntryOffsetToData = 0;

/// RESOURCE directory location in PE32+ headers.
struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_resource_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_RESOURCE <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_RESOURCE];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

/// Read a directory header at offset `off_in_section` of the host
/// section. Returns nullopt when the read crosses a section boundary.
[[nodiscard]] std::optional<pe::IMAGE_RESOURCE_DIRECTORY> read_dir_header(
    const pe::SectionInfo& sec,
    std::uint32_t          off_in_section)
{
    if (off_in_section + kDirHeaderSize > sec.data.size()) {
        return std::nullopt;
    }
    pe::IMAGE_RESOURCE_DIRECTORY h{};
    std::memcpy(&h, sec.data.data() + off_in_section, kDirHeaderSize);
    return h;
}

/// Read one directory entry at the given offset. Returns nullopt on
/// OOB.
[[nodiscard]] std::optional<pe::IMAGE_RESOURCE_DIRECTORY_ENTRY> read_dir_entry(
    const pe::SectionInfo& sec,
    std::uint32_t          off_in_section)
{
    if (off_in_section + kDirEntrySize > sec.data.size()) {
        return std::nullopt;
    }
    pe::IMAGE_RESOURCE_DIRECTORY_ENTRY e{};
    std::memcpy(&e, sec.data.data() + off_in_section, kDirEntrySize);
    return e;
}

/// Append a `byte4`/`rva`/`resource_data_entry` reference for one
/// leaf data entry's `OffsetToData` slot.
void emit_data_entry_ref(
    Rva                                 entry_rva,
    const pe::IMAGE_RESOURCE_DATA_ENTRY& data,
    ReferenceTable&                     table)
{
    if (data.OffsetToData == 0) return;
    table.add(Reference{
        .location_rva = static_cast<Rva>(entry_rva +
                                         kOffDataEntryOffsetToData),
        .target_rva   = data.OffsetToData,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::resource_data_entry,
    });
}

/// Resolve a leaf data entry at `data_off_in_rsrc` (an offset
/// relative to the .rsrc base) and emit the reference for its
/// OffsetToData slot.
void process_data_entry(
    const pe::SectionInfo& sec,
    Rva                    rsrc_base_rva,
    std::uint32_t          rsrc_base_off,
    std::uint32_t          data_off_in_rsrc,
    ReferenceTable&        table)
{
    const std::uint32_t off_in_section = rsrc_base_off + data_off_in_rsrc;
    if (off_in_section + kDataEntrySize > sec.data.size()) return;

    pe::IMAGE_RESOURCE_DATA_ENTRY data{};
    std::memcpy(&data, sec.data.data() + off_in_section, kDataEntrySize);

    const Rva entry_rva = static_cast<Rva>(rsrc_base_rva + data_off_in_rsrc);
    emit_data_entry_ref(entry_rva, data, table);
}

/// Recursive directory walker.
void walk_directory(
    const pe::SectionInfo& sec,
    Rva                    rsrc_base_rva,
    std::uint32_t          rsrc_base_off,
    std::uint32_t          dir_off_in_rsrc,
    std::uint32_t          depth,
    ReferenceTable&        table)
{
    if (depth >= kMaxRecursionDepth) return;

    const std::uint32_t hdr_off = rsrc_base_off + dir_off_in_rsrc;
    const auto hdr = read_dir_header(sec, hdr_off);
    if (!hdr) return;

    const std::uint32_t total_entries =
        static_cast<std::uint32_t>(hdr->NumberOfNamedEntries) +
        static_cast<std::uint32_t>(hdr->NumberOfIdEntries);

    for (std::uint32_t i = 0; i < total_entries; ++i) {
        const std::uint32_t entry_off =
            hdr_off + kDirHeaderSize + i * kDirEntrySize;
        const auto entry = read_dir_entry(sec, entry_off);
        if (!entry) break;

        const std::uint32_t off = entry->OffsetToData &
            ~pe::IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG;
        const bool is_subdir = (entry->OffsetToData &
            pe::IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG) != 0;

        if (is_subdir) {
            walk_directory(sec, rsrc_base_rva, rsrc_base_off,
                           off, depth + 1, table);
        } else {
            process_data_entry(sec, rsrc_base_rva, rsrc_base_off,
                               off, table);
        }
    }
}

} // anonymous namespace

void ResourceDirectoryScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_resource_directory(image);
    if (loc.rva == 0) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const std::uint32_t rsrc_base_off =
        loc.rva - sec->virtual_address;
    walk_directory(*sec, loc.rva, rsrc_base_off,
                   /*dir_off_in_rsrc=*/0,
                   /*depth=*/0, table);
}

} // namespace mx::pe::refmap
