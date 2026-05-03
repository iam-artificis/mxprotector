/**
 * @file debug_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/debug_atom_source.hpp"

#include <algorithm>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kDebugEntrySize =
    sizeof(pe::IMAGE_DEBUG_DIRECTORY);

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_debug_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_DEBUG <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_DEBUG];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

} // anonymous namespace

void DebugAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_debug_directory(image);
    if (loc.rva == 0 || loc.size < kDebugEntrySize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const auto off = loc.rva - sec->virtual_address;
    const auto bytes_in_section =
        sec->data.size() > off ? sec->data.size() - off : 0;
    const auto walk_size = std::min(
        static_cast<std::size_t>(loc.size),
        bytes_in_section);

    const std::uint32_t entry_count =
        static_cast<std::uint32_t>(walk_size / kDebugEntrySize);
    if (entry_count == 0) return;

    out.add(Atom{
        .start_rva = loc.rva,
        .size      = entry_count * kDebugEntrySize,
        .origin    = AtomOrigin::debug_directory_entry,
    });
}

} // namespace mx::pe::chaos
