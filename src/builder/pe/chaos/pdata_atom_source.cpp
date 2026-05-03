/**
 * @file pdata_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/pdata_atom_source.hpp"

#include <algorithm>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// One RUNTIME_FUNCTION = three 4-byte RVAs = 12 bytes.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_pdata_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

} // anonymous namespace

void PdataAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const auto off = loc.rva - sec->virtual_address;
    const auto bytes_in_section =
        sec->data.size() > off ? sec->data.size() - off : 0;
    const auto walk_size = std::min(
        static_cast<std::size_t>(loc.size),
        bytes_in_section);

    const std::uint32_t entry_count =
        static_cast<std::uint32_t>(walk_size / kRuntimeFunctionSize);

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        out.add(Atom{
            .start_rva = static_cast<Rva>(
                loc.rva + i * kRuntimeFunctionSize),
            .size      = kRuntimeFunctionSize,
            .origin    = AtomOrigin::pdata_runtime_function,
        });
    }
}

} // namespace mx::pe::chaos
