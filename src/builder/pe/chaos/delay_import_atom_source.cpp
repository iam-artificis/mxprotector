/**
 * @file delay_import_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/delay_import_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kDescriptorSize =
    sizeof(pe::IMAGE_DELAYLOAD_DESCRIPTOR);

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_delay_import_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<pe::IMAGE_DELAYLOAD_DESCRIPTOR> read_descriptor(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + kDescriptorSize > sec->data.size()) return std::nullopt;
    pe::IMAGE_DELAYLOAD_DESCRIPTOR d{};
    std::memcpy(&d, sec->data.data() + off, kDescriptorSize);
    return d;
}

[[nodiscard]] bool is_terminator(
    const pe::IMAGE_DELAYLOAD_DESCRIPTOR& d) noexcept
{
    return d.Attributes                 == 0 &&
           d.DllNameRVA                 == 0 &&
           d.ModuleHandleRVA            == 0 &&
           d.ImportAddressTableRVA      == 0 &&
           d.ImportNameTableRVA         == 0 &&
           d.BoundImportAddressTableRVA == 0 &&
           d.UnloadInformationTableRVA  == 0 &&
           d.TimeDateStamp              == 0;
}

} // anonymous namespace

void DelayImportAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_delay_import_directory(image);
    if (loc.rva == 0) return;

    const std::uint32_t max_entries = loc.size > 0
        ? loc.size / kDescriptorSize + 1
        : 1024;

    // Count descriptors (including the all-zero terminator), then
    // emit ONE atom for the whole array. Loader walks descriptors
    // linearly until the terminator, so array bytes must stay
    // contiguous.
    Rva           cursor = loc.rva;
    std::uint32_t count  = 0;
    for (std::uint32_t i = 0; i < max_entries; ++i) {
        const auto desc = read_descriptor(image, cursor);
        if (!desc) break;
        ++count;
        if (is_terminator(*desc)) break;
        cursor = static_cast<Rva>(cursor + kDescriptorSize);
    }

    if (count > 0) {
        out.add(Atom{
            .start_rva = loc.rva,
            .size      = count * kDescriptorSize,
            .origin    = AtomOrigin::delay_import_descriptor,
        });
    }
}

} // namespace mx::pe::chaos
