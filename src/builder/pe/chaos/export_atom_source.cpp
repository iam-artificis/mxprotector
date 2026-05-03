/**
 * @file export_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/export_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kExportDirSize =
    sizeof(pe::IMAGE_EXPORT_DIRECTORY);

[[nodiscard]] Rva find_export_directory_rva(const PeImage& image) noexcept {
    Rva result = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXPORT <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                result = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<pe::IMAGE_EXPORT_DIRECTORY> read_export_dir(
    const PeImage& image, Rva dir_rva)
{
    const auto* sec = image.section_by_rva(dir_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = dir_rva - sec->virtual_address;
    if (off + kExportDirSize > sec->data.size()) return std::nullopt;
    pe::IMAGE_EXPORT_DIRECTORY d{};
    std::memcpy(&d, sec->data.data() + off, kExportDirSize);
    return d;
}

void emit_array_atom(
    const PeImage& image,
    Rva            base_rva,
    std::uint32_t  byte_size,
    AtomOrigin     origin,
    AtomTable&     out)
{
    if (base_rva == 0 || byte_size == 0) return;
    const auto* sec = image.section_by_rva(base_rva);
    if (sec == nullptr) return;
    const auto off = base_rva - sec->virtual_address;
    if (off + byte_size > sec->data.size()) return;
    out.add(Atom{
        .start_rva = base_rva,
        .size      = byte_size,
        .origin    = origin,
    });
}

} // anonymous namespace

void ExportAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const Rva dir_rva = find_export_directory_rva(image);
    if (dir_rva == 0) return;
    const auto dir = read_export_dir(image, dir_rva);
    if (!dir) return;

    out.add(Atom{
        .start_rva = dir_rva,
        .size      = kExportDirSize,
        .origin    = AtomOrigin::export_directory,
    });

    emit_array_atom(image,
        dir->AddressOfFunctions,
        dir->NumberOfFunctions * sizeof(std::uint32_t),
        AtomOrigin::export_address_table, out);
    emit_array_atom(image,
        dir->AddressOfNames,
        dir->NumberOfNames * sizeof(std::uint32_t),
        AtomOrigin::export_name_table, out);
    emit_array_atom(image,
        dir->AddressOfNameOrdinals,
        dir->NumberOfNames * sizeof(std::uint16_t),
        AtomOrigin::export_ordinal_table, out);
}

} // namespace mx::pe::chaos
