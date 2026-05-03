/**
 * @file export_directory_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/export_directory_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// One EAT entry: 4-byte function/forwarder RVA.
constexpr std::uint32_t kEatEntrySize = sizeof(std::uint32_t);

/// One name-pointer entry: 4-byte string RVA.
constexpr std::uint32_t kNameEntrySize = sizeof(std::uint32_t);

/// IMAGE_EXPORT_DIRECTORY field offsets (hand-encoded for layout
/// stability across SDKs / compiler vendors).
constexpr std::uint32_t kOffName                  = 12;
constexpr std::uint32_t kOffAddressOfFunctions    = 28;
constexpr std::uint32_t kOffAddressOfNames        = 32;
constexpr std::uint32_t kOffAddressOfNameOrdinals = 36;

constexpr std::uint32_t kExportDirectorySize =
    sizeof(pe::IMAGE_EXPORT_DIRECTORY);

/// EXPORT directory location in PE32+ headers.
struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_export_directory(const PeImage& image) noexcept {
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXPORT <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXPORT];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

/// Read `kExportDirectorySize` bytes at `dir_rva`. Returns nullopt
/// when the read crosses a section boundary.
[[nodiscard]] std::optional<pe::IMAGE_EXPORT_DIRECTORY> read_export_directory(
    const PeImage& image,
    Rva            dir_rva)
{
    const auto* sec = image.section_by_rva(dir_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = dir_rva - sec->virtual_address;
    if (off + kExportDirectorySize > sec->data.size()) return std::nullopt;

    pe::IMAGE_EXPORT_DIRECTORY d{};
    std::memcpy(&d, sec->data.data() + off, kExportDirectorySize);
    return d;
}

/// Append a `byte4`/`rva` reference for one directory field.
void emit_directory_field(
    Rva             slot_rva,
    std::uint32_t   target_rva,
    ReferenceTable& table)
{
    if (target_rva == 0) return;
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::export_directory,
    });
}

/// Append a `byte4`/`rva` reference for one EAT or name-table entry.
void emit_table_entry(
    Rva             slot_rva,
    std::uint32_t   target_rva,
    ReferenceOrigin origin,
    ReferenceTable& table)
{
    if (target_rva == 0) return;
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = origin,
    });
}

/// Walk an array of `count` 4-byte RVAs at `base_rva`, emitting one
/// reference per non-zero entry. Truncates to the entries that fully
/// fit inside the host section.
void scan_rva_array(
    const PeImage&  image,
    Rva             base_rva,
    std::uint32_t   count,
    ReferenceOrigin origin,
    ReferenceTable& table)
{
    if (base_rva == 0 || count == 0) return;
    const auto* sec = image.section_by_rva(base_rva);
    if (sec == nullptr) return;

    const auto off = base_rva - sec->virtual_address;
    const auto    available = (sec->data.size() > off)
        ? sec->data.size() - off
        : 0;
    const std::uint32_t bounded =
        static_cast<std::uint32_t>(available / kEatEntrySize);
    const std::uint32_t walk_count = std::min(count, bounded);

    for (std::uint32_t i = 0; i < walk_count; ++i) {
        std::uint32_t target = 0;
        std::memcpy(&target,
                    sec->data.data() + off + i * kEatEntrySize,
                    kEatEntrySize);
        emit_table_entry(
            static_cast<Rva>(base_rva + i * kEatEntrySize),
            target, origin, table);
    }
}

/// Emit refs for the four pointer slots inside the
/// IMAGE_EXPORT_DIRECTORY at `dir_rva`.
void emit_directory_pointer_slots(
    Rva                              dir_rva,
    const pe::IMAGE_EXPORT_DIRECTORY& d,
    ReferenceTable&                  table)
{
    emit_directory_field(
        static_cast<Rva>(dir_rva + kOffName),
        d.Name, table);
    emit_directory_field(
        static_cast<Rva>(dir_rva + kOffAddressOfFunctions),
        d.AddressOfFunctions, table);
    emit_directory_field(
        static_cast<Rva>(dir_rva + kOffAddressOfNames),
        d.AddressOfNames, table);
    emit_directory_field(
        static_cast<Rva>(dir_rva + kOffAddressOfNameOrdinals),
        d.AddressOfNameOrdinals, table);
}

} // anonymous namespace

void ExportDirectoryScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_export_directory(image);
    if (loc.rva == 0) return;

    const auto dir = read_export_directory(image, loc.rva);
    if (!dir) return;

    emit_directory_pointer_slots(loc.rva, *dir, table);

    // EAT — function RVAs (or forwarder-string RVAs).
    scan_rva_array(image,
        dir->AddressOfFunctions, dir->NumberOfFunctions,
        ReferenceOrigin::export_function_rva, table);

    // Name pointer table — name string RVAs.
    scan_rva_array(image,
        dir->AddressOfNames, dir->NumberOfNames,
        ReferenceOrigin::export_name_rva, table);

    // AddressOfNameOrdinals points at a 2-byte-per-entry ordinal
    // table; ordinals are not RVAs and are not scanned.
}

} // namespace mx::pe::refmap
