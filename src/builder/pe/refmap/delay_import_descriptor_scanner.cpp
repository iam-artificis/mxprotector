/**
 * @file delay_import_descriptor_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/delay_import_descriptor_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// One IMAGE_THUNK_DATA64 slot is 8 bytes.
constexpr std::uint32_t kThunkSize = sizeof(std::uint64_t);

constexpr std::uint32_t kDescriptorSize =
    sizeof(pe::IMAGE_DELAYLOAD_DESCRIPTOR);

/// Bit-mask for the `RvaBased` attribute bit in
/// `IMAGE_DELAYLOAD_DESCRIPTOR.Attributes`. Modern toolchains always
/// set it; the scanner refuses to rewrite legacy (VA-based)
/// descriptors because their fields cannot pass through `RvaRemapper`.
constexpr std::uint32_t kRvaBasedBit = 0x1;

/// Field offsets inside `IMAGE_DELAYLOAD_DESCRIPTOR`. We hand-encode
/// these (rather than using `offsetof`) for layout-stability across
/// SDK versions; the struct is documented to be 32 bytes total.
constexpr std::uint32_t kOffAttributes                 = 0;
constexpr std::uint32_t kOffDllNameRva                 = 4;
constexpr std::uint32_t kOffModuleHandleRva            = 8;
constexpr std::uint32_t kOffImportAddressTableRva      = 12;
constexpr std::uint32_t kOffImportNameTableRva         = 16;
constexpr std::uint32_t kOffBoundImportAddressTableRva = 20;
constexpr std::uint32_t kOffUnloadInformationTableRva  = 24;

/// DELAY_IMPORT directory location in PE32+ headers.
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

/// Read 8 bytes at `rva` and return as `uint64_t`. Returns nullopt
/// when the read crosses a section boundary.
[[nodiscard]] std::optional<std::uint64_t> read_thunk_at(
    const PeImage& image,
    Rva            rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint64_t) > sec->data.size()) return std::nullopt;
    std::uint64_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

/// Read one IMAGE_DELAYLOAD_DESCRIPTOR. Returns nullopt when the
/// read crosses a section boundary.
[[nodiscard]] std::optional<pe::IMAGE_DELAYLOAD_DESCRIPTOR> read_descriptor(
    const PeImage& image,
    Rva            desc_rva)
{
    const auto* sec = image.section_by_rva(desc_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = desc_rva - sec->virtual_address;
    if (off + kDescriptorSize > sec->data.size()) return std::nullopt;

    pe::IMAGE_DELAYLOAD_DESCRIPTOR d{};
    std::memcpy(&d, sec->data.data() + off, kDescriptorSize);
    return d;
}

/// True when every field of the descriptor is zero — the canonical
/// end-of-array terminator.
[[nodiscard]] bool descriptor_is_terminator(
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

/// Append a `byte4`/`rva` reference for one descriptor field.
void emit_descriptor_field(
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
        .origin       = ReferenceOrigin::delay_import_descriptor,
    });
}

/// Append a `byte4`/`rva` reference for one thunk's name pointer.
void emit_thunk_name_ref(
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
        .origin       = ReferenceOrigin::delay_import_thunk,
    });
}

/// Walk a null-terminated thunk array starting at `array_rva`. For
/// each non-ordinal entry, emit a thunk-name reference. Bounded by
/// the section that holds the array.
void scan_thunk_array(
    const PeImage&  image,
    Rva             array_rva,
    ReferenceTable& table)
{
    if (array_rva == 0) return;

    Rva cursor = array_rva;
    for (;;) {
        const auto thunk = read_thunk_at(image, cursor);
        if (!thunk) break;
        if (*thunk == 0) break;
        if ((*thunk & pe::IMAGE_ORDINAL_FLAG64) == 0) {
            const auto rva_to_name = static_cast<std::uint32_t>(
                *thunk & 0xFFFFFFFFu);
            emit_thunk_name_ref(cursor, rva_to_name, table);
        }
        cursor = static_cast<Rva>(cursor + kThunkSize);
    }
}

/// Walk one descriptor: emit refs for every non-zero RVA-bearing
/// field, then walk the INT and IAT thunk arrays.
void scan_one_descriptor(
    const PeImage&                        image,
    Rva                                   desc_rva,
    const pe::IMAGE_DELAYLOAD_DESCRIPTOR& d,
    ReferenceTable&                       table)
{
    if ((d.Attributes & kRvaBasedBit) == 0) {
        // Legacy VA-based descriptor: cannot remap. Skip silently.
        return;
    }

    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffDllNameRva),
        d.DllNameRVA, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffModuleHandleRva),
        d.ModuleHandleRVA, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffImportAddressTableRva),
        d.ImportAddressTableRVA, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffImportNameTableRva),
        d.ImportNameTableRVA, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffBoundImportAddressTableRva),
        d.BoundImportAddressTableRVA, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffUnloadInformationTableRva),
        d.UnloadInformationTableRVA, table);

    // INT and IAT both point at thunk arrays of identical layout.
    // BoundImportAddressTable is also a thunk array but its entries
    // are runtime-resolved VAs (or zero pre-load) — not RVAs to
    // IMAGE_IMPORT_BY_NAME, so we skip it.
    scan_thunk_array(image, d.ImportNameTableRVA,    table);
    scan_thunk_array(image, d.ImportAddressTableRVA, table);

    // Suppress unused-variable warning for kOffAttributes — kept for
    // documentation.
    (void)kOffAttributes;
}

} // anonymous namespace

void DelayImportDescriptorScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_delay_import_directory(image);
    if (loc.rva == 0) return;

    const std::uint32_t max_entries = loc.size > 0
        ? loc.size / kDescriptorSize + 1
        : 1024;

    Rva cursor = loc.rva;
    for (std::uint32_t i = 0; i < max_entries; ++i) {
        const auto desc = read_descriptor(image, cursor);
        if (!desc) break;
        if (descriptor_is_terminator(*desc)) break;
        scan_one_descriptor(image, cursor, *desc, table);
        cursor = static_cast<Rva>(cursor + kDescriptorSize);
    }
}

} // namespace mx::pe::refmap
