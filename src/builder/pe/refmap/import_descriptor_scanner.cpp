/**
 * @file import_descriptor_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/import_descriptor_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// One IMAGE_THUNK_DATA64 slot is 8 bytes (a single 64-bit field).
constexpr std::uint32_t kThunkSize = sizeof(std::uint64_t);

/// One IMAGE_IMPORT_DESCRIPTOR is 20 bytes (5 × 4-byte fields).
constexpr std::uint32_t kDescriptorSize = sizeof(pe::IMAGE_IMPORT_DESCRIPTOR);

/// Locate the IMPORT directory's RVA + size in PE32+ headers.
struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_import_directory(const PeImage& image) noexcept {
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_IMPORT];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

/// Read a 32-bit little-endian RVA at the given location in `image`.
/// Returns nullopt when the slot is not fully inside any section.
[[nodiscard]] std::optional<std::uint32_t> read_u32_at(
    const PeImage& image,
    Rva            rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return std::nullopt;
    std::uint32_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

/// Read a 64-bit little-endian thunk value at the given location.
/// Returns nullopt when the slot is not fully inside any section.
[[nodiscard]] std::optional<std::uint64_t> read_u64_at(
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
        .origin       = ReferenceOrigin::import_descriptor,
    });
}

/// Append a `byte4`/`rva` reference for one thunk's name pointer.
/// The thunk slot is 8 bytes wide but for non-ordinal entries the
/// upper 32 bits are zero; writing 4 bytes at the slot's start is
/// safe because we never widen the value.
void emit_thunk_name_ref(
    Rva             slot_rva,
    std::uint32_t   target_rva,
    ReferenceTable& table)
{
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rva,
        .origin       = ReferenceOrigin::import_thunk,
    });
}

/// Walk a null-terminated thunk array starting at `array_rva`. For
/// each non-ordinal entry, emit a thunk-name reference. Bounded by
/// the section that holds the array — a malformed (unterminated)
/// array stops cleanly when the next read goes out-of-bounds.
void scan_thunk_array(
    const PeImage&  image,
    Rva             array_rva,
    ReferenceTable& table)
{
    if (array_rva == 0) return;

    Rva cursor = array_rva;
    for (;;) {
        const auto thunk = read_u64_at(image, cursor);
        if (!thunk) break;            // OOB — stop walking.
        if (*thunk == 0) break;       // Null terminator.
        if ((*thunk & pe::IMAGE_ORDINAL_FLAG64) == 0) {
            // Non-ordinal: lower 32 bits are RVA of IMAGE_IMPORT_BY_NAME.
            const auto rva_to_name = static_cast<std::uint32_t>(
                *thunk & 0xFFFFFFFFu);
            if (rva_to_name != 0) {
                emit_thunk_name_ref(cursor, rva_to_name, table);
            }
        }
        cursor = static_cast<Rva>(cursor + kThunkSize);
    }
}

/// Read a single IMAGE_IMPORT_DESCRIPTOR at `desc_rva`, returning
/// nullopt when the read crosses a section boundary.
[[nodiscard]] std::optional<pe::IMAGE_IMPORT_DESCRIPTOR> read_descriptor(
    const PeImage& image,
    Rva            desc_rva)
{
    const auto* sec = image.section_by_rva(desc_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = desc_rva - sec->virtual_address;
    if (off + kDescriptorSize > sec->data.size()) return std::nullopt;

    pe::IMAGE_IMPORT_DESCRIPTOR d{};
    std::memcpy(&d, sec->data.data() + off, kDescriptorSize);
    return d;
}

/// True when every RVA-bearing field of the descriptor is zero — the
/// canonical end-of-array terminator.
[[nodiscard]] bool descriptor_is_terminator(
    const pe::IMAGE_IMPORT_DESCRIPTOR& d) noexcept
{
    return d.OriginalFirstThunk == 0 &&
           d.TimeDateStamp      == 0 &&
           d.ForwarderChain     == 0 &&
           d.Name               == 0 &&
           d.FirstThunk         == 0;
}

/// Field offsets inside `IMAGE_IMPORT_DESCRIPTOR`. We hand-encode
/// these (rather than using `offsetof`) because the
/// `Characteristics` / `OriginalFirstThunk` slot lives in an
/// anonymous union, and `offsetof` on an anonymous union member is
/// not portable C++.
constexpr std::uint32_t kOffOriginalFirstThunk = 0;
constexpr std::uint32_t kOffName               = 12;
constexpr std::uint32_t kOffFirstThunk         = 16;

/// Walk one descriptor: emit refs for Name/OFT/FT slots, then walk
/// the INT and IAT thunk arrays.
void scan_one_descriptor(
    const PeImage&                     image,
    Rva                                desc_rva,
    const pe::IMAGE_IMPORT_DESCRIPTOR& d,
    ReferenceTable&                    table)
{
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffOriginalFirstThunk),
        d.OriginalFirstThunk, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffName),
        d.Name, table);
    emit_descriptor_field(
        static_cast<Rva>(desc_rva + kOffFirstThunk),
        d.FirstThunk, table);

    // Walk INT (preferred — read-only) and IAT (loader rewrites at
    // runtime). Both have identical layout pre-load.
    scan_thunk_array(image, d.OriginalFirstThunk, table);
    scan_thunk_array(image, d.FirstThunk,         table);
}

} // anonymous namespace

void ImportDescriptorScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_import_directory(image);
    if (loc.rva == 0) return;

    Rva cursor = loc.rva;
    // A defensive cap: never walk more descriptors than the directory
    // bytes allow (the array is null-terminated, but we still bound
    // the walk to avoid a runaway in the face of a corrupted image).
    const std::uint32_t max_entries = loc.size > 0
        ? loc.size / kDescriptorSize + 1   // +1 for the terminator
        : 1024;                            // fallback when Size is unset

    for (std::uint32_t i = 0; i < max_entries; ++i) {
        const auto desc = read_descriptor(image, cursor);
        if (!desc) break;
        if (descriptor_is_terminator(*desc)) break;
        scan_one_descriptor(image, cursor, *desc, table);
        cursor = static_cast<Rva>(cursor + kDescriptorSize);
    }
}

} // namespace mx::pe::refmap
