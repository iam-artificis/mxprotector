/**
 * @file tls_directory_scanner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/refmap/tls_directory_scanner.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::refmap {

namespace {

/// One TLS callback array entry is an 8-byte absolute VA.
constexpr std::uint32_t kCallbackEntrySize = sizeof(std::uint64_t);

constexpr std::uint32_t kTlsDirectorySize =
    sizeof(pe::IMAGE_TLS_DIRECTORY64);

/// IMAGE_TLS_DIRECTORY64 field offsets (hand-encoded for layout
/// stability across SDK versions).
constexpr std::uint32_t kOffStartAddressOfRawData = 0;
constexpr std::uint32_t kOffEndAddressOfRawData   = 8;
constexpr std::uint32_t kOffAddressOfIndex        = 16;
constexpr std::uint32_t kOffAddressOfCallBacks    = 24;

/// TLS directory location in PE32+ headers.
struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_tls_directory(const PeImage& image) noexcept {
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_TLS <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_TLS];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

/// Read the IMAGE_TLS_DIRECTORY64 struct at `dir_rva`. Returns
/// nullopt when the read crosses a section boundary.
[[nodiscard]] std::optional<pe::IMAGE_TLS_DIRECTORY64> read_tls_directory(
    const PeImage& image,
    Rva            dir_rva)
{
    const auto* sec = image.section_by_rva(dir_rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = dir_rva - sec->virtual_address;
    if (off + kTlsDirectorySize > sec->data.size()) return std::nullopt;

    pe::IMAGE_TLS_DIRECTORY64 d{};
    std::memcpy(&d, sec->data.data() + off, kTlsDirectorySize);
    return d;
}

/// Read 8 bytes at `rva` and return as `uint64_t`. Returns nullopt
/// when the read crosses a section boundary.
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

/// Convert an absolute VA to its RVA, returning nullopt when the
/// VA is below `image_base` (a malformed entry that would
/// underflow the subtraction).
[[nodiscard]] std::optional<Rva> va_to_rva(
    std::uint64_t va, std::uint64_t image_base) noexcept
{
    if (va == 0)         return std::nullopt;  // null = empty slot
    if (va < image_base) return std::nullopt;  // would underflow
    return static_cast<Rva>(va - image_base);
}

/// Append a `byte8`/`absolute_va` reference for one slot.
void emit_va_ref(
    Rva             slot_rva,
    Rva             target_rva,
    ReferenceOrigin origin,
    ReferenceTable& table)
{
    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte8,
        .encoding     = ReferenceEncoding::absolute_va,
        .origin       = origin,
    });
}

/// Read the absolute VA stored at `slot_rva`, convert to an RVA, and
/// emit a tls_directory reference. No-op when the read fails or the
/// slot's value is null/below-image-base.
void scan_directory_va_field(
    const PeImage&  image,
    Rva             slot_rva,
    ReferenceTable& table)
{
    const auto va = read_u64_at(image, slot_rva);
    if (!va) return;
    const auto target = va_to_rva(*va, image.image_base());
    if (!target) return;
    emit_va_ref(slot_rva, *target,
                ReferenceOrigin::tls_directory, table);
}

/// Walk a null-terminated array of 8-byte absolute VAs starting at
/// `array_rva`. For each non-zero entry, emit one tls_callback
/// reference. The walk halts at the first OOB read or the null
/// terminator.
void scan_callback_array(
    const PeImage&  image,
    Rva             array_rva,
    ReferenceTable& table)
{
    if (array_rva == 0) return;

    Rva cursor = array_rva;
    for (;;) {
        const auto va = read_u64_at(image, cursor);
        if (!va)        break;
        if (*va == 0)   break;  // Null terminator.
        if (auto rva = va_to_rva(*va, image.image_base())) {
            emit_va_ref(cursor, *rva,
                        ReferenceOrigin::tls_callback, table);
        }
        cursor = static_cast<Rva>(cursor + kCallbackEntrySize);
    }
}

} // anonymous namespace

void TlsDirectoryScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_tls_directory(image);
    if (loc.rva == 0) return;

    const auto dir = read_tls_directory(image, loc.rva);
    if (!dir) return;

    const std::uint64_t image_base = image.image_base();

    // 1. The four VA-bearing fields of the directory itself.
    scan_directory_va_field(image,
        static_cast<Rva>(loc.rva + kOffStartAddressOfRawData), table);
    scan_directory_va_field(image,
        static_cast<Rva>(loc.rva + kOffEndAddressOfRawData),   table);
    scan_directory_va_field(image,
        static_cast<Rva>(loc.rva + kOffAddressOfIndex),        table);
    scan_directory_va_field(image,
        static_cast<Rva>(loc.rva + kOffAddressOfCallBacks),    table);

    // 2. The callback array's contents — only when the pointer
    //    actually resolves inside the image.
    if (dir->AddressOfCallBacks >= image_base) {
        scan_callback_array(image,
            static_cast<Rva>(dir->AddressOfCallBacks - image_base),
            table);
    }
}

} // namespace mx::pe::refmap
