/**
 * @file unwind_info_reference_scanner.cpp
 * @brief Implementation — see header.
 *
 * Layout of one `UNWIND_INFO`:
 *
 *   offset 0  : Version : 3, Flags : 5
 *   offset 1  : SizeOfProlog
 *   offset 2  : CountOfCodes
 *   offset 3  : FrameRegister : 4, FrameOffset : 4
 *   offset 4  : UNWIND_CODE[CountOfCodes]                (2 B each)
 *   offset 4 + 2*CountOfCodes (rounded up to 4 B):
 *               * if EHANDLER / UHANDLER flag: 4 B ExceptionHandler RVA
 *                 + ExceptionData[] (handler-defined size — we stop
 *                 at the handler RVA; the data after it does not
 *                 hold image-RVA pointers in any layout we care
 *                 about).
 *               * if CHAININFO flag:           12 B chained
 *                 RUNTIME_FUNCTION (BeginAddress, EndAddress,
 *                 UnwindData).
 *
 * The two flag families are mutually exclusive.
 */

#include "mxprotector/pe/refmap/unwind_info_reference_scanner.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <variant>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::refmap {

namespace {

/// `RUNTIME_FUNCTION` is three 4-byte RVAs.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

/// One UNWIND_CODE slot is 2 bytes.
constexpr std::uint32_t kUnwindCodeSize = 2;

/// MS x64 unwind flag bits — see `winnt.h::UNW_FLAG_*`.
constexpr std::uint8_t kUnwFlagEHandler  = 0x01;
constexpr std::uint8_t kUnwFlagUHandler  = 0x02;
constexpr std::uint8_t kUnwFlagChainInfo = 0x04;

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

/// Read four little-endian bytes from `image` at `rva`. Returns
/// `nullopt` if the read crosses a section boundary.
[[nodiscard]] std::optional<std::uint32_t> read_u32(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return std::nullopt;
    std::uint32_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

/// Read one byte; returns `nullopt` on out-of-bounds.
[[nodiscard]] std::optional<std::uint8_t> read_u8(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off >= sec->data.size()) return std::nullopt;
    return sec->data[off];
}

/// Append one `rva`-encoded reference at `slot_rva` pointing at
/// `target_rva`.
void emit_rva_reference(
    Rva             slot_rva,
    Rva             target_rva,
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

/// Compute the offset of the trailer (post-`UnwindCode`) inside
/// the `UNWIND_INFO` block. The trailer is 4-byte aligned, so
/// when `CountOfCodes` is odd we pad up by one slot.
[[nodiscard]] constexpr std::uint32_t trailer_offset(
    std::uint8_t count_of_codes) noexcept
{
    const std::uint32_t code_bytes = count_of_codes * kUnwindCodeSize;
    const std::uint32_t aligned    = (code_bytes + 3u) & ~3u;
    return 4u + aligned;
}

/// Parse one `UNWIND_INFO` block at `unwind_rva` and emit the
/// trailer references it carries. Bails on malformed reads.
void parse_one_unwind_info(
    const PeImage&  image,
    Rva             unwind_rva,
    ReferenceTable& table)
{
    const auto version_flags = read_u8(image, unwind_rva);
    if (!version_flags) return;
    const std::uint8_t flags = (*version_flags >> 3) & 0x1F;
    if ((flags & (kUnwFlagEHandler | kUnwFlagUHandler |
                  kUnwFlagChainInfo)) == 0)
    {
        return;  // No trailer, nothing for us to scan.
    }

    const auto count_of_codes = read_u8(
        image, static_cast<Rva>(unwind_rva + 2));
    if (!count_of_codes) return;

    const Rva trailer_rva = static_cast<Rva>(
        unwind_rva + trailer_offset(*count_of_codes));

    if ((flags & (kUnwFlagEHandler | kUnwFlagUHandler)) != 0) {
        const auto handler_rva = read_u32(image, trailer_rva);
        if (!handler_rva) return;
        emit_rva_reference(trailer_rva, *handler_rva,
                           ReferenceOrigin::unwind_exception_handler,
                           table);
        return;
    }

    if ((flags & kUnwFlagChainInfo) != 0) {
        // Chained RUNTIME_FUNCTION at trailer.
        const auto begin = read_u32(image, trailer_rva);
        if (!begin) return;
        const auto end = read_u32(
            image, static_cast<Rva>(trailer_rva + 4));
        if (!end) return;
        const auto chain = read_u32(
            image, static_cast<Rva>(trailer_rva + 8));
        if (!chain) return;

        emit_rva_reference(trailer_rva, *begin,
                           ReferenceOrigin::unwind_chain_info, table);
        emit_rva_reference(static_cast<Rva>(trailer_rva + 4), *end,
                           ReferenceOrigin::unwind_chain_info, table);
        emit_rva_reference(static_cast<Rva>(trailer_rva + 8), *chain,
                           ReferenceOrigin::unwind_chain_info, table);
    }
}

} // anonymous namespace

void UnwindInfoReferenceScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return;

    const auto off_in_section = loc.rva - sec->virtual_address;
    if (off_in_section + loc.size > sec->data.size()) return;

    const std::uint8_t* dir = sec->data.data() + off_in_section;
    const std::uint32_t entry_count = loc.size / kRuntimeFunctionSize;

    for (std::uint32_t i = 0; i < entry_count; ++i) {
        std::uint32_t unwind_rva = 0;
        std::memcpy(&unwind_rva,
                    dir + i * kRuntimeFunctionSize + 8,
                    sizeof(unwind_rva));
        if (unwind_rva == 0) continue;
        parse_one_unwind_info(image, static_cast<Rva>(unwind_rva), table);
    }
}

} // namespace mx::pe::refmap
