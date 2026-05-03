/**
 * @file volatile_metadata_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/volatile_metadata_atom_source.hpp"

#include <cstring>
#include <optional>
#include <variant>

#include "../refmap/load_config_field_offsets.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kVaSlotSize = sizeof(std::uint64_t);

/// Minimum sane volatile-metadata header size — `Size` + `Version`
/// + 4 RVA fields = 24 bytes. Anything smaller is malformed; pin
/// nothing.
constexpr std::uint32_t kMinHeaderBytes = 24;

/// Defensive upper bound on the metadata header size — real
/// binaries top out around 40-60 bytes; anything over 1 KiB is
/// almost certainly a corrupted `Size` field. Treat as malformed.
constexpr std::uint32_t kMaxHeaderBytes = 1024;

struct DirLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] DirLocation find_load_config_directory(
    const PeImage& image) noexcept
{
    DirLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

[[nodiscard]] std::optional<std::uint32_t> read_u32_at(
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

[[nodiscard]] std::optional<std::uint64_t> read_u64_at(
    const PeImage& image, Rva rva)
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return std::nullopt;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint64_t) > sec->data.size()) return std::nullopt;
    std::uint64_t v = 0;
    std::memcpy(&v, sec->data.data() + off, sizeof(v));
    return v;
}

/// Smallest `Size` from `LOAD_CONFIG.Size` (offset 0) and the
/// directory's outer `Size`.
[[nodiscard]] std::uint32_t effective_lcfg_size(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  outer_size)
{
    const auto inner = read_u32_at(image,
        static_cast<Rva>(dir_rva + refmap::lcfg::kOffSize));
    if (!inner) return 0;
    return outer_size > 0 ? std::min(outer_size, *inner) : *inner;
}

} // anonymous namespace

void VolatileMetadataAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_load_config_directory(image);
    if (loc.rva == 0) return;

    const auto eff = effective_lcfg_size(image, loc.rva, loc.size);
    if (eff < refmap::lcfg::kOffVolatileMetadataPointer + kVaSlotSize) {
        return;
    }

    const auto va = read_u64_at(image,
        static_cast<Rva>(loc.rva + refmap::lcfg::kOffVolatileMetadataPointer));
    if (!va || *va == 0) return;

    const std::uint64_t image_base = image.image_base();
    if (*va < image_base) return;

    const Rva target = static_cast<Rva>(*va - image_base);
    const auto size = read_u32_at(image, target);
    if (!size) return;
    if (*size < kMinHeaderBytes || *size > kMaxHeaderBytes) return;

    out.add(Atom{
        .start_rva = target,
        .size      = *size,
        .origin    = AtomOrigin::load_config_table,
    });
}

} // namespace mx::pe::chaos
