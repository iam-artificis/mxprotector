/**
 * @file load_config_pin_helper.cpp
 * @brief Implementation — see header.
 *
 * Reuses the LOAD_CONFIG field-offset constants from the refmap
 * scanner module so we don't duplicate the catalogue in two places.
 */

#include "mxprotector/pe/chaos/load_config_pin_helper.hpp"

#include <array>
#include <cstring>
#include <optional>
#include <variant>

#include "../refmap/load_config_field_offsets.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kVaSlotSize = sizeof(std::uint64_t);

/// Offsets inside LOAD_CONFIG of the table-pointer fields whose
/// targets must be pinned. Each pointed-to region is an array of
/// records; the records have to stay contiguous post-shuffle.
constexpr std::array<std::uint32_t, 5> kTablePointerOffsets = {
    refmap::lcfg::kOffSEHandlerTable,
    refmap::lcfg::kOffGuardCFFunctionTable,
    refmap::lcfg::kOffGuardAddressTakenIatEntryTable,
    refmap::lcfg::kOffGuardLongJumpTargetTable,
    refmap::lcfg::kOffGuardEHContinuationTable,
};

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

/// Compute the effective LOAD_CONFIG block size — the smaller of
/// the directory `Size` and the inner `Size` (offset 0).
[[nodiscard]] std::uint32_t effective_size(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  outer_size)
{
    const auto inner = read_u32_at(image,
        static_cast<Rva>(dir_rva + refmap::lcfg::kOffSize));
    if (!inner) return 0;
    return outer_size > 0 ? std::min(outer_size, *inner) : *inner;
}

/// For one VA-bearing field at offset `slot_off` inside the LOAD_CONFIG
/// block, append a pin range covering the whole section holding the
/// VA's target — when the field is in-bounds and the VA resolves.
void try_pin_field_target(
    const PeImage&            image,
    Rva                       dir_rva,
    std::uint32_t             slot_off,
    std::uint32_t             eff_size,
    std::vector<PinnedRange>& out)
{
    if (slot_off + kVaSlotSize > eff_size) return;
    const auto va = read_u64_at(image,
        static_cast<Rva>(dir_rva + slot_off));
    if (!va || *va == 0) return;
    const std::uint64_t image_base = image.image_base();
    if (*va < image_base) return;
    const Rva target = static_cast<Rva>(*va - image_base);
    const auto* sec = image.section_by_rva(target);
    if (sec == nullptr || sec->virtual_size == 0) return;
    out.push_back(PinnedRange{
        .start = sec->virtual_address,
        .size  = sec->virtual_size,
    });
}

} // anonymous namespace

std::vector<PinnedRange> compute_load_config_target_pins(
    const PeImage& image)
{
    std::vector<PinnedRange> out;
    if (!image.is_64bit()) return out;

    const auto loc = find_load_config_directory(image);
    if (loc.rva == 0) return out;

    const auto* dir_sec = image.section_by_rva(loc.rva);
    if (dir_sec == nullptr) return out;

    const std::uint32_t eff = effective_size(image, loc.rva, loc.size);
    if (eff == 0) return out;

    out.reserve(kTablePointerOffsets.size());
    for (const auto off : kTablePointerOffsets) {
        try_pin_field_target(image, loc.rva, off, eff, out);
    }
    return out;
}

} // namespace mx::pe::chaos
