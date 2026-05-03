/**
 * @file load_config_atom_source.cpp
 * @brief Implementation — see header.
 *
 * Reuses LOAD_CONFIG field-offset constants from the refmap module
 * so the offset catalogue lives in exactly one place.
 */

#include "mxprotector/pe/chaos/load_config_atom_source.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <variant>

#include "../refmap/load_config_field_offsets.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint32_t kVaSlotSize  = sizeof(std::uint64_t);
constexpr std::uint32_t kRvaSlotSize = sizeof(std::uint32_t);

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

[[nodiscard]] std::optional<std::uint64_t> read_u64(
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

[[nodiscard]] std::uint32_t cfg_stride(
    const PeImage& image, Rva dir_rva, std::uint32_t effective)
{
    if (refmap::lcfg::kOffGuardFlags + kRvaSlotSize > effective) {
        return kRvaSlotSize;
    }
    const auto flags = read_u32(image,
        static_cast<Rva>(dir_rva + refmap::lcfg::kOffGuardFlags));
    if (!flags) return kRvaSlotSize;
    return kRvaSlotSize + ((*flags >> 28) & 0xFu);
}

void emit_table_atom(
    const PeImage& image,
    Rva            dir_rva,
    std::uint32_t  effective,
    std::uint32_t  off_table_va,
    std::uint32_t  off_count,
    std::uint32_t  stride,
    AtomTable&     out)
{
    if (off_table_va + kVaSlotSize > effective) return;
    if (off_count    + kVaSlotSize > effective) return;

    const auto va = read_u64(image, static_cast<Rva>(dir_rva + off_table_va));
    if (!va || *va == 0) return;
    const auto image_base = image.image_base();
    if (*va < image_base) return;

    const auto count = read_u64(image, static_cast<Rva>(dir_rva + off_count));
    if (!count || *count == 0) return;

    const Rva table_rva = static_cast<Rva>(*va - image_base);
    const auto* sec = image.section_by_rva(table_rva);
    if (sec == nullptr) return;

    const std::uint64_t total_bytes = *count * stride;
    if (total_bytes == 0 ||
        total_bytes > std::numeric_limits<std::uint32_t>::max())
    {
        return;
    }

    out.add(Atom{
        .start_rva = table_rva,
        .size      = static_cast<std::uint32_t>(total_bytes),
        .origin    = AtomOrigin::load_config_table,
    });
}

} // anonymous namespace

void LoadConfigAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    if (!image.is_64bit()) return;

    const auto loc = find_load_config_directory(image);
    if (loc.rva == 0) return;

    const auto inner = read_u32(image,
        static_cast<Rva>(loc.rva + refmap::lcfg::kOffSize));
    if (!inner) return;
    const std::uint32_t effective =
        loc.size > 0 ? std::min(loc.size, *inner) : *inner;

    // 1. Whole LOAD_CONFIG block as one atom.
    out.add(Atom{
        .start_rva = loc.rva,
        .size      = effective,
        .origin    = AtomOrigin::load_config_directory,
    });

    // 2. CFG / IAT-taken / longjmp tables (CFG stride applies).
    const std::uint32_t stride = cfg_stride(image, loc.rva, effective);
    emit_table_atom(image, loc.rva, effective,
        refmap::lcfg::kOffGuardCFFunctionTable,
        refmap::lcfg::kOffGuardCFFunctionCount, stride, out);
    emit_table_atom(image, loc.rva, effective,
        refmap::lcfg::kOffGuardAddressTakenIatEntryTable,
        refmap::lcfg::kOffGuardAddressTakenIatEntryCount, stride, out);
    emit_table_atom(image, loc.rva, effective,
        refmap::lcfg::kOffGuardLongJumpTargetTable,
        refmap::lcfg::kOffGuardLongJumpTargetCount, stride, out);

    // 3. EH continuation table (plain 4-byte stride).
    emit_table_atom(image, loc.rva, effective,
        refmap::lcfg::kOffGuardEHContinuationTable,
        refmap::lcfg::kOffGuardEHContinuationCount,
        kRvaSlotSize, out);

    // 4. SEH handler table (32-bit only, often unused on x64).
    emit_table_atom(image, loc.rva, effective,
        refmap::lcfg::kOffSEHandlerTable,
        refmap::lcfg::kOffSEHandlerCount,
        kRvaSlotSize, out);
}

} // namespace mx::pe::chaos
