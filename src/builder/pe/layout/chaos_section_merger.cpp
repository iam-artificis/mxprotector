/**
 * @file chaos_section_merger.cpp
 * @brief Implementation of the unified-section merge — see header.
 */

#include "mxprotector/pe/layout/chaos_section_merger.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <variant>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace mx::pe::chaos {

namespace {

/// Canonical chaos intent — every section claims to hold both code
/// and data and demands RWX runtime permissions.
constexpr SectionIntent kChaosIntent{
    SectionContentType::mixed_code_data,
    SectionPermissions::rwx,
};

/// The bit-mask that `make_section_characteristics` produces for
/// `kChaosIntent`. Computed as a `constexpr` constant so the
/// stamp loop does not redo the lookup per section.
constexpr std::uint32_t kChaosCharacteristics =
    make_section_characteristics(kChaosIntent);

/// Fill byte for the gaps that appear between the originals' bytes
/// inside the merged section. `0xCC` is `INT3` — looks like inline
/// debug-trap padding to a disassembler walking the unified region,
/// keeps the bytes recognisable in a hex dump, and guarantees a
/// hard fault if control flow ever reaches a gap (defence in depth).
constexpr std::uint8_t kGapFillByte = 0xCC;

struct MergedExtent {
    Rva           first_va;
    std::uint32_t total_vsize;
};

[[nodiscard]] MergedExtent compute_extent(const PeImage& image) noexcept {
    Rva           first_va = std::numeric_limits<Rva>::max();
    std::uint32_t last_end = 0;
    for (const auto& s : image.sections()) {
        first_va = std::min(first_va, s.virtual_address);
        last_end = std::max(last_end, s.virtual_address + s.virtual_size);
    }
    return MergedExtent{
        .first_va    = first_va,
        .total_vsize = static_cast<std::uint32_t>(last_end - first_va),
    };
}

[[nodiscard]] ByteBuffer build_merged_buffer(
    const PeImage&     image,
    const MergedExtent extent)
{
    ByteBuffer buf(extent.total_vsize, kGapFillByte);
    for (const auto& s : image.sections()) {
        const auto off = static_cast<std::size_t>(
            s.virtual_address - extent.first_va);

        std::memset(buf.data() + off, 0, s.virtual_size);

        if (!s.data.empty()) {
            const auto count = std::min(
                s.data.size(),
                static_cast<std::size_t>(s.virtual_size));
            std::memcpy(buf.data() + off, s.data.data(), count);
        }
    }
    return buf;
}

[[nodiscard]] std::string pick_merged_section_name() {
    return std::string{".mxchaos"};
}

[[nodiscard]] std::uint32_t compute_section_table_end_offset(
    const PeImage& image,
    std::size_t    section_count) noexcept
{
    std::uint32_t end = 0;
    std::visit([&](const auto& nt) {
        const auto lfanew = static_cast<std::uint32_t>(
            image.dos_header().e_lfanew);
        using NtType = std::decay_t<decltype(nt)>;
        end = lfanew
            + static_cast<std::uint32_t>(offsetof(NtType, OptionalHeader))
            + nt.FileHeader.SizeOfOptionalHeader
            + static_cast<std::uint32_t>(
                section_count * sizeof(pe::IMAGE_SECTION_HEADER));
    }, image.nt_headers());
    return end;
}

void install_unified_section(
    PeImage&            image,
    const MergedExtent  extent,
    ByteBuffer&&        merged_data)
{
    const std::uint32_t fa = image.file_alignment();
    const std::uint32_t headers_end = compute_section_table_end_offset(
        image, /*section_count=*/1);
    const std::uint32_t raw_offset = static_cast<std::uint32_t>(
        align_up(headers_end, fa));
    const std::uint32_t raw_size = static_cast<std::uint32_t>(
        align_up(merged_data.size(), fa));

    SectionInfo unified;
    unified.name            = pick_merged_section_name();
    unified.virtual_address = extent.first_va;
    unified.virtual_size    = extent.total_vsize;
    unified.data            = std::move(merged_data);
    unified.characteristics = kChaosCharacteristics;
    unified.raw_offset      = raw_offset;
    unified.raw_size        = raw_size;

    auto& sections = image.sections();
    sections.clear();
    sections.push_back(std::move(unified));

    std::visit([](auto& nt) {
        nt.FileHeader.NumberOfSections = 1;
    }, image.nt_headers());
}

} // namespace

void merge_into_unified_section(PeImage& image) {
    if (image.sections().size() < 2) return;

    const auto extent = compute_extent(image);
    if (extent.total_vsize == 0) return;

    auto merged = build_merged_buffer(image, extent);
    install_unified_section(image, extent, std::move(merged));
}

void stamp_chaos_characteristics(PeImage& image) noexcept {
    for (auto& sec : image.sections()) {
        sec.characteristics |= kChaosCharacteristics;
    }
}

} // namespace mx::pe::chaos
