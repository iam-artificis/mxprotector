/**
 * @file chaos_layout.cpp
 * @brief Implementation of `ChaosLayout` — see header.
 */

#include "mxprotector/pe/layout/chaos_layout.hpp"

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_intent.hpp"

#include <algorithm>
#include <cstring>
#include <utility>
#include <variant>

namespace mx::pe {

namespace {

/// Canonical chaos intent — every section claims to hold both code
/// and data and demands RWX runtime permissions.
constexpr SectionIntent kChaosIntent{
    SectionContentType::mixed_code_data,
    SectionPermissions::rwx,
};

/// The bit-mask that `make_section_characteristics` produces for
/// `kChaosIntent`. Computed as a `constexpr` constant so the
/// `finalize()` sweep does not redo the lookup per section.
constexpr std::uint32_t kChaosCharacteristics =
    make_section_characteristics(kChaosIntent);

/// Fill byte for the gaps that appear between the originals' bytes
/// inside the merged section. `0xCC` is `INT3` — looks like inline
/// debug-trap padding to a disassembler walking the unified region,
/// keeps the bytes recognisable in a hex dump, and guarantees a
/// hard fault if control flow ever reaches a gap (defence in depth).
constexpr std::uint8_t kGapFillByte = 0xCC;

/// Stamp the chaos bit-mask into every existing section's
/// characteristics. Discardable / shared / aligned bits the section
/// already had stay set — chaos has no opinion on them.
void stamp_chaos_characteristics(PeImage& image) noexcept {
    for (auto& sec : image.sections()) {
        sec.characteristics |= kChaosCharacteristics;
    }
}

/// Compute the merged-section extent — first byte's RVA and the
/// total span (`max(va + virtual_size) - min(va)`). Pre-condition:
/// at least one non-empty section exists.
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

/// Build the merged buffer.
///
/// Bytewise layout (RVA preserved exactly, so every internal RVA
/// reference still resolves to the same byte after the merge):
///
///   * Inter-section gaps — initial `kGapFillByte` (`0xCC`/INT3).
///   * Per-section body `[va, va + virtual_size)` — first
///     `min(data.size(), virtual_size)` bytes copied from `s.data`,
///     remaining bytes zero-filled to mirror the loader's
///     `virtual_size > raw_size` semantics. Any trailing bytes in
///     `s.data` past `virtual_size` (i.e. file-alignment padding
///     beyond the in-memory mapping) are dropped.
[[nodiscard]] ByteBuffer build_merged_buffer(
    const PeImage&     image,
    const MergedExtent extent)
{
    ByteBuffer buf(extent.total_vsize, kGapFillByte);
    for (const auto& s : image.sections()) {
        const auto off = static_cast<std::size_t>(
            s.virtual_address - extent.first_va);

        // Zero out the section's full virtual span first — within a
        // section, anything past the on-disk bytes is loader-visible
        // as zero, never as the chaos gap fill.
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

/// Pick a name for the merged unified section. `--debug-sections`
/// cannot reach here directly (the policy is selected before the
/// section-name pool runs), so we hand-pick a name that visibly
/// hints at the chaos transform: `.mxchaos` truncates to 8 bytes
/// to stay within `IMAGE_SIZEOF_SHORT_NAME`.
[[nodiscard]] std::string pick_merged_section_name() {
    return std::string{".mxchaos"};
}

/// Compute the file offset of the section table for a hypothetical
/// `section_count`-section image. Mirrors what `PeBuilder` will
/// compute at serialisation time, so the merged section's
/// `raw_offset` lines up with where the writer is about to put it.
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

/// Replace the image's section table with a single unified section
/// covering `[first_va, first_va + total_vsize)`. `NumberOfSections`
/// in the FileHeader is rewritten to 1, and the new section's
/// `raw_offset` / `raw_size` are computed exactly so `PeBuilder` can
/// serialise the file without further recomputation.
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

/// Collapse every section in the image into one unified RWX
/// section. RVAs of all original bytes are preserved exactly; only
/// the section *table* changes. Skipped (no-op) when the image has
/// fewer than two sections — a single section is already merged by
/// definition.
void merge_into_unified_section(PeImage& image) {
    if (image.sections().size() < 2) return;

    const auto extent = compute_extent(image);
    if (extent.total_vsize == 0) return;

    auto merged = build_merged_buffer(image, extent);
    install_unified_section(image, extent, std::move(merged));
}

} // anonymous namespace

SectionIntent ChaosLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    /*requested*/) const noexcept
{
    return kChaosIntent;
}

MxStatus ChaosLayout::finalize(PeImage& image) const {
    // Step 1 — stamp every section's characteristics with the chaos
    // bits, so legacy paths that bypassed `SectionEmitter`/`resolve`
    // still end up RWX/mixed.
    stamp_chaos_characteristics(image);

    // Step 2 — collapse the section table into a single unified
    // RWX/mixed section. RVAs of every byte stay identical, so no
    // reference patching is required: DataDirectory entries, .reloc
    // page RVAs, .pdata RUNTIME_FUNCTION fields, internal directory
    // pointers — everything keeps resolving to the right byte
    // because the byte itself never moved.
    merge_into_unified_section(image);

    return {};
}

std::string_view ChaosLayout::name() const noexcept {
    return "chaos";
}

} // namespace mx::pe
