/**
 * @file chaos_layout.cpp
 * @brief Implementation of `ChaosLayout` — see header.
 */

#include "mxprotector/pe/layout/chaos_layout.hpp"

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/chaos_shuffler.hpp"
#include "mxprotector/pe/chaos/chunk_planner.hpp"
#include "mxprotector/pe/chaos/load_config_pin_helper.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/code_reference_scanner.hpp"
#include "mxprotector/pe/refmap/delay_import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/export_directory_scanner.hpp"
#include "mxprotector/pe/refmap/import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/load_config_directory_scanner.hpp"
#include "mxprotector/pe/refmap/reference.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/reloc_absolute_va_scanner.hpp"
#include "mxprotector/pe/refmap/resource_directory_scanner.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/refmap/structure_reference_scanner.hpp"
#include "mxprotector/pe/refmap/tls_directory_scanner.hpp"
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

/// Walk the image with every refmap scanner and accumulate every
/// emitted reference into one table.
///
/// The scanner ordering is irrelevant — each scanner only appends —
/// but we run code before structure before deep-directory before
/// reloc, so logs (when enabled) read in increasing-detail order.
[[nodiscard]] refmap::ReferenceTable scan_all_references(const PeImage& image) {
    refmap::ReferenceTable table;
    table.reserve(8192);

    // 1. Code-side references: rel32 / rel8 branches + RIP-relative
    //    operands. Emit per-section, ignoring per-section decode-error
    //    counts (chaos is best-effort, not a verifier).
    refmap::CodeReferenceScanner code;
    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        [[maybe_unused]] const auto errors = code.scan(
            ByteView{sec.data.data(),
                     std::min(sec.data.size(),
                              static_cast<std::size_t>(sec.virtual_size))},
            sec.virtual_address,
            table);
    }

    // 2. Top-level PE structure: entry point, DataDirectory pointers,
    //    .pdata RUNTIME_FUNCTION entries.
    refmap::StructureReferenceScanner{}.scan(image, table);

    // 3. Deep-directory scanners — IMPORT / EXPORT / DELAY_IMPORT /
    //    TLS / LOAD_CONFIG / RESOURCE. Each module pulls every
    //    RVA-bearing slot inside its directory into the table.
    refmap::ImportDescriptorScanner{}.scan(image, table);
    refmap::ExportDirectoryScanner{}.scan(image, table);
    refmap::DelayImportDescriptorScanner{}.scan(image, table);
    refmap::TlsDirectoryScanner{}.scan(image, table);
    refmap::LoadConfigDirectoryScanner{}.scan(image, table);
    refmap::ResourceDirectoryScanner{}.scan(image, table);

    // 4. Final pass — every IMAGE_REL_BASED_DIR64 entry the linker
    //    emitted. Catches any absolute-VA slot the targeted scanners
    //    missed (defence in depth).
    refmap::RelocAbsoluteVaScanner{}.scan(image, table);

    return table;
}

/// Run the post-merge fragment shuffle. Uses the fixed-256B
/// `ChunkPlanner` (B.4.7) which pins entire sections containing
/// DataDirectory entries plus LOAD_CONFIG-pointed table sections.
///
/// The B.4.9 atom-based planner (`chaos::AtomicChunkPlanner` plus
/// 13 atom sources) is implemented and unit-tested but NOT yet
/// wired here. Replacing the production planner with the atomic
/// one requires solving three sub-problems first:
///
///   1. **Alignment** — atoms get packed back-to-back regardless
///      of alignment. CFG/XFG function-pointer slots inside
///      LOAD_CONFIG and other 8-byte aligned PE structures get
///      placed at unaligned RVAs after shuffle, which the Windows
///      loader rejects on module load.
///
///   2. **`.reloc` rebuild** — every relocatable slot moves to a
///      new RVA, but the existing `.reloc` page-RVA + offset
///      entries still point at the OLD positions. Stripping
///      relocs sacrifices ASLR; rebuilding `.reloc` post-shuffle
///      is the proper fix.
///
///   3. **Sub-directory atom coverage** — LOAD_CONFIG carries
///      pointers to volatile-metadata blocks, XFG dispatch
///      tables, and similar substructures whose targets aren't
///      yet covered by a dedicated atom source. Without coverage
///      those bytes shuffle freely and break the runtime.
///
/// The atomic infrastructure (B.4.9.1-6) is shipped as foundation
/// for that follow-up. For production, `--chaos-shuffle` continues
/// to use the fixed-chunk planner — verified end-to-end on
/// `test_vm_showcase` across all four protection levels in B.4.8.7.
void apply_fragment_shuffle(PeImage& image) {
    if (image.sections().size() < 2) return;

    // Phase 1 — scan references (consumes the pre-merge layout).
    auto refs = scan_all_references(image);

    // Phase 2 — plan chunks. Pinned set computed from pre-merge
    // sections + DataDirectory layout so .text + dir bodies are
    // anchored. LOAD_CONFIG-pointed table sections are pinned via
    // `compute_load_config_target_pins`.
    Randomizer rng;
    chaos::ChunkPlanner planner;
    const auto extra_pins = chaos::compute_load_config_target_pins(image);
    auto remapper = planner.plan(image, rng, extra_pins);

    // Phase 3 — merge sections into the unified .mxchaos section.
    merge_into_unified_section(image);

    // Phase 4 — shuffle bytes inside the unified section per the
    // remapper's chunk plan.
    if (!image.sections().empty()) {
        auto& unified = image.sections()[0];
        chaos::apply_chunk_shuffle(
            unified.data, unified.virtual_address, remapper);
    }

    // Phase 5 — patch every reference's slot at its post-shuffle
    // location to point at its post-shuffle target.
    refmap::ReferencePatcher patcher;
    [[maybe_unused]] const auto stats =
        patcher.apply(image, refs, remapper);
}

} // anonymous namespace

SectionIntent ChaosLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    /*requested*/) const noexcept
{
    return kChaosIntent;
}

MxStatus ChaosLayout::finalize(PeImage& image) const {
    // Step 1 — collapse + (optionally) shuffle FIRST. Both paths end
    // up overwriting the section table with a single unified section
    // whose `characteristics` are already chaos-stamped (see
    // `install_unified_section`). The `apply_fragment_shuffle` path
    // additionally scans references, plans chunks, shuffles bytes,
    // and patches references — all of which read the *original*
    // per-section characteristics (e.g. `is_code()` on .text vs
    // .rdata).
    //
    // The fragment shuffle is opt-in because deep internal-directory
    // references that B.4.8 added (IMPORT descriptor pointers, EXPORT
    // name table, LOAD_CONFIG CFG tables, TLS callback array, etc.)
    // are now scanned, but the policy is conservative — flip on via
    // `--chaos-shuffle` and stress-test before defaulting on.
    if (enable_fragment_shuffle_) {
        apply_fragment_shuffle(image);
    } else {
        merge_into_unified_section(image);
    }

    // Step 2 — stamp the chaos bit-mask onto the now-unified section.
    // The merge already sets `unified.characteristics =
    // kChaosCharacteristics`, so this is normally a no-op; the loop
    // exists as defence in depth for any external code that bypasses
    // the merge path.
    stamp_chaos_characteristics(image);

    return {};
}

std::string_view ChaosLayout::name() const noexcept {
    return "chaos";
}

} // namespace mx::pe
