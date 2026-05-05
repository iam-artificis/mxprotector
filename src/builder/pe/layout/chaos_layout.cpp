/**
 * @file chaos_layout.cpp
 * @brief Implementation of `ChaosLayout` — see header.
 *
 * @details Top-level orchestration only: every helper that does the
 *          actual work lives in a sibling under `pe/layout/`:
 *
 *            * `chaos_section_merger.hpp`        — collapse N sections
 *                                                  into one unified
 *                                                  RWX section.
 *            * `chaos_reference_collector.hpp`   — run every refmap
 *                                                  scanner over the
 *                                                  pre-merge image.
 *            * `chaos_atom_source_registry.hpp`  — register the
 *                                                  canonical atom-source
 *                                                  line-up + parse the
 *                                                  per-build seed.
 */

#include "mxprotector/pe/layout/chaos_layout.hpp"

#include <span>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"
#include "mxprotector/pe/chaos/chaos_shuffler.hpp"
#include "mxprotector/pe/chaos/handler_table_integrity_refinalizer.hpp"
#include "mxprotector/pe/chaos/pdata_chain_emitter.hpp"
#include "mxprotector/pe/chaos/self_crc_refinalizer.hpp"
#include "mxprotector/pe/layout/chaos_atom_source_registry.hpp"
#include "mxprotector/pe/layout/chaos_reference_collector.hpp"
#include "mxprotector/pe/layout/chaos_section_merger.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/refmap/reference_overlap_filter.hpp"
#include "mxprotector/pe/refmap/reference_patcher.hpp"
#include "mxprotector/pe/refmap/reloc_rebuilder.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace mx::pe {

namespace {

/// Canonical chaos intent — every section claims to hold both code
/// and data and demands RWX runtime permissions.
constexpr SectionIntent kChaosIntent{
    SectionContentType::mixed_code_data,
    SectionPermissions::rwx,
};

/// Run the post-merge fragment shuffle (B.4.12 atomic-mode wire).
///
/// Pipeline:
///   1. Scan references (consumes the pre-merge per-section layout).
///   2. Plan with `AtomicChunkPlanner` — function atoms shuffle
///      inside `.text`; data sections stay pinned; every chunk
///      boundary lands on an 8-aligned RVA so no naturally-aligned
///      64-bit value is split across chunks.
///   3. Merge sections into the unified `.mxchaos` section.
///   4. Apply the byte shuffle in the unified section.
///   5. Patch every reference slot at its new RVA to point at its
///      new target RVA.
///   6. Rebuild `.reloc` so the loader's ASLR delta lands on the
///      new slot positions.
///   7. Re-finalise the handler-table XOR-sum integrity check.
///   8. Re-finalise every self-CRC anti-tamper check.
void apply_fragment_shuffle(PeImage& image) {
    if (image.sections().size() < 2) return;

    auto refs = chaos::scan_all_references(image);

    // Drop bogus `rel`/`rip-rel` references whose byte range overlaps
    // a structurally-encoded slot OR a section-registered data region
    // (VM bytecode, handler tables, immediate pools).
    {
        std::vector<DataRegion> data_regions;
        for (const auto& sec : image.sections()) {
            data_regions.insert(
                data_regions.end(),
                sec.data_regions.begin(), sec.data_regions.end());
        }
        refs = refmap::ReferenceOverlapFilter{}.filter(
            refs,
            std::span<const DataRegion>{
                data_regions.data(), data_regions.size()});
    }

    Randomizer rng{chaos::fresh_seed()};
    chaos::AtomicChunkPlanner planner{
        chaos::kMinLooseChunkSize, chaos::kMaxLooseChunkSize};
    chaos::register_atom_sources(planner);
    auto remapper = planner.plan(image, rng);

    chaos::merge_into_unified_section(image);

    if (!image.sections().empty()) {
        auto& unified = image.sections()[0];
        chaos::apply_chunk_shuffle(
            unified.data, unified.virtual_address, remapper);
    }

    refmap::ReferencePatcher patcher;
    [[maybe_unused]] const auto patch_stats =
        patcher.apply(image, refs, remapper);

    refmap::RelocRebuilder reloc_rebuilder;
    [[maybe_unused]] const auto reloc_stats =
        reloc_rebuilder.rebuild(image, remapper);

    // The handler-table XOR-sum integrity check sits inside the
    // self-CRC byte range, so updating it FIRST lets the self-CRC
    // hash stabilise on the final byte content.
    chaos::HandlerTableIntegrityRefinalizer{}.refinalize(image);
    chaos::SelfCrcRefinalizer{}.refinalize(image);
}

} // namespace

SectionIntent ChaosLayout::resolve(
    std::string_view /*section_name*/,
    SectionIntent    /*requested*/) const noexcept
{
    return kChaosIntent;
}

MxStatus ChaosLayout::finalize(PeImage& image) const {
    // Step 1a — emit chained `.pdata` + `.mxchain` so SEH can
    // dispatch for any RIP after `BasicBlockAtomSource` scatters
    // a function's sub-blocks. The emitter is a no-op when no
    // function yields a usable split.
    if (enable_fragment_shuffle_) {
        SectionManager     mgr{image};
        pe::SectionEmitter emitter{mgr, *this};
        [[maybe_unused]] const auto chained =
            chaos::PdataChainEmitter{}.emit(image, emitter);
    }

    // Step 1 — collapse + (optionally) shuffle. Both paths end up
    // overwriting the section table with a single unified section
    // whose `characteristics` are already chaos-stamped (see
    // `install_unified_section`).
    if (enable_fragment_shuffle_) {
        apply_fragment_shuffle(image);
    } else {
        chaos::merge_into_unified_section(image);
    }

    // Step 2 — defence in depth: stamp the chaos bit-mask onto every
    // section in case any external code path bypassed the merge.
    chaos::stamp_chaos_characteristics(image);

    return {};
}

std::string_view ChaosLayout::name() const noexcept {
    return "chaos";
}

} // namespace mx::pe
