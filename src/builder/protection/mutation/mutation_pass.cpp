/**
 * @file mutation_pass.cpp
 * @brief [BUILDER] MutationPass — implements `IProtectionPass`.
 *
 * @details MutationPass orchestrates the mutation phase:
 *          1. Locate every `MX_MUTATE_BEGIN/END` region (or fall back
 *             to all code sections when no markers are present).
 *          2. Build the expansion sink chain (Feature A — primary
 *             grow-source, fallback shared overflow section).
 *          3. Construct a `MutationEngine`, install the sink, and
 *             mutate each region.
 *          4. Scan NOP/INT3 padding between functions and fill it
 *             with junk + opaque predicates.
 *
 * `MutationEngine`'s impl lives in `mutation_engine.cpp`
 * (extracted to keep this TU under the project's ~300 LOC cap and
 * to give the engine a dedicated place to host the expansion-sink
 * redirect logic introduced by Feature A).
 */

#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/protection/mutation/overflow/extend_in_place_sink.hpp"
#include "mxprotector/protection/mutation/padding_filler.hpp"
#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_manager.hpp"

#include <algorithm>
#include <format>

namespace mx {

// Padding detection + filling lives in `padding_filler.{hpp,cpp}`
// (R3.3 split-out). The helpers used to live in this TU's anonymous
// namespace; consolidating the logic in its own pair lets future
// tightening (e.g. a finer "is this NOP run truly dead?" heuristic)
// land in one place without touching the substitution-driven
// `MutationEngine`.

// ============================================================================
// MutationPass::is_applicable
// ============================================================================

bool MutationPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    if (!ctx.config().enable_mutation)     return false;
    // Substitution rules + junk generator emit x86/x64 byte sequences;
    // every other architecture would either reject the encodings or
    // misinterpret them at runtime. Gate on the canonical
    // "fully-supported target" predicate so non-PE / non-x64 inputs
    // skip cleanly. EXE / DLL / SYS / EFI are all acceptable — the
    // mutation works at the byte level and has no runtime infra
    // dependency.
    if (!ctx.target().is_windows_pe_x64()) return false;
    return true;
}

// ============================================================================
// MutationPass::execute — главный метод прохода
// ============================================================================

MxStatus MutationPass::execute(ProtectionContext& ctx) {
    ctx.log("MutationPass: начало мутации маркированных регионов");

    std::vector<const MarkedRegion*> mutation_regions;
    for (const auto& marker : ctx.markers()) {
        if (marker.type == MarkerType::mutate_begin) {
            mutation_regions.push_back(&marker);
        }
    }

    Randomizer rng;
    auto rules = SubstitutionRuleRegistry::create_default();
    if (ctx.config().enable_mba_substitution) {
        // Mixed-Boolean-Arithmetic rewriting is opt-in — the bodies
        // change OF/AF flag effects relative to the original ALU op
        // and need flag-insensitive call sites to ship safely. See
        // `ProtectionConfig::enable_mba_substitution`.
        mutation::rules::register_mba_rules(rules);
        ctx.log("MutationPass: MBA substitution enabled "
                "(adds 1 adapter rule wrapping the MBA registry)");
    }
    auto junk = std::make_unique<JunkGenerator>(ctx.pe_image().architecture());
    MutationEngine engine(std::move(rules), std::move(junk), rng);

    // Feature A — wire the expansion sink chain. The chain prefers
    // growing the source section in place (no new section, no
    // section-table noise), falling back to a shared MxProtector-
    // owned overflow section when the source's section-alignment
    // slack is exhausted. Lifetimes are scoped to this `execute`
    // body — the engine borrows the sink pointer and never outlives
    // these stack objects.
    // The expansion sink chain places spilled bytes outside the
    // original instruction's slot. We deliberately use only the
    // shared-section sink (`ExtendInPlaceSink`) and skip
    // `GrowSourceSectionSink`: growing the source section past its
    // alignment slack pushes every subsequent section's VA forward,
    // and nothing in this pass walks the post-mutation byte stream
    // to update RIP-relative references that targeted those moved
    // sections — a silently-malformed PE rejected by the loader.
    // The shared overflow section appended at the tail of
    // `sections()` adds capacity without shifting any existing
    // section, so RIP-relative references in `.text` keep pointing
    // at the right `.rdata` / `.data` content.
    SectionManager     sec_mgr(ctx.pe_image());
    pe::SectionEmitter emitter{sec_mgr, ctx.layout_policy()};
    mutation::overflow::ExtendInPlaceSink shared_overflow{
        emitter, ctx.section_names().mut};
    engine.set_expansion_sink(&shared_overflow);

    // Downstream code-rewriting passes (VM lifter, Guard relocator)
    // parse the post-mutation byte stream of their own marked regions
    // and assume original instruction shapes are still in place. A
    // size-changing rule that plants `JMP rel32 + NOPs` would break
    // those lifters. We fold every VM/Guard region into a single
    // exclusion list so the engine refuses redirects there — same-
    // size substitutions still apply and stay invisible to the
    // lifters via Zydis decoding.
    {
        std::vector<AddressRange> excluded;
        const auto image_base = ctx.pe_image().image_base();
        for (const auto& m : ctx.markers()) {
            if (m.type != MarkerType::vm_begin &&
                m.type != MarkerType::guard_begin)
            {
                continue;
            }
            const Va start_va = image_base + m.start_rva;
            const auto size = static_cast<std::uint64_t>(
                m.end_rva - m.start_rva);
            excluded.push_back(AddressRange{start_va, size});
        }
        if (!excluded.empty()) {
            ctx.log_fmt("MutationPass: {} VM/Guard regions excluded "
                        "from size-changing redirects", excluded.size());
            engine.set_excluded_redirect_ranges(std::move(excluded));
        }
    }

    uint32_t total_mutations = 0;

    // ====================================================================
    // Phase 1: Instruction substitution
    // ====================================================================

    if (mutation_regions.empty()) {
        ctx.log("MutationPass: маркеров MX_MUTATE не найдено");

        bool has_code_sections = false;
        for (const auto& sec : ctx.pe_image().sections()) {
            if (sec.is_code() && sec.virtual_size > 0) {
                has_code_sections = true;
                break;
            }
        }

        if (!has_code_sections) {
            ctx.log("MutationPass: нет кодовых секций, пропуск");
            return {};
        }

        ctx.log("MutationPass: мутация всех кодовых секций (нет маркеров)");

        // Capture each section's identity (name + VA) so the
        // refresher can re-find it across `IExpansionSink::plant`
        // calls — those may grow the source section's data vector
        // *or* the outer `sections()` vector (when a fallback sink
        // lazily adds an overflow section), invalidating any
        // pre-captured `&sec` reference.
        std::vector<std::pair<std::string, Va>> code_section_keys;
        for (const auto& sec : ctx.pe_image().sections()) {
            if (!sec.is_code() || sec.data.empty()) continue;
            code_section_keys.emplace_back(sec.name, sec.virtual_address);
        }

        for (const auto& [sec_name, sec_va] : code_section_keys) {
            const Va section_va = ctx.pe_image().image_base() + sec_va;

            auto refresher = [&img = ctx.pe_image(),
                              name = sec_name,
                              va = sec_va]() noexcept -> MutableByteView {
                for (auto& s : img.sections()) {
                    if (s.name == name && s.virtual_address == va) {
                        return MutableByteView{s.data.data(), s.data.size()};
                    }
                }
                return MutableByteView{};
            };

            auto result = engine.mutate_region(
                std::move(refresher), section_va, *ctx.disassembler(), ctx);

            if (result) {
                total_mutations += *result;
            } else {
                ctx.log_fmt("MutationPass: ошибка мутации секции '{}': {}",
                    sec_name, result.error().message());
            }
        }
    } else {
        uint32_t regions_processed = 0;

        for (const auto* region : mutation_regions) {
            const Rva start_rva = region->start_rva;
            const Rva end_rva = region->end_rva;
            const uint32_t region_size = end_rva - start_rva;

            if (region_size == 0) {
                ctx.log_fmt("MutationPass: пустой регион [0x{:08X}-0x{:08X}], пропуск",
                    start_rva, end_rva);
                continue;
            }

            ctx.log_fmt("MutationPass: обработка региона [0x{:08X}-0x{:08X}] ({} байт)",
                start_rva, end_rva, region_size);

            const auto* section = ctx.pe_image().section_by_rva(start_rva);
            if (!section) {
                ctx.log_fmt("MutationPass: ОШИБКА: не найдена секция для RVA 0x{:08X}", start_rva);
                continue;
            }

            const uint32_t offset_in_section = start_rva - section->virtual_address;
            if (offset_in_section + region_size > section->data.size()) {
                ctx.log_fmt("MutationPass: ОШИБКА: регион выходит за пределы секции '{}'",
                    section->name);
                continue;
            }

            // Refresher rebinds the byte view on every call so a
            // realloc inside `plant` cannot leave the engine writing
            // through a dangling pointer. Captures the section's name
            // + VA + the per-region offset/size so it can re-derive
            // the writable span fresh each time.
            auto refresher = [&img = ctx.pe_image(),
                              name = section->name,
                              sec_va = section->virtual_address,
                              offset_in_section,
                              region_size]() noexcept -> MutableByteView {
                for (auto& s : img.sections()) {
                    if (s.name != name || s.virtual_address != sec_va) {
                        continue;
                    }
                    if (offset_in_section + region_size > s.data.size()) {
                        return MutableByteView{};
                    }
                    return MutableByteView{
                        s.data.data() + offset_in_section, region_size};
                }
                return MutableByteView{};
            };

            const Va region_va = ctx.pe_image().image_base() + start_rva;

            auto result = engine.mutate_region(
                std::move(refresher), region_va, *ctx.disassembler(), ctx);

            if (result) {
                total_mutations += *result;
                ++regions_processed;
                ctx.log_fmt("  Регион: {} мутаций применено", *result);
            } else {
                ctx.log_fmt("  Регион: ошибка мутации: {}", result.error().message());
            }
        }

        ctx.log_fmt("MutationPass: маркерных регионов: {}/{}",
            regions_processed, mutation_regions.size());
    }

    // ====================================================================
    // Phase 2: Fill NOP/INT3 padding with junk + opaque predicates
    // ====================================================================

    uint32_t total_padding_filled = 0;
    uint32_t total_predicates = 0;
    uint32_t total_junk_bytes = 0;

    {
        JunkGenerator padding_gen(ctx.pe_image().architecture());
        OpaquePredicateGenerator pred_gen(ctx.pe_image().architecture());

        for (auto& sec : ctx.pe_image().sections()) {
            if (!sec.is_code() || sec.data.empty()) continue;

            const Va section_va = ctx.pe_image().image_base() + sec.virtual_address;
            MutableByteView code_view(sec.data.data(), sec.data.size());

            auto stats = mutation::fill_section_padding(
                code_view, section_va, *ctx.disassembler(),
                padding_gen, pred_gen, rng);

            total_padding_filled += stats.regions_filled;
            total_predicates += stats.predicates_inserted;
            total_junk_bytes += stats.junk_bytes;
        }
    }

    ctx.log_fmt("MutationPass: завершено. Подстановок: {} (in-place: {}, "
                "redirected: {}), правил: {}, padding→junk: {} ({} байт), "
                "opaque predicates: {}",
        total_mutations,
        total_mutations - engine.total_redirected_expansions(),
        engine.total_redirected_expansions(),
        SubstitutionRuleRegistry::create_default().rule_count(),
        total_padding_filled, total_junk_bytes, total_predicates);

    if (engine.total_redirected_expansions() > 0) {
        ctx.log_fmt("MutationPass: {} расширенных подстановок направлено в "
                    "shared-section overflow ('{}')",
            engine.total_redirected_expansions(),
            ctx.section_names().mut);
    }

    return {};
}

} // namespace mx
