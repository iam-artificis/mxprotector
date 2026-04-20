/**
 * @file cfg_flattening_pipeline.cpp
 * @brief Per-execution orchestrator for `CfgFlatteningPass`.
 *
 * The dispatch is straight-forward:
 *
 *   1. `gather_candidates` picks a source (markers → .map → .pdata)
 *      and returns the list of functions to try.
 *   2. For each candidate, `try_flatten` attempts the full single-
 *      function CFF flow and updates counters / trampoline list.
 *   3. If any candidate produced a trampoline entry, they're
 *      committed into a dedicated `.mxprot1` section.
 *   4. A summary line reports the per-category counts.
 *
 * The per-candidate algorithm itself — CFG build, reachability pruning,
 * safety filters, state-reg selection, `CfgFlattener::flatten` — lives
 * inline in `try_flatten`; that's the cohesive hot path and splitting it
 * further would obscure more than it would clarify. Independent leaf
 * operations (trampoline writes, fixups, safety filters) are separate TUs.
 */

#include "mxprotector/protection/cfg/cfg_flattening_pipeline.hpp"

#include <algorithm>
#include <queue>
#include <unordered_set>

#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/trace_hints.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/cfg/cff_function_source.hpp"
#include "mxprotector/protection/cfg/cff_safety_filters.hpp"
#include "mxprotector/protection/cfg/cff_trampoline_section.hpp"
#include "mxprotector/protection/cfg/state_reg_picker.hpp"

namespace mx::cff {

namespace {

/// Remove any block that can't be reached from the entry via successor
/// edges. These are typically int3 padding runs after a `ret` that the
/// CFG builder still picked up as a standalone block.
void prune_unreachable_blocks(analysis::ControlFlowGraph& cfg) {
    std::unordered_set<uint32_t> reachable;
    std::queue<uint32_t>         bfs;
    bfs.push(cfg.entry_block_id());
    reachable.insert(cfg.entry_block_id());
    while (!bfs.empty()) {
        const auto cur = bfs.front();
        bfs.pop();
        const auto* blk = cfg.block_by_id(cur);
        if (!blk) continue;
        for (const auto succ : blk->successors()) {
            if (reachable.insert(succ).second) {
                bfs.push(succ);
            }
        }
    }
    std::vector<uint32_t> to_remove;
    for (const auto& [id, _] : cfg.blocks()) {
        if (!reachable.contains(id)) {
            to_remove.push_back(id);
        }
    }
    for (const auto id : to_remove) {
        cfg.blocks().erase(id);
    }
}

/// A function is unsafe if any terminator jump targets a VA outside
/// the function bounds or has no recorded target at all. Such jumps
/// indicate external code references the flattener can't rewrite.
[[nodiscard]] bool has_external_or_unresolved_jump(
    const analysis::ControlFlowGraph& cfg, Va base_va, size_t func_size)
{
    for (const auto& [_, block] : cfg.blocks()) {
        const auto* term = block.terminator();
        if (!term) continue;
        if (!term->is_unconditional_jump()) continue;

        if (term->branch_targets().empty()) return true;

        bool all_external = true;
        for (const auto target : term->branch_targets()) {
            if (target >= base_va && target < base_va + func_size) {
                all_external = false;
                break;
            }
        }
        if (all_external) return true;
    }
    return false;
}

/// A function with a CFG that covers less than half its byte footprint
/// probably has data interleaved with code. Flattening those is prone
/// to corrupting the data regions, so skip.
[[nodiscard]] bool has_insufficient_coverage(
    const analysis::ControlFlowGraph& cfg, size_t func_size)
{
    uint64_t covered = 0;
    for (const auto& [_, block] : cfg.blocks()) {
        covered += block.size();
    }
    return covered < func_size / 2;
}

/// Locate the code section holding `rva` and return pointer+offset.
/// Returns nullptr if no code section contains it or the range would
/// spill past the section's raw data.
struct LocatedFunction {
    pe::SectionInfo* section;
    uint32_t         offset_in_section;
};
[[nodiscard]] LocatedFunction locate_function(PeImage& image,
                                              Rva      rva,
                                              uint32_t size)
{
    for (auto& s : image.sections()) {
        if (!s.is_code() || !s.contains_rva(rva)) continue;
        const uint32_t offset = rva - s.virtual_address;
        if (offset + size > s.data.size()) return {nullptr, 0};
        return {&s, offset};
    }
    return {nullptr, 0};
}

} // namespace

CfgFlatteningPipeline::CfgFlatteningPipeline(ProtectionContext& ctx) noexcept
    : ctx_(ctx)
{
    flat_config_.enable_bogus_flow      = true;
    flat_config_.bogus_probability      = 0.5;
    flat_config_.enable_mba_transitions = true;
    flat_config_.enable_junk_blocks     = true;
    flat_config_.junk_block_ratio       = 0.12;
}

CfgFlatteningPipeline::Outcome
CfgFlatteningPipeline::try_flatten(pe::SectionInfo&         section,
                                   const FunctionCandidate& candidate)
{
    const Rva      func_rva  = candidate.rva;
    const uint32_t func_size = candidate.size;

    if (func_size < 16) return Outcome::skipped;

    const uint32_t offset = func_rva - section.virtual_address;
    const Va       base_va = ctx_.pe_image().image_base() + func_rva;

    ByteBuffer code_snapshot(section.data.begin() + offset,
                             section.data.begin() + offset + func_size);
    ByteView   code_view{code_snapshot.data(), code_snapshot.size()};

    analysis::CfgBuilder cfg_builder(ctx_.disassembler());
    auto cfg_result = cfg_builder.build(code_view, base_va);
    if (!cfg_result) return Outcome::skipped;

    auto& cfg = *cfg_result;
    prune_unreachable_blocks(cfg);
    if (cfg.block_count() < 3) return Outcome::skipped;

    if (first_instruction_is_mov_rax_rsp(code_view)) {
        ctx_.log_fmt("  CFF: RVA=0x{:08X} size={} — skipped "
                     "(mov rax, rsp prologue pattern)",
            func_rva, func_size);
        return Outcome::skipped;
    }

    if (has_external_or_unresolved_jump(cfg, base_va, func_size) ||
        has_insufficient_coverage(cfg, func_size))
    {
        return Outcome::skipped;
    }

    const auto chosen_reg = select_state_register(code_view);
    if (!chosen_reg) {
        ctx_.log_fmt("  CFF: RVA=0x{:08X} size={} — skipped "
                     "(no free state register)",
            func_rva, func_size);
        return Outcome::skipped;
    }

    auto func_config = flat_config_;
    func_config.state_var_reg = *chosen_reg;

    const char* reg_name = (*chosen_reg == x86::Reg::r11) ? "R11" : "R10";
    ctx_.log_fmt("  CFF: RVA=0x{:08X} size={} blocks={} state_reg={}",
        func_rva, func_size, cfg.block_count(), reg_name);

    CfgFlattener flattener(ctx_.pe_image().architecture(), func_config);
    auto flat_result = flattener.flatten(cfg, code_view, base_va, rng_);
    if (!flat_result) return Outcome::skipped;

    total_blocks_ += flat_result->original_block_count;

    if (flat_result->flattened_code.size() <= func_size) {
        std::copy(flat_result->flattened_code.begin(),
                  flat_result->flattened_code.end(),
                  section.data.begin() + offset);
        if (flat_result->flattened_code.size() < func_size) {
            std::fill(section.data.begin() + offset + flat_result->flattened_code.size(),
                      section.data.begin() + offset + func_size,
                      static_cast<uint8_t>(0xCC));
        }
        return Outcome::in_place;
    }

    CffTrampolineEntry entry;
    entry.original_func_rva  = func_rva;
    entry.original_func_size = func_size;
    entry.flattened_code     = std::move(flat_result->flattened_code);
    entry.block_placements   = std::move(flat_result->block_placements);
    trampolines_.push_back(std::move(entry));
    return Outcome::trampolined;
}

MxStatus CfgFlatteningPipeline::execute() {
    ctx_.log("CfgFlatteningPass: начало расплющивания потока управления");

    const auto candidates = gather_candidates(ctx_);
    const bool emit_hints = ctx_.config().emit_trace_hints;
    for (const auto& c : candidates) {
        auto located = locate_function(ctx_.pe_image(), c.rva, c.size);
        if (!located.section) continue;

        const auto outcome = try_flatten(*located.section, c);
        switch (outcome) {
        case Outcome::in_place:    ++flattened_inplace_; break;
        case Outcome::trampolined: ++trampolined_;       break;
        case Outcome::skipped:     ++skipped_;           break;
        }
        // Emit protected_function entry for every successfully defended
        // candidate — both in-place and trampolined outcomes produce
        // protection metadata the benchmark wants to filter against.
        // Skipped candidates are not included: they still contain their
        // original code and the baseline measurement should count them
        // as "not protected".
        if (emit_hints && (outcome == Outcome::in_place ||
                           outcome == Outcome::trampolined))
        {
            ctx_.trace_hints().add_protected_function(
                static_cast<std::uint32_t>(c.rva),
                c.size,
                analysis::ProtectedFunctionKind::cff);
        }
    }

    commit_trampoline_section(ctx_, trampolines_);

    ctx_.log_fmt("CfgFlatteningPass: завершено. In-place: {}, трамплинов: {}, "
                 "пропущено: {}, блоков: {}",
        flattened_inplace_, trampolined_, skipped_, total_blocks_);

    return {};
}

} // namespace mx::cff
