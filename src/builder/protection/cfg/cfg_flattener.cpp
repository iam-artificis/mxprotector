/**
 * @file cfg_flattener.cpp
 * @brief Implementation of the `CfgFlattener` per-function algorithm.
 *
 * The class takes a built `ControlFlowGraph` and returns the bytes of
 * the flattened equivalent: every original basic block has its
 * terminator stripped, the bodies are reordered by random state id,
 * and a dispatcher switches between them via a state variable. Bogus
 * flow can be layered on top of each block as a prefix of an opaque-
 * predicate guard + junk code, and the dispatcher can use MBA
 * transitions for the state update.
 *
 * This file only handles ONE function at a time. Candidate discovery,
 * section injection, and trampoline relocation live in
 * `CfgFlatteningPipeline` and the adjacent leaf modules.
 */

#include "mxprotector/protection/cfg/cfg_flattening.hpp"

#include <utility>

#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/protection/cfg/bogus_flow.hpp"
#include "mxprotector/protection/cfg/dispatcher_gen.hpp"

namespace mx {

CfgFlattener::CfgFlattener(Architecture arch, FlatteningConfig config)
    : arch_(arch)
    , config_(std::move(config))
{}

ByteBuffer CfgFlattener::extract_block_code(
    const analysis::BasicBlock& block,
    ByteView                    original_code,
    Va                          base_address) const
{
    const auto start_offset = static_cast<size_t>(block.start_address() - base_address);
    auto       end_offset   = static_cast<size_t>(block.end_address() - base_address);

    if (end_offset > original_code.size()) {
        end_offset = original_code.size();
    }
    if (start_offset >= end_offset) {
        return {};
    }

    ByteBuffer code(original_code.begin() + start_offset,
                    original_code.begin() + end_offset);

    // Strip the terminator for jumps — the flattener emits its own
    // dispatcher jump. `ret` is kept below as part of the block body
    // because returns leave the function entirely.
    const auto* terminator = block.terminator();
    if (terminator && (terminator->is_unconditional_jump() ||
                       terminator->is_conditional_branch())) {
        const auto term_len = terminator->length();
        if (code.size() >= term_len) {
            code.resize(code.size() - term_len);
        }
    }
    return code;
}

MxResult<FlatteningResult> CfgFlattener::flatten(
    const analysis::ControlFlowGraph& cfg,
    ByteView                          original_code,
    Va                                base_address,
    Randomizer&                       rng)
{
    if (cfg.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::cfg_build_error,
            "CfgFlattener: empty CFG"));
    }

    std::vector<uint32_t> block_ids;
    block_ids.reserve(cfg.block_count());
    for (const auto& [id, block] : cfg.blocks()) {
        block_ids.push_back(id);
    }

    DispatcherGenerator disp_gen(arch_);
    auto                state_map = disp_gen.assign_state_ids(block_ids, rng);

    std::vector<FlattenedBlock> flat_blocks;
    flat_blocks.reserve(cfg.block_count());

    for (const auto& [id, block] : cfg.blocks()) {
        FlattenedBlock fb;
        fb.original_block_id = id;
        fb.state_id          = state_map[id];
        fb.original_va       = block.start_address();

        fb.code = extract_block_code(block, original_code, base_address);

        for (const auto succ_id : block.successors()) {
            if (state_map.contains(succ_id)) {
                fb.successor_states.push_back(state_map[succ_id]);
            }
        }

        if (block.terminator() && block.terminator()->is_conditional_branch()) {
            const auto& raw = block.terminator()->raw_bytes();
            if (raw.size() >= 2 && raw[0] == 0x0F && (raw[1] & 0xF0) == 0x80) {
                fb.branch_cc = static_cast<analysis::ConditionCode>(raw[1] & 0x0F);
            } else if (raw.size() >= 1 && (raw[0] & 0xF0) == 0x70) {
                fb.branch_cc = static_cast<analysis::ConditionCode>(raw[0] & 0x0F);
            }
        }

        if (block.terminator() && block.terminator()->is_return()) {
            fb.successor_states.clear();
            const auto* term = block.terminator();
            fb.code.insert(fb.code.end(),
                term->raw_bytes().begin(), term->raw_bytes().end());
        }

        flat_blocks.push_back(std::move(fb));
    }

    uint32_t bogus_count = 0;
    if (config_.enable_bogus_flow) {
        BogusFlowGenerator bogus_gen(arch_);
        auto               bogus_blocks = bogus_gen.generate_for_function(
            static_cast<uint32_t>(flat_blocks.size()),
            config_.bogus_probability,
            rng);

        for (size_t i = 0; i < flat_blocks.size() && i < bogus_blocks.size(); ++i) {
            if (bogus_blocks[i].total_size == 0) continue;

            const uint32_t prefix_size = static_cast<uint32_t>(
                bogus_blocks[i].predicate_code.size() +
                bogus_blocks[i].junk_code.size());

            ByteBuffer augmented;
            augmented.reserve(prefix_size + flat_blocks[i].code.size());
            augmented.insert(augmented.end(),
                bogus_blocks[i].predicate_code.begin(),
                bogus_blocks[i].predicate_code.end());
            augmented.insert(augmented.end(),
                bogus_blocks[i].junk_code.begin(),
                bogus_blocks[i].junk_code.end());
            augmented.insert(augmented.end(),
                flat_blocks[i].code.begin(),
                flat_blocks[i].code.end());

            flat_blocks[i].code              = std::move(augmented);
            flat_blocks[i].bogus_prefix_size = prefix_size;
            ++bogus_count;
        }
    }

    const uint32_t entry_state = state_map[cfg.entry_block_id()];

    DispatcherConfig disp_config;
    disp_config.enable_mba_transitions = config_.enable_mba_transitions;
    disp_config.enable_junk_blocks     = config_.enable_junk_blocks;
    disp_config.junk_block_ratio       = config_.junk_block_ratio;

    auto disp_result = disp_gen.generate(
        flat_blocks, entry_state, config_.state_var_reg, rng, disp_config);
    if (!disp_result) {
        return std::unexpected(disp_result.error());
    }

    FlatteningResult result;
    result.flattened_code      = std::move(disp_result->full_function);
    result.original_block_count = static_cast<uint32_t>(cfg.block_count());
    result.total_block_count    = static_cast<uint32_t>(cfg.block_count() + bogus_count);
    result.bogus_blocks_added   = bogus_count;
    result.total_size           = static_cast<uint32_t>(result.flattened_code.size());
    result.block_placements     = std::move(disp_result->block_placements);
    return result;
}

} // namespace mx
