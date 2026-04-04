/**
 * @file dispatcher_gen.cpp
 * @brief [BUILDER] Реализация генератора диспетчера CFF.
 *
 * @details Генерирует x86/x64 машинный код для dispatcher-блока:
 *          серию CMP + JE для каждого state_id, заканчивающуюся JMP на exit.
 *          Каждый расплющенный блок завершается обновлением state variable
 *          и безусловным переходом обратно в dispatcher.
 *
 *          State IDs назначаются случайно (не последовательно), что затрудняет
 *          восстановление оригинального порядка блоков.
 */

#include "mxprotector/protection/cfg/dispatcher_gen.hpp"

#include <algorithm>
#include <format>
#include <unordered_set>

namespace mx {

DispatcherGenerator::DispatcherGenerator(Architecture arch)
    : arch_(arch)
{}

std::unordered_map<uint32_t, uint32_t> DispatcherGenerator::assign_state_ids(
    const std::vector<uint32_t>& block_ids,
    Randomizer& rng)
{
    std::unordered_map<uint32_t, uint32_t> mapping;
    std::unordered_set<uint32_t> used_states;

    for (const auto block_id : block_ids) {
        uint32_t state;
        do {
            state = rng.next_u32();
        } while (used_states.contains(state));

        used_states.insert(state);
        mapping[block_id] = state;
    }

    return mapping;
}

MxResult<DispatcherResult> DispatcherGenerator::generate(
    std::vector<FlattenedBlock>& blocks,
    uint32_t entry_state_id,
    x86::Reg state_var_reg,
    Randomizer& rng)
{
    if (blocks.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "DispatcherGenerator: no blocks to flatten"));
    }

    // Shuffle block order to break spatial correlation with original layout
    std::ranges::shuffle(blocks, rng.engine());

    analysis::X86CodeEmitter em(is_64bit());

    // ====================================================================
    // Prologue: initialize state variable to entry state
    // ====================================================================
    em.mov(state_var_reg, static_cast<uint64_t>(entry_state_id));

    // ====================================================================
    // Dispatcher: CMP state_reg, state_id; JE block_label
    // ====================================================================
    auto dispatcher_label = em.create_label();
    em.bind_label(dispatcher_label);

    std::vector<analysis::Label> block_labels;
    block_labels.reserve(blocks.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        block_labels.push_back(em.create_label());
    }
    auto exit_label = em.create_label();

    for (size_t i = 0; i < blocks.size(); ++i) {
        em.cmp(state_var_reg, static_cast<int32_t>(blocks[i].state_id));
        em.jcc(analysis::ConditionCode::equal, block_labels[i]);
    }

    // Fallthrough: exit (should never be reached in correct execution)
    em.jmp(exit_label);

    // ====================================================================
    // Block bodies: each block ends with state update + jmp dispatcher
    // ====================================================================
    std::vector<BlockPlacement> placements;
    placements.reserve(blocks.size());

    for (size_t i = 0; i < blocks.size(); ++i) {
        em.bind_label(block_labels[i]);

        BlockPlacement bp;
        bp.output_offset = static_cast<uint32_t>(em.current_size());
        bp.code_size = static_cast<uint32_t>(blocks[i].code.size());
        bp.original_va = blocks[i].original_va;
        placements.push_back(bp);

        em.raw(ByteView{blocks[i].code.data(), blocks[i].code.size()});

        // State transition: set next state and jump back to dispatcher
        if (!blocks[i].successor_states.empty()) {
            if (blocks[i].successor_states.size() == 1) {
                const uint32_t next_state = blocks[i].successor_states[0];
                em.mov(state_var_reg, static_cast<uint64_t>(next_state));
                em.jmp(dispatcher_label);
            } else {
                const uint32_t taken_state = blocks[i].successor_states[0];
                const uint32_t fallthrough_state = blocks[i].successor_states[1];

                auto taken_label = em.create_label();
                auto merge_label = em.create_label();

                em.mov(state_var_reg, static_cast<uint64_t>(fallthrough_state));
                em.jcc(blocks[i].branch_cc, taken_label);
                em.jmp(merge_label);

                em.bind_label(taken_label);
                em.mov(state_var_reg, static_cast<uint64_t>(taken_state));

                em.bind_label(merge_label);
                em.jmp(dispatcher_label);
            }
        } else {
            // Terminal block (ret or similar) — jump to exit
            em.jmp(exit_label);
        }
    }

    // ====================================================================
    // Exit label (safety trap — should never be reached)
    // ====================================================================
    em.bind_label(exit_label);
    em.raw(ByteView{reinterpret_cast<const uint8_t*>("\xCC"), 1});

    auto code = em.build();
    if (!code) {
        return std::unexpected(code.error());
    }

    DispatcherResult result;
    result.full_function = std::move(*code);
    result.total_size = static_cast<uint32_t>(result.full_function.size());
    result.blocks = std::move(blocks);
    result.block_placements = std::move(placements);
    return result;
}

} // namespace mx
