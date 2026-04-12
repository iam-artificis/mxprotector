/**
 * @file dispatcher_gen.cpp
 * @brief [BUILDER] Реализация генератора диспетчера CFF с MBA-переходами и junk-блоками.
 *
 * @details Генерирует x86/x64 машинный код для dispatcher-блока:
 *          серию CMP + JE для каждого state_id, заканчивающуюся JMP на exit.
 *
 *          Улучшения:
 *          - MBA-переходы: вместо `mov r10, next_state` используется цепочка
 *            из 5–10 операций, вычисляющих следующий state из предыдущего.
 *          - Junk-блоки: 10–15% ложных путей в диспетчере, содержащих
 *            реалистичный мусорный код с возвратом в диспетчер.
 *          - State IDs ограничены 31 битом для совместимости с sign-extension.
 */

#include "mxprotector/protection/cfg/dispatcher_gen.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <format>
#include <unordered_set>

namespace mx {

namespace {

/**
 * @brief Проверяет, не клобберит ли блок state_reg. Клобберят:
 *  - CALL (portable volatile клобберится по ABI);
 *  - явная запись в state_reg;
 *  - любая инструкция, у которой dest-операнд = state_reg.
 */
bool block_preserves_state_reg(ByteView code, x86::Reg state_reg) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const ZydisRegister target_largest = ZydisRegisterGetLargestEnclosing(
        ZYDIS_MACHINE_MODE_LONG_64,
        (state_reg == x86::Reg::r10) ? ZYDIS_REGISTER_R10 : ZYDIS_REGISTER_R11);

    size_t off = 0;
    while (off < code.size()) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + off, code.size() - off,
                &insn, operands))) {
            ++off;
            continue;
        }

        if (insn.meta.category == ZYDIS_CATEGORY_CALL) return false;

        // Any write-visible register operand matching state_reg kills preservation.
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = operands[i];
            if (op.type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
            if (!(op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) continue;
            const auto enc = ZydisRegisterGetLargestEnclosing(
                ZYDIS_MACHINE_MODE_LONG_64, op.reg.value);
            if (enc == target_largest) return false;
        }

        off += insn.length;
    }
    return true;
}

} // anonymous namespace

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
            state = MbaTransitionGenerator::sanitize_state_id(rng.next_u32());
        } while (state == 0 || used_states.contains(state));

        used_states.insert(state);
        mapping[block_id] = state;
    }

    return mapping;
}

ByteBuffer DispatcherGenerator::generate_junk_block_body(
    uint32_t insn_count, Randomizer& rng) const
{
    analysis::X86CodeEmitter em(is_64bit());

    // Stack frame to look realistic
    em.push(x86::Reg::rbx);
    em.sub(x86::Reg::rsp, 0x20);

    for (uint32_t i = 0; i < insn_count; ++i) {
        switch (rng.next_range(0, 7)) {
            case 0:
                em.mov(x86::Reg::rbx, static_cast<uint64_t>(rng.next_u32()));
                break;
            case 1:
                em.add(x86::Reg::rbx, static_cast<int32_t>(rng.next_range(1, 0x7FFF)));
                break;
            case 2:
                em.xor_(x86::Reg::rbx, static_cast<int32_t>(rng.next_u32()));
                break;
            case 3:
                em.sub(x86::Reg::rbx, static_cast<int32_t>(rng.next_range(1, 0x7FFF)));
                break;
            case 4:
                em.mov(x86::Reg::rax, static_cast<uint64_t>(rng.next_u32()));
                break;
            case 5:
                em.xor_(x86::Reg::rax, x86::Reg::rbx);
                break;
            case 6:
                em.and_(x86::Reg::rbx, static_cast<int32_t>(rng.next_u32()));
                break;
            case 7:
                em.or_(x86::Reg::rbx, static_cast<int32_t>(rng.next_range(0, 0xFF)));
                break;
        }
    }

    // Teardown (balance the stack)
    em.add(x86::Reg::rsp, 0x20);
    em.pop(x86::Reg::rbx);

    auto code = em.build();
    if (!code) return {};
    return std::move(*code);
}

MxResult<DispatcherResult> DispatcherGenerator::generate(
    std::vector<FlattenedBlock>& blocks,
    uint32_t entry_state_id,
    x86::Reg state_var_reg,
    Randomizer& rng,
    const DispatcherConfig& config)
{
    if (blocks.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "DispatcherGenerator: no blocks to flatten"));
    }

    // Sanitize all state IDs to 31-bit
    entry_state_id = MbaTransitionGenerator::sanitize_state_id(entry_state_id);
    for (auto& block : blocks) {
        block.state_id = MbaTransitionGenerator::sanitize_state_id(block.state_id);
        for (auto& s : block.successor_states) {
            s = MbaTransitionGenerator::sanitize_state_id(s);
        }
    }

    // Shuffle block order to break spatial correlation with original layout
    std::ranges::shuffle(blocks, rng.engine());

    // Generate junk block data
    struct JunkEntry {
        uint32_t   fake_state_id;
        ByteBuffer body;
    };
    std::vector<JunkEntry> junk_entries;

    if (config.enable_junk_blocks) {
        std::unordered_set<uint32_t> all_states;
        all_states.insert(entry_state_id);
        for (const auto& b : blocks) {
            all_states.insert(b.state_id);
        }

        const uint32_t junk_count = std::max(
            1u,
            static_cast<uint32_t>(blocks.size() * config.junk_block_ratio));

        for (uint32_t i = 0; i < junk_count; ++i) {
            uint32_t fake_state;
            do {
                fake_state = MbaTransitionGenerator::sanitize_state_id(rng.next_u32());
            } while (fake_state == 0 || all_states.contains(fake_state));
            all_states.insert(fake_state);

            const uint32_t insn_count = rng.next_range(
                config.min_junk_insns, config.max_junk_insns);

            JunkEntry entry;
            entry.fake_state_id = fake_state;
            entry.body = generate_junk_block_body(insn_count, rng);
            junk_entries.push_back(std::move(entry));
        }
    }

    MbaTransitionGenerator mba_gen(arch_);

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

    std::vector<analysis::Label> junk_labels;
    junk_labels.reserve(junk_entries.size());
    for (size_t i = 0; i < junk_entries.size(); ++i) {
        junk_labels.push_back(em.create_label());
    }

    auto exit_label = em.create_label();

    // Interleave real and junk CMP entries for better obfuscation
    // Build a combined entry list and shuffle
    struct CmpEntry {
        uint32_t state_id;
        size_t   index;
        bool     is_junk;
    };
    std::vector<CmpEntry> cmp_entries;
    cmp_entries.reserve(blocks.size() + junk_entries.size());

    for (size_t i = 0; i < blocks.size(); ++i) {
        cmp_entries.push_back({blocks[i].state_id, i, false});
    }
    for (size_t i = 0; i < junk_entries.size(); ++i) {
        cmp_entries.push_back({junk_entries[i].fake_state_id, i, true});
    }
    std::ranges::shuffle(cmp_entries, rng.engine());

    for (const auto& entry : cmp_entries) {
        em.cmp(state_var_reg, static_cast<int32_t>(entry.state_id));
        if (entry.is_junk) {
            em.jcc(analysis::ConditionCode::equal, junk_labels[entry.index]);
        } else {
            em.jcc(analysis::ConditionCode::equal, block_labels[entry.index]);
        }
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
        bp.output_offset = static_cast<uint32_t>(em.current_size())
                         + blocks[i].bogus_prefix_size;
        bp.code_size = static_cast<uint32_t>(blocks[i].code.size())
                     - blocks[i].bogus_prefix_size;
        bp.original_va = blocks[i].original_va;
        placements.push_back(bp);

        em.raw(ByteView{blocks[i].code.data(), blocks[i].code.size()});

        // Determine whether the block body preserves state_var_reg.
        // If it does, we generate a dependency-rich chain that consumes the
        // current state from the register; otherwise we fall back to seeding
        // the chain with a random constant via `mov reg, imm32`.
        const bool state_preserved = block_preserves_state_reg(
            ByteView{blocks[i].code.data(), blocks[i].code.size()}, state_var_reg);

        // State transition
        if (!blocks[i].successor_states.empty()) {
            if (blocks[i].successor_states.size() == 1) {
                const uint32_t next_state = blocks[i].successor_states[0];

                if (config.enable_mba_transitions) {
                    auto mba_code = mba_gen.generate(
                        blocks[i].state_id, next_state, state_var_reg, rng,
                        state_preserved);
                    em.raw(ByteView{mba_code.data(), mba_code.size()});
                } else {
                    em.mov(state_var_reg, static_cast<uint64_t>(next_state));
                }
                em.jmp(dispatcher_label);
            } else {
                // Conditional: two successors
                const uint32_t taken_state = blocks[i].successor_states[0];
                const uint32_t fallthrough_state = blocks[i].successor_states[1];

                auto taken_label = em.create_label();
                auto merge_label = em.create_label();

                if (config.enable_mba_transitions) {
                    // Fallthrough path MBA transition
                    auto ft_code = mba_gen.generate(
                        blocks[i].state_id, fallthrough_state, state_var_reg, rng,
                        state_preserved);

                    em.jcc(blocks[i].branch_cc, taken_label);
                    em.raw(ByteView{ft_code.data(), ft_code.size()});
                    em.jmp(merge_label);

                    em.bind_label(taken_label);
                    auto tk_code = mba_gen.generate(
                        blocks[i].state_id, taken_state, state_var_reg, rng,
                        state_preserved);
                    em.raw(ByteView{tk_code.data(), tk_code.size()});

                    em.bind_label(merge_label);
                } else {
                    em.mov(state_var_reg, static_cast<uint64_t>(fallthrough_state));
                    em.jcc(blocks[i].branch_cc, taken_label);
                    em.jmp(merge_label);

                    em.bind_label(taken_label);
                    em.mov(state_var_reg, static_cast<uint64_t>(taken_state));

                    em.bind_label(merge_label);
                }

                em.jmp(dispatcher_label);
            }
        } else {
            // Terminal block (ret or similar)
            em.jmp(exit_label);
        }
    }

    // ====================================================================
    // Junk block bodies
    // ====================================================================
    for (size_t i = 0; i < junk_entries.size(); ++i) {
        em.bind_label(junk_labels[i]);

        em.raw(ByteView{junk_entries[i].body.data(), junk_entries[i].body.size()});

        // Set random invalid state and jump back to dispatcher
        const uint32_t random_state =
            MbaTransitionGenerator::sanitize_state_id(rng.next_u32());
        em.mov(state_var_reg, static_cast<uint64_t>(random_state));
        em.jmp(dispatcher_label);
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
