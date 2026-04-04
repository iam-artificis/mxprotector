/**
 * @file cfg_builder.cpp
 * @brief [BUILDER] Реализация построителя графа потока управления (CfgBuilder).
 *
 * @details Содержит два алгоритма построения CFG:
 *          1. build() — линейная развёртка (linear sweep): декодирует все инструкции
 *             последовательно и разбивает на блоки по терминаторам.
 *          2. build_function() — рекурсивный спуск (recursive descent): начинает
 *             с адреса функции, следует по целевым адресам переходов, разделяет
 *             блоки при обнаружении новых точек входа.
 *
 * @note Рекурсивный спуск ограничен адресами внутри переданного буфера.
 *       Переходы за пределы буфера игнорируются (внешние вызовы и т.д.).
 */

#include "mxprotector/analysis/cfg.hpp"

#include <algorithm>
#include <format>
#include <queue>
#include <set>
#include <unordered_set>

namespace mx::analysis {

// ============================================================================
// Конструктор / деструктор
// ============================================================================

CfgBuilder::CfgBuilder(std::shared_ptr<IDisassembler> disasm)
    : disasm_(std::move(disasm))
{}

CfgBuilder::~CfgBuilder() = default;

// ============================================================================
// build() — линейная развёртка
// ============================================================================

MxResult<ControlFlowGraph> CfgBuilder::build(ByteView code, Va base_address) {
    if (code.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::cfg_build_error,
            "Пустой буфер кода для построения CFG"));
    }

    next_block_id_ = 0;
    ControlFlowGraph cfg;

    auto insns_result = disasm_->decode_buffer(code, base_address);
    if (!insns_result) {
        return std::unexpected(insns_result.error());
    }

    auto& instructions = *insns_result;
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::cfg_build_error,
            "Не удалось декодировать ни одной инструкции"));
    }

    std::set<Va> block_leaders;
    block_leaders.insert(base_address);

    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& insn = instructions[i];

        if (insn.is_terminator()) {
            if (i + 1 < instructions.size()) {
                block_leaders.insert(instructions[i + 1].address());
            }

            for (const auto target : insn.branch_targets()) {
                if (target >= base_address && target < base_address + code.size()) {
                    block_leaders.insert(target);
                }
            }
        }
    }

    std::unordered_map<Va, uint32_t> leader_to_block_id;
    for (const auto leader : block_leaders) {
        const auto id = allocate_block_id();
        leader_to_block_id[leader] = id;
    }

    std::unordered_map<Va, BasicBlock> blocks_by_start;
    uint32_t current_block_id = leader_to_block_id.at(base_address);
    BasicBlock current_block(current_block_id, base_address);

    for (const auto& insn : instructions) {
        if (auto it = leader_to_block_id.find(insn.address());
            it != leader_to_block_id.end() && it->second != current_block_id)
        {
            if (!current_block.empty()) {
                blocks_by_start.emplace(current_block.start_address(), std::move(current_block));
            }
            current_block_id = it->second;
            current_block = BasicBlock(current_block_id, insn.address());
        }

        current_block.add_instruction(insn);
    }

    if (!current_block.empty()) {
        blocks_by_start.emplace(current_block.start_address(), std::move(current_block));
    }

    for (auto& [start_addr, block] : blocks_by_start) {
        const auto* term = block.terminator();
        if (!term) continue;

        if (term->is_terminator()) {
            // CALL targets are call-graph edges, not CFG edges —
            // the call returns and execution continues at the fallthrough.
            if (!term->is_call()) {
                for (const auto target : term->branch_targets()) {
                    if (auto it = leader_to_block_id.find(target); it != leader_to_block_id.end()) {
                        block.add_successor(it->second);
                        if (auto target_block_it = blocks_by_start.find(target);
                            target_block_it != blocks_by_start.end())
                        {
                            target_block_it->second.add_predecessor(block.id());
                        }
                    }
                }
            }

            // CALL and Jcc both fall through to the next instruction
            if (term->is_conditional_branch() || term->is_call()) {
                const Va fallthrough = term->next_address();
                if (auto it = leader_to_block_id.find(fallthrough); it != leader_to_block_id.end()) {
                    block.add_successor(it->second);
                    if (auto ft_block_it = blocks_by_start.find(fallthrough);
                        ft_block_it != blocks_by_start.end())
                    {
                        ft_block_it->second.add_predecessor(block.id());
                    }
                }
            }
        } else {
            const Va fallthrough = block.end_address();
            if (auto it = leader_to_block_id.find(fallthrough); it != leader_to_block_id.end()) {
                block.add_successor(it->second);
                if (auto ft_block_it = blocks_by_start.find(fallthrough);
                    ft_block_it != blocks_by_start.end())
                {
                    ft_block_it->second.add_predecessor(block.id());
                }
            }
        }
    }

    cfg.set_entry_block_id(leader_to_block_id.at(base_address));
    for (auto& [start_addr, block] : blocks_by_start) {
        cfg.add_block(std::move(block));
    }

    return cfg;
}

// ============================================================================
// build_function() — рекурсивный спуск
// ============================================================================

MxResult<ControlFlowGraph> CfgBuilder::build_function(ByteView code, Va function_start) {
    if (code.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::cfg_build_error,
            "Пустой буфер кода для построения CFG функции"));
    }

    const Va code_end = function_start + code.size();

    next_block_id_ = 0;
    ControlFlowGraph cfg;

    std::unordered_map<Va, std::vector<Instruction>> decoded_cache;
    std::unordered_set<Va> visited_leaders;
    std::queue<Va> worklist;

    worklist.push(function_start);
    visited_leaders.insert(function_start);

    while (!worklist.empty()) {
        const Va leader = worklist.front();
        worklist.pop();

        if (leader < function_start || leader >= code_end) continue;

        const size_t offset = static_cast<size_t>(leader - function_start);
        const ByteView remaining{code.data() + offset, code.size() - offset};

        std::vector<Instruction> block_insns;
        size_t decode_offset = 0;

        while (decode_offset < remaining.size()) {
            const ByteView sub{remaining.data() + decode_offset, remaining.size() - decode_offset};
            const Va addr = leader + decode_offset;

            auto insn_result = disasm_->decode_one(sub, addr);
            if (!insn_result) break;

            auto& insn = *insn_result;
            decode_offset += insn.length();
            block_insns.push_back(std::move(insn));

            const auto& last = block_insns.back();
            if (last.is_terminator()) {
                for (const auto target : last.branch_targets()) {
                    if (target >= function_start && target < code_end) {
                        if (visited_leaders.insert(target).second) {
                            worklist.push(target);
                        }
                    }
                }

                if (last.is_conditional_branch()) {
                    const Va fallthrough = last.next_address();
                    if (fallthrough >= function_start && fallthrough < code_end) {
                        if (visited_leaders.insert(fallthrough).second) {
                            worklist.push(fallthrough);
                        }
                    }
                }
                break;
            }

            const Va next = last.next_address();
            if (visited_leaders.contains(next) && next != leader) {
                if (visited_leaders.insert(next).second) {
                    worklist.push(next);
                }
                break;
            }
        }

        decoded_cache[leader] = std::move(block_insns);
    }

    std::unordered_map<Va, uint32_t> leader_to_id;
    for (const auto& [leader, insns] : decoded_cache) {
        const auto id = allocate_block_id();
        leader_to_id[leader] = id;
    }

    for (auto& [leader, insns] : decoded_cache) {
        const auto block_id = leader_to_id.at(leader);
        BasicBlock block(block_id, leader);

        for (auto& insn : insns) {
            block.add_instruction(std::move(insn));
        }

        cfg.add_block(std::move(block));
    }

    for (auto& [id, block] : cfg.blocks()) {
        const auto* term = block.terminator();
        if (!term) {
            const Va fallthrough = block.end_address();
            if (auto it = leader_to_id.find(fallthrough); it != leader_to_id.end()) {
                block.add_successor(it->second);
                if (auto* succ = const_cast<BasicBlock*>(cfg.block_by_id(it->second))) {
                    succ->add_predecessor(block.id());
                }
            }
            continue;
        }

        if (term->is_return()) continue;

        for (const auto target : term->branch_targets()) {
            if (auto it = leader_to_id.find(target); it != leader_to_id.end()) {
                block.add_successor(it->second);
                if (auto* succ = const_cast<BasicBlock*>(cfg.block_by_id(it->second))) {
                    succ->add_predecessor(block.id());
                }
            }
        }

        if (term->is_conditional_branch()) {
            const Va fallthrough = term->next_address();
            if (auto it = leader_to_id.find(fallthrough); it != leader_to_id.end()) {
                block.add_successor(it->second);
                if (auto* succ = const_cast<BasicBlock*>(cfg.block_by_id(it->second))) {
                    succ->add_predecessor(block.id());
                }
            }
        }
    }

    if (auto it = leader_to_id.find(function_start); it != leader_to_id.end()) {
        cfg.set_entry_block_id(it->second);
    }

    return cfg;
}

} // namespace mx::analysis
