/**
 * @file cfg_flattening_test.cpp
 * @brief [TESTS] Модульные тесты Phase 3: X86CodeEmitter, MBA, InstructionSplitter, CFF.
 *
 * @details Тестирует:
 *          - X86CodeEmitter: генерация инструкций, label resolution, fluent API
 *          - MbaTransform: MBA-тождества (add, sub, xor, or, and), constant obfuscation
 *          - InstructionSplitter: стратегии разбиения (ADD/SUB/XOR/MOV split)
 *          - DispatcherGenerator: назначение state IDs, генерация dispatcher
 *          - BogusFlowGenerator: генерация bogus-блоков
 *          - CfgFlattener: полный цикл расплющивания CFG
 */

#include <gtest/gtest.h>
#include <cstring>
#include <fstream>
#include <unordered_set>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/basic_block.hpp"
#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/instruction_splitter.hpp"
#include "mxprotector/protection/obfuscation/mba_transform.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/cfg/dispatcher_gen.hpp"
#include "mxprotector/protection/cfg/bogus_flow.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"
#include "mxprotector/protection/cfg/map_parser.hpp"

namespace {

mx::analysis::Instruction make_insn(
    mx::Va address,
    mx::ByteBuffer raw_bytes,
    std::string mnemonic,
    std::string operands = "",
    bool is_branch = false,
    bool is_cond_branch = false,
    bool is_call = false,
    bool is_return = false,
    bool is_uncond_jmp = false,
    std::vector<mx::Va> targets = {})
{
    const auto length = static_cast<uint8_t>(raw_bytes.size());
    return mx::analysis::Instruction(
        address, length, std::move(raw_bytes),
        std::move(mnemonic), std::move(operands),
        is_branch, is_cond_branch, is_call, is_return, is_uncond_jmp,
        std::move(targets));
}

// ============================================================================
// X86CodeEmitter tests
// ============================================================================

TEST(X86CodeEmitter, EmitMov64RegImm) {
    mx::analysis::X86CodeEmitter em(true);
    em.mov(mx::x86::Reg::rax, 0x12345678ULL);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 7u);
}

TEST(X86CodeEmitter, EmitMovRegReg) {
    mx::analysis::X86CodeEmitter em(true);
    em.mov(mx::x86::Reg::rcx, mx::x86::Reg::rdx);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 3u);
}

TEST(X86CodeEmitter, EmitAddSubImm) {
    mx::analysis::X86CodeEmitter em(true);
    em.add(mx::x86::Reg::rax, 42);
    em.sub(mx::x86::Reg::rbx, 10);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 6u);
}

TEST(X86CodeEmitter, EmitXorAndOr) {
    mx::analysis::X86CodeEmitter em(true);
    em.xor_(mx::x86::Reg::rax, mx::x86::Reg::rcx);
    em.and_(mx::x86::Reg::rdx, mx::x86::Reg::rsi);
    em.or_(mx::x86::Reg::rdi, 0xFF);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 6u);
}

TEST(X86CodeEmitter, EmitPushPopRet) {
    mx::analysis::X86CodeEmitter em(true);
    em.push(mx::x86::Reg::rbp);
    em.mov(mx::x86::Reg::rbp, mx::x86::Reg::rsp);
    em.pop(mx::x86::Reg::rbp);
    em.ret();
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 6u);
}

TEST(X86CodeEmitter, LabelResolution) {
    mx::analysis::X86CodeEmitter em(true);
    auto loop_label = em.create_label();
    auto exit_label = em.create_label();

    em.bind_label(loop_label);
    em.add(mx::x86::Reg::rax, 1);
    em.cmp(mx::x86::Reg::rax, 10);
    em.jcc(mx::analysis::ConditionCode::less, loop_label);
    em.bind_label(exit_label);
    em.ret();

    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GT(code->size(), 10u);
}

TEST(X86CodeEmitter, UnresolvedLabelFails) {
    mx::analysis::X86CodeEmitter em(true);
    auto label = em.create_label();
    em.jmp(label);

    auto code = em.build();
    EXPECT_FALSE(code.has_value());
}

TEST(X86CodeEmitter, EmitExtendedRegisters) {
    mx::analysis::X86CodeEmitter em(true);
    em.mov(mx::x86::Reg::r8, 0x42ULL);
    em.add(mx::x86::Reg::r12, mx::x86::Reg::r15);
    em.push(mx::x86::Reg::r9);
    em.pop(mx::x86::Reg::r10);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 10u);
}

TEST(X86CodeEmitter, EmitShifts) {
    mx::analysis::X86CodeEmitter em(true);
    em.shl(mx::x86::Reg::rax, 1);
    em.shr(mx::x86::Reg::rcx, 4);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 4u);
}

TEST(X86CodeEmitter, EmitNotNeg) {
    mx::analysis::X86CodeEmitter em(true);
    em.not_(mx::x86::Reg::rax);
    em.neg(mx::x86::Reg::rbx);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 6u);
}

TEST(X86CodeEmitter, EmitImul) {
    mx::analysis::X86CodeEmitter em(true);
    em.imul(mx::x86::Reg::rax, mx::x86::Reg::rcx, 7);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 4u);
}

TEST(X86CodeEmitter, ClearAndReuse) {
    mx::analysis::X86CodeEmitter em(true);
    em.nop(5);
    em.clear();
    em.ret();
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_EQ(code->size(), 1u);
    EXPECT_EQ((*code)[0], 0xC3);
}

TEST(X86CodeEmitter, FluentChaining) {
    mx::analysis::X86CodeEmitter em(true);
    em.push(mx::x86::Reg::rbp)
      .mov(mx::x86::Reg::rbp, mx::x86::Reg::rsp)
      .sub(mx::x86::Reg::rsp, 0x20)
      .xor_(mx::x86::Reg::rax, mx::x86::Reg::rax)
      .add(mx::x86::Reg::rsp, 0x20)
      .pop(mx::x86::Reg::rbp)
      .ret();
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GT(code->size(), 10u);
}

// ============================================================================
// MbaTransform tests
// ============================================================================

TEST(MbaTransform, TransformAddProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.transform_add(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
    EXPECT_GE(result->instruction_count, 4u);
}

TEST(MbaTransform, TransformSubProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.transform_sub(
        mx::x86::Reg::rbx, mx::x86::Reg::rsi, mx::x86::Reg::rdi, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
}

TEST(MbaTransform, TransformXorProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.transform_xor(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
}

TEST(MbaTransform, TransformOrProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.transform_or(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
}

TEST(MbaTransform, TransformAndProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.transform_and(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
}

TEST(MbaTransform, DepthIncreasesCodeSize) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng1(42);
    mx::Randomizer rng2(42);

    auto depth1 = mba.transform_add(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng1, 1);
    auto depth2 = mba.transform_add(
        mx::x86::Reg::rax, mx::x86::Reg::rcx, mx::x86::Reg::rdx, rng2, 2);

    ASSERT_TRUE(depth1.has_value());
    ASSERT_TRUE(depth2.has_value());
    EXPECT_LT(depth1->code.size(), depth2->code.size());
}

TEST(MbaTransform, ObfuscateConstantProducesCode) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = mba.obfuscate_constant(mx::x86::Reg::rax, 0xDEADBEEF, rng, 4);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->code.empty());
    EXPECT_GE(result->instruction_count, 3u);
}

TEST(MbaTransform, ObfuscateConstantPolymorphic) {
    mx::MbaTransform mba(mx::Architecture::x64);
    mx::Randomizer rng1(100);
    mx::Randomizer rng2(200);

    auto r1 = mba.obfuscate_constant(mx::x86::Reg::rax, 0x12345678, rng1);
    auto r2 = mba.obfuscate_constant(mx::x86::Reg::rax, 0x12345678, rng2);

    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());
    EXPECT_NE(r1->code, r2->code);
}

// ============================================================================
// InstructionSplitter tests
// ============================================================================

TEST(InstructionSplitter, CreateDefault) {
    auto splitter = mx::InstructionSplitter::create_default();
    EXPECT_GE(splitter.strategy_count(), 4u);
}

TEST(InstructionSplitter, CanSplitAddImm) {
    auto splitter = mx::InstructionSplitter::create_default();
    // ADD ecx, 5 : 83 C1 05
    auto insn = make_insn(0x1000, {0x83, 0xC1, 0x05}, "add", "ecx, 5");
    EXPECT_TRUE(splitter.can_split(insn));
}

TEST(InstructionSplitter, CanSplitSubImm) {
    auto splitter = mx::InstructionSplitter::create_default();
    // SUB ecx, 10 : 83 E9 0A
    auto insn = make_insn(0x1000, {0x83, 0xE9, 0x0A}, "sub", "ecx, 10");
    EXPECT_TRUE(splitter.can_split(insn));
}

TEST(InstructionSplitter, CanSplitMovImm32) {
    auto splitter = mx::InstructionSplitter::create_default();
    // MOV eax, 0x12345678 : B8 78 56 34 12
    auto insn = make_insn(0x1000, {0xB8, 0x78, 0x56, 0x34, 0x12}, "mov", "eax, 0x12345678");
    EXPECT_TRUE(splitter.can_split(insn));
}

TEST(InstructionSplitter, CannotSplitBranch) {
    auto splitter = mx::InstructionSplitter::create_default();
    auto insn = make_insn(0x1000, {0xEB, 0x05}, "jmp", "0x1007", true);
    EXPECT_FALSE(splitter.can_split(insn));
}

TEST(InstructionSplitter, SplitAddProducesCode) {
    auto splitter = mx::InstructionSplitter::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x83, 0xC1, 0x05}, "add", "ecx, 5");
    auto result = splitter.split(insn, rng, true);

    EXPECT_FALSE(result.code.empty());
    EXPECT_GE(result.instruction_count, 1u);
}

TEST(InstructionSplitter, SplitMovProducesCode) {
    auto splitter = mx::InstructionSplitter::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0xB8, 0x78, 0x56, 0x34, 0x12}, "mov", "eax, 0x12345678");
    auto result = splitter.split(insn, rng, true);

    EXPECT_FALSE(result.code.empty());
    EXPECT_GE(result.instruction_count, 1u);
}

TEST(InstructionSplitter, SplitIsPolymorphic) {
    auto splitter = mx::InstructionSplitter::create_default();
    mx::Randomizer rng1(100);
    mx::Randomizer rng2(200);

    auto insn = make_insn(0x1000, {0xB8, 0x78, 0x56, 0x34, 0x12}, "mov", "eax, 0x12345678");
    auto r1 = splitter.split(insn, rng1, true);
    auto r2 = splitter.split(insn, rng2, true);

    if (!r1.code.empty() && !r2.code.empty()) {
        EXPECT_NE(r1.code, r2.code)
            << "Split results should differ with different seeds";
    }
}

// ============================================================================
// DispatcherGenerator tests
// ============================================================================

TEST(DispatcherGenerator, AssignStateIds) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<uint32_t> block_ids = {0, 1, 2, 3, 4};
    auto mapping = gen.assign_state_ids(block_ids, rng);

    EXPECT_EQ(mapping.size(), 5u);

    std::unordered_set<uint32_t> states;
    for (const auto& [id, state] : mapping) {
        states.insert(state);
    }
    EXPECT_EQ(states.size(), 5u);
}

TEST(DispatcherGenerator, GenerateProducesCode) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<mx::FlattenedBlock> blocks;

    mx::FlattenedBlock b0;
    b0.original_block_id = 0;
    b0.state_id = 100;
    b0.code = {0x90};
    b0.successor_states = {200};
    b0.original_va = 0x140001000;
    blocks.push_back(std::move(b0));

    mx::FlattenedBlock b1;
    b1.original_block_id = 1;
    b1.state_id = 200;
    b1.code = {0xC3};
    b1.original_va = 0x140001001;
    blocks.push_back(std::move(b1));

    auto result = gen.generate(blocks, 100, mx::x86::Reg::r10, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->full_function.empty());
    EXPECT_GT(result->total_size, 10u);
}

TEST(DispatcherGenerator, BlockPlacementsTracked) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<mx::FlattenedBlock> blocks;

    mx::FlattenedBlock b0;
    b0.original_block_id = 0;
    b0.state_id = 100;
    b0.code = {0x48, 0x89, 0xE5};
    b0.successor_states = {200};
    b0.original_va = 0x140001000;
    blocks.push_back(std::move(b0));

    mx::FlattenedBlock b1;
    b1.original_block_id = 1;
    b1.state_id = 200;
    b1.code = {0x5D, 0xC3};
    b1.original_va = 0x140001003;
    blocks.push_back(std::move(b1));

    auto result = gen.generate(blocks, 100, mx::x86::Reg::r10, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->block_placements.size(), 2u);

    for (const auto& bp : result->block_placements) {
        EXPECT_GT(bp.code_size, 0u);
        EXPECT_NE(bp.original_va, 0u);
        EXPECT_LT(bp.output_offset + bp.code_size,
                   result->full_function.size() + 1);
    }
}

TEST(CffTrampoline, JmpRel32Encoding) {
    mx::Rva source_rva = 0x1000;
    mx::Rva target_rva = 0x5000;
    auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) - static_cast<int64_t>(source_rva) - 5);

    EXPECT_EQ(rel32, 0x3FFB);

    uint8_t jmp_code[5] = { 0xE9 };
    std::memcpy(jmp_code + 1, &rel32, 4);
    EXPECT_EQ(jmp_code[0], 0xE9);

    int32_t decoded_rel32 = 0;
    std::memcpy(&decoded_rel32, jmp_code + 1, 4);
    mx::Rva decoded_target = source_rva + 5 + decoded_rel32;
    EXPECT_EQ(decoded_target, target_rva);
}

TEST(CffTrampoline, CallRel32Fixup) {
    mx::Rva original_block_rva = 0x1000;
    mx::Rva new_block_rva = 0x5000;
    auto delta = static_cast<int64_t>(new_block_rva) - static_cast<int64_t>(original_block_rva);

    int32_t original_rel32 = 0x2000;
    auto new_rel32 = static_cast<int32_t>(original_rel32 - delta);

    mx::Va original_call_va = 0x140000000ULL + original_block_rva;
    mx::Va orig_target = original_call_va + 5 + original_rel32;
    mx::Va new_call_va = 0x140000000ULL + new_block_rva;
    mx::Va new_target = new_call_va + 5 + new_rel32;

    EXPECT_EQ(orig_target, new_target);
}

TEST(CffTrampoline, SectionCreationLayout) {
    constexpr uint32_t func_alignment = 16;
    mx::ByteBuffer section_data;

    mx::ByteBuffer func1(50, 0x90);
    mx::ByteBuffer func2(80, 0x90);

    uint32_t offset1 = 0;
    section_data.insert(section_data.end(), func1.begin(), func1.end());
    while (section_data.size() % func_alignment != 0)
        section_data.push_back(0xCC);

    uint32_t offset2 = static_cast<uint32_t>(section_data.size());
    section_data.insert(section_data.end(), func2.begin(), func2.end());
    while (section_data.size() % func_alignment != 0)
        section_data.push_back(0xCC);

    EXPECT_EQ(offset1, 0u);
    EXPECT_EQ(offset2 % func_alignment, 0u);
    EXPECT_GE(section_data.size(), func1.size() + func2.size());
}

TEST(DispatcherGenerator, EmptyBlocksFails) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<mx::FlattenedBlock> blocks;
    auto result = gen.generate(blocks, 0, mx::x86::Reg::r10, rng);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// BogusFlowGenerator tests
// ============================================================================

TEST(BogusFlowGenerator, GenerateProducesBogus) {
    mx::BogusFlowGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto bogus = gen.generate(16, rng);
    EXPECT_GT(bogus.total_size, 0u);
    EXPECT_FALSE(bogus.predicate_code.empty());
    EXPECT_FALSE(bogus.junk_code.empty());
}

TEST(BogusFlowGenerator, GenerateForFunction) {
    mx::BogusFlowGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto bogus_blocks = gen.generate_for_function(10, 1.0, rng);
    EXPECT_EQ(bogus_blocks.size(), 10u);

    uint32_t non_empty = 0;
    for (const auto& b : bogus_blocks) {
        if (b.total_size > 0) ++non_empty;
    }
    EXPECT_EQ(non_empty, 10u);
}

TEST(BogusFlowGenerator, ZeroProbability) {
    mx::BogusFlowGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto bogus_blocks = gen.generate_for_function(5, 0.0, rng);
    EXPECT_EQ(bogus_blocks.size(), 5u);

    for (const auto& b : bogus_blocks) {
        EXPECT_EQ(b.total_size, 0u);
    }
}

// ============================================================================
// CfgFlattener tests
// ============================================================================

TEST(CfgFlattener, FlattenSimpleCfg) {
    // Build a simple CFG: block0 → block1 → ret
    mx::analysis::ControlFlowGraph cfg;

    mx::analysis::BasicBlock b0(0, 0x1000);
    b0.add_instruction(make_insn(0x1000, {0x90}, "nop"));
    b0.add_instruction(make_insn(0x1001, {0xEB, 0x00}, "jmp", "0x1003",
        true, false, false, false, true, {0x1003}));
    b0.add_successor(1);

    mx::analysis::BasicBlock b1(1, 0x1003);
    b1.add_instruction(make_insn(0x1003, {0xC3}, "ret", "",
        true, false, false, true));
    b1.add_predecessor(0);

    cfg.add_block(std::move(b0));
    cfg.add_block(std::move(b1));
    cfg.set_entry_block_id(0);

    mx::ByteBuffer original_code = {0x90, 0xEB, 0x00, 0xC3};
    mx::Randomizer rng(42);
    mx::FlatteningConfig flat_config;
    flat_config.enable_bogus_flow = false;
    flat_config.enable_mba_transitions = false;

    mx::CfgFlattener flattener(mx::Architecture::x64, flat_config);
    auto result = flattener.flatten(cfg, mx::ByteView{original_code}, 0x1000, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->flattened_code.empty());
    EXPECT_EQ(result->original_block_count, 2u);
    EXPECT_GT(result->total_size, 0u);
}

TEST(CfgFlattener, FlattenEmptyCfgFails) {
    mx::analysis::ControlFlowGraph cfg;
    mx::ByteBuffer code;
    mx::Randomizer rng(42);
    mx::FlatteningConfig flat_config;

    mx::CfgFlattener flattener(mx::Architecture::x64, flat_config);
    auto result = flattener.flatten(cfg, mx::ByteView{code}, 0, rng);

    EXPECT_FALSE(result.has_value());
}

TEST(CfgFlattener, FlattenWithBogusFlow) {
    mx::analysis::ControlFlowGraph cfg;

    mx::analysis::BasicBlock b0(0, 0x1000);
    b0.add_instruction(make_insn(0x1000, {0x90}, "nop"));
    b0.add_instruction(make_insn(0x1001, {0xEB, 0x01}, "jmp", "0x1004",
        true, false, false, false, true, {0x1004}));
    b0.add_successor(1);

    mx::analysis::BasicBlock b1(1, 0x1004);
    b1.add_instruction(make_insn(0x1004, {0x90}, "nop"));
    b1.add_instruction(make_insn(0x1005, {0xC3}, "ret", "",
        true, false, false, true));
    b1.add_predecessor(0);

    cfg.add_block(std::move(b0));
    cfg.add_block(std::move(b1));
    cfg.set_entry_block_id(0);

    mx::ByteBuffer original_code = {0x90, 0xEB, 0x01, 0x90, 0x90, 0xC3};
    mx::Randomizer rng(42);
    mx::FlatteningConfig flat_config;
    flat_config.enable_bogus_flow = true;
    flat_config.bogus_probability = 1.0;
    flat_config.enable_mba_transitions = true;

    mx::CfgFlattener flattener(mx::Architecture::x64, flat_config);
    auto result = flattener.flatten(cfg, mx::ByteView{original_code}, 0x1000, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->bogus_blocks_added, 0u);
    EXPECT_GT(result->flattened_code.size(), original_code.size());
}

// ============================================================================
// MbaTransitionGenerator tests
// ============================================================================

TEST(MbaTransitionGenerator, ProducesNonEmptyCode) {
    mx::MbaTransitionGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto code = gen.generate(0x100, 0x200, mx::x86::Reg::r10, rng);
    EXPECT_FALSE(code.empty());
    EXPECT_GE(code.size(), 10u);
}

namespace {

/// Simulate the MBA chain in software. `initial` is the starting value of
/// state_reg before the chain runs. Returns the final value.
///
/// Decodes the same subset of x86 instructions `MbaTransitionGenerator` emits:
///   MOV r32, imm32          B8+rd id
///   ADD r32, imm32          81 /0 id
///   SUB r32, imm32          81 /5 id
///   XOR r32, imm32          81 /6 id
///   NOT r32                 F7 /2
///   ROL r32, imm8 / 1       C1 /0 / D1 /0
///   ROR r32, imm8 / 1       C1 /1 / D1 /1
[[nodiscard]] uint32_t simulate_mba_chain(mx::ByteView code, uint32_t initial) {
    uint32_t value = initial;
    size_t offset = 0;

    while (offset < code.size()) {
        if (code[offset] == 0x41) ++offset;  // REX.B prefix — skip
        if (offset >= code.size()) break;

        const uint8_t opcode = code[offset++];

        if (opcode >= 0xB8 && opcode <= 0xBF) {
            // MOV r32, imm32
            if (offset + 4 > code.size()) break;
            uint32_t imm = 0;
            std::memcpy(&imm, code.data() + offset, 4);
            offset += 4;
            value = imm;
        } else if (opcode == 0x81 && offset < code.size()) {
            const uint8_t modrm = code[offset++];
            const uint8_t reg_field = (modrm >> 3) & 0x07;
            if (offset + 4 > code.size()) break;
            uint32_t imm = 0;
            std::memcpy(&imm, code.data() + offset, 4);
            offset += 4;
            switch (reg_field) {
                case 0: value += imm; break;
                case 5: value -= imm; break;
                case 6: value ^= imm; break;
                default: break;
            }
        } else if (opcode == 0xF7 && offset < code.size()) {
            const uint8_t modrm = code[offset++];
            const uint8_t reg_field = (modrm >> 3) & 0x07;
            if (reg_field == 2) value = ~value;
        } else if (opcode == 0xC1 && offset + 1 < code.size()) {
            const uint8_t modrm = code[offset++];
            const uint8_t reg_field = (modrm >> 3) & 0x07;
            const uint8_t count = code[offset++] & 31;
            if (count == 0) continue;
            if (reg_field == 0) value = (value << count) | (value >> (32 - count));
            else if (reg_field == 1) value = (value >> count) | (value << (32 - count));
        } else if (opcode == 0xD1 && offset < code.size()) {
            const uint8_t modrm = code[offset++];
            const uint8_t reg_field = (modrm >> 3) & 0x07;
            if (reg_field == 0) value = (value << 1) | (value >> 31);
            else if (reg_field == 1) value = (value >> 1) | (value << 31);
        } else {
            break;  // unknown instruction — bail
        }
    }

    return value;
}

} // namespace

// When state_preserved == true, the generator assumes state_reg already holds
// `current` at entry to the chain and omits the initialising MOV. The chain
// transforms `current → target` directly on the register.
TEST(MbaTransitionGenerator, SimulationCorrectness_StatePreserved) {
    mx::MbaTransitionGenerator gen(mx::Architecture::x64);

    for (uint64_t seed = 0; seed < 50; ++seed) {
        mx::Randomizer rng(seed);
        const uint32_t current = mx::MbaTransitionGenerator::sanitize_state_id(rng.next_u32());
        const uint32_t target  = mx::MbaTransitionGenerator::sanitize_state_id(rng.next_u32());

        auto code = gen.generate(current, target, mx::x86::Reg::r10, rng, /*state_preserved=*/true);
        ASSERT_FALSE(code.empty()) << "Empty code for seed=" << seed;

        const uint32_t value = simulate_mba_chain(
            mx::ByteView{code.data(), code.size()}, current);

        EXPECT_EQ(value, target)
            << "MBA chain failed for seed=" << seed
            << std::hex << " current=0x" << current
            << " target=0x" << target
            << " got=0x" << value;
    }
}

// When state_preserved == false, the generator loads a random seed via
// `MOV r32, imm32` first (because the block may have clobbered state_reg)
// and then applies the chain. The simulator starts at garbage; the MOV is
// the very first thing that sets a defined value.
TEST(MbaTransitionGenerator, SimulationCorrectness_StateNotPreserved) {
    mx::MbaTransitionGenerator gen(mx::Architecture::x64);

    for (uint64_t seed = 0; seed < 50; ++seed) {
        mx::Randomizer rng(seed);
        const uint32_t current = mx::MbaTransitionGenerator::sanitize_state_id(rng.next_u32());
        const uint32_t target  = mx::MbaTransitionGenerator::sanitize_state_id(rng.next_u32());

        auto code = gen.generate(current, target, mx::x86::Reg::r10, rng, /*state_preserved=*/false);
        ASSERT_FALSE(code.empty()) << "Empty code for seed=" << seed;

        const uint32_t value = simulate_mba_chain(
            mx::ByteView{code.data(), code.size()}, 0xDEADBEEF /*garbage*/);

        EXPECT_EQ(value, target)
            << "MBA chain failed for seed=" << seed
            << std::hex << " current=0x" << current
            << " target=0x" << target
            << " got=0x" << value;
    }
}

TEST(MbaTransitionGenerator, PolymorphicOutput) {
    mx::MbaTransitionGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng1(100);
    mx::Randomizer rng2(200);

    auto code1 = gen.generate(0x1000, 0x2000, mx::x86::Reg::r10, rng1);
    auto code2 = gen.generate(0x1000, 0x2000, mx::x86::Reg::r10, rng2);

    EXPECT_NE(code1, code2)
        << "Different seeds should produce different MBA chains";
}

TEST(MbaTransitionGenerator, SanitizeStateId) {
    EXPECT_EQ(mx::MbaTransitionGenerator::sanitize_state_id(0x80000001), 0x00000001u);
    EXPECT_EQ(mx::MbaTransitionGenerator::sanitize_state_id(0xFFFFFFFF), 0x7FFFFFFFu);
    EXPECT_EQ(mx::MbaTransitionGenerator::sanitize_state_id(0x12345678), 0x12345678u);
}

TEST(MbaTransitionGenerator, ChainLengthAtLeast6) {
    mx::MbaTransitionGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto code = gen.generate(0x100, 0x200, mx::x86::Reg::r10, rng);
    // At minimum: 1 initial XOR (6-7 bytes) + 5 chain ops (4-7 bytes each)
    EXPECT_GE(code.size(), 20u);
}

// ============================================================================
// X86CodeEmitter ROL/ROR tests
// ============================================================================

TEST(X86CodeEmitter, EmitRolRor) {
    mx::analysis::X86CodeEmitter em(true);
    em.rol(mx::x86::Reg::rax, 3);
    em.ror(mx::x86::Reg::rcx, 7);
    em.rol(mx::x86::Reg::r10, 1);
    em.ror(mx::x86::Reg::r15, 13);
    auto code = em.build();
    ASSERT_TRUE(code.has_value());
    EXPECT_GE(code->size(), 8u);
}

// ============================================================================
// Dispatcher with junk blocks tests
// ============================================================================

TEST(DispatcherGenerator, GenerateWithJunkBlocks) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<mx::FlattenedBlock> blocks;

    mx::FlattenedBlock b0;
    b0.original_block_id = 0;
    b0.state_id = 100;
    b0.code = {0x90};
    b0.successor_states = {200};
    b0.original_va = 0x140001000;
    blocks.push_back(std::move(b0));

    mx::FlattenedBlock b1;
    b1.original_block_id = 1;
    b1.state_id = 200;
    b1.code = {0xC3};
    b1.original_va = 0x140001001;
    blocks.push_back(std::move(b1));

    mx::DispatcherConfig config;
    config.enable_mba_transitions = true;
    config.enable_junk_blocks = true;
    config.junk_block_ratio = 0.5;

    auto result = gen.generate(blocks, 100, mx::x86::Reg::r10, rng, config);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->full_function.empty());
    // With junk blocks and MBA, the code should be significantly larger
    EXPECT_GT(result->total_size, 50u);
}

TEST(DispatcherGenerator, GenerateWithMbaTransitions) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<mx::FlattenedBlock> blocks;

    mx::FlattenedBlock b0;
    b0.original_block_id = 0;
    b0.state_id = 0x1000;
    b0.code = {0x48, 0x89, 0xE5};
    b0.successor_states = {0x2000};
    b0.original_va = 0x140001000;
    blocks.push_back(std::move(b0));

    mx::FlattenedBlock b1;
    b1.original_block_id = 1;
    b1.state_id = 0x2000;
    b1.code = {0x5D, 0xC3};
    b1.original_va = 0x140001003;
    blocks.push_back(std::move(b1));

    mx::DispatcherConfig config;
    config.enable_mba_transitions = true;
    config.enable_junk_blocks = false;

    auto result_mba = gen.generate(blocks, 0x1000, mx::x86::Reg::r10, rng, config);
    ASSERT_TRUE(result_mba.has_value());

    // Compare with non-MBA version
    mx::Randomizer rng2(42);
    std::vector<mx::FlattenedBlock> blocks2;
    blocks2.push_back(mx::FlattenedBlock{0, 0x1000, {0x48, 0x89, 0xE5}, {0x2000}, 0x140001000});
    blocks2.push_back(mx::FlattenedBlock{1, 0x2000, {0x5D, 0xC3}, {}, 0x140001003});

    mx::DispatcherConfig config_no_mba;
    config_no_mba.enable_mba_transitions = false;
    config_no_mba.enable_junk_blocks = false;

    auto result_plain = gen.generate(blocks2, 0x1000, mx::x86::Reg::r10, rng2, config_no_mba);
    ASSERT_TRUE(result_plain.has_value());

    // MBA version should be significantly larger
    EXPECT_GT(result_mba->total_size, result_plain->total_size);
}

TEST(DispatcherGenerator, StateIdsSanitized) {
    mx::DispatcherGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    std::vector<uint32_t> ids = {0, 1, 2, 3, 4};
    auto mapping = gen.assign_state_ids(ids, rng);

    for (const auto& [id, state] : mapping) {
        EXPECT_LT(state, 0x80000000u)
            << "State ID should be < 0x80000000 for sign-extension compatibility";
        EXPECT_NE(state, 0u)
            << "State ID should not be 0";
    }
}

// ============================================================================
// MapParser tests
// ============================================================================

TEST(MapParser, ParseValidMapFile) {
    // Create a temporary .map file
    const std::string map_content =
        " test_target\n"
        "\n"
        " Timestamp is 6823a1b8 (Wed May 14 02:21:28 2025)\n"
        "\n"
        " Preferred load address is 0000000140000000\n"
        "\n"
        " Start         Length     Name                   Class\n"
        " 0001:00000000 000082fcH .text$mn                CODE\n"
        " 0002:00000000 00000428H .rdata                  DATA\n"
        "\n"
        "  Address         Publics by Value              Rva+Base               Lib:Object\n"
        "\n"
        " 0001:00000000       compute_fibonacci          0000000140001000     test_target.obj\n"
        " 0001:00000040       compute_hash               0000000140001040     test_target.obj\n"
        " 0001:00000080       do_arithmetic_work         0000000140001080     test_target.obj\n"
        " 0001:00000100       main                       0000000140001100     test_target.obj\n"
        " 0001:00001000       _acrt_init                 0000000140002000     libucrt.lib:init.obj\n"
        " 0001:00001050       __scrt_startup             0000000140002050     libvcruntime.lib:startup.obj\n"
        "\n";

    const auto tmp_path = std::filesystem::temp_directory_path() / "test_mxp.map";
    {
        std::ofstream f(tmp_path);
        f << map_content;
    }

    auto result = mx::MapParser::parse(tmp_path);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->image_base, 0x140000000ULL);
    EXPECT_GE(result->all_functions.size(), 4u);

    // Check that user functions are not marked as library
    uint32_t user_count = 0;
    uint32_t lib_count = 0;
    for (const auto& f : result->all_functions) {
        if (f.is_library) ++lib_count;
        else ++user_count;
    }
    EXPECT_GE(user_count, 4u);
    EXPECT_GE(lib_count, 2u);

    // Verify function sizes were computed
    for (size_t i = 0; i + 1 < result->all_functions.size(); ++i) {
        EXPECT_GT(result->all_functions[i].size, 0u);
    }

    std::filesystem::remove(tmp_path);
}

TEST(MapParser, FilterExcludesLibraryFunctions) {
    std::vector<mx::MapFunctionEntry> funcs;

    mx::MapFunctionEntry user_func;
    user_func.name = "compute_fibonacci";
    user_func.rva = 0x1000;
    user_func.size = 64;
    user_func.object_file = "test_target.obj";
    user_func.is_library = false;
    funcs.push_back(user_func);

    mx::MapFunctionEntry lib_func;
    lib_func.name = "_acrt_init";
    lib_func.rva = 0x2000;
    lib_func.size = 128;
    lib_func.object_file = "libucrt.lib:init.obj";
    lib_func.is_library = true;
    funcs.push_back(lib_func);

    mx::ByteBuffer fake_code(0x3000, 0x90);
    auto candidates = mx::MapParser::filter_candidates(
        funcs, mx::ByteView{fake_code}, 0x1000, 0x3000);

    EXPECT_EQ(candidates.size(), 1u);
    EXPECT_EQ(candidates[0].name, "compute_fibonacci");
}

TEST(MapParser, FilterExcludesTooSmallFunctions) {
    std::vector<mx::MapFunctionEntry> funcs;

    mx::MapFunctionEntry small_func;
    small_func.name = "tiny_func";
    small_func.rva = 0x1000;
    small_func.size = 16;
    small_func.is_library = false;
    funcs.push_back(small_func);

    mx::ByteBuffer fake_code(0x2000, 0x90);
    auto candidates = mx::MapParser::filter_candidates(
        funcs, mx::ByteView{fake_code}, 0x1000, 0x2000);

    EXPECT_TRUE(candidates.empty());
}

TEST(MapParser, FilterExcludesThunks) {
    std::vector<mx::MapFunctionEntry> funcs;

    mx::MapFunctionEntry thunk_func;
    thunk_func.name = "FlsSetValue";
    thunk_func.rva = 0x1000;
    thunk_func.size = 64;
    thunk_func.is_library = false;
    funcs.push_back(thunk_func);

    // Build code that starts with jmp [rip+disp32] thunk: 48 FF 25 ...
    mx::ByteBuffer fake_code(0x2000, 0xCC);
    fake_code[0] = 0x48;
    fake_code[1] = 0xFF;
    fake_code[2] = 0x25;

    auto candidates = mx::MapParser::filter_candidates(
        funcs, mx::ByteView{fake_code}, 0x1000, 0x2000);

    EXPECT_TRUE(candidates.empty());
}

TEST(MapParser, FilterExcludesTooLargeFunctions) {
    std::vector<mx::MapFunctionEntry> funcs;

    mx::MapFunctionEntry large_func;
    large_func.name = "huge_function";
    large_func.rva = 0x1000;
    large_func.size = 10000;
    large_func.is_library = false;
    funcs.push_back(large_func);

    mx::ByteBuffer fake_code(0x5000, 0x90);
    auto candidates = mx::MapParser::filter_candidates(
        funcs, mx::ByteView{fake_code}, 0x1000, 0x5000);

    EXPECT_TRUE(candidates.empty());
}

// ============================================================================
// Full CFF pipeline with all enhancements test
// ============================================================================

TEST(CfgFlattener, FlattenWithMbaAndJunkBlocks) {
    mx::analysis::ControlFlowGraph cfg;

    mx::analysis::BasicBlock b0(0, 0x1000);
    b0.add_instruction(make_insn(0x1000, {0x90}, "nop"));
    b0.add_instruction(make_insn(0x1001, {0xEB, 0x00}, "jmp", "0x1003",
        true, false, false, false, true, {0x1003}));
    b0.add_successor(1);

    mx::analysis::BasicBlock b1(1, 0x1003);
    b1.add_instruction(make_insn(0x1003, {0x90}, "nop"));
    b1.add_instruction(make_insn(0x1004, {0xEB, 0x00}, "jmp", "0x1006",
        true, false, false, false, true, {0x1006}));
    b1.add_successor(2);
    b1.add_predecessor(0);

    mx::analysis::BasicBlock b2(2, 0x1006);
    b2.add_instruction(make_insn(0x1006, {0xC3}, "ret", "",
        true, false, false, true));
    b2.add_predecessor(1);

    cfg.add_block(std::move(b0));
    cfg.add_block(std::move(b1));
    cfg.add_block(std::move(b2));
    cfg.set_entry_block_id(0);

    mx::ByteBuffer original_code = {0x90, 0xEB, 0x00, 0x90, 0xEB, 0x00, 0xC3};
    mx::Randomizer rng(42);
    mx::FlatteningConfig flat_config;
    flat_config.enable_bogus_flow      = true;
    flat_config.bogus_probability      = 0.5;
    flat_config.enable_mba_transitions = true;
    flat_config.enable_junk_blocks     = true;
    flat_config.junk_block_ratio       = 0.3;

    mx::CfgFlattener flattener(mx::Architecture::x64, flat_config);
    auto result = flattener.flatten(cfg, mx::ByteView{original_code}, 0x1000, rng);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->flattened_code.empty());
    EXPECT_EQ(result->original_block_count, 3u);
    // With MBA + junk + bogus, code should be much larger than original
    EXPECT_GT(result->flattened_code.size(), original_code.size() * 5);
}

} // anonymous namespace
