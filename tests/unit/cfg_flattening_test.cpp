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

} // anonymous namespace
