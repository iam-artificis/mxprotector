/**
 * @file mutation_engine_test.cpp
 * @brief [TESTS] Модульные тесты Phase 2: подстановка инструкций, junk, обфускация.
 *
 * @details Тестирует:
 *          - SubstitutionRuleRegistry: создание, поиск, применение правил
 *          - Конкретные правила: xor↔sub, test↔and↔or, direction flip, imm8 negation
 *          - JunkGenerator: корректность размера, NOP-эквивалентность
 *          - ConstantUnfolder: декомпозиция констант
 *          - OpaquePredicateGenerator: генерация предикатов
 *          - x86 encoding helpers: prefix parsing, ModR/M, NOP generation
 */

#include <gtest/gtest.h>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"
#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/protection/obfuscation/constant_unfolding.hpp"

namespace {

/// @brief Создаёт Instruction из сырых байтов с указанной мнемоникой.
mx::analysis::Instruction make_insn(
    mx::Va address,
    mx::ByteBuffer raw_bytes,
    std::string mnemonic,
    std::string operands = "",
    bool is_branch = false)
{
    const auto length = static_cast<uint8_t>(raw_bytes.size());
    return mx::analysis::Instruction(
        address,
        length,
        std::move(raw_bytes),
        std::move(mnemonic),
        std::move(operands),
        is_branch, false, false, false, false,
        {});
}

// ============================================================================
// Тесты x86 encoding helpers
// ============================================================================

TEST(X86Encoding, IsLegacyPrefix) {
    EXPECT_TRUE(mx::x86::is_legacy_prefix(0x66));
    EXPECT_TRUE(mx::x86::is_legacy_prefix(0x67));
    EXPECT_TRUE(mx::x86::is_legacy_prefix(0xF0));
    EXPECT_TRUE(mx::x86::is_legacy_prefix(0xF2));
    EXPECT_TRUE(mx::x86::is_legacy_prefix(0xF3));
    EXPECT_FALSE(mx::x86::is_legacy_prefix(0x90));
    EXPECT_FALSE(mx::x86::is_legacy_prefix(0x31));
}

TEST(X86Encoding, IsRex) {
    EXPECT_TRUE(mx::x86::is_rex(0x40));
    EXPECT_TRUE(mx::x86::is_rex(0x48));
    EXPECT_TRUE(mx::x86::is_rex(0x4F));
    EXPECT_FALSE(mx::x86::is_rex(0x39));
    EXPECT_FALSE(mx::x86::is_rex(0x50));
}

TEST(X86Encoding, RexFields) {
    EXPECT_TRUE(mx::x86::rex_w(0x48));
    EXPECT_FALSE(mx::x86::rex_w(0x40));
    EXPECT_TRUE(mx::x86::rex_r(0x44));
    EXPECT_TRUE(mx::x86::rex_b(0x41));
}

TEST(X86Encoding, ModrmFields) {
    EXPECT_EQ(mx::x86::modrm_mod(0xC0), 3);
    EXPECT_EQ(mx::x86::modrm_reg(0xC0), 0);
    EXPECT_EQ(mx::x86::modrm_rm(0xC0), 0);
    EXPECT_EQ(mx::x86::modrm_reg(0xC9), 1);
    EXPECT_EQ(mx::x86::modrm_rm(0xC9), 1);
    EXPECT_EQ(mx::x86::make_modrm(3, 1, 1), 0xC9);
}

TEST(X86Encoding, FindOpcodeOffset) {
    mx::ByteBuffer xor_eax{0x31, 0xC0};
    EXPECT_EQ(mx::x86::find_opcode_offset(mx::ByteView{xor_eax}), 0);

    mx::ByteBuffer xor_rax{0x48, 0x31, 0xC0};
    EXPECT_EQ(mx::x86::find_opcode_offset(mx::ByteView{xor_rax}), 1);

    mx::ByteBuffer with_prefix{0x66, 0x48, 0x31, 0xC0};
    EXPECT_EQ(mx::x86::find_opcode_offset(mx::ByteView{with_prefix}), 2);
}

TEST(X86Encoding, IsSameRegOperands) {
    mx::ByteBuffer xor_eax_eax{0x31, 0xC0};
    EXPECT_TRUE(mx::x86::is_same_reg_operands(mx::ByteView{xor_eax_eax}));

    mx::ByteBuffer xor_eax_ecx{0x31, 0xC8};
    EXPECT_FALSE(mx::x86::is_same_reg_operands(mx::ByteView{xor_eax_ecx}));

    mx::ByteBuffer xor_r8_r8{0x45, 0x31, 0xC0};
    EXPECT_TRUE(mx::x86::is_same_reg_operands(mx::ByteView{xor_r8_r8}));
}

TEST(X86Encoding, MakeNop) {
    auto nop1 = mx::x86::make_nop(1);
    EXPECT_EQ(nop1.size(), 1u);
    EXPECT_EQ(nop1[0], 0x90);

    auto nop3 = mx::x86::make_nop(3);
    EXPECT_EQ(nop3.size(), 3u);

    auto nop9 = mx::x86::make_nop(9);
    EXPECT_EQ(nop9.size(), 9u);

    auto nop15 = mx::x86::make_nop(15);
    EXPECT_EQ(nop15.size(), 15u);
}

TEST(X86Encoding, SwapRexRB) {
    EXPECT_EQ(mx::x86::swap_rex_rb(0x41), 0x44);
    EXPECT_EQ(mx::x86::swap_rex_rb(0x44), 0x41);
    EXPECT_EQ(mx::x86::swap_rex_rb(0x45), 0x45);
    EXPECT_EQ(mx::x86::swap_rex_rb(0x48), 0x48);
}

// ============================================================================
// Тесты SubstitutionRuleRegistry
// ============================================================================

TEST(SubstitutionRuleRegistry, CreateDefault) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    EXPECT_GE(registry.rule_count(), 25u);
}

TEST(SubstitutionRuleRegistry, FindMatchingXorSameReg) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    auto insn = make_insn(0x1000, {0x31, 0xC0}, "xor", "eax, eax");
    auto matches = registry.find_matching(insn);
    EXPECT_GE(matches.size(), 1u);
}

TEST(SubstitutionRuleRegistry, NoMatchForBranch) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    auto insn = make_insn(0x1000, {0xEB, 0x05}, "jmp", "0x1007", true);
    auto matches = registry.find_matching(insn);
    EXPECT_EQ(matches.size(), 0u);
}

// ============================================================================
// Тесты конкретных правил подстановки
// ============================================================================

TEST(SubstitutionRules, XorToSub) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x31, 0xC0}, "xor", "eax, eax");
    auto matches = registry.find_matching(insn);

    bool found_xor_to_sub = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), insn.length());
        if (result[0] == 0x29 && result[1] == 0xC0) {
            found_xor_to_sub = true;
        }
    }
    EXPECT_TRUE(found_xor_to_sub);
}

TEST(SubstitutionRules, XorToSubWithRex) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x48, 0x31, 0xC0}, "xor", "rax, rax");
    auto matches = registry.find_matching(insn);

    bool found = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 3u);
        if (result[0] == 0x48 && result[1] == 0x29) {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST(SubstitutionRules, TestToAnd) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x85, 0xC0}, "test", "eax, eax");
    auto matches = registry.find_matching(insn);

    bool found_and = false;
    bool found_or = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 2u);
        if (result[0] == 0x21) found_and = true;
        if (result[0] == 0x09) found_or = true;
    }
    EXPECT_TRUE(found_and);
    EXPECT_TRUE(found_or);
}

TEST(SubstitutionRules, DirectionFlipAdd) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x01, 0xC8}, "add", "eax, ecx");
    auto matches = registry.find_matching(insn);

    bool found_flip = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 2u);
        if (result[0] == 0x03 && result[1] == 0xC1) {
            found_flip = true;
        }
    }
    EXPECT_TRUE(found_flip);
}

TEST(SubstitutionRules, AddImm8ToSubNeg) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x83, 0xC1, 0x05}, "add", "ecx, 5");
    auto matches = registry.find_matching(insn);

    bool found = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 3u);
        if (result[0] == 0x83 &&
            mx::x86::modrm_reg(result[1]) == 5 &&
            mx::x86::modrm_rm(result[1]) == 1 &&
            result[2] == 0xFB)
        {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST(SubstitutionRules, Shl1ToAddSelf) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0xD1, 0xE0}, "shl", "eax, 1");
    auto matches = registry.find_matching(insn);

    bool found = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 2u);
        if (result[0] == 0x01 && result[1] == 0xC0) {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST(SubstitutionRules, CmpZeroToTest) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0x83, 0xF8, 0x00}, "cmp", "eax, 0");
    auto matches = registry.find_matching(insn);

    bool found = false;
    for (const auto* rule : matches) {
        auto result = rule->apply(insn, rng);
        EXPECT_EQ(result.size(), 3u);
        if (result[0] == 0x85 && result[1] == 0xC0) {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

TEST(SubstitutionRules, SameSizeGuarantee) {
    auto registry = mx::SubstitutionRuleRegistry::create_default();
    mx::Randomizer rng(42);

    std::vector<mx::analysis::Instruction> test_insns = {
        make_insn(0x1000, {0x31, 0xC0}, "xor", "eax, eax"),
        make_insn(0x1002, {0x48, 0x31, 0xC0}, "xor", "rax, rax"),
        make_insn(0x1005, {0x85, 0xC9}, "test", "ecx, ecx"),
        make_insn(0x1007, {0x01, 0xC8}, "add", "eax, ecx"),
        make_insn(0x1009, {0x83, 0xC1, 0x05}, "add", "ecx, 5"),
        make_insn(0x100C, {0xD1, 0xE0}, "shl", "eax, 1"),
    };

    for (const auto& insn : test_insns) {
        auto matches = registry.find_matching(insn);
        for (const auto* rule : matches) {
            auto result = rule->apply(insn, rng);
            EXPECT_EQ(result.size(), insn.length())
                << "Правило '" << rule->name() << "' изменило размер для '"
                << insn.to_string() << "'";
        }
    }
}

// ============================================================================
// Тесты JunkGenerator
// ============================================================================

TEST(JunkGenerator, GenerateCorrectSize) {
    mx::JunkGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    for (size_t size = 1; size <= 20; ++size) {
        auto junk = gen.generate(size, rng);
        EXPECT_LE(junk.size(), size) << "Junk превысил размер для size=" << size;
    }
}

TEST(JunkGenerator, GenerateZero) {
    mx::JunkGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);
    auto junk = gen.generate(0, rng);
    EXPECT_TRUE(junk.empty());
}

TEST(JunkGenerator, GenerateNonEmpty) {
    mx::JunkGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);
    auto junk = gen.generate(10, rng);
    EXPECT_FALSE(junk.empty());
}

TEST(JunkGenerator, SinglePatternSize) {
    mx::JunkGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    for (int i = 0; i < 50; ++i) {
        auto pattern = gen.generate_single_pattern(rng);
        EXPECT_GE(pattern.size(), 2u);
        EXPECT_LE(pattern.size(), 10u);
    }
}

// ============================================================================
// Тесты ConstantUnfolder
// ============================================================================

TEST(ConstantUnfolder, CanUnfoldMovImm32) {
    mx::ConstantUnfolder unfolder(mx::Architecture::x64);

    auto insn = make_insn(0x1000, {0xB8, 0x78, 0x56, 0x34, 0x12}, "mov", "eax, 0x12345678");
    EXPECT_TRUE(unfolder.can_unfold(insn));
}

TEST(ConstantUnfolder, CannotUnfoldZero) {
    mx::ConstantUnfolder unfolder(mx::Architecture::x64);

    auto insn = make_insn(0x1000, {0xB8, 0x00, 0x00, 0x00, 0x00}, "mov", "eax, 0");
    EXPECT_FALSE(unfolder.can_unfold(insn));
}

TEST(ConstantUnfolder, CannotUnfoldNonMov) {
    mx::ConstantUnfolder unfolder(mx::Architecture::x64);

    auto insn = make_insn(0x1000, {0x31, 0xC0}, "xor", "eax, eax");
    EXPECT_FALSE(unfolder.can_unfold(insn));
}

TEST(ConstantUnfolder, UnfoldProducesCode) {
    mx::ConstantUnfolder unfolder(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto insn = make_insn(0x1000, {0xB8, 0x78, 0x56, 0x34, 0x12}, "mov", "eax, 0x12345678");
    auto result = unfolder.unfold(insn, rng);

    EXPECT_FALSE(result.code.empty());
    EXPECT_GE(result.instruction_count, 2);
    EXPECT_GT(result.total_size, 0);
}

TEST(ConstantUnfolder, UnfoldImm32Direct) {
    mx::ConstantUnfolder unfolder(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto result = unfolder.unfold_imm32(0, 0xDEADBEEF, rng);
    EXPECT_FALSE(result.code.empty());
    EXPECT_GE(result.instruction_count, 2);
}

// ============================================================================
// Тесты OpaquePredicateGenerator
// ============================================================================

TEST(OpaquePredicates, GenerateAlwaysTrue) {
    mx::OpaquePredicateGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto pred = gen.generate_always_true(rng);
    EXPECT_FALSE(pred.code.empty());
    EXPECT_TRUE(pred.is_always_true);
    EXPECT_GT(pred.total_size, 0);
}

TEST(OpaquePredicates, GenerateAlwaysFalse) {
    mx::OpaquePredicateGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto pred = gen.generate_always_false(rng);
    EXPECT_FALSE(pred.code.empty());
    EXPECT_FALSE(pred.is_always_true);
}

TEST(OpaquePredicates, PolymorphicOutput) {
    mx::OpaquePredicateGenerator gen(mx::Architecture::x64);
    mx::Randomizer rng(42);

    auto pred1 = gen.generate_always_true(rng);
    auto pred2 = gen.generate_always_true(rng);

    bool different = (pred1.code.size() != pred2.code.size());
    if (!different && !pred1.code.empty()) {
        for (size_t i = 0; i < pred1.code.size(); ++i) {
            if (pred1.code[i] != pred2.code[i]) {
                different = true;
                break;
            }
        }
    }
    EXPECT_TRUE(different) << "Два последовательных предиката должны различаться";
}

// ============================================================================
// Тесты Randomizer
// ============================================================================

TEST(Randomizer, DeterministicSeed) {
    mx::Randomizer rng1(12345);
    mx::Randomizer rng2(12345);
    EXPECT_EQ(rng1.next_u64(), rng2.next_u64());
    EXPECT_EQ(rng1.next_u32(), rng2.next_u32());
}

TEST(Randomizer, NextRange) {
    mx::Randomizer rng(42);
    for (int i = 0; i < 100; ++i) {
        uint32_t val = rng.next_range(10, 20);
        EXPECT_GE(val, 10u);
        EXPECT_LE(val, 20u);
    }
}

TEST(Randomizer, NextBool) {
    mx::Randomizer rng(42);
    int true_count = 0;
    for (int i = 0; i < 1000; ++i) {
        if (rng.next_bool(0.5)) ++true_count;
    }
    EXPECT_GT(true_count, 350);
    EXPECT_LT(true_count, 650);
}

} // anonymous namespace
