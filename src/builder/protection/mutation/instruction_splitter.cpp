/**
 * @file instruction_splitter.cpp
 * @brief [BUILDER] Реализация стратегий разбиения инструкций.
 *
 * @details Содержит конкретные стратегии разбиения:
 *          - AddImmSplitStrategy:  ADD reg, imm → ADD reg, a; ADD reg, b
 *          - SubImmSplitStrategy:  SUB reg, imm → SUB reg, a; SUB reg, b
 *          - XorImmSplitStrategy:  XOR reg, imm → XOR reg, a; XOR reg, b
 *          - MovImmSplitStrategy:  MOV reg, imm → MOV reg, a; XOR reg, b
 *          - OrImmSplitStrategy:   OR reg, imm → OR reg, p1; OR reg, p2  (non-overlapping bits)
 *          - AndImmSplitStrategy:  AND reg, imm → AND reg, m1; AND reg, m2
 *
 *          Все стратегии используют X86CodeEmitter для генерации машинного кода.
 *          Рандомизация: каждое разбиение использует случайное разделение immediate.
 */

#include "mxprotector/protection/mutation/instruction_splitter.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <algorithm>

namespace mx {

// ============================================================================
// InstructionSplitter — базовые методы
// ============================================================================

void InstructionSplitter::add_strategy(std::unique_ptr<IInstructionSplitStrategy> strategy) {
    if (strategy) {
        strategies_.push_back(std::move(strategy));
    }
}

bool InstructionSplitter::can_split(const analysis::Instruction& insn) const {
    return std::ranges::any_of(strategies_,
        [&](const auto& s) { return s->can_split(insn); });
}

SplitResult InstructionSplitter::split(
    const analysis::Instruction& insn,
    Randomizer& rng,
    bool is_64bit) const
{
    std::vector<const IInstructionSplitStrategy*> applicable;
    for (const auto& s : strategies_) {
        if (s->can_split(insn)) {
            applicable.push_back(s.get());
        }
    }

    if (applicable.empty()) {
        return {};
    }

    const auto idx = rng.next_range(0, static_cast<uint32_t>(applicable.size() - 1));
    return applicable[idx]->split(insn, rng, is_64bit);
}

// ============================================================================
// Concrete split strategies (internal)
// ============================================================================

namespace {

/**
 * @brief Извлекает reg_id и immediate из инструкции 0x83 формата.
 */
struct Imm8Info {
    uint8_t reg_id = 0;
    int8_t  imm    = 0;
    bool    valid  = false;
};

Imm8Info parse_alu_imm8(const analysis::Instruction& insn, uint8_t expected_reg_field) {
    const auto bytes = insn.raw_bytes();
    const uint8_t op_off = x86::find_opcode_offset(bytes);
    if (op_off + 2 >= bytes.size()) return {};
    if (bytes[op_off] != 0x83) return {};

    const uint8_t modrm = bytes[op_off + 1];
    if (x86::modrm_mod(modrm) != 3) return {};
    if (x86::modrm_reg(modrm) != expected_reg_field) return {};

    const uint8_t rm = x86::modrm_rm(modrm);
    const uint8_t rex = x86::find_rex(bytes);
    uint8_t reg_id = rm;
    if (rex && x86::rex_b(rex)) reg_id |= 8;

    return {reg_id, static_cast<int8_t>(bytes[op_off + 2]), true};
}

// --------------------------------------------------------------------------
// ADD reg, imm8 → ADD reg, a; ADD reg, b  (a + b = imm)
// --------------------------------------------------------------------------
class AddImmSplitStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "add_imm_split"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "add") return false;
        auto info = parse_alu_imm8(insn, 0);
        return info.valid && info.imm != 0 && info.imm != 1 && info.imm != -1;
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const override
    {
        auto info = parse_alu_imm8(insn, 0);
        if (!info.valid) return {};

        const int32_t total = info.imm;
        const int32_t a = static_cast<int32_t>(rng.next_range(1,
            static_cast<uint32_t>(std::abs(total) - 1)));
        const int32_t part1 = (total > 0) ? a : -a;
        const int32_t part2 = total - part1;

        analysis::X86CodeEmitter em(is_64bit);
        auto reg = static_cast<x86::Reg>(info.reg_id);
        em.add(reg, part1);
        em.add(reg, part2);

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 2;
        return result;
    }
};

// --------------------------------------------------------------------------
// SUB reg, imm8 → SUB reg, a; SUB reg, b  (a + b = imm)
// --------------------------------------------------------------------------
class SubImmSplitStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "sub_imm_split"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "sub") return false;
        auto info = parse_alu_imm8(insn, 5);
        return info.valid && info.imm != 0 && info.imm != 1 && info.imm != -1;
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const override
    {
        auto info = parse_alu_imm8(insn, 5);
        if (!info.valid) return {};

        const int32_t total = info.imm;
        const int32_t a = static_cast<int32_t>(rng.next_range(1,
            static_cast<uint32_t>(std::abs(total) - 1)));
        const int32_t part1 = (total > 0) ? a : -a;
        const int32_t part2 = total - part1;

        analysis::X86CodeEmitter em(is_64bit);
        auto reg = static_cast<x86::Reg>(info.reg_id);
        em.sub(reg, part1);
        em.sub(reg, part2);

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 2;
        return result;
    }
};

// --------------------------------------------------------------------------
// XOR reg, imm8 → XOR reg, a; XOR reg, b  (a ^ b = imm)
// --------------------------------------------------------------------------
class XorImmSplitStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "xor_imm_split"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "xor") return false;
        auto info = parse_alu_imm8(insn, 6);
        return info.valid && info.imm != 0;
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const override
    {
        auto info = parse_alu_imm8(insn, 6);
        if (!info.valid) return {};

        const int32_t total = info.imm;
        const auto rand_val = static_cast<int32_t>(rng.next_u8());
        const int32_t part1 = rand_val;
        const int32_t part2 = total ^ rand_val;

        analysis::X86CodeEmitter em(is_64bit);
        auto reg = static_cast<x86::Reg>(info.reg_id);
        em.xor_(reg, part1);
        em.xor_(reg, part2);

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 2;
        return result;
    }
};

// --------------------------------------------------------------------------
// MOV reg, imm32 → MOV reg, A; XOR reg, B  (A ^ B = imm)
// --------------------------------------------------------------------------
class MovImmSplitStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "mov_imm_split"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "mov") return false;
        const auto bytes = insn.raw_bytes();
        if (bytes.size() < 5) return false;
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        if (op_off >= bytes.size()) return false;
        const uint8_t op = bytes[op_off];
        return (op >= 0xB8 && op <= 0xBF);
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const override
    {
        const auto bytes = insn.raw_bytes();
        const uint8_t op_off = x86::find_opcode_offset(bytes);
        const uint8_t op = bytes[op_off];
        const uint8_t rex = x86::find_rex(bytes);

        uint8_t reg_3bit = op - 0xB8;
        uint8_t reg_id = reg_3bit;
        if (rex && x86::rex_b(rex)) reg_id |= 8;

        uint32_t imm = 0;
        if (op_off + 5 <= bytes.size()) {
            imm = static_cast<uint32_t>(bytes[op_off + 1])
                | (static_cast<uint32_t>(bytes[op_off + 2]) << 8)
                | (static_cast<uint32_t>(bytes[op_off + 3]) << 16)
                | (static_cast<uint32_t>(bytes[op_off + 4]) << 24);
        }

        if (imm == 0) return {};

        const auto mask = rng.next_u32();

        analysis::X86CodeEmitter em(is_64bit);
        auto reg = static_cast<x86::Reg>(reg_id);
        em.mov(reg, static_cast<uint64_t>(imm ^ mask));
        em.xor_(reg, static_cast<int32_t>(mask));

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 2;
        return result;
    }
};

// --------------------------------------------------------------------------
// ADD reg, imm8 → LEA reg, [reg + imm]  (single instruction replacement)
// --------------------------------------------------------------------------
class AddToLeaStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "add_to_lea"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "add") return false;
        auto info = parse_alu_imm8(insn, 0);
        if (!info.valid) return false;
        auto reg = static_cast<x86::Reg>(info.reg_id);
        return reg != x86::Reg::rsp && reg != x86::Reg::rbp;
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        [[maybe_unused]] Randomizer& rng,
        bool is_64bit) const override
    {
        auto info = parse_alu_imm8(insn, 0);
        if (!info.valid) return {};

        auto reg = static_cast<x86::Reg>(info.reg_id);

        analysis::X86CodeEmitter em(is_64bit);
        em.lea(reg, analysis::MemOperand::reg_indirect(reg, info.imm));

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 1;
        return result;
    }
};

// --------------------------------------------------------------------------
// SUB reg, imm8 → LEA reg, [reg - imm]
// --------------------------------------------------------------------------
class SubToLeaStrategy final : public IInstructionSplitStrategy {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "sub_to_lea"; }

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const override {
        if (insn.mnemonic() != "sub") return false;
        auto info = parse_alu_imm8(insn, 5);
        if (!info.valid) return false;
        auto reg = static_cast<x86::Reg>(info.reg_id);
        return reg != x86::Reg::rsp && reg != x86::Reg::rbp;
    }

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        [[maybe_unused]] Randomizer& rng,
        bool is_64bit) const override
    {
        auto info = parse_alu_imm8(insn, 5);
        if (!info.valid) return {};

        auto reg = static_cast<x86::Reg>(info.reg_id);

        analysis::X86CodeEmitter em(is_64bit);
        em.lea(reg, analysis::MemOperand::reg_indirect(reg, -static_cast<int32_t>(info.imm)));

        auto code = em.build();
        if (!code) return {};

        SplitResult result;
        result.code = std::move(*code);
        result.total_size = static_cast<uint32_t>(result.code.size());
        result.instruction_count = 1;
        return result;
    }
};

} // anonymous namespace

// ============================================================================
// create_default — фабрика с 6 стратегиями
// ============================================================================

InstructionSplitter InstructionSplitter::create_default() {
    InstructionSplitter splitter;

    splitter.add_strategy(std::make_unique<AddImmSplitStrategy>());
    splitter.add_strategy(std::make_unique<SubImmSplitStrategy>());
    splitter.add_strategy(std::make_unique<XorImmSplitStrategy>());
    splitter.add_strategy(std::make_unique<MovImmSplitStrategy>());
    splitter.add_strategy(std::make_unique<AddToLeaStrategy>());
    splitter.add_strategy(std::make_unique<SubToLeaStrategy>());

    return splitter;
}

} // namespace mx
