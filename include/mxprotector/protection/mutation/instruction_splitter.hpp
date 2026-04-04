/**
 * @file instruction_splitter.hpp
 * @brief [BUILDER] Разбиение инструкций на эквивалентные последовательности (Instruction Splitting).
 *
 * @details InstructionSplitter анализирует машинные инструкции и разбивает их
 *          на серию семантически эквивалентных инструкций меньшей гранулярности.
 *          Усиливает мутацию: одна инструкция становится 2–4, каждая из которых
 *          может быть дополнительно мутирована подстановками.
 *
 *          Поддерживаемые разбиения:
 *          - ADD reg, imm  → ADD reg, imm1; ADD reg, imm2  (imm1 + imm2 = imm)
 *          - SUB reg, imm  → SUB reg, imm1; SUB reg, imm2  (imm1 + imm2 = imm)
 *          - XOR reg, imm  → XOR reg, imm1; XOR reg, imm2  (imm1 ^ imm2 = imm)
 *          - MOV reg, imm  → MOV reg, A; XOR reg, B; ADD reg, C  (вычислительная цепочка)
 *          - AND reg, imm  → AND reg, mask1; AND reg, mask2  (mask1 & mask2 = imm)
 *          - OR  reg, imm  → OR reg, part1; OR reg, part2   (part1 | part2 = imm, non-overlapping)
 *
 *          Стратегия: IInstructionSplitStrategy (Strategy pattern, SOLID OCP).
 *          Каждая стратегия знает, к каким инструкциям применима и как разбить.
 *
 * @note Разбиение увеличивает размер кода. Применяется только к маркированным
 *       регионам, где допускается расширение (или в padding-области).
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/assembler.hpp"

namespace mx {

/**
 * @brief Результат разбиения одной инструкции.
 */
struct SplitResult {
    ByteBuffer code;
    uint32_t   instruction_count = 0;
    uint32_t   total_size        = 0;
};

/**
 * @brief Абстрактная стратегия разбиения инструкции.
 *
 * @details Каждая стратегия отвечает за конкретный тип разбиения
 *          (ADD splitting, XOR splitting и т.д.).
 *
 *          SOLID (OCP): новые стратегии добавляются без модификации InstructionSplitter.
 *          SOLID (LSP): любая стратегия подставляется через указатель на базовый класс.
 */
class IInstructionSplitStrategy {
public:
    virtual ~IInstructionSplitStrategy() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    [[nodiscard]] virtual bool can_split(const analysis::Instruction& insn) const = 0;

    [[nodiscard]] virtual SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const = 0;
};

/**
 * @brief Реестр стратегий разбиения и координатор splitting.
 *
 * @details Хранит коллекцию IInstructionSplitStrategy и для каждой инструкции
 *          подбирает подходящую стратегию. Фабричный метод create_default()
 *          регистрирует все встроенные стратегии.
 *
 *          SOLID (OCP): расширяется через add_strategy() без модификации.
 *          SOLID (DIP): зависит от абстракции IInstructionSplitStrategy.
 */
class InstructionSplitter final {
public:
    InstructionSplitter() = default;
    ~InstructionSplitter() = default;

    InstructionSplitter(const InstructionSplitter&) = delete;
    InstructionSplitter& operator=(const InstructionSplitter&) = delete;
    InstructionSplitter(InstructionSplitter&&) noexcept = default;
    InstructionSplitter& operator=(InstructionSplitter&&) noexcept = default;

    void add_strategy(std::unique_ptr<IInstructionSplitStrategy> strategy);

    [[nodiscard]] bool can_split(const analysis::Instruction& insn) const;

    [[nodiscard]] SplitResult split(
        const analysis::Instruction& insn,
        Randomizer& rng,
        bool is_64bit) const;

    [[nodiscard]] const std::vector<std::unique_ptr<IInstructionSplitStrategy>>& strategies() const noexcept {
        return strategies_;
    }

    [[nodiscard]] size_t strategy_count() const noexcept { return strategies_.size(); }

    [[nodiscard]] static InstructionSplitter create_default();

private:
    std::vector<std::unique_ptr<IInstructionSplitStrategy>> strategies_;
};

} // namespace mx
