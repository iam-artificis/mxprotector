/**
 * @file constant_unfolding.hpp
 * @brief [BUILDER] Замена констант на вычисления (constant unfolding / constant hiding).
 *
 * @details ConstantUnfolder заменяет явные числовые константы в инструкциях
 *          на эквивалентные последовательности арифметических операций.
 *          Например: mov eax, 0x12345678 → mov eax, A; xor eax, B (где A^B = 0x12345678).
 *          Усложняет статический анализ: константы не видны в дизассемблере явно.
 *
 * @note Поддерживаемые формы:
 *       - XOR-decomposition: C = A ^ B
 *       - ADD-decomposition: C = A + B
 *       - SUB-decomposition: C = A - B
 *       - Multi-step: C = ((A ^ B) + D) (3+ инструкции)
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/instruction.hpp"

namespace mx {

/**
 * @brief Результат декомпозиции константы: последовательность инструкций.
 */
struct UnfoldedConstant {
    ByteBuffer code;         ///< Машинный код (серия инструкций)
    uint8_t total_size;       ///< Суммарный размер в байтах
    uint8_t instruction_count;///< Количество инструкций в последовательности
};

/**
 * @brief Декомпозитор констант — заменяет MOV reg, imm на вычислительные цепочки.
 *
 * @details Анализирует инструкции вида MOV reg, imm32/imm64 и генерирует
 *          замену из 2–4 инструкций, вычисляющих ту же константу.
 *          Декомпозиция рандомизируется: при каждом вызове генерируется
 *          уникальная последовательность.
 *
 *          SOLID (SRP): отвечает только за декомпозицию констант.
 */
class ConstantUnfolder final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     */
    explicit ConstantUnfolder(Architecture arch) : arch_(arch) {}

    ~ConstantUnfolder() = default;

    /**
     * @brief Проверяет, можно ли декомпозировать данную инструкцию.
     * @param insn Инструкция для проверки.
     * @return true если это MOV reg, imm32/imm64 с ненулевой константой.
     */
    [[nodiscard]] bool can_unfold(const analysis::Instruction& insn) const;

    /**
     * @brief Декомпозирует константу в вычислительную последовательность.
     * @param insn Оригинальная инструкция MOV reg, imm.
     * @param rng Генератор случайных чисел.
     * @return Декомпозированная последовательность или пустая структура при неудаче.
     */
    [[nodiscard]] UnfoldedConstant unfold(
        const analysis::Instruction& insn, Randomizer& rng) const;

    /**
     * @brief Декомпозирует 32-битную константу для указанного регистра.
     * @param reg_id 4-битный ID регистра (0–15).
     * @param value Значение константы.
     * @param rng Генератор случайных чисел.
     * @return Декомпозированная последовательность.
     */
    [[nodiscard]] UnfoldedConstant unfold_imm32(
        uint8_t reg_id, uint32_t value, Randomizer& rng) const;

    /// @brief Возвращает целевую архитектуру.
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_; ///< Целевая архитектура

    /// @brief Генерирует XOR-декомпозицию: mov reg, A; xor reg, B (A^B == value).
    [[nodiscard]] UnfoldedConstant gen_xor_decomposition(
        uint8_t reg_id, uint32_t value, Randomizer& rng) const;

    /// @brief Генерирует ADD-декомпозицию: mov reg, A; add reg, B (A+B == value).
    [[nodiscard]] UnfoldedConstant gen_add_decomposition(
        uint8_t reg_id, uint32_t value, Randomizer& rng) const;

    /// @brief Генерирует SUB-декомпозицию: mov reg, A; sub reg, B (A-B == value).
    [[nodiscard]] UnfoldedConstant gen_sub_decomposition(
        uint8_t reg_id, uint32_t value, Randomizer& rng) const;

    /// @brief Генерирует multi-step: mov reg, A; xor reg, B; add reg, C.
    [[nodiscard]] UnfoldedConstant gen_multi_step(
        uint8_t reg_id, uint32_t value, Randomizer& rng) const;
};

} // namespace mx
