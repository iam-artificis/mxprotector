/**
 * @file junk_generator.hpp
 * @brief [BUILDER] Генератор мёртвого кода (junk code) для мутации.
 *
 * @details JunkGenerator создаёт последовательности машинного кода x86/x64,
 *          которые не изменяют семантику программы (не влияют на регистры,
 *          флаги и память), но неотличимы от настоящего кода для статических
 *          анализаторов. Используется MutationEngine для вставки мёртвого кода
 *          между инструкциями маркированных регионов.
 *
 * @note Все паттерны junk-кода являются NOP-эквивалентами:
 *       push/pop одного регистра, xchg reg,reg, lahf/sahf-обёрнутая арифметика и т.д.
 *       Генерируемый код варьируется случайным образом при каждом вызове.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"

namespace mx {

/**
 * @brief Генератор мёртвого кода x86/x64.
 *
 * @details Создаёт байтовые последовательности, не влияющие на состояние
 *          процессора (регистры, флаги, стек, память). Каждая последовательность
 *          представляет собой замкнутый блок: все изменения компенсируются.
 *          Поддерживает генерацию фрагментов заданной длины.
 */
class JunkGenerator final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура (x86 или x64).
     */
    explicit JunkGenerator(Architecture arch) : arch_(arch) {}

    ~JunkGenerator() = default;

    JunkGenerator(const JunkGenerator&) = delete;
    JunkGenerator& operator=(const JunkGenerator&) = delete;

    /**
     * @brief Генерирует фрагмент мёртвого кода заданной длины.
     * @param desired_size Желаемый размер в байтах (результат может быть <= desired_size).
     * @param rng Генератор случайных чисел.
     * @return Буфер с junk-кодом.
     *
     * @note Результат гарантированно не превышает desired_size байт.
     *       Если точное заполнение невозможно, остаток дополняется NOP.
     */
    [[nodiscard]] ByteBuffer generate(size_t desired_size, Randomizer& rng) const;

    /**
     * @brief Генерирует один junk-паттерн случайного размера (2–8 байт).
     * @param rng Генератор случайных чисел.
     * @return Один junk-паттерн.
     */
    [[nodiscard]] ByteBuffer generate_single_pattern(Randomizer& rng) const;

    /**
     * @brief Генерирует один junk-паттерн, гарантированно безопасный для
     *        выполнения как native VM handler (не модифицирует регистры,
     *        флаги или стек в net-эффекте).
     */
    [[nodiscard]] ByteBuffer generate_vm_safe_pattern(Randomizer& rng) const;

    /// @brief Возвращает целевую архитектуру.
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_; ///< Целевая архитектура

    /// @brief Генерирует push/pop одного регистра (2 байта для rax–rdi, 4 для r8–r15).
    [[nodiscard]] ByteBuffer gen_push_pop(Randomizer& rng) const;

    /// @brief Генерирует арифметику, компенсирующую саму себя (add+sub, xor+xor).
    [[nodiscard]] ByteBuffer gen_self_canceling_arithmetic(Randomizer& rng) const;

    /// @brief Генерирует LAHF/SAHF-обёрнутую мёртвую арифметику (сохраняет/восстанавливает флаги).
    [[nodiscard]] ByteBuffer gen_flag_safe_arithmetic(Randomizer& rng) const;

    /// @brief Генерирует dead MOV (mov reg, reg — NOP для 32-bit, zero-extends для 64-bit).
    [[nodiscard]] ByteBuffer gen_dead_mov(Randomizer& rng) const;

    /// @brief Генерирует XCHG reg1,reg2; XCHG reg1,reg2 — полный NOP-эквивалент (4 байта).
    [[nodiscard]] ByteBuffer gen_xchg_pair(Randomizer& rng) const;

    /// @brief Генерирует NOT reg; NOT reg — double-NOT identity (4 байта, dead code only).
    [[nodiscard]] ByteBuffer gen_double_not(Randomizer& rng) const;

    /// @brief Генерирует BSWAP reg; BSWAP reg — double byte-swap identity (4 байта, dead code only).
    [[nodiscard]] ByteBuffer gen_double_bswap(Randomizer& rng) const;

    /// @brief LEA reg, [reg+0] — looks like address computation (3–4 bytes).
    [[nodiscard]] ByteBuffer gen_lea_identity(Randomizer& rng) const;

    /// @brief NEG reg; NEG reg — identity (4–6 bytes).
    [[nodiscard]] ByteBuffer gen_double_neg(Randomizer& rng) const;

    /// @brief ROL reg, N; ROR reg, N — rotate/unrotate (6 bytes).
    [[nodiscard]] ByteBuffer gen_rotate_pair(Randomizer& rng) const;

    /// @brief CMP reg, reg — always-equal comparison (2–3 bytes, looks like branch setup).
    [[nodiscard]] ByteBuffer gen_fake_cmp(Randomizer& rng) const;
};

} // namespace mx
