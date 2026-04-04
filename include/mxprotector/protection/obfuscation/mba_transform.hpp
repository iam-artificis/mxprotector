/**
 * @file mba_transform.hpp
 * @brief [BUILDER] Mixed Boolean Arithmetic (MBA) трансформации.
 *
 * @details MBA трансформации заменяют простые арифметические/логические выражения
 *          на математически эквивалентные комбинации арифметики и булевых операций.
 *          Экспоненциально усложняют анализ для SAT-решателей (Triton, Angr, Z3).
 *
 *          Основные тождества:
 *          - x + y  ≡ (x ^ y) + 2*(x & y)
 *          - x - y  ≡ (x ^ y) - 2*(~x & y)
 *          - x ^ y  ≡ (x | y) - (x & y)
 *          - x | y  ≡ (x ^ y) + (x & y)
 *          - x & y  ≡ (x | y) - (x ^ y)
 *          - ~x     ≡ -x - 1
 *          - -x     ≡ ~x + 1
 *
 *          Многоуровневые MBA: каждая подоперация рекурсивно раскладывается,
 *          создавая экспоненциально сложное выражение для анализаторов.
 *
 * @note Глубина рекурсии контролируется параметром depth (1–4).
 *       Уровень 1: одна замена. Уровень 4: ~256 инструкций на одну операцию.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <memory>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/assembler.hpp"

namespace mx {

/**
 * @brief Тип MBA-тождества для замены.
 */
enum class MbaIdentity : uint8_t {
    add_to_xor_and,     ///< x + y → (x ^ y) + 2*(x & y)
    sub_to_xor_and,     ///< x - y → (x ^ y) - 2*(~x & y)
    xor_to_or_and,      ///< x ^ y → (x | y) - (x & y)
    or_to_xor_and,      ///< x | y → (x ^ y) + (x & y)
    and_to_or_xor,      ///< x & y → (x | y) - (x ^ y)
    neg_to_not_add,     ///< -x    → ~x + 1
    not_to_neg_sub,     ///< ~x    → -x - 1
};

/**
 * @brief Результат MBA-трансформации: сгенерированный код.
 */
struct MbaTransformResult {
    ByteBuffer code;
    uint32_t   instruction_count = 0;
    uint32_t   depth_applied     = 0;
};

/**
 * @brief Генератор MBA-трансформаций — замена арифметики на MBA-эквиваленты.
 *
 * @details Принимает описание операции (тип, регистры) и генерирует
 *          эквивалентный x86/x64 код с применением MBA-тождеств.
 *          Глубина рекурсии определяет сложность результата.
 *
 *          Использует X86CodeEmitter для генерации машинного кода.
 *          Все трансформации математически доказуемо корректны.
 *
 *          SOLID (SRP): отвечает только за генерацию MBA-кода.
 *          SOLID (OCP): новые тождества добавляются без модификации существующих.
 */
class MbaTransform final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     */
    explicit MbaTransform(Architecture arch);
    ~MbaTransform();

    MbaTransform(const MbaTransform&) = delete;
    MbaTransform& operator=(const MbaTransform&) = delete;

    /**
     * @brief Генерирует MBA-замену для ADD dst, src.
     * @param dst Регистр-приёмник.
     * @param src Регистр-источник.
     * @param scratch Временный регистр (не пересекается с dst/src).
     * @param rng Генератор случайных чисел.
     * @param depth Глубина рекурсии (1–4).
     * @return Сгенерированный код или ошибка.
     */
    [[nodiscard]] MxResult<MbaTransformResult> transform_add(
        x86::Reg dst, x86::Reg src, x86::Reg scratch,
        Randomizer& rng, uint32_t depth = 1);

    /**
     * @brief Генерирует MBA-замену для SUB dst, src.
     */
    [[nodiscard]] MxResult<MbaTransformResult> transform_sub(
        x86::Reg dst, x86::Reg src, x86::Reg scratch,
        Randomizer& rng, uint32_t depth = 1);

    /**
     * @brief Генерирует MBA-замену для XOR dst, src.
     */
    [[nodiscard]] MxResult<MbaTransformResult> transform_xor(
        x86::Reg dst, x86::Reg src, x86::Reg scratch,
        Randomizer& rng, uint32_t depth = 1);

    /**
     * @brief Генерирует MBA-замену для OR dst, src.
     */
    [[nodiscard]] MxResult<MbaTransformResult> transform_or(
        x86::Reg dst, x86::Reg src, x86::Reg scratch,
        Randomizer& rng, uint32_t depth = 1);

    /**
     * @brief Генерирует MBA-замену для AND dst, src.
     */
    [[nodiscard]] MxResult<MbaTransformResult> transform_and(
        x86::Reg dst, x86::Reg src, x86::Reg scratch,
        Randomizer& rng, uint32_t depth = 1);

    /**
     * @brief Генерирует линейную MBA-обфускацию для константы.
     *
     * @details Заменяет `mov dst, C` на серию операций:
     *          mov dst, A; xor dst, B; add dst, D; sub dst, E; ...
     *          где результат вычислений == C.
     *
     * @param dst Регистр-приёмник.
     * @param value Целевое значение константы.
     * @param rng Генератор случайных чисел.
     * @param term_count Количество термов (2–8).
     * @return Сгенерированный код.
     */
    [[nodiscard]] MxResult<MbaTransformResult> obfuscate_constant(
        x86::Reg dst, uint64_t value,
        Randomizer& rng, uint32_t term_count = 4);

    /// @brief Возвращает целевую архитектуру.
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_;

    [[nodiscard]] bool is_64bit() const noexcept { return arch_ == Architecture::x64; }

    /**
     * @brief Генерирует x + y ≡ (x ^ y) + 2*(x & y) в emitter.
     *
     * @details dst = x, src = y. После выполнения: dst = x + y.
     *          Использует scratch для промежуточных вычислений.
     *          src НЕ модифицируется (сохраняется через scratch).
     */
    void emit_add_mba(analysis::X86CodeEmitter& em,
                      x86::Reg dst, x86::Reg src, x86::Reg scratch);

    /**
     * @brief Генерирует x - y ≡ (x ^ y) - 2*(~x & y).
     */
    void emit_sub_mba(analysis::X86CodeEmitter& em,
                      x86::Reg dst, x86::Reg src, x86::Reg scratch);

    /**
     * @brief Генерирует x ^ y ≡ (x | y) - (x & y).
     */
    void emit_xor_mba(analysis::X86CodeEmitter& em,
                      x86::Reg dst, x86::Reg src, x86::Reg scratch);

    /**
     * @brief Генерирует x | y ≡ (x ^ y) + (x & y).
     */
    void emit_or_mba(analysis::X86CodeEmitter& em,
                     x86::Reg dst, x86::Reg src, x86::Reg scratch);

    /**
     * @brief Генерирует x & y ≡ (x | y) - (x ^ y).
     */
    void emit_and_mba(analysis::X86CodeEmitter& em,
                      x86::Reg dst, x86::Reg src, x86::Reg scratch);
};

} // namespace mx
