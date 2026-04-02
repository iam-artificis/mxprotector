/**
 * @file opaque_predicates.hpp
 * @brief [BUILDER] Генерация opaque predicates и проход обфускации.
 *
 * @details OpaquePredicateGenerator создаёт математически доказуемые предикаты
 *          (выражения, результат которых всегда true или всегда false),
 *          кодированные как x86/x64 машинный код. Вставляются в код как
 *          условные переходы: IDA/Hex-Rays не может свернуть их статически.
 *
 *          ObfuscationPass реализует IProtectionPass и координирует применение
 *          opaque predicates + constant unfolding к маркированным регионам.
 *
 * @note Примеры opaque predicates:
 *       - x*(x+1) mod 2 == 0  (всегда true: произведение двух последовательных чисел чётно)
 *       - (x | 1) != 0        (всегда true: младший бит всегда установлен)
 *       - x^2 >= 0            (всегда true для unsigned)
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

/**
 * @brief Результат генерации opaque predicate: машинный код + метаданные.
 */
struct OpaquePredicateCode {
    ByteBuffer code;           ///< Машинный код (вычисление + условный переход)
    uint8_t true_branch_offset; ///< Смещение JCC для always-true ветви
    uint8_t total_size;         ///< Полный размер в байтах
    bool is_always_true;        ///< true = всегда-true предикат, false = всегда-false
};

/**
 * @brief Генератор opaque predicates — математически доказуемых предикатов.
 *
 * @details Создаёт фрагменты x86/x64 кода, которые вычисляют выражение
 *          с заведомо известным результатом (всегда true или false).
 *          За вычислением следует условный переход. Для always-true: JCC
 *          всегда выполняется, и код между JCC и target — мёртвый (junk).
 *          Для always-false: JCC никогда не выполняется.
 *
 *          Поддерживаемые предикаты:
 *          - x*(x+1) % 2 == 0           (квадратичная чётность)
 *          - (x | 1) != 0               (бит всегда установлен)
 *          - (x & x) == x               (идемпотентность AND)
 *          - (x ^ x) == 0               (XOR самого с собой)
 *          - (x*x + x) % 2 == 0         (квадратичная чётность, форма 2)
 *
 *          Предикаты полиморфны: каждый вызов использует случайный регистр и вариант.
 */
class OpaquePredicateGenerator final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     */
    explicit OpaquePredicateGenerator(Architecture arch) : arch_(arch) {}

    ~OpaquePredicateGenerator() = default;

    /**
     * @brief Генерирует always-true opaque predicate.
     * @param rng Генератор случайных чисел.
     * @param junk_size Размер junk-кода в мёртвой ветви (0 = без junk).
     * @return Структура с кодом предиката.
     */
    [[nodiscard]] OpaquePredicateCode generate_always_true(
        Randomizer& rng, uint8_t junk_size = 0) const;

    /**
     * @brief Генерирует always-false opaque predicate.
     * @param rng Генератор случайных чисел.
     * @return Структура с кодом предиката.
     */
    [[nodiscard]] OpaquePredicateCode generate_always_false(Randomizer& rng) const;

    /// @brief Возвращает целевую архитектуру.
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_; ///< Целевая архитектура

    /// @brief Предикат: x*(x+1) % 2 == 0 (вычисление в регистре + TEST + JZ).
    [[nodiscard]] OpaquePredicateCode gen_quadratic_parity(Randomizer& rng, bool always_true) const;

    /// @brief Предикат: (x | 1) != 0 (OR + TEST + JNZ).
    [[nodiscard]] OpaquePredicateCode gen_or_one_nonzero(Randomizer& rng) const;

    /// @brief Предикат: (x ^ x) == 0 (XOR + TEST + JZ).
    [[nodiscard]] OpaquePredicateCode gen_xor_self_zero(Randomizer& rng) const;

    /// @brief Выбирает случайный «безопасный» регистр (не RSP, не RBP).
    [[nodiscard]] uint8_t pick_safe_register(Randomizer& rng) const;
};

/**
 * @brief Проход обфускации для пайплайна защиты.
 *
 * @details Реализует IProtectionPass. Ищет маркированные регионы
 *          MX_OBFUSCATE_BEGIN/END и применяет:
 *          - Opaque predicates (мёртвые условные переходы)
 *          - Constant unfolding (замена констант на вычисления)
 *
 * @note Приоритет: 200 (после мутации, до виртуализации).
 */
class ObfuscationPass final : public IProtectionPass {
public:
    ObfuscationPass() = default;
    ~ObfuscationPass() override = default;

    /// @brief Возвращает имя прохода.
    [[nodiscard]] std::string_view name() const noexcept override {
        return "ObfuscationPass";
    }

    /// @brief Категория — обфускация.
    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::obfuscation;
    }

    /// @brief Приоритет — 200 (после мутации).
    [[nodiscard]] uint32_t priority() const noexcept override {
        return 200;
    }

    /// @brief Выполняет обфускацию всех маркированных регионов.
    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;

    /// @brief Проверяет: config.enable_obfuscation == true.
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
