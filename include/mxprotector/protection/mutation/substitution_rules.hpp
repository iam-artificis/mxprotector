/**
 * @file substitution_rules.hpp
 * @brief [BUILDER] Интерфейс правил подстановки инструкций и реестр правил.
 *
 * @details Определяет абстрактный интерфейс ISubstitutionRule для замены одной
 *          x86/x64 инструкции на семантически эквивалентную. Реестр SubstitutionRuleRegistry
 *          хранит все зарегистрированные правила и ищет подходящие для конкретной инструкции.
 *
 * @note Конкретные правила реализованы в instruction_substitution.cpp.
 *       Все подстановки сохраняют размер инструкции (дополняются NOP при необходимости).
 *       SOLID (OCP): новые правила добавляются без модификации существующего кода.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/instruction.hpp"

namespace mx {

/**
 * @brief Абстрактный интерфейс правила подстановки одной инструкции.
 *
 * @details Каждое правило определяет:
 *          - name()    — уникальное имя для логирования
 *          - matches() — проверяет, применимо ли правило к инструкции
 *          - apply()   — генерирует замену (байты той же длины, что и оригинал)
 *
 *          SOLID (LSP): любая реализация может подставляться на место ISubstitutionRule.
 */
class ISubstitutionRule {
public:
    virtual ~ISubstitutionRule() = default;

    /// @brief Уникальное имя правила для логирования.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /**
     * @brief Проверяет, применимо ли правило к данной инструкции.
     * @param insn Декодированная инструкция.
     * @return true если правило может быть применено.
     */
    [[nodiscard]] virtual bool matches(const analysis::Instruction& insn) const = 0;

    /**
     * @brief Применяет правило и генерирует замену.
     * @param insn Оригинальная инструкция.
     * @param rng Генератор случайных чисел (для вариативности).
     * @return Буфер байтов-замены (ГАРАНТИРОВАННО той же длины, что и оригинал).
     */
    [[nodiscard]] virtual ByteBuffer apply(
        const analysis::Instruction& insn, Randomizer& rng) const = 0;

    /**
     * @brief Whether the rewrite leaves EFLAGS in a state that
     *        differs from the original instruction's effect.
     *
     * Default: `false` — most rules are size-preserving and produce
     * the same flag side-effects as the original (`xor`↔`sub`-same-reg,
     * direction flips, semantic transforms on flag-equivalent forms).
     *
     * MBA rewriters override this to `true`: their final ALU op
     * produces a different OF/AF (sometimes CF) than the original
     * `<op> reg, imm32`. The engine consults the predicate together
     * with `analysis::safe_to_clobber_flags_after` to skip flag-
     * affecting rules at sites where the next instruction reads
     * EFLAGS — see `mutation_engine.cpp`.
     *
     * Returning `false` is the safe default: a rule is "honest" by
     * claiming it doesn't preserve flags only if it actually
     * doesn't, otherwise the engine misses the lookahead guard.
     */
    [[nodiscard]] virtual bool affects_observable_flags() const noexcept {
        return false;
    }
};

/**
 * @brief Реестр правил подстановки инструкций.
 *
 * @details Владеет коллекцией ISubstitutionRule через unique_ptr.
 *          Предоставляет поиск подходящих правил для конкретной инструкции.
 *          Фабричный метод create_default() регистрирует все встроенные правила.
 *
 *          SOLID (OCP): новые правила добавляются через add_rule() без изменения реестра.
 */
class SubstitutionRuleRegistry final {
public:
    SubstitutionRuleRegistry() = default;
    ~SubstitutionRuleRegistry() = default;

    SubstitutionRuleRegistry(const SubstitutionRuleRegistry&) = delete;
    SubstitutionRuleRegistry& operator=(const SubstitutionRuleRegistry&) = delete;
    SubstitutionRuleRegistry(SubstitutionRuleRegistry&&) noexcept = default;
    SubstitutionRuleRegistry& operator=(SubstitutionRuleRegistry&&) noexcept = default;

    /**
     * @brief Добавляет правило в реестр.
     * @param rule Уникальный указатель на правило (владение передаётся).
     */
    void add_rule(std::unique_ptr<ISubstitutionRule> rule);

    /// @brief Неизменяемый доступ ко всем правилам.
    [[nodiscard]] const std::vector<std::unique_ptr<ISubstitutionRule>>& rules() const noexcept {
        return rules_;
    }

    /// @brief Количество зарегистрированных правил.
    [[nodiscard]] size_t rule_count() const noexcept { return rules_.size(); }

    /**
     * @brief Ищет все правила, применимые к инструкции.
     * @param insn Инструкция для проверки.
     * @return Вектор указателей на подходящие правила (не владеющие).
     */
    [[nodiscard]] std::vector<const ISubstitutionRule*> find_matching(
        const analysis::Instruction& insn) const;

    /**
     * @brief Фабричный метод: создаёт реестр со всеми встроенными правилами.
     * @return Реестр с 20+ правилами подстановки (50+ конкретных паттернов).
     */
    [[nodiscard]] static SubstitutionRuleRegistry create_default();

private:
    std::vector<std::unique_ptr<ISubstitutionRule>> rules_; ///< Зарегистрированные правила
};

} // namespace mx
