/**
 * @file mutation_engine.hpp
 * @brief [BUILDER] Движок мутации инструкций и проход мутации для пайплайна.
 *
 * @details MutationEngine координирует все трансформации мутации:
 *          подстановку инструкций (SubstitutionRuleRegistry), генерацию
 *          мёртвого кода (JunkGenerator) и переназначение регистров.
 *          MutationPass реализует IProtectionPass и вызывается PassManager.
 *
 * @note Мутация применяется к регионам, помеченным MX_MUTATE_BEGIN/END.
 *       Все подстановки in-place (не изменяют размер региона).
 *       Junk-код вставляется в доступные области padding/NOP.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/protection/pass.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"
#include "mxprotector/protection/mutation/junk_generator.hpp"

namespace mx::mutation {
class IExpansionSink;
} // namespace mx::mutation

namespace mx {

class ProtectionContext;

/**
 * @brief Движок мутации — координирует подстановку инструкций и junk-генерацию.
 *
 * @details Принимает буфер кода, дизассемблирует его и применяет случайные
 *          трансформации (подстановки и junk-вставки). Результат записывается
 *          обратно в PE-образ. Не изменяет суммарный размер кода.
 *
 *          SOLID (SRP): отвечает за координацию мутации одного региона.
 */
class MutationEngine final {
public:
    /**
     * @brief Конструктор с зависимостями.
     * @param rules Реестр правил подстановки.
     * @param junk Генератор мёртвого кода.
     * @param rng Генератор случайных чисел.
     */
    MutationEngine(SubstitutionRuleRegistry rules,
                   std::unique_ptr<JunkGenerator> junk,
                   Randomizer& rng);

    ~MutationEngine();

    MutationEngine(const MutationEngine&) = delete;
    MutationEngine& operator=(const MutationEngine&) = delete;

    /**
     * @brief Мутирует регион кода in-place.
     * @param code Буфер кода для мутации (модифицируется).
     * @param base_address Виртуальный адрес начала буфера.
     * @param disasm Дизассемблер для декодирования.
     * @param ctx Контекст (для логирования).
     * @return Количество применённых мутаций или ошибка.
     */
    [[nodiscard]] MxResult<uint32_t> mutate_region(
        MutableByteView code,
        Va base_address,
        analysis::IDisassembler& disasm,
        ProtectionContext& ctx);

    /// @brief Количество применённых подстановок за всё время жизни.
    [[nodiscard]] uint32_t total_substitutions() const noexcept { return total_substitutions_; }

    /// @brief Количество вставленных junk-паттернов за всё время жизни.
    [[nodiscard]] uint32_t total_junk_insertions() const noexcept { return total_junk_insertions_; }

    /// @brief Number of substitutions redirected via the expansion
    /// sink (i.e. the rule produced longer bytes than the original
    /// instruction's slot). Tracked separately from
    /// `total_substitutions_` so callers can tell apart in-place
    /// mutations from spilled ones in logs.
    [[nodiscard]] uint32_t total_redirected_expansions() const noexcept {
        return total_redirected_expansions_;
    }

    /**
     * @brief Install (or clear) the expansion sink used when a rule
     *        produces longer bytes than the substituted instruction.
     *
     * Default: `nullptr`, meaning the engine refuses size-changing
     * substitutions (the current pre-A behaviour). When set, the
     * engine inspects each oversize replacement: if the original
     * instruction is at least 5 bytes (room for `JMP rel32`) and
     * Zydis confirms the replacement is position-independent (no
     * branches/calls/returns), the bytes are routed through the sink
     * and a `JMP rel32` is patched in at the original site, padding
     * the residual slot bytes with `0x90` NOPs.
     *
     * Construction-time injection is intentionally avoided so the
     * common case (no sink) keeps the existing 3-argument constructor
     * shape. Callers wire the sink up after constructing the engine.
     *
     * @param sink Borrowed pointer; lifetime must outlive the engine.
     *             Pass `nullptr` to disable expansion handling.
     */
    void set_expansion_sink(mx::mutation::IExpansionSink* sink) noexcept {
        expansion_sink_ = sink;
    }

private:
    SubstitutionRuleRegistry rules_;                ///< Реестр правил подстановки
    std::unique_ptr<JunkGenerator> junk_gen_;       ///< Генератор junk-кода
    Randomizer& rng_;                               ///< ГСЧ (внешняя ссылка)

    uint32_t total_substitutions_         = 0;      ///< Счётчик подстановок
    uint32_t total_junk_insertions_       = 0;      ///< Счётчик junk-вставок
    uint32_t total_redirected_expansions_ = 0;      ///< Счётчик расширенных подстановок

    /// Optional expansion sink — see `set_expansion_sink`. The engine
    /// borrows the pointer; ownership stays with the caller.
    mx::mutation::IExpansionSink* expansion_sink_ = nullptr;

    static constexpr double substitution_probability_ = 1.0;  ///< Вероятность подстановки
    static constexpr double junk_probability_ = 0.3;          ///< Вероятность вставки junk
};

/**
 * @brief Проход мутации для пайплайна защиты.
 *
 * @details Реализует IProtectionPass. Ищет маркированные регионы
 *          MX_MUTATE_BEGIN/END, создаёт MutationEngine и мутирует каждый регион.
 *          Также применяет базовое переназначение регистров.
 *
 * @note Приоритет: 100 (категория mutation, выполняется первым).
 */
class MutationPass final : public IProtectionPass {
public:
    MutationPass() = default;
    ~MutationPass() override = default;

    /// @brief Возвращает имя прохода.
    [[nodiscard]] std::string_view name() const noexcept override {
        return "MutationPass";
    }

    /// @brief Категория — мутация.
    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::mutation;
    }

    /// @brief Приоритет — 100 (ранний проход).
    [[nodiscard]] uint32_t priority() const noexcept override {
        return 100;
    }

    /**
     * @brief Выполняет мутацию всех маркированных регионов.
     * @param ctx Контекст пайплайна.
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;

    /**
     * @brief Проверяет применимость: config.enable_mutation == true.
     * @param ctx Контекст пайплайна.
     * @return true если мутация включена.
     */
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
