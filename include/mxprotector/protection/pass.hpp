/**
 * @file pass.hpp
 * @brief [BUILDER] Абстрактный интерфейс прохода защиты (IProtectionPass).
 *
 * @details Каждый проход защиты (мутация, обфускация, VM, шифрование и т.д.)
 *          реализует этот интерфейс. PassManager оркестрирует выполнение проходов:
 *          сортирует по приоритету, проверяет применимость (is_applicable),
 *          вызывает execute и логирует результат.
 *
 * @note Порядок выполнения определяется priority() — меньшее значение = раньше.
 *       Проход может отказаться от выполнения через is_applicable() = false.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"

namespace mx {

class ProtectionContext;

/**
 * @brief Абстрактный интерфейс прохода защиты.
 *
 * @details Контракт для всех проходов пайплайна:
 *          - name()           — человекочитаемое имя прохода
 *          - category()       — категория (mutation, obfuscation, vm и т.д.)
 *          - priority()       — приоритет (меньше = раньше)
 *          - is_applicable()  — проверка применимости к текущему контексту
 *          - execute()        — выполнение прохода
 *
 *          SOLID (OCP): новые проходы добавляются без модификации PassManager.
 *          SOLID (LSP): любая реализация может быть подставлена на место IProtectionPass.
 */
class IProtectionPass {
public:
    virtual ~IProtectionPass() = default;

    /**
     * @brief Уникальное имя прохода (для логирования и диагностики).
     * @return Строковое представление имени.
     */
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /**
     * @brief Категория прохода.
     * @return PassCategory — определяет группу прохода.
     */
    [[nodiscard]] virtual PassCategory category() const noexcept = 0;

    /**
     * @brief Приоритет выполнения (меньшее значение = ранее в пайплайне).
     * @return Числовой приоритет.
     *
     * @note Рекомендуемые диапазоны:
     *       0-99:   подготовительные (analysis, marker scanning)
     *       100-199: мутация
     *       200-299: обфускация
     *       300-399: виртуализация
     *       400-499: CFG-трансформации
     *       500-599: anti-analysis
     *       600-699: шифрование
     *       700-799: упаковка
     *       800-899: stub injection
     *       900+:    финализация
     */
    [[nodiscard]] virtual uint32_t priority() const noexcept = 0;

    /**
     * @brief Выполняет проход защиты над контекстом.
     * @param ctx Разделяемый мутабельный контекст пайплайна.
     * @return MxStatus — успех или ошибка выполнения.
     */
    [[nodiscard]] virtual MxStatus execute(ProtectionContext& ctx) = 0;

    /**
     * @brief Проверяет, применим ли проход к текущему контексту.
     * @param ctx Константный контекст пайплайна.
     * @return true если проход может быть выполнен.
     *
     * @note Вызывается PassManager перед execute().
     *       Проход может проверять конфигурацию, наличие маркеров,
     *       архитектуру и другие условия.
     */
    [[nodiscard]] virtual bool is_applicable(const ProtectionContext& ctx) const noexcept = 0;
};

} // namespace mx
