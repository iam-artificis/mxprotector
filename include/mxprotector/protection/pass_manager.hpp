/**
 * @file pass_manager.hpp
 * @brief [BUILDER] Менеджер проходов защиты — оркестрация пайплайна.
 *
 * @details PassManager регистрирует проходы защиты (IProtectionPass) и управляет
 *          их выполнением: сортировка по приоритету, проверка применимости,
 *          последовательное выполнение с логированием имени и длительности каждого прохода.
 *          Поддерживает выполнение всех проходов или только выбранной категории.
 *
 * @note Проходы выполняются в порядке возрастания priority().
 *       Неприменимые проходы (is_applicable() = false) пропускаются с логом.
 *       Первый сбой прерывает выполнение и возвращает ошибку.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

/**
 * @brief Менеджер проходов защиты — регистрация и оркестрация.
 *
 * @details Владеет всеми зарегистрированными проходами через unique_ptr.
 *          Обеспечивает выполнение в корректном порядке с полным логированием.
 *
 *          SOLID (OCP): новые проходы добавляются через register_pass без
 *          модификации менеджера.
 *          SOLID (DIP): менеджер зависит от абстракции IProtectionPass.
 */
class PassManager final {
public:
    PassManager() = default;
    ~PassManager() = default;

    PassManager(const PassManager&) = delete;
    PassManager& operator=(const PassManager&) = delete;
    PassManager(PassManager&&) noexcept = default;
    PassManager& operator=(PassManager&&) noexcept = default;

    /**
     * @brief Регистрирует проход защиты.
     * @param pass Уникальный указатель на проход (владение передаётся).
     */
    void register_pass(std::unique_ptr<IProtectionPass> pass);

    /**
     * @brief Выполняет все зарегистрированные проходы в порядке приоритета.
     * @param ctx Контекст пайплайна.
     * @return MxStatus — успех или первая ошибка.
     *
     * @note Неприменимые проходы пропускаются. Каждый проход логируется.
     */
    [[nodiscard]] MxStatus execute_all(ProtectionContext& ctx);

    /**
     * @brief Выполняет только проходы указанной категории.
     * @param category Категория проходов для выполнения.
     * @param ctx Контекст пайплайна.
     * @return MxStatus — успех или первая ошибка.
     */
    [[nodiscard]] MxStatus execute_category(PassCategory category, ProtectionContext& ctx);

    /**
     * @brief Возвращает неизменяемый список зарегистрированных проходов.
     * @return Span указателей на проходы.
     */
    [[nodiscard]] std::span<const std::unique_ptr<IProtectionPass>> passes() const noexcept {
        return std::span<const std::unique_ptr<IProtectionPass>>{passes_.data(), passes_.size()};
    }

    /// @brief Количество зарегистрированных проходов.
    [[nodiscard]] size_t pass_count() const noexcept { return passes_.size(); }

private:
    std::vector<std::unique_ptr<IProtectionPass>> passes_; ///< Зарегистрированные проходы

    /**
     * @brief Сортирует проходы по приоритету (ascending).
     */
    void sort_passes();

    /**
     * @brief Выполняет один проход с логированием.
     * @param pass Указатель на проход.
     * @param ctx Контекст пайплайна.
     * @return MxStatus — результат выполнения.
     */
    [[nodiscard]] MxStatus execute_single(IProtectionPass& pass, ProtectionContext& ctx);
};

} // namespace mx
