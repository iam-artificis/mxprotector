/**
 * @file pass_manager.cpp
 * @brief [BUILDER] Реализация менеджера проходов защиты.
 *
 * @details Содержит логику регистрации, сортировки и последовательного
 *          выполнения проходов защиты. Каждый проход логируется: имя,
 *          категория, время выполнения. Неприменимые проходы пропускаются.
 *          Первый сбой прерывает цепочку выполнения.
 *
 * @note Время выполнения измеряется через std::chrono::high_resolution_clock.
 */

#include "mxprotector/protection/pass_manager.hpp"
#include "mxprotector/core/context.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <ranges>

namespace mx {

// ============================================================================
// register_pass
// ============================================================================

void PassManager::register_pass(std::unique_ptr<IProtectionPass> pass) {
    if (pass) {
        passes_.push_back(std::move(pass));
    }
}

// ============================================================================
// execute_all
// ============================================================================

MxStatus PassManager::execute_all(ProtectionContext& ctx) {
    if (passes_.empty()) {
        ctx.log("PassManager: нет зарегистрированных проходов, пропуск");
        return {};
    }

    sort_passes();

    ctx.log_fmt("PassManager: начало выполнения {} проходов", passes_.size());

    for (auto& pass : passes_) {
        if (!pass->is_applicable(ctx)) {
            ctx.log_fmt("  [ПРОПУСК] {} (не применим к текущему контексту)", pass->name());
            continue;
        }

        auto result = execute_single(*pass, ctx);
        if (!result) {
            ctx.log_fmt("  [ОШИБКА] {} завершился с ошибкой: {}", pass->name(), result.error().message());
            return result;
        }
    }

    ctx.log("PassManager: все проходы выполнены успешно");
    return {};
}

// ============================================================================
// execute_category
// ============================================================================

MxStatus PassManager::execute_category(PassCategory category, ProtectionContext& ctx) {
    sort_passes();

    uint32_t executed_count = 0;

    for (auto& pass : passes_) {
        if (pass->category() != category) continue;

        if (!pass->is_applicable(ctx)) {
            ctx.log_fmt("  [ПРОПУСК] {} (не применим)", pass->name());
            continue;
        }

        auto result = execute_single(*pass, ctx);
        if (!result) {
            ctx.log_fmt("  [ОШИБКА] {} завершился с ошибкой: {}", pass->name(), result.error().message());
            return result;
        }

        ++executed_count;
    }

    if (executed_count == 0) {
        ctx.log_fmt("PassManager: нет применимых проходов категории {}", static_cast<int>(category));
    }

    return {};
}

// ============================================================================
// sort_passes — сортировка по приоритету
// ============================================================================

void PassManager::sort_passes() {
    std::ranges::sort(passes_, [](const auto& a, const auto& b) {
        return a->priority() < b->priority();
    });
}

// ============================================================================
// execute_single — выполнение одного прохода с замером времени
// ============================================================================

MxStatus PassManager::execute_single(IProtectionPass& pass, ProtectionContext& ctx) {
    const auto start_time = std::chrono::high_resolution_clock::now();

    auto result = pass.execute(ctx);

    const auto end_time = std::chrono::high_resolution_clock::now();
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();

    if (result) {
        ctx.log_fmt("  [OK] {} (приоритет: {}, время: {}мс)",
            pass.name(), pass.priority(), duration_ms);
    }

    return result;
}

} // namespace mx
