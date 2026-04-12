/**
 * @file virtualization_pass.hpp
 * @brief [BUILDER] VirtualizationPass — IProtectionPass для x64 виртуализации.
 *
 * Для каждого маркированного региона MX_VM_BEGIN..MX_VM_END:
 *   1. Лифтит сырые байты региона в VmInstruction (VmLifter)
 *   2. Генерирует VM runtime через VmRuntimeGenerator
 *   3. Размещает runtime в новой секции .mxvm
 *   4. Заменяет оригинальный регион JMP rel32 на vm_entry + INT3 паддинг
 *   5. Стирает SDK-маркеры (begin/end) из .text
 *
 * После выполнения VM control-flow возвращается через CALL/RET обратно
 * в .text к инструкции, следующей сразу за end-маркером.
 *
 * Priority: 300 (virtualization — ДО CFG flattening и encryption).
 */

#pragma once

#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

class VirtualizationPass final : public IProtectionPass {
public:
    VirtualizationPass() = default;
    ~VirtualizationPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "VirtualizationPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::virtualization;
    }

    [[nodiscard]] uint32_t priority() const noexcept override {
        return 300;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
