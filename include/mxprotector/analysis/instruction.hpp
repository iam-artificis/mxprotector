/**
 * @file instruction.hpp
 * @brief [BUILDER] Обёртка над декодированной инструкцией x86/x64, не зависящая от Zydis.
 *
 * @details Класс Instruction хранит результат декодирования одной машинной инструкции:
 *          виртуальный адрес, длину, сырые байты, мнемонику, текст операндов,
 *          классификацию (ветвление, вызов, возврат) и целевые адреса переходов.
 *          Используется как единица данных во всех модулях анализа (CFG, маркеры и т.д.).
 *          Полностью изолирован от деталей конкретного дизассемблера.
 *
 * @note Все поля неизменяемы после конструирования (immutable value object).
 *       Перемещение поддерживается для эффективной работы с контейнерами.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::analysis {

/**
 * @brief Высокоуровневое представление одной машинной инструкции x86/x64.
 *
 * @details Абстрагирует детали конкретного дизассемблера (Zydis, Capstone и т.д.).
 *          Хранит всю необходимую информацию для построения CFG, определения
 *          границ базовых блоков и анализа потока управления.
 */
class Instruction final {
public:
    /**
     * @brief Конструктор с полной инициализацией всех полей.
     * @param address Виртуальный адрес инструкции.
     * @param length Длина инструкции в байтах.
     * @param raw_bytes Сырые закодированные байты инструкции.
     * @param mnemonic Мнемоника (например, "mov", "push", "jmp").
     * @param operands_text Форматированный текст операндов.
     * @param is_branch Является ли инструкция ветвлением (jmp/jcc/call/ret).
     * @param is_conditional_branch Является ли условным переходом (jcc).
     * @param is_call Является ли вызовом (call).
     * @param is_return Является ли возвратом (ret/retn).
     * @param is_unconditional_jump Является ли безусловным переходом (jmp).
     * @param branch_targets Целевые адреса ветвлений.
     */
    Instruction(Va address,
                uint8_t length,
                ByteBuffer raw_bytes,
                std::string mnemonic,
                std::string operands_text,
                bool is_branch,
                bool is_conditional_branch,
                bool is_call,
                bool is_return,
                bool is_unconditional_jump,
                std::vector<Va> branch_targets)
        : address_(address)
        , length_(length)
        , raw_bytes_(std::move(raw_bytes))
        , mnemonic_(std::move(mnemonic))
        , operands_text_(std::move(operands_text))
        , is_branch_(is_branch)
        , is_conditional_branch_(is_conditional_branch)
        , is_call_(is_call)
        , is_return_(is_return)
        , is_unconditional_jump_(is_unconditional_jump)
        , branch_targets_(std::move(branch_targets))
    {}

    ~Instruction() = default;
    Instruction(const Instruction&) = default;
    Instruction& operator=(const Instruction&) = default;
    Instruction(Instruction&&) noexcept = default;
    Instruction& operator=(Instruction&&) noexcept = default;

    // ====================================================================
    // Геттеры
    // ====================================================================

    /// @brief Виртуальный адрес инструкции.
    [[nodiscard]] Va address() const noexcept { return address_; }

    /// @brief Длина инструкции в байтах.
    [[nodiscard]] uint8_t length() const noexcept { return length_; }

    /// @brief Адрес следующей инструкции (address + length).
    [[nodiscard]] Va next_address() const noexcept { return address_ + length_; }

    /// @brief Неизменяемое представление сырых байтов инструкции.
    [[nodiscard]] ByteView raw_bytes() const noexcept {
        return ByteView{raw_bytes_.data(), raw_bytes_.size()};
    }

    /// @brief Мнемоника инструкции (нижний регистр).
    [[nodiscard]] std::string_view mnemonic() const noexcept { return mnemonic_; }

    /// @brief Форматированный текст операндов.
    [[nodiscard]] std::string_view operands_text() const noexcept { return operands_text_; }

    /// @brief Полная текстовая запись: "мнемоника операнды".
    [[nodiscard]] std::string to_string() const {
        if (operands_text_.empty()) {
            return mnemonic_;
        }
        return mnemonic_ + " " + operands_text_;
    }

    // ====================================================================
    // Классификация
    // ====================================================================

    /// @brief Является ли инструкция любым ветвлением (jmp, jcc, call, ret).
    [[nodiscard]] bool is_branch() const noexcept { return is_branch_; }

    /// @brief Является ли условным переходом (jcc: je, jne, jl, jge и т.д.).
    [[nodiscard]] bool is_conditional_branch() const noexcept { return is_conditional_branch_; }

    /// @brief Является ли инструкцией вызова (call).
    [[nodiscard]] bool is_call() const noexcept { return is_call_; }

    /// @brief Является ли инструкцией возврата (ret/retn).
    [[nodiscard]] bool is_return() const noexcept { return is_return_; }

    /// @brief Является ли безусловным переходом (jmp).
    [[nodiscard]] bool is_unconditional_jump() const noexcept { return is_unconditional_jump_; }

    /**
     * @brief Является ли инструкция терминатором базового блока.
     * @return true если это ветвление или возврат.
     */
    [[nodiscard]] bool is_terminator() const noexcept {
        return is_branch_ || is_return_;
    }

    /// @brief Целевые адреса ветвлений (пуст для не-ветвлений).
    [[nodiscard]] const std::vector<Va>& branch_targets() const noexcept {
        return branch_targets_;
    }

private:
    Va                address_;                ///< Виртуальный адрес
    uint8_t           length_;                 ///< Длина инструкции в байтах
    ByteBuffer        raw_bytes_;              ///< Сырые закодированные байты
    std::string       mnemonic_;               ///< Мнемоника (например, "mov")
    std::string       operands_text_;          ///< Форматированные операнды
    bool              is_branch_;              ///< Любое ветвление (jmp, jcc, call, ret)
    bool              is_conditional_branch_;  ///< Условный переход (jcc)
    bool              is_call_;                ///< Вызов (call)
    bool              is_return_;              ///< Возврат (ret/retn)
    bool              is_unconditional_jump_;  ///< Безусловный переход (jmp)
    std::vector<Va>   branch_targets_;         ///< Целевые адреса переходов
};

} // namespace mx::analysis
