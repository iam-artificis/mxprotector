/**
 * @file basic_block.hpp
 * @brief [BUILDER] Базовый блок графа потока управления (CFG).
 *
 * @details BasicBlock — это линейная последовательность инструкций без ветвлений
 *          посередине: вход только через первую инструкцию, выход — только через
 *          последнюю (терминатор). Каждый блок хранит уникальный идентификатор,
 *          диапазон адресов, список инструкций и связи с предшественниками/преемниками.
 *
 * @note Идентификаторы блоков (id_) уникальны в пределах одного ControlFlowGraph.
 *       Связи (successors_, predecessors_) хранятся как id блоков, а не указатели,
 *       для безопасности при перемещении/копировании графа.
 */

#pragma once

#include <cstdint>
#include <vector>
#include <algorithm>

#include "mxprotector/core/types.hpp"
#include "mxprotector/analysis/instruction.hpp"

namespace mx::analysis {

/**
 * @brief Базовый блок — линейная последовательность инструкций в CFG.
 *
 * @details Инварианты:
 *          - Все инструкции имеют последовательные адреса (без пробелов).
 *          - Терминатор (ветвление/возврат) может быть только последней инструкцией.
 *          - Вход в блок — только через start_address.
 *          - successors_ содержит id блоков, в которые передаётся управление.
 *          - predecessors_ содержит id блоков, из которых управление приходит.
 */
class BasicBlock final {
public:
    /**
     * @brief Конструктор с обязательным идентификатором и стартовым адресом.
     * @param id Уникальный идентификатор блока в графе.
     * @param start_address Виртуальный адрес первой инструкции блока.
     */
    explicit BasicBlock(uint32_t id, Va start_address)
        : id_(id)
        , start_address_(start_address)
        , end_address_(start_address)
    {}

    ~BasicBlock() = default;
    BasicBlock(const BasicBlock&) = default;
    BasicBlock& operator=(const BasicBlock&) = default;
    BasicBlock(BasicBlock&&) noexcept = default;
    BasicBlock& operator=(BasicBlock&&) noexcept = default;

    // ====================================================================
    // Основные свойства
    // ====================================================================

    /// @brief Уникальный идентификатор блока в графе.
    [[nodiscard]] uint32_t id() const noexcept { return id_; }

    /// @brief Виртуальный адрес первой инструкции.
    [[nodiscard]] Va start_address() const noexcept { return start_address_; }

    /// @brief Виртуальный адрес конца блока (адрес после последнего байта последней инструкции).
    [[nodiscard]] Va end_address() const noexcept { return end_address_; }

    /// @brief Размер блока в байтах.
    [[nodiscard]] uint64_t size() const noexcept { return end_address_ - start_address_; }

    /// @brief Проверяет, пуст ли блок (нет инструкций).
    [[nodiscard]] bool empty() const noexcept { return instructions_.empty(); }

    /// @brief Количество инструкций в блоке.
    [[nodiscard]] size_t instruction_count() const noexcept { return instructions_.size(); }

    // ====================================================================
    // Инструкции
    // ====================================================================

    /// @brief Неизменяемый доступ к списку инструкций.
    [[nodiscard]] const std::vector<Instruction>& instructions() const noexcept {
        return instructions_;
    }

    /// @brief Изменяемый доступ к списку инструкций.
    [[nodiscard]] std::vector<Instruction>& instructions() noexcept {
        return instructions_;
    }

    /**
     * @brief Добавляет инструкцию в конец блока.
     * @param insn Инструкция для добавления.
     * @note Обновляет end_address_ по адресу + длине добавленной инструкции.
     */
    void add_instruction(Instruction insn) {
        end_address_ = insn.address() + insn.length();
        instructions_.push_back(std::move(insn));
    }

    /**
     * @brief Проверяет, содержит ли блок указанный адрес.
     * @param address Виртуальный адрес для проверки.
     * @return true если address ∈ [start_address_, end_address_).
     */
    [[nodiscard]] bool contains_address(Va address) const noexcept {
        return address >= start_address_ && address < end_address_;
    }

    /**
     * @brief Возвращает последнюю инструкцию блока (терминатор).
     * @return Указатель на последнюю инструкцию или nullptr если блок пуст.
     */
    [[nodiscard]] const Instruction* terminator() const noexcept {
        if (instructions_.empty()) return nullptr;
        return &instructions_.back();
    }

    // ====================================================================
    // Связи в графе
    // ====================================================================

    /// @brief Идентификаторы блоков-преемников (куда переходит управление).
    [[nodiscard]] const std::vector<uint32_t>& successors() const noexcept {
        return successors_;
    }

    /// @brief Идентификаторы блоков-предшественников (откуда приходит управление).
    [[nodiscard]] const std::vector<uint32_t>& predecessors() const noexcept {
        return predecessors_;
    }

    /**
     * @brief Добавляет идентификатор блока-преемника (если ещё не добавлен).
     * @param successor_id Идентификатор преемника.
     */
    void add_successor(uint32_t successor_id) {
        if (std::ranges::find(successors_, successor_id) == successors_.end()) {
            successors_.push_back(successor_id);
        }
    }

    /**
     * @brief Добавляет идентификатор блока-предшественника (если ещё не добавлен).
     * @param predecessor_id Идентификатор предшественника.
     */
    void add_predecessor(uint32_t predecessor_id) {
        if (std::ranges::find(predecessors_, predecessor_id) == predecessors_.end()) {
            predecessors_.push_back(predecessor_id);
        }
    }

private:
    uint32_t              id_;              ///< Уникальный идентификатор
    Va                    start_address_;   ///< Адрес первой инструкции
    Va                    end_address_;     ///< Адрес после последнего байта
    std::vector<Instruction>  instructions_;///< Упорядоченные инструкции
    std::vector<uint32_t> successors_;      ///< ID блоков-преемников
    std::vector<uint32_t> predecessors_;    ///< ID блоков-предшественников
};

} // namespace mx::analysis
