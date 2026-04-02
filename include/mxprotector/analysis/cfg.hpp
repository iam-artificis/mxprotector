/**
 * @file cfg.hpp
 * @brief [BUILDER] Граф потока управления (Control Flow Graph) и его построитель.
 *
 * @details ControlFlowGraph хранит коллекцию базовых блоков (BasicBlock) и связи
 *          между ними. CfgBuilder использует IDisassembler для декодирования
 *          инструкций и построения графа рекурсивным обходом целевых адресов
 *          переходов (recursive descent disassembly).
 *
 * @note Граф строится от одной точки входа (build_function) или для всего буфера
 *       (build — линейная развёртка). Блоки идентифицируются по uint32_t id.
 *       Адреса → блоки можно найти через find_block_by_address.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/analysis/basic_block.hpp"
#include "mxprotector/analysis/disassembler.hpp"

namespace mx::analysis {

/**
 * @brief Граф потока управления — коллекция связанных базовых блоков.
 *
 * @details Хранит блоки в unordered_map по id. Предоставляет навигацию:
 *          поиск по адресу, доступ к entry-блоку, итерацию по всем блокам.
 */
class ControlFlowGraph final {
public:
    ControlFlowGraph() = default;
    ~ControlFlowGraph() = default;
    ControlFlowGraph(const ControlFlowGraph&) = default;
    ControlFlowGraph& operator=(const ControlFlowGraph&) = default;
    ControlFlowGraph(ControlFlowGraph&&) noexcept = default;
    ControlFlowGraph& operator=(ControlFlowGraph&&) noexcept = default;

    // ====================================================================
    // Доступ к блокам
    // ====================================================================

    /// @brief Количество блоков в графе.
    [[nodiscard]] size_t block_count() const noexcept { return blocks_.size(); }

    /// @brief Проверяет, пуст ли граф.
    [[nodiscard]] bool empty() const noexcept { return blocks_.empty(); }

    /// @brief Неизменяемый доступ ко всем блокам (id → BasicBlock).
    [[nodiscard]] const std::unordered_map<uint32_t, BasicBlock>& blocks() const noexcept {
        return blocks_;
    }

    /// @brief Изменяемый доступ ко всем блокам.
    [[nodiscard]] std::unordered_map<uint32_t, BasicBlock>& blocks() noexcept {
        return blocks_;
    }

    /// @brief Идентификатор входного блока графа.
    [[nodiscard]] uint32_t entry_block_id() const noexcept { return entry_block_id_; }

    /**
     * @brief Возвращает константную ссылку на входной блок.
     * @return Указатель на entry-блок или nullptr если граф пуст.
     */
    [[nodiscard]] const BasicBlock* entry_block() const noexcept {
        const auto it = blocks_.find(entry_block_id_);
        return (it != blocks_.end()) ? &it->second : nullptr;
    }

    /**
     * @brief Ищет блок, содержащий указанный виртуальный адрес.
     * @param address Виртуальный адрес для поиска.
     * @return Указатель на блок или nullptr если адрес не найден.
     */
    [[nodiscard]] const BasicBlock* find_block_by_address(Va address) const noexcept {
        for (const auto& [id, block] : blocks_) {
            if (block.contains_address(address)) {
                return &block;
            }
        }
        return nullptr;
    }

    /**
     * @brief Ищет блок по начальному адресу (точное совпадение).
     * @param start_address Стартовый адрес блока.
     * @return Указатель на блок или nullptr.
     */
    [[nodiscard]] const BasicBlock* find_block_by_start(Va start_address) const noexcept {
        for (const auto& [id, block] : blocks_) {
            if (block.start_address() == start_address) {
                return &block;
            }
        }
        return nullptr;
    }

    /**
     * @brief Возвращает блок по идентификатору.
     * @param id Идентификатор блока.
     * @return Указатель на блок или nullptr.
     */
    [[nodiscard]] const BasicBlock* block_by_id(uint32_t id) const noexcept {
        const auto it = blocks_.find(id);
        return (it != blocks_.end()) ? &it->second : nullptr;
    }

    // ====================================================================
    // Мутация (используется CfgBuilder)
    // ====================================================================

    /**
     * @brief Добавляет блок в граф.
     * @param block Блок для добавления (перемещается).
     */
    void add_block(BasicBlock block) {
        const auto id = block.id();
        blocks_.emplace(id, std::move(block));
    }

    /**
     * @brief Устанавливает идентификатор входного блока.
     * @param id Идентификатор entry-блока.
     */
    void set_entry_block_id(uint32_t id) noexcept { entry_block_id_ = id; }

private:
    std::unordered_map<uint32_t, BasicBlock> blocks_;  ///< Все блоки графа
    uint32_t entry_block_id_ = 0;                      ///< ID входного блока
};

/**
 * @brief Построитель графа потока управления (CFG).
 *
 * @details Использует IDisassembler для декодирования инструкций и строит CFG
 *          методом рекурсивного спуска (recursive descent disassembly).
 *          Начинает с адреса функции, следует по целевым адресам переходов
 *          и разделяет линейные последовательности на базовые блоки.
 *
 *          SOLID (DIP): зависит от абстракции IDisassembler, а не от конкретного Zydis.
 */
class CfgBuilder final {
public:
    /**
     * @brief Конструктор с дизассемблером.
     * @param disasm Общий указатель на дизассемблер.
     */
    explicit CfgBuilder(std::shared_ptr<IDisassembler> disasm);
    ~CfgBuilder();

    CfgBuilder(const CfgBuilder&) = delete;
    CfgBuilder& operator=(const CfgBuilder&) = delete;

    /**
     * @brief Строит CFG линейным проходом по всему буферу кода.
     * @param code Буфер машинного кода.
     * @param base_address Виртуальный адрес начала буфера.
     * @return ControlFlowGraph или ошибка.
     */
    MxResult<ControlFlowGraph> build(ByteView code, Va base_address);

    /**
     * @brief Строит CFG для одной функции рекурсивным спуском.
     * @param code Буфер машинного кода (вся секция или регион).
     * @param function_start Виртуальный адрес точки входа функции.
     * @return ControlFlowGraph или ошибка.
     */
    MxResult<ControlFlowGraph> build_function(ByteView code, Va function_start);

private:
    std::shared_ptr<IDisassembler> disasm_;    ///< Дизассемблер
    uint32_t next_block_id_ = 0;               ///< Счётчик ID блоков

    /// @brief Выделяет следующий уникальный ID блока.
    uint32_t allocate_block_id() noexcept { return next_block_id_++; }
};

} // namespace mx::analysis
