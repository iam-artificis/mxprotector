/**
 * @file disassembler.hpp
 * @brief [BUILDER] Интерфейс дизассемблера и реализация на базе Zydis.
 *
 * @details Определяет абстрактный интерфейс IDisassembler для декодирования
 *          машинных инструкций x86/x64. Конкретная реализация ZydisDisassembler
 *          использует библиотеку Zydis (ZydisDecoder + ZydisFormatter).
 *          Интерфейс позволяет подменять дизассемблер в тестах и при необходимости
 *          использовать альтернативные движки (Capstone и т.д.).
 *
 * @note ZydisDisassembler инициализируется под конкретную архитектуру (x86/x64).
 *       Все ошибки декодирования возвращаются через MxResult.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/analysis/instruction.hpp"

namespace mx::analysis {

/**
 * @brief Абстрактный интерфейс дизассемблера x86/x64.
 *
 * @details Предоставляет операции декодирования: одна инструкция (decode_one)
 *          и буфер инструкций (decode_buffer). Конкретные реализации
 *          могут использовать разные движки декодирования.
 *
 *          SOLID (ISP): интерфейс минимален — только декодирование.
 *          Форматирование встроено в Instruction (to_string).
 */
class IDisassembler {
public:
    virtual ~IDisassembler() = default;

    /**
     * @brief Декодирует одну инструкцию из начала буфера.
     * @param code Буфер с машинным кодом.
     * @param address Виртуальный адрес первого байта буфера.
     * @return Декодированная инструкция или ошибка.
     */
    virtual MxResult<Instruction> decode_one(ByteView code, Va address) = 0;

    /**
     * @brief Декодирует последовательность инструкций из буфера.
     * @param code Буфер с машинным кодом.
     * @param address Виртуальный адрес первого байта буфера.
     * @param max_instructions Максимальное количество инструкций (0 = без ограничения).
     * @return Вектор декодированных инструкций или ошибка.
     */
    virtual MxResult<std::vector<Instruction>> decode_buffer(
        ByteView code, Va address, size_t max_instructions = 0) = 0;

    /**
     * @brief Возвращает архитектуру, для которой настроен дизассемблер.
     * @return Architecture::x86 или Architecture::x64.
     */
    [[nodiscard]] virtual Architecture architecture() const noexcept = 0;
};

/**
 * @brief Реализация дизассемблера на базе библиотеки Zydis.
 *
 * @details Инкапсулирует ZydisDecoder и ZydisFormatter. Инициализируется
 *          под конкретную архитектуру. Декодирование преобразует внутренние
 *          структуры Zydis в абстрактный Instruction.
 *
 * @note Класс final — не предназначен для наследования.
 *       Реализация в src/builder/analysis/zydis_disassembler.cpp.
 */
class ZydisDisassembler final : public IDisassembler {
public:
    /**
     * @brief Конструктор с указанием целевой архитектуры.
     * @param arch Архитектура (x86 или x64).
     */
    explicit ZydisDisassembler(Architecture arch);
    ~ZydisDisassembler() override;

    ZydisDisassembler(const ZydisDisassembler&) = delete;
    ZydisDisassembler& operator=(const ZydisDisassembler&) = delete;
    ZydisDisassembler(ZydisDisassembler&&) noexcept;
    ZydisDisassembler& operator=(ZydisDisassembler&&) noexcept;

    /// @copydoc IDisassembler::decode_one
    MxResult<Instruction> decode_one(ByteView code, Va address) override;

    /// @copydoc IDisassembler::decode_buffer
    MxResult<std::vector<Instruction>> decode_buffer(
        ByteView code, Va address, size_t max_instructions = 0) override;

    /// @copydoc IDisassembler::architecture
    [[nodiscard]] Architecture architecture() const noexcept override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_; ///< PIMPL для изоляции заголовков Zydis
};

} // namespace mx::analysis
