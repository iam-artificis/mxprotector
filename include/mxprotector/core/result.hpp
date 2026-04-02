/**
 * @file result.hpp
 * @brief [BUILDER/STUB/SDK] Система обработки ошибок на базе std::expected.
 *
 * @details Реализует монадическую обработку ошибок без исключений.
 *          MxError хранит категорию, числовой код и текстовое описание.
 *          MxResult<T> = std::expected<T, MxError> — основной возвращаемый тип.
 *          MxStatus = MxResult<void> — для операций без возвращаемого значения.
 *
 * @note Исключения запрещены в STUB. В BUILDER также предпочитаем std::expected
 *       для единообразия и предсказуемости потока управления.
 */

#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <format>
#include <utility>
#include <source_location>

namespace mx {

/**
 * @brief Категория ошибки — определяет модуль-источник.
 * @details Позволяет фильтровать и маршрутизировать ошибки по подсистемам.
 */
enum class ErrorCategory : uint8_t {
    pe_parsing   = 0,  ///< Ошибки парсинга PE-файла
    pe_building  = 1,  ///< Ошибки сборки PE-файла
    disassembly  = 2,  ///< Ошибки дизассемблирования
    cfg_analysis = 3,  ///< Ошибки анализа потока управления
    protection   = 4,  ///< Ошибки проходов защиты
    encryption   = 5,  ///< Ошибки шифрования/дешифрования
    io           = 6,  ///< Ошибки ввода-вывода (файлы, потоки)
    config       = 7,  ///< Ошибки конфигурации
    marker       = 8   ///< Ошибки сканирования SDK-маркеров
};

/**
 * @brief Коды ошибок PE-парсинга.
 */
enum class PeErrorCode : uint16_t {
    invalid_dos_signature        = 100, ///< e_magic != 0x5A4D
    invalid_nt_signature         = 101, ///< Signature != 0x00004550
    invalid_optional_header      = 102, ///< Magic не 0x10B и не 0x20B
    lfanew_out_of_bounds         = 103, ///< e_lfanew указывает за пределы файла
    section_out_of_bounds        = 104, ///< Секция выходит за границы файла
    invalid_rva                  = 105, ///< RVA не принадлежит ни одной секции
    invalid_import_table         = 106, ///< Повреждена таблица импортов
    invalid_export_table         = 107, ///< Повреждена таблица экспортов
    invalid_relocation_table     = 108, ///< Повреждена таблица релокаций
    invalid_tls_directory        = 109, ///< Повреждена TLS-директория
    unsupported_architecture     = 110, ///< Неподдерживаемая архитектура (не x86/x64)
    file_too_small               = 111, ///< Файл меньше минимального размера PE
    corrupted_data_directory     = 112, ///< Повреждён элемент DataDirectory
    section_alignment_violation  = 113  ///< Нарушение выравнивания секции
};

/**
 * @brief Коды ошибок дизассемблирования.
 */
enum class DisasmErrorCode : uint16_t {
    invalid_instruction = 200, ///< Невалидная инструкция
    buffer_too_small    = 201, ///< Буфер слишком мал для декодирования
    unsupported_mode    = 202  ///< Неподдерживаемый режим (16-bit)
};

/**
 * @brief Коды ошибок защиты.
 */
enum class ProtectionErrorCode : uint16_t {
    pass_failed          = 300, ///< Проход защиты завершился с ошибкой
    marker_not_found     = 301, ///< SDK-маркер не найден
    marker_mismatch      = 302, ///< Непарный маркер (begin без end)
    region_too_small     = 303, ///< Маркированный регион слишком мал
    vm_translation_error = 304, ///< Ошибка трансляции в VM bytecode
    cfg_build_error      = 305  ///< Ошибка построения CFG
};

/**
 * @brief Универсальная ошибка проекта MxProtector.
 *
 * @details Хранит категорию (модуль-источник), числовой код ошибки
 *          и человекочитаемое описание. Легковесна для копирования.
 *          Поддерживает форматирование через std::format.
 */
class MxError final {
public:
    /// @brief Конструктор с категорией, кодом и сообщением.
    MxError(ErrorCategory category, uint16_t code, std::string message)
        : category_(category)
        , code_(code)
        , message_(std::move(message))
    {}

    /// @brief Конструктор с категорией, типизированным кодом PE и сообщением.
    MxError(PeErrorCode code, std::string message)
        : category_(ErrorCategory::pe_parsing)
        , code_(static_cast<uint16_t>(code))
        , message_(std::move(message))
    {}

    /// @brief Конструктор с кодом дизассемблирования.
    MxError(DisasmErrorCode code, std::string message)
        : category_(ErrorCategory::disassembly)
        , code_(static_cast<uint16_t>(code))
        , message_(std::move(message))
    {}

    /// @brief Конструктор с кодом защиты.
    MxError(ProtectionErrorCode code, std::string message)
        : category_(ErrorCategory::protection)
        , code_(static_cast<uint16_t>(code))
        , message_(std::move(message))
    {}

    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] uint16_t code() const noexcept { return code_; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

    /**
     * @brief Форматированное строковое представление ошибки.
     * @return Строка вида "[PE_PARSING:105] Invalid RVA 0x1234"
     */
    [[nodiscard]] std::string format() const {
        return std::format("[{}:{}] {}",
            category_name(), code_, message_);
    }

private:
    ErrorCategory category_;
    uint16_t      code_;
    std::string   message_;

    /// @brief Возвращает строковое имя категории.
    [[nodiscard]] std::string_view category_name() const noexcept {
        switch (category_) {
            case ErrorCategory::pe_parsing:   return "PE_PARSING";
            case ErrorCategory::pe_building:  return "PE_BUILDING";
            case ErrorCategory::disassembly:  return "DISASM";
            case ErrorCategory::cfg_analysis: return "CFG";
            case ErrorCategory::protection:   return "PROTECTION";
            case ErrorCategory::encryption:   return "ENCRYPTION";
            case ErrorCategory::io:           return "IO";
            case ErrorCategory::config:       return "CONFIG";
            case ErrorCategory::marker:       return "MARKER";
            default:                          return "UNKNOWN";
        }
    }
};

// ============================================================================
// Основные типы результатов
// ============================================================================

/**
 * @brief Результат операции, возвращающей значение типа T.
 * @tparam T Тип успешного значения.
 */
template <typename T>
using MxResult = std::expected<T, MxError>;

/**
 * @brief Результат операции без возвращаемого значения (success/failure).
 */
using MxStatus = std::expected<void, MxError>;

// ============================================================================
// Фабричные функции для создания ошибок
// ============================================================================

namespace error {

/**
 * @brief Создаёт ошибку PE-парсинга.
 * @param code Код ошибки PE.
 * @param msg Описание ошибки.
 * @return MxError с категорией pe_parsing.
 */
[[nodiscard]] inline MxError pe(PeErrorCode code, std::string msg) {
    return MxError(code, std::move(msg));
}

/**
 * @brief Создаёт ошибку PE-парсинга с форматированием.
 * @tparam Args Типы аргументов форматирования.
 * @param code Код ошибки PE.
 * @param fmt Строка формата.
 * @param args Аргументы.
 * @return MxError с категорией pe_parsing.
 */
template <typename... Args>
[[nodiscard]] MxError pe_fmt(PeErrorCode code, std::format_string<Args...> fmt, Args&&... args) {
    return MxError(code, std::format(fmt, std::forward<Args>(args)...));
}

/// @brief Создаёт ошибку дизассемблирования.
[[nodiscard]] inline MxError disasm(DisasmErrorCode code, std::string msg) {
    return MxError(code, std::move(msg));
}

/// @brief Создаёт ошибку защиты.
[[nodiscard]] inline MxError protection(ProtectionErrorCode code, std::string msg) {
    return MxError(code, std::move(msg));
}

/// @brief Создаёт ошибку ввода-вывода.
[[nodiscard]] inline MxError io(std::string msg) {
    return MxError(ErrorCategory::io, 0, std::move(msg));
}

/// @brief Создаёт ошибку конфигурации.
[[nodiscard]] inline MxError config(std::string msg) {
    return MxError(ErrorCategory::config, 0, std::move(msg));
}

} // namespace error

} // namespace mx
