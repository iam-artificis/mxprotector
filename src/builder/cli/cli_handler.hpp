/**
 * @file cli_handler.hpp
 * @brief [BUILDER] Обработчик аргументов командной строки.
 *
 * @details CliHandler парсит аргументы CLI и формирует ProtectionConfig.
 *          Поддерживает: --input/-i, --output/-o, --level/-l, флаги отключения
 *          проходов (--no-vm, --no-mutation и т.д.), --help/-h, --version/-v.
 *          Выводит баннер, справку и версию.
 *
 * @note Класс без состояния — вся функциональность через статические методы.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/config/protection_config.hpp"

namespace mx {

/**
 * @brief Обработчик аргументов командной строки MxProtector.
 *
 * @details Парсит массив argv в ProtectionConfig. При невалидных аргументах
 *          возвращает MxError с описанием проблемы.
 */
class CliHandler {
public:
    CliHandler() = delete;

    /**
     * @brief Парсит аргументы командной строки в ProtectionConfig.
     * @param argc Количество аргументов.
     * @param argv Массив аргументов.
     * @return ProtectionConfig или ошибка.
     *
     * @note При --help или --version возвращает ошибку с кодом config
     *       и специальным сообщением (не является реальной ошибкой).
     */
    [[nodiscard]] static MxResult<ProtectionConfig> parse_args(int argc, char** argv);

    /// @brief Выводит баннер MxProtector в stdout.
    static void print_banner();

    /// @brief Выводит справку по аргументам в stdout.
    static void print_usage();

    /// @brief Выводит версию в stdout.
    static void print_version();

private:
    /**
     * @brief Парсит строку уровня защиты в ProtectionLevel.
     * @param level_str Строка уровня ("minimal", "standard", "strong", "maximum").
     * @return ProtectionLevel или ошибка.
     */
    [[nodiscard]] static MxResult<ProtectionLevel> parse_level(std::string_view level_str);
};

} // namespace mx
