/**
 * @file export_table.hpp
 * @brief [BUILDER] Менеджер таблицы экспортов PE — парсинг и реконструкция.
 *
 * @details ExportTableManager обеспечивает разбор таблицы экспортов из сырых байтов
 *          (IMAGE_EXPORT_DIRECTORY → ExportTable) и реконструкцию обратно в бинарный формат.
 *          Поддерживает именованные экспорты, экспорты по ординалу и forwarded exports.
 *
 * @note Все RVA-доступы строго валидируются. Forwarded exports определяются по тому,
 *       попадает ли RVA функции в диапазон директории экспортов.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx {

namespace pe {
    struct ExportTable;
}

/**
 * @brief Менеджер таблицы экспортов PE-образа.
 *
 * @details Класс без состояния — вся функциональность через статические методы.
 *          parse_exports разбирает экспорты из сырых данных,
 *          rebuild_export_table сериализует обратно в бинарный формат.
 */
class ExportTableManager {
public:
    ExportTableManager() = delete;

    /**
     * @brief Разбирает таблицу экспортов из сырых данных PE.
     * @param data Полные сырые данные файла.
     * @param export_dir_rva RVA директории экспортов (из DataDirectory[0]).
     * @param export_dir_size Размер директории экспортов.
     * @param rva_to_offset Функция конвертации RVA → FileOffset.
     * @return ExportTable с разобранными экспортами или ошибка.
     */
    [[nodiscard]] static MxResult<pe::ExportTable> parse_exports(
        ByteView data,
        Rva export_dir_rva,
        uint32_t export_dir_size,
        std::function<MxResult<FileOffset>(Rva)> rva_to_offset);

    /**
     * @brief Реконструирует бинарную таблицу экспортов из высокоуровневого представления.
     * @param exports Таблица экспортов для сериализации.
     * @return ByteBuffer с готовой таблицей экспортов или ошибка.
     */
    [[nodiscard]] static MxResult<ByteBuffer> rebuild_export_table(
        const pe::ExportTable& exports);

private:
    /**
     * @brief Безопасно читает ASCIIZ-строку из буфера по файловому смещению.
     * @param data Сырые данные файла.
     * @param offset Файловое смещение начала строки.
     * @param max_len Максимальная длина строки.
     * @return Прочитанная строка или ошибка.
     */
    [[nodiscard]] static MxResult<std::string> read_ascii_string(
        ByteView data, FileOffset offset, size_t max_len = 512);
};

} // namespace mx
