/**
 * @file import_table.hpp
 * @brief [BUILDER] Менеджер таблицы импортов PE — парсинг, модификация, реконструкция.
 *
 * @details ImportTableManager обеспечивает полный цикл работы с таблицей импортов PE:
 *          разбор из сырых байтов (IMAGE_IMPORT_DESCRIPTOR → ImportEntry),
 *          добавление/удаление отдельных импортов, реконструкция в бинарный формат.
 *          Поддерживает как PE32 (32-bit thunks), так и PE32+ (64-bit thunks).
 *
 * @note Статические методы parse_imports и rebuild_import_table работают автономно.
 *       Методы add_import/remove_import модифицируют PeImage через хранимую ссылку.
 *       Все RVA-доступы строго валидируются — ни одно чтение не выходит за границы.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <functional>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx {

/**
 * @brief Менеджер таблицы импортов PE-образа.
 *
 * @details Предоставляет статические методы для парсинга и реконструкции
 *          таблицы импортов, а также экземплярные методы для модификации
 *          импортов конкретного PeImage.
 */
class ImportTableManager {
public:
    /**
     * @brief Конструктор с привязкой к PeImage.
     * @param image Ссылка на PeImage для модификации.
     */
    explicit ImportTableManager(PeImage& image) noexcept : image_(image) {}

    /**
     * @brief Разбирает таблицу импортов из сырых данных PE.
     * @param data Полные сырые данные файла.
     * @param import_dir_rva RVA директории импортов (из DataDirectory[1]).
     * @param import_dir_size Размер директории импортов.
     * @param is_64 true для PE32+ (64-bit thunks).
     * @param rva_to_offset Функция конвертации RVA → FileOffset.
     * @return Вектор ImportEntry или ошибка при повреждённых данных.
     */
    [[nodiscard]] static MxResult<std::vector<pe::ImportEntry>> parse_imports(
        ByteView data,
        Rva import_dir_rva,
        uint32_t import_dir_size,
        bool is_64,
        std::function<MxResult<FileOffset>(Rva)> rva_to_offset);

    /**
     * @brief Добавляет импортируемую функцию в таблицу импортов PeImage.
     * @param dll_name Имя DLL (например, "kernel32.dll").
     * @param function_name Имя функции (например, "VirtualAlloc").
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus add_import(std::string_view dll_name, std::string_view function_name);

    /**
     * @brief Удаляет импортируемую функцию из таблицы импортов PeImage.
     * @param dll_name Имя DLL.
     * @param function_name Имя функции.
     * @return Успех или ошибка (функция не найдена).
     */
    [[nodiscard]] MxStatus remove_import(std::string_view dll_name, std::string_view function_name);

    /**
     * @brief Реконструирует бинарную таблицу импортов из высокоуровневого представления.
     * @param imports Вектор ImportEntry для сериализации.
     * @param file_alignment Файловое выравнивание PE.
     * @return ByteBuffer с готовой таблицей импортов или ошибка.
     */
    [[nodiscard]] static MxResult<ByteBuffer> rebuild_import_table(
        const std::vector<pe::ImportEntry>& imports,
        uint32_t file_alignment);

private:
    PeImage& image_; ///< Ссылка на модифицируемый PeImage

    /**
     * @brief Разбирает thunk-массив (INT/IAT) для одного дескриптора импорта.
     * @param data Сырые данные файла.
     * @param thunk_rva RVA первого thunk-элемента.
     * @param is_64 true для 64-bit thunks.
     * @param rva_to_offset Конвертер RVA → FileOffset.
     * @return Вектор ImportFunction или ошибка.
     */
    [[nodiscard]] static MxResult<std::vector<pe::ImportFunction>> parse_thunks(
        ByteView data,
        Rva thunk_rva,
        bool is_64,
        const std::function<MxResult<FileOffset>(Rva)>& rva_to_offset);

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
