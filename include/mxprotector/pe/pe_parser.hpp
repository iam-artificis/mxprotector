/**
 * @file pe_parser.hpp
 * @brief [BUILDER] Парсер PE-файлов — преобразует сырые байты в PeImage.
 *
 * @details PeParser выполняет полную валидацию и разбор PE-файла:
 *          DOS-заголовок, NT-заголовки, таблица секций, импорты, экспорты,
 *          релокации. Все проверки границ выполняются строго — каждый доступ
 *          по RVA/смещению валидируется относительно размера файла.
 *
 * @note Все ошибки возвращаются через MxResult/MxStatus с описательными
 *       русскоязычными сообщениями через error::pe_fmt.
 *       Парсер не модифицирует входные данные — создаёт независимый PeImage.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <functional>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx {

/**
 * @brief Парсер Portable Executable файлов.
 *
 * @details Класс без состояния — вся функциональность через статические методы.
 *          Основной метод parse() выполняет полный разбор PE и возвращает
 *          заполненный PeImage или подробную ошибку.
 *
 *          Порядок парсинга:
 *          1. Валидация DOS-заголовка (сигнатура, e_lfanew)
 *          2. Валидация NT-заголовков (сигнатура, Magic, Machine)
 *          3. Определение архитектуры и типа PE
 *          4. Разбор таблицы секций
 *          5. Разбор импортов (через ImportTableManager)
 *          6. Разбор экспортов (через ExportTableManager)
 *          7. Разбор релокаций (через RelocationTableManager)
 */
class PeParser {
public:
    PeParser() = delete;

    /**
     * @brief Парсит PE-файл из сырых байтов.
     * @param raw_data Неизменяемое представление данных файла.
     * @return PeImage — полностью разобранный образ, или MxError с описанием проблемы.
     */
    [[nodiscard]] static MxResult<PeImage> parse(ByteView raw_data);

    /**
     * @brief Pure mapping from raw PE header fields to a `PeType`.
     *
     * UEFI subsystems (10..13) outrank the DLL characteristics bit:
     * a real-world EFI runtime driver typically sets both, and
     * without this ordering it would silently parse as a user-mode
     * dynamic library and engage Win32-only passes that have no
     * business running on UEFI.
     *
     * @param characteristics  `IMAGE_FILE_HEADER.Characteristics`.
     * @param subsystem        `IMAGE_OPTIONAL_HEADER.Subsystem`.
     * @return                 `executable` / `dynamic_library` /
     *                         `kernel_driver` / `efi_application`.
     *
     * Public so unit tests can pin the mapping without going through
     * a full PE parse — the function is pure and deterministic, and
     * exposing it keeps the test surface focused.
     */
    [[nodiscard]] static PeType detect_pe_type(uint16_t characteristics, uint16_t subsystem);

private:
    /**
     * @brief Валидирует и читает DOS-заголовок.
     * @param data Сырые данные файла.
     * @return Копия DOS-заголовка или ошибка.
     */
    [[nodiscard]] static MxResult<pe::IMAGE_DOS_HEADER> parse_dos_header(ByteView data);

    /**
     * @brief Определяет архитектуру по полю Machine в FILE_HEADER.
     * @param machine Значение поля Machine.
     * @return Архитектура или ошибка для неподдерживаемых типов.
     */
    [[nodiscard]] static MxResult<Architecture> detect_architecture(uint16_t machine);

    /**
     * @brief Разбирает таблицу секций.
     * @param data Сырые данные файла.
     * @param section_header_offset Файловое смещение первого заголовка секции.
     * @param num_sections Количество секций.
     * @return Вектор SectionInfo или ошибка.
     */
    [[nodiscard]] static MxResult<std::vector<pe::SectionInfo>> parse_sections(
        ByteView data,
        uint32_t section_header_offset,
        uint16_t num_sections);

    /**
     * @brief Создаёт функцию конвертации RVA → FileOffset на основе таблицы секций.
     * @param sections Разобранные секции.
     * @param data_size Размер файла (для валидации заголовочной области).
     * @return Лямбда для конвертации RVA в файловое смещение.
     */
    [[nodiscard]] static std::function<MxResult<FileOffset>(Rva)> make_rva_converter(
        const std::vector<pe::SectionInfo>& sections,
        size_t data_size);
};

} // namespace mx
