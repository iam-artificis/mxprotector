/**
 * @file pe_builder.hpp
 * @brief [BUILDER] Сборщик PE-файлов — реконструирует PE из PeImage в ByteBuffer.
 *
 * @details PeBuilder выполняет полную реконструкцию PE-файла из высокоуровневого
 *          представления PeImage: заголовки, таблица секций, данные секций (с
 *          выравниванием), пересчёт SizeOfImage/SizeOfHeaders.
 *          Предоставляет утилиту генерации выходного пути (file.exe → file.mx.exe).
 *
 * @note Выходной файл сохраняет оригинальную структуру PE с пересчитанными полями.
 *       Таблицы импорта/экспорта/релокаций берутся из данных секций PeImage.
 *       Для перестроения таблиц используйте соответствующие менеджеры перед вызовом build().
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/layout_policy.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx {

/**
 * @brief Сборщик PE-файлов из высокоуровневого представления PeImage.
 *
 * @details Класс без состояния — вся функциональность через статические методы.
 *          Метод build() собирает валидный PE-файл с корректными заголовками,
 *          выровненными секциями и пересчитанными размерами.
 *
 *          Порядок сборки:
 *          1. Запись DOS-заголовка и DOS-стаба
 *          2. Запись NT-заголовков (PE32 или PE32+)
 *          3. Запись таблицы заголовков секций
 *          4. Запись данных каждой секции с выравниванием по FileAlignment
 *          5. Пересчёт SizeOfHeaders, SizeOfImage, контрольной суммы
 */
class PeBuilder {
public:
    PeBuilder() = delete;

    /**
     * @brief Собирает PE-файл из PeImage с применением layout policy.
     *
     * R2.5 introduced the layout-policy seam: before serialisation
     * the active `ILayoutPolicy::finalize` runs against the image so
     * a chaos / merge / interleave policy can rewrite the section
     * table in one place. `StandardLayout::finalize` is a no-op so
     * existing builds keep producing byte-identical output.
     *
     * @param image  Mutable PeImage — `policy.finalize` may rewrite
     *               sections / order / characteristics in place.
     * @param policy Active layout policy. The caller (typically
     *               `main.cpp` via `ProtectionContext::layout_policy`)
     *               owns it.
     * @return       Serialised PE bytes or an `MxError` from the
     *               finalize hook / writer.
     */
    [[nodiscard]] static MxResult<ByteBuffer> build(
        PeImage&             image,
        const pe::ILayoutPolicy& policy);

    /**
     * @brief Генерирует путь выходного файла: input.exe → input.mx.exe.
     * @param input_path Путь к исходному файлу.
     * @return Путь с суффиксом ".mx" перед расширением.
     */
    [[nodiscard]] static std::filesystem::path generate_output_path(
        const std::filesystem::path& input_path);

private:
    /**
     * @brief Записывает DOS-заголовок и DOS-стаб в буфер.
     * @param output Выходной буфер.
     * @param image Исходный PeImage.
     */
    static void write_dos_header(ByteBuffer& output, const PeImage& image);

    /**
     * @brief Записывает NT-заголовки в буфер по смещению e_lfanew.
     * @param output Выходной буфер.
     * @param image Исходный PeImage.
     */
    static void write_nt_headers(ByteBuffer& output, const PeImage& image);

    /**
     * @brief Записывает таблицу заголовков секций.
     * @param output Выходной буфер.
     * @param image Исходный PeImage.
     * @param section_header_offset Смещение первого заголовка секции.
     */
    static void write_section_headers(ByteBuffer& output, const PeImage& image,
                                      uint32_t section_header_offset);

    /**
     * @brief Записывает данные секций с выравниванием.
     * @param output Выходной буфер.
     * @param image Исходный PeImage.
     */
    static void write_section_data(ByteBuffer& output, const PeImage& image);

    /**
     * @brief Пересчитывает SizeOfImage на основе секций.
     * @param image Исходный PeImage.
     * @return Выровненный размер образа в памяти.
     */
    [[nodiscard]] static uint32_t calculate_size_of_image(const PeImage& image);

    /**
     * @brief Пересчитывает SizeOfHeaders с учётом всех заголовков и таблицы секций.
     * @param image Исходный PeImage.
     * @return Выровненный размер заголовков.
     */
    [[nodiscard]] static uint32_t calculate_size_of_headers(const PeImage& image);
};

} // namespace mx
