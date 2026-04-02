/**
 * @file relocation_table.hpp
 * @brief [BUILDER] Менеджер таблицы релокаций PE — парсинг, добавление, реконструкция.
 *
 * @details RelocationTableManager обеспечивает полный цикл работы с таблицей
 *          базовых релокаций PE: разбор из сырых байтов (IMAGE_BASE_RELOCATION →
 *          RelocationBlock), добавление новых записей, реконструкция в бинарный формат.
 *          Каждая запись кодирует тип (4 бита) и смещение (12 бит) внутри страницы.
 *
 * @note Записи с типом IMAGE_REL_BASED_ABSOLUTE игнорируются при парсинге (padding).
 *       При реконструкции блоки дополняются padding-записями до кратности 4 байт.
 */

#pragma once

#include <cstdint>
#include <vector>
#include <functional>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx {

/**
 * @brief Менеджер таблицы базовых релокаций PE-образа.
 *
 * @details Предоставляет статические методы для парсинга и реконструкции
 *          таблицы релокаций, а также экземплярный метод для добавления
 *          новых записей релокаций в PeImage.
 */
class RelocationTableManager {
public:
    /**
     * @brief Конструктор с привязкой к PeImage.
     * @param image Ссылка на PeImage для модификации.
     */
    explicit RelocationTableManager(PeImage& image) noexcept : image_(image) {}

    /**
     * @brief Разбирает таблицу релокаций из сырых данных PE.
     * @param data Полные сырые данные файла.
     * @param reloc_dir_rva RVA директории релокаций (из DataDirectory[5]).
     * @param reloc_dir_size Размер директории релокаций.
     * @param rva_to_offset Функция конвертации RVA → FileOffset.
     * @return Вектор RelocationBlock или ошибка при повреждённых данных.
     */
    [[nodiscard]] static MxResult<std::vector<pe::RelocationBlock>> parse_relocations(
        ByteView data,
        Rva reloc_dir_rva,
        uint32_t reloc_dir_size,
        std::function<MxResult<FileOffset>(Rva)> rva_to_offset);

    /**
     * @brief Добавляет запись релокации в таблицу PeImage.
     * @param target_rva RVA целевого адреса для релокации.
     * @param type Тип релокации (IMAGE_REL_BASED_*).
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus add_relocation(Rva target_rva, uint16_t type);

    /**
     * @brief Реконструирует бинарную таблицу релокаций из высокоуровневого представления.
     * @param blocks Вектор блоков релокаций для сериализации.
     * @return ByteBuffer с готовой таблицей релокаций или ошибка.
     */
    [[nodiscard]] static MxResult<ByteBuffer> rebuild_relocation_table(
        const std::vector<pe::RelocationBlock>& blocks);

private:
    PeImage& image_; ///< Ссылка на модифицируемый PeImage
};

} // namespace mx
