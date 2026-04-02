/**
 * @file section_manager.hpp
 * @brief [BUILDER] Менеджер секций PE — добавление, удаление, изменение размера секций.
 *
 * @details SectionManager работает с PeImage и предоставляет операции над секциями:
 *          добавление новых секций, удаление, изменение размера, поиск code caves
 *          (пустых участков в секциях), заполнение промежутков, выравнивание.
 *          Все операции корректно обновляют метаданные в заголовках PE.
 *
 * @note Максимальное количество секций ограничено 96 (по спецификации PE).
 *       Все методы возвращают MxResult/MxStatus с детальными сообщениями об ошибках.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx {

/**
 * @brief Менеджер секций PE-образа.
 *
 * @details Предоставляет высокоуровневые операции над секциями PeImage:
 *          добавление, удаление, изменение размера, поиск незанятых участков,
 *          заполнение промежутков между секциями, выравнивание.
 *          Хранит ссылку на PeImage и модифицирует его напрямую.
 */
class SectionManager {
public:
    /**
     * @brief Конструктор с привязкой к PeImage.
     * @param image Ссылка на PeImage для модификации.
     */
    explicit SectionManager(PeImage& image) noexcept : image_(image) {}

    /**
     * @brief Добавляет новую секцию в конец таблицы секций.
     * @param name Имя секции (до 8 символов, например ".mxprot").
     * @param data Содержимое секции.
     * @param characteristics Флаги секции (IMAGE_SCN_*).
     * @return Индекс добавленной секции или ошибка.
     */
    [[nodiscard]] MxResult<uint32_t> add_section(
        std::string_view name,
        ByteView data,
        uint32_t characteristics);

    /**
     * @brief Удаляет секцию по индексу.
     * @param index Индекс секции (0-based).
     * @return Успех или ошибка (индекс за пределами).
     */
    [[nodiscard]] MxStatus remove_section(uint32_t index);

    /**
     * @brief Изменяет размер секции (расширяет или сжимает).
     * @param index Индекс секции (0-based).
     * @param new_size Новый размер данных в байтах.
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus resize_section(uint32_t index, uint32_t new_size);

    /**
     * @brief Ищет code caves — участки заполненные нулями/0xCC внутри секций.
     * @param min_size Минимальный размер cave в байтах.
     * @return Вектор диапазонов адресов найденных caves.
     */
    [[nodiscard]] std::vector<AddressRange> find_code_caves(uint32_t min_size) const;

    /**
     * @brief Заполняет промежутки между секциями указанным байтом.
     * @param fill_byte Байт-заполнитель (по умолчанию 0xCC — int3).
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus fill_section_gaps(uint8_t fill_byte = 0xCC);

    /**
     * @brief Пересчитывает выравнивание всех секций.
     * @param file_alignment Файловое выравнивание.
     * @param section_alignment Выравнивание секций в памяти.
     * @return Успех или ошибка.
     */
    [[nodiscard]] MxStatus align_sections(uint32_t file_alignment, uint32_t section_alignment);

private:
    PeImage& image_; ///< Ссылка на модифицируемый PeImage

    /**
     * @brief Пересчитывает файловые смещения и виртуальные адреса всех секций.
     * @param starting_from Индекс секции, начиная с которой пересчитывать.
     */
    void recalculate_layout(uint32_t starting_from = 0);
};

} // namespace mx
