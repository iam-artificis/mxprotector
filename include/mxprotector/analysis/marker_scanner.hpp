/**
 * @file marker_scanner.hpp
 * @brief [BUILDER] Сканер SDK-маркеров в PE-образе.
 *
 * @details MarkerScanner ищет в исполняемых секциях PE специальные сигнатуры,
 *          вставленные SDK (mxprotector_sdk.h). Формат маркера:
 *            - 8 байт: магическое число (0x4D585F50524F5400 = "MX_PROT\0")
 *            - 1 байт: тип маркера (MarkerType)
 *
 *          Сканер находит все маркеры, валидирует их парность (begin → end)
 *          и формирует список MarkedRegion для дальнейшей обработки проходами защиты.
 *
 * @note Маркеры ищутся ТОЛЬКО в секциях с флагом IMAGE_SCN_CNT_CODE.
 *       Непарные маркеры генерируют ошибку.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"

namespace mx {
class PeImage;
} // namespace mx

namespace mx::analysis {

/**
 * @brief Сканер SDK-маркеров в PE-образе.
 *
 * @details Класс без состояния — вся функциональность через статические методы.
 *          Основной метод find_markers() сканирует все code-секции PeImage,
 *          находит магические сигнатуры и формирует валидированный список
 *          маркированных регионов.
 */
class MarkerScanner {
public:
    MarkerScanner() = delete;

    /// @brief 7-байтовый префикс магии ("MX_PROT" в little-endian).
    /// @details Полный 8-байтовый маркер: младшие 7 байт = префикс,
    ///          старший байт = MarkerType. Каждый тип — уникальный imm64,
    ///          что блокирует shared-load в MSVC /O2.
    static constexpr uint64_t marker_prefix_mask = 0x00FFFFFFFFFFFFFFULL;
    static constexpr uint64_t marker_prefix      = 0x00544F52505F584DULL;

    /// @brief Полный размер одного маркера (8 байт — magic+type в одном qword).
    static constexpr size_t marker_size = sizeof(uint64_t);

    /**
     * @brief Сканирует PE-образ на наличие SDK-маркеров.
     * @param image PE-образ для сканирования.
     * @return Вектор валидированных маркированных регионов или ошибка.
     *
     * @note Маркеры ищутся только в code-секциях.
     *       Возвращает ошибку при непарных маркерах (begin без end или наоборот).
     */
    [[nodiscard]] static MxResult<std::vector<MarkedRegion>> find_markers(const PeImage& image);

private:
    /**
     * @brief Описание найденного сырого маркера (до валидации парности).
     */
    struct RawMarker {
        MarkerType type;          ///< Тип маркера
        Rva        rva;           ///< RVA первого байта marker-конструкции (инструкции)
        uint32_t   total_size;    ///< Полная длина marker-конструкции в байтах
        uint32_t   section_index; ///< Индекс секции
    };

    /**
     * @brief Сканирует одну секцию на наличие маркеров.
     * @param section_data Данные секции.
     * @param section_rva RVA начала секции.
     * @param section_index Индекс секции в таблице секций.
     * @return Вектор найденных сырых маркеров.
     */
    [[nodiscard]] static std::vector<RawMarker> scan_section(
        ByteView section_data, Rva section_rva, uint32_t section_index);

    /**
     * @brief Валидирует парность маркеров и формирует MarkedRegion.
     * @param raw_markers Сырые маркеры, отсортированные по RVA.
     * @return Вектор валидированных маркированных регионов или ошибка.
     */
    [[nodiscard]] static MxResult<std::vector<MarkedRegion>> validate_and_pair(
        std::vector<RawMarker>& raw_markers);

    /**
     * @brief Проверяет, является ли тип маркера «begin».
     * @param type Тип маркера.
     * @return true для vm_begin, mutate_begin, obfuscate_begin.
     */
    [[nodiscard]] static constexpr bool is_begin_marker(MarkerType type) noexcept {
        return type == MarkerType::vm_begin ||
               type == MarkerType::mutate_begin ||
               type == MarkerType::obfuscate_begin;
    }

    /**
     * @brief Возвращает ожидаемый парный тип маркера (begin → end).
     * @param begin_type Тип begin-маркера.
     * @return Парный end-тип.
     */
    [[nodiscard]] static constexpr MarkerType matching_end_type(MarkerType begin_type) noexcept {
        switch (begin_type) {
            case MarkerType::vm_begin:        return MarkerType::vm_end;
            case MarkerType::mutate_begin:    return MarkerType::mutate_end;
            case MarkerType::obfuscate_begin: return MarkerType::obfuscate_end;
            default:                          return begin_type;
        }
    }

    /**
     * @brief Возвращает строковое имя типа маркера (для диагностики).
     * @param type Тип маркера.
     * @return Строковое представление.
     */
    [[nodiscard]] static constexpr std::string_view marker_type_name(MarkerType type) noexcept {
        switch (type) {
            case MarkerType::vm_begin:        return "VM_BEGIN";
            case MarkerType::vm_end:          return "VM_END";
            case MarkerType::mutate_begin:    return "MUTATE_BEGIN";
            case MarkerType::mutate_end:      return "MUTATE_END";
            case MarkerType::obfuscate_begin: return "OBFUSCATE_BEGIN";
            case MarkerType::obfuscate_end:   return "OBFUSCATE_END";
            default:                          return "UNKNOWN";
        }
    }
};

} // namespace mx::analysis
