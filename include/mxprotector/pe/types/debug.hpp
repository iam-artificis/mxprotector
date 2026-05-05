/**
 * @file debug.hpp
 * @brief PE debug directory entry.
 */

#pragma once

#include <cstdint>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Запись отладочной директории PE.
 */
struct IMAGE_DEBUG_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;                ///< Тип отладочной информации
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;    ///< RVA
    uint32_t PointerToRawData;    ///< Файловое смещение
};

#pragma pack(pop)

} // namespace mx::pe
