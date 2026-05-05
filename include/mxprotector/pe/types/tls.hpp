/**
 * @file tls.hpp
 * @brief PE thread-local-storage directory (PE32 and PE32+).
 */

#pragma once

#include <cstdint>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief TLS-директория для PE32.
 */
struct IMAGE_TLS_DIRECTORY32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;   ///< VA массива TLS callback функций
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

/**
 * @brief TLS-директория для PE32+.
 */
struct IMAGE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;   ///< VA массива TLS callback функций
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

#pragma pack(pop)

} // namespace mx::pe
