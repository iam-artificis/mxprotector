/**
 * @file imports.hpp
 * @brief PE import-table structures (raw + high-level).
 *
 * @details Raw on-disk types: `IMAGE_IMPORT_DESCRIPTOR`,
 *          `IMAGE_IMPORT_BY_NAME`, `IMAGE_THUNK_DATA32/64`. High-level
 *          builder-side views: `ImportFunction`, `ImportEntry`.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Дескриптор импортируемой DLL.
 * @details Массив этих структур завершается нулевым элементом.
 */
struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;       ///< 0 для терминирующего элемента
        uint32_t OriginalFirstThunk;    ///< RVA массива INT (Import Name Table)
    };
    uint32_t TimeDateStamp;             ///< Временная метка (0 если не bound)
    uint32_t ForwarderChain;            ///< Индекс первого forwarder
    uint32_t Name;                      ///< RVA имени DLL (ASCIIZ)
    uint32_t FirstThunk;                ///< RVA массива IAT (Import Address Table)
};

/**
 * @brief Запись импорта по имени.
 */
struct IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;     ///< Подсказка индекса в таблице экспортов
    char     Name[1];  ///< ASCIIZ имя функции (flexible array)
};

/**
 * @brief Thunk-запись для 32-битных PE.
 */
struct IMAGE_THUNK_DATA32 {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;  ///< RVA IMAGE_IMPORT_BY_NAME
    } u1;
};

/**
 * @brief Thunk-запись для 64-битных PE.
 */
struct IMAGE_THUNK_DATA64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;  ///< RVA IMAGE_IMPORT_BY_NAME
    } u1;
};

#pragma pack(pop)

/**
 * @brief Информация об одной импортируемой функции.
 */
struct ImportFunction {
    std::string name;         ///< Имя функции (пусто если по ординалу)
    uint16_t    hint = 0;     ///< Hint из IMAGE_IMPORT_BY_NAME
    uint16_t    ordinal = 0;  ///< Ординал (если импорт по ординалу)
    bool        by_ordinal = false; ///< true = импорт по ординалу
    uint32_t    thunk_rva = 0;      ///< RVA записи в IAT (для патчинга)
};

/**
 * @brief Информация об одной импортируемой DLL и её функциях.
 */
struct ImportEntry {
    std::string                  dll_name;   ///< Имя DLL (kernel32.dll и т.д.)
    uint32_t                     descriptor_rva = 0; ///< RVA дескриптора
    std::vector<ImportFunction>  functions;   ///< Список импортируемых функций
};

} // namespace mx::pe
