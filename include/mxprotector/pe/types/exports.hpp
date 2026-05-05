/**
 * @file exports.hpp
 * @brief PE export-table structures (raw `IMAGE_EXPORT_DIRECTORY` +
 *        high-level `ExportFunction` / `ExportTable`).
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Директория экспортов PE.
 */
struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;       ///< Зарезервировано (обычно 0)
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;                  ///< RVA имени DLL
    uint32_t Base;                  ///< Начальный ординал
    uint32_t NumberOfFunctions;     ///< Количество экспортируемых функций
    uint32_t NumberOfNames;         ///< Количество именованных экспортов
    uint32_t AddressOfFunctions;    ///< RVA массива EAT (Export Address Table)
    uint32_t AddressOfNames;        ///< RVA массива имён
    uint32_t AddressOfNameOrdinals; ///< RVA массива ординалов имён
};

#pragma pack(pop)

/**
 * @brief Информация об одной экспортируемой функции.
 */
struct ExportFunction {
    std::string name;          ///< Имя функции (пусто если только по ординалу)
    uint32_t    rva = 0;       ///< RVA функции (или RVA forwarder строки)
    uint16_t    ordinal = 0;   ///< Ординал функции
    bool        is_forwarder = false; ///< true = forwarded export
    std::string forwarder;     ///< Строка forwarder (e.g. "NTDLL.RtlAllocateHeap")
};

/**
 * @brief Полная информация о таблице экспортов PE.
 */
struct ExportTable {
    std::string                   dll_name;   ///< Имя модуля
    uint32_t                      base = 0;   ///< Начальный ординал
    std::vector<ExportFunction>   functions;  ///< Все экспортируемые функции
};

} // namespace mx::pe
