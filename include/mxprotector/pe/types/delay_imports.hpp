/**
 * @file delay_imports.hpp
 * @brief PE delay-load import descriptor.
 *
 * @details The `IMAGE_DELAYLOAD_DESCRIPTOR` is the delay-loading v2
 *          descriptor written by modern toolchains. The `RvaBased`
 *          attribute bit decides whether the seven RVA-shaped fields
 *          carry RVAs (modern, remappable) or absolute VAs (legacy,
 *          skipped by the chaos sanner).
 */

#pragma once

#include <cstdint>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Delay-load импорт-дескриптор (PE delay loading version 2).
 *
 * Все семь *RVA полей являются 32-битными RVA когда `Attributes` бит 0
 * (`RvaBased`) установлен — современный формат, который используют
 * MSVC/clang на x64. Когда `RvaBased=0` (legacy формат), это
 * абсолютные 32-битные VA, и их нельзя ремапить через
 * `RvaRemapper` — chaos сканер пропускает такие записи.
 */
struct IMAGE_DELAYLOAD_DESCRIPTOR {
    uint32_t Attributes;                  ///< Бит 0 = RvaBased (1 = RVA, 0 = VA)
    uint32_t DllNameRVA;                  ///< RVA имени DLL (ASCIIZ)
    uint32_t ModuleHandleRVA;             ///< RVA на ячейку HMODULE
    uint32_t ImportAddressTableRVA;       ///< RVA таблицы IAT
    uint32_t ImportNameTableRVA;          ///< RVA таблицы INT
    uint32_t BoundImportAddressTableRVA;  ///< RVA опциональной bound IAT (может быть 0)
    uint32_t UnloadInformationTableRVA;   ///< RVA опциональной unload-info таблицы (может быть 0)
    uint32_t TimeDateStamp;
};

static_assert(sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) == 32,
              "IMAGE_DELAYLOAD_DESCRIPTOR должен быть 32 байта");

#pragma pack(pop)

} // namespace mx::pe
