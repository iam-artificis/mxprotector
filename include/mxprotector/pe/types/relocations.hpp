/**
 * @file relocations.hpp
 * @brief PE base-relocation block + high-level entry / block views.
 */

#pragma once

#include <cstdint>
#include <vector>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Блок базовых релокаций.
 *
 * @details За этой структурой следует массив uint16_t записей.
 *          Старшие 4 бита — тип, младшие 12 — смещение от VirtualAddress.
 */
struct IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress; ///< RVA страницы, к которой применяются релокации
    uint32_t SizeOfBlock;    ///< Размер блока (включая этот заголовок)
};

#pragma pack(pop)

/**
 * @brief Одна запись релокации (4 бита тип + 12 бит смещение).
 */
struct RelocationEntry {
    uint32_t rva;     ///< Абсолютный RVA, к которому применяется релокация
    uint16_t type;    ///< Тип (IMAGE_REL_BASED_*)
};

/**
 * @brief Блок релокаций (одна страница).
 */
struct RelocationBlock {
    uint32_t                      page_rva;   ///< RVA страницы
    std::vector<RelocationEntry>  entries;    ///< Записи релокаций на этой странице
};

} // namespace mx::pe
