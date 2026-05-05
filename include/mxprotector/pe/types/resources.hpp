/**
 * @file resources.hpp
 * @brief PE resource-tree structures (`.rsrc`).
 */

#pragma once

#include <cstdint>

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief Узел дерева ресурсов: каталог, содержащий вложенные записи.
 *
 * @details За структурой следует массив `IMAGE_RESOURCE_DIRECTORY_ENTRY`
 *          размером `NumberOfNamedEntries + NumberOfIdEntries`.
 *          Дерево обычно три уровня: Type → Name/Id → Language.
 */
struct IMAGE_RESOURCE_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint16_t NumberOfNamedEntries;
    uint16_t NumberOfIdEntries;
};

static_assert(sizeof(IMAGE_RESOURCE_DIRECTORY) == 16,
              "IMAGE_RESOURCE_DIRECTORY должен быть 16 байт");

/**
 * @brief Запись каталога ресурсов: либо имя/ID + ссылка на подкаталог,
 *        либо имя/ID + ссылка на лист данных.
 *
 * @details Старший бит `OffsetToData` (`0x80000000`):
 *          - 1: смещение указывает на вложенную `IMAGE_RESOURCE_DIRECTORY`
 *               (относительно начала `.rsrc`).
 *          - 0: смещение указывает на `IMAGE_RESOURCE_DATA_ENTRY`
 *               (относительно начала `.rsrc`).
 *          Старший бит `Name` различает строковое имя и числовой ID.
 */
struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    uint32_t Name;          ///< Строка-имя (старший бит) или числовой ID
    uint32_t OffsetToData;  ///< Высший бит: каталог; иначе лист данных (относ. .rsrc)
};

static_assert(sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) == 8,
              "IMAGE_RESOURCE_DIRECTORY_ENTRY должен быть 8 байт");

/**
 * @brief Лист дерева ресурсов — указатель на сами байты ресурса.
 *
 * @note `OffsetToData` — это **полный RVA** (а не смещение от начала
 *       `.rsrc`), несмотря на название. Так требует PE-формат.
 */
struct IMAGE_RESOURCE_DATA_ENTRY {
    uint32_t OffsetToData;  ///< RVA байтов ресурса (полный, не относ. .rsrc)
    uint32_t Size;          ///< Размер байтов в байтах
    uint32_t CodePage;      ///< Код-страница для текстовых ресурсов
    uint32_t Reserved;
};

static_assert(sizeof(IMAGE_RESOURCE_DATA_ENTRY) == 16,
              "IMAGE_RESOURCE_DATA_ENTRY должен быть 16 байт");

#pragma pack(pop)

constexpr uint32_t IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG = 0x80000000u;
constexpr uint32_t IMAGE_RESOURCE_DIRECTORY_ENTRY_NAME_FLAG   = 0x80000000u;

} // namespace mx::pe
