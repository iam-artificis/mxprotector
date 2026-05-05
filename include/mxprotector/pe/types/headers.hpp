/**
 * @file headers.hpp
 * @brief PE primary headers — DOS, file, optional 32/64, NT 32/64, section.
 *
 * @details Vendored definitions of the IMAGE_DOS_HEADER /
 *          IMAGE_FILE_HEADER / IMAGE_OPTIONAL_HEADER32-64 /
 *          IMAGE_NT_HEADERS32-64 / IMAGE_SECTION_HEADER / IMAGE_DATA_DIRECTORY
 *          structs — exact-sized fields, `#pragma pack(push, 1)`,
 *          static_assert on size to catch ABI drift.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/types/constants.hpp"

namespace mx::pe {

#pragma pack(push, 1)

/**
 * @brief DOS-заголовок PE-файла.
 * @details Первые 64 байта любого PE. Ключевое поле — e_lfanew,
 *          указывающее на смещение NT-заголовков.
 */
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;      ///< Сигнатура "MZ" (0x5A4D)
    uint16_t e_cblp;       ///< Байтов на последней странице
    uint16_t e_cp;         ///< Количество страниц
    uint16_t e_crlc;       ///< Количество элементов в таблице релокаций
    uint16_t e_cparhdr;    ///< Размер заголовка в параграфах
    uint16_t e_minalloc;   ///< Минимальное выделение
    uint16_t e_maxalloc;   ///< Максимальное выделение
    uint16_t e_ss;         ///< Начальное значение SS
    uint16_t e_sp;         ///< Начальное значение SP
    uint16_t e_csum;       ///< Контрольная сумма
    uint16_t e_ip;         ///< Начальное значение IP
    uint16_t e_cs;         ///< Начальное значение CS
    uint16_t e_lfarlc;     ///< Смещение таблицы релокаций
    uint16_t e_ovno;       ///< Номер оверлея
    uint16_t e_res[4];     ///< Зарезервировано
    uint16_t e_oemid;      ///< OEM идентификатор
    uint16_t e_oeminfo;    ///< OEM информация
    uint16_t e_res2[10];   ///< Зарезервировано
    int32_t  e_lfanew;     ///< Смещение NT-заголовков от начала файла
};

static_assert(sizeof(IMAGE_DOS_HEADER) == 64, "IMAGE_DOS_HEADER должен быть 64 байта");

/**
 * @brief Элемент DataDirectory — описывает расположение и размер таблицы данных.
 */
struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress; ///< RVA таблицы данных
    uint32_t Size;           ///< Размер таблицы в байтах
};

static_assert(sizeof(IMAGE_DATA_DIRECTORY) == 8, "IMAGE_DATA_DIRECTORY должен быть 8 байт");

/**
 * @brief Заголовок файла — общие характеристики PE.
 */
struct IMAGE_FILE_HEADER {
    uint16_t Machine;              ///< Тип машины (I386/AMD64)
    uint16_t NumberOfSections;     ///< Количество секций
    uint32_t TimeDateStamp;        ///< Временная метка создания
    uint32_t PointerToSymbolTable; ///< Смещение таблицы символов (обычно 0)
    uint32_t NumberOfSymbols;      ///< Количество символов (обычно 0)
    uint16_t SizeOfOptionalHeader; ///< Размер Optional Header
    uint16_t Characteristics;      ///< Флаги характеристик файла
};

static_assert(sizeof(IMAGE_FILE_HEADER) == 20, "IMAGE_FILE_HEADER должен быть 20 байт");

/**
 * @brief Optional Header для 32-битных PE (PE32).
 */
struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                        ///< 0x10B для PE32
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;          ///< RVA точки входа
    uint32_t BaseOfCode;
    uint32_t BaseOfData;                   ///< Только в PE32
    uint32_t ImageBase;                    ///< Предпочтительная база загрузки
    uint32_t SectionAlignment;             ///< Выравнивание секций в памяти
    uint32_t FileAlignment;                ///< Выравнивание секций на диске
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;                  ///< Размер образа в памяти (выровнен)
    uint32_t SizeOfHeaders;                ///< Размер всех заголовков (выровнен)
    uint32_t CheckSum;                     ///< Контрольная сумма PE
    uint16_t Subsystem;                    ///< Подсистема (GUI/CUI/Native)
    uint16_t DllCharacteristics;           ///< Флаги DLL
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;          ///< Количество элементов DataDirectory
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

/**
 * @brief Optional Header для 64-битных PE (PE32+).
 * @note Отличия от PE32: нет BaseOfData, ImageBase и Stack/Heap — 64-bit.
 */
struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                        ///< 0x20B для PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;          ///< RVA точки входа
    uint32_t BaseOfCode;
    uint64_t ImageBase;                    ///< Предпочтительная база загрузки (64-bit)
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;           ///< 64-bit
    uint64_t SizeOfStackCommit;            ///< 64-bit
    uint64_t SizeOfHeapReserve;            ///< 64-bit
    uint64_t SizeOfHeapCommit;             ///< 64-bit
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

/**
 * @brief NT-заголовки для PE32.
 */
struct IMAGE_NT_HEADERS32 {
    uint32_t                Signature;       ///< "PE\0\0" (0x00004550)
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

/**
 * @brief NT-заголовки для PE32+ (64-bit).
 */
struct IMAGE_NT_HEADERS64 {
    uint32_t                Signature;       ///< "PE\0\0" (0x00004550)
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

/**
 * @brief Заголовок секции PE.
 */
struct IMAGE_SECTION_HEADER {
    uint8_t  Name[IMAGE_SIZEOF_SHORT_NAME]; ///< Имя секции (до 8 символов, null-padded)
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;               ///< Виртуальный размер секции
    } Misc;
    uint32_t VirtualAddress;                ///< RVA секции в памяти
    uint32_t SizeOfRawData;                 ///< Размер секции на диске (выровнен)
    uint32_t PointerToRawData;              ///< Файловое смещение секции
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;               ///< Флаги секции (RWX, CODE, DATA)
};

static_assert(sizeof(IMAGE_SECTION_HEADER) == 40, "IMAGE_SECTION_HEADER должен быть 40 байт");

#pragma pack(pop)

} // namespace mx::pe
