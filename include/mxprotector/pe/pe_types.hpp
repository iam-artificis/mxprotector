/**
 * @file pe_types.hpp
 * @brief [BUILDER] Определения структур PE-формата (Portable Executable).
 *
 * @details Собственные определения всех PE-структур с exact-sized типами
 *          и #pragma pack(push, 1). Имена структур и полей идентичны
 *          стандартным из Windows SDK (winnt.h) для совместимости.
 *          Определяем самостоятельно для полного контроля и независимости
 *          от Windows.h (исключает macro pollution).
 *
 * @note Все структуры упакованы (#pragma pack(push, 1)).
 *       Стандартные имена (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64 и т.д.) сохранены.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/pe/data_region.hpp"
#include "mxprotector/pe/pre_scanned_ref_slot.hpp"

namespace mx::pe {

// ============================================================================
// Константы PE-формата
// ============================================================================

/// @name Сигнатуры
/// @{
constexpr uint16_t IMAGE_DOS_SIGNATURE          = 0x5A4D;       ///< "MZ"
constexpr uint32_t IMAGE_NT_SIGNATURE           = 0x00004550;   ///< "PE\0\0"
/// @}

/// @name Машинные типы (IMAGE_FILE_HEADER.Machine)
/// @{
constexpr uint16_t IMAGE_FILE_MACHINE_I386      = 0x014C;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64     = 0x8664;
/// @}

/// @name Optional Header Magic
/// @{
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;
/// @}

/// @name Количество элементов DataDirectory
/// @{
constexpr uint32_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
/// @}

/// @name Индексы DataDirectory
/// @{
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT    = 0;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT    = 1;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_SECURITY  = 4;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_DEBUG     = 6;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_TLS       = 9;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IAT       = 12;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;
/// @}

/// @name Характеристики файла (IMAGE_FILE_HEADER.Characteristics)
/// @{
constexpr uint16_t IMAGE_FILE_RELOCS_STRIPPED      = 0x0001;
constexpr uint16_t IMAGE_FILE_EXECUTABLE_IMAGE     = 0x0002;
constexpr uint16_t IMAGE_FILE_LINE_NUMS_STRIPPED   = 0x0004;
constexpr uint16_t IMAGE_FILE_LOCAL_SYMS_STRIPPED  = 0x0008;
constexpr uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE  = 0x0020;
constexpr uint16_t IMAGE_FILE_32BIT_MACHINE        = 0x0100;
constexpr uint16_t IMAGE_FILE_DEBUG_STRIPPED       = 0x0200;
constexpr uint16_t IMAGE_FILE_DLL                  = 0x2000;
constexpr uint16_t IMAGE_FILE_SYSTEM               = 0x1000;
/// @}

/// @name Подсистема (OptionalHeader.Subsystem)
/// @{
constexpr uint16_t IMAGE_SUBSYSTEM_UNKNOWN                  = 0;
constexpr uint16_t IMAGE_SUBSYSTEM_NATIVE                   = 1;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3;
constexpr uint16_t IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10;
constexpr uint16_t IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11;
constexpr uint16_t IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12;
constexpr uint16_t IMAGE_SUBSYSTEM_EFI_ROM                  = 13;
/// @}

/// @brief True iff @p subsystem is one of the four UEFI variants.
///
/// Covers `EFI_APPLICATION` (10), `EFI_BOOT_SERVICE_DRIVER` (11),
/// `EFI_RUNTIME_DRIVER` (12) and `EFI_ROM` (13). All four share the
/// "no Win32 user-mode infra" property — no PEB, no IAT, no VEH, no
/// TLS callbacks — so MxProtector treats them as a single
/// `BinaryKind::efi_application` for applicability purposes.
[[nodiscard]] constexpr bool is_efi_subsystem(uint16_t subsystem) noexcept {
    return subsystem >= IMAGE_SUBSYSTEM_EFI_APPLICATION
        && subsystem <= IMAGE_SUBSYSTEM_EFI_ROM;
}

/// @name Характеристики секций (IMAGE_SECTION_HEADER.Characteristics)
/// @{
constexpr uint32_t IMAGE_SCN_CNT_CODE                = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA    = 0x00000040;
constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA  = 0x00000080;
constexpr uint32_t IMAGE_SCN_LNK_NRELOC_OVFL         = 0x01000000;
constexpr uint32_t IMAGE_SCN_MEM_DISCARDABLE         = 0x02000000;
constexpr uint32_t IMAGE_SCN_MEM_NOT_CACHED          = 0x04000000;
constexpr uint32_t IMAGE_SCN_MEM_NOT_PAGED           = 0x08000000;
constexpr uint32_t IMAGE_SCN_MEM_SHARED              = 0x10000000;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE             = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ                = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE               = 0x80000000;
/// @}

/// @name DLL характеристики (OptionalHeader.DllCharacteristics)
/// @{
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   = 0x0040;
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_NX_COMPAT      = 0x0100;
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_NO_SEH         = 0x0400;
constexpr uint16_t IMAGE_DLLCHARACTERISTICS_GUARD_CF       = 0x4000;  ///< Control Flow Guard
/// @}

/// @name Типы релокаций
/// @{
constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
constexpr uint16_t IMAGE_REL_BASED_HIGH     = 1;
constexpr uint16_t IMAGE_REL_BASED_LOW      = 2;
constexpr uint16_t IMAGE_REL_BASED_HIGHLOW  = 3;
constexpr uint16_t IMAGE_REL_BASED_DIR64    = 10;
/// @}

/// @name Флаги ординалов импорта
/// @{
constexpr uint32_t IMAGE_ORDINAL_FLAG32 = 0x80000000u;
constexpr uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000ull;
/// @}

/// @brief Размер имени секции.
constexpr size_t IMAGE_SIZEOF_SHORT_NAME = 8;

// ============================================================================
// PE-структуры (#pragma pack(push, 1))
// ============================================================================

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

// ============================================================================
// Структуры таблицы импортов
// ============================================================================

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

// ============================================================================
// Структуры таблицы экспортов
// ============================================================================

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

// ============================================================================
// Структуры таблицы релокаций
// ============================================================================

/**
 * @brief Блок базовых релокаций.
 * @details За этой структурой следует массив uint16_t записей.
 *          Старшие 4 бита — тип, младшие 12 — смещение от VirtualAddress.
 */
struct IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress; ///< RVA страницы, к которой применяются релокации
    uint32_t SizeOfBlock;    ///< Размер блока (включая этот заголовок)
};

// ============================================================================
// Структуры TLS
// ============================================================================

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

// ============================================================================
// Структуры дерева ресурсов (.rsrc)
// ============================================================================

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

constexpr uint32_t IMAGE_RESOURCE_DIRECTORY_ENTRY_SUBDIR_FLAG = 0x80000000u;
constexpr uint32_t IMAGE_RESOURCE_DIRECTORY_ENTRY_NAME_FLAG   = 0x80000000u;

// ============================================================================
// Структуры delay-load импортов
// ============================================================================

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

// ============================================================================
// Структура Debug Directory
// ============================================================================

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

// ============================================================================
// Вспомогательные типы для высокоуровневого представления
// ============================================================================

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

/**
 * @brief Высокоуровневое описание секции PE.
 */
struct SectionInfo {
    std::string  name;                ///< Имя секции (декодированное из 8 байт)
    uint32_t     virtual_size = 0;    ///< Виртуальный размер
    uint32_t     virtual_address = 0; ///< RVA секции
    uint32_t     raw_size = 0;        ///< Размер на диске
    uint32_t     raw_offset = 0;      ///< Файловое смещение
    uint32_t     characteristics = 0; ///< Флаги (RWX и т.д.)
    ByteBuffer   data;                ///< Содержимое секции

    /// Byte ranges inside `data` that are *not* x86 instructions —
    /// jump tables, encrypted bytecode, immediate pools. The chaos
    /// pipeline reads this list to keep the reference patcher out of
    /// these bytes (see `pe/data_region.hpp` for the full rationale).
    /// Default empty: the section is pure code or pure data.
    std::vector<DataRegion> data_regions;

    /// Byte runs inside `data` that the emitting pass declares safe
    /// for chaos-shuffle to relocate as movable atoms (indirect-call
    /// stubs, CFF blocks). Default empty — sections without a
    /// natural sub-block carving stay pinned the way they always
    /// did. See `pe/data_region.hpp` for the contract a block must
    /// satisfy to be movable.
    std::vector<MovableBlock> movable_blocks;

    /// Reference-slot overrides emitted by passes that already know
    /// the right `(slot, target, K)` triple for a `rel32` slot whose
    /// effective displacement is `(target - slot - 4) - K`. The chaos
    /// pipeline appends these to its scanned reference table and
    /// drops any `rel` reference `CodeReferenceScanner` produced for
    /// the same slot (the scanner cannot know `K` from the on-disk
    /// disp32 alone). Used by non-balanced indirect-call stubs whose
    /// LEA carries a non-zero algebraic offset. Default empty.
    /// See `pe/pre_scanned_ref_slot.hpp` for the value type.
    std::vector<PreScannedRefSlot> pre_scanned_refs;

    /// @brief Проверяет, содержит ли секция код.
    [[nodiscard]] bool is_code() const noexcept {
        return (characteristics & IMAGE_SCN_CNT_CODE) != 0;
    }

    /// @brief Проверяет, исполняемая ли секция.
    [[nodiscard]] bool is_executable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    /// @brief Проверяет, записываемая ли секция.
    [[nodiscard]] bool is_writable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    /// @brief Проверяет, содержит ли секция указанный RVA.
    [[nodiscard]] bool contains_rva(uint32_t rva) const noexcept {
        return rva >= virtual_address &&
               rva < virtual_address + virtual_size;
    }
};

} // namespace mx::pe

// Для удобства: подтягиваем ImportFunction/ImportEntry и другие типы в общий namespace
#include <string>
#include <vector>
#include "mxprotector/core/types.hpp"
