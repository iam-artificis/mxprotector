/**
 * @file constants.hpp
 * @brief PE format constants — signatures, machine types, characteristics.
 *
 * @details Pulled out of `pe_types.hpp` so the constants — which never
 *          change once defined and are independent of any struct — can
 *          be included on their own. Constants are namespaced under
 *          `mx::pe`.
 */

#pragma once

#include <cstdint>

namespace mx::pe {

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
constexpr std::size_t IMAGE_SIZEOF_SHORT_NAME = 8;

} // namespace mx::pe
