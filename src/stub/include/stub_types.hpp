/**
 * @file stub_types.hpp
 * @brief [STUB] Базовые типы и утилиты для PIC-кода STUB (без CRT/STL).
 *
 * @details Определяет минимальные типы и примитивы для работы STUB:
 *          - Типы данных (uint8_t и т.д. через stdint.h)
 *          - PIC-безопасные утилиты: memcpy, memset, memcmp, strlen
 *          - Минимальные PE-структуры для inline-парсинга
 *          - Хеширование строк (DJB2) для динамического разрешения API
 *
 * @note НИКАКИХ зависимостей от CRT/STL. Все функции inline/constexpr.
 *       Код ДОЛЖЕН быть 100% PIC — никаких глобальных переменных,
 *       никаких строковых литералов (используем constexpr-массивы).
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace mx::stub::pic {

// ============================================================================
// Базовые memory-операции (замена CRT memcpy/memset/memcmp)
// ============================================================================

/// @brief PIC-безопасный memcpy (не зависит от CRT).
inline void* mem_copy(void* dst, const void* src, size_t count) noexcept {
    auto* d = static_cast<uint8_t*>(dst);
    const auto* s = static_cast<const uint8_t*>(src);
    for (size_t i = 0; i < count; ++i) {
        d[i] = s[i];
    }
    return dst;
}

/// @brief PIC-безопасный memset.
inline void* mem_set(void* dst, uint8_t value, size_t count) noexcept {
    auto* d = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < count; ++i) {
        d[i] = value;
    }
    return dst;
}

/// @brief PIC-безопасный memcmp. Возвращает 0 при совпадении.
[[nodiscard]] inline int mem_cmp(const void* a, const void* b, size_t count) noexcept {
    const auto* pa = static_cast<const uint8_t*>(a);
    const auto* pb = static_cast<const uint8_t*>(b);
    for (size_t i = 0; i < count; ++i) {
        if (pa[i] != pb[i]) {
            return pa[i] < pb[i] ? -1 : 1;
        }
    }
    return 0;
}

/// @brief PIC-безопасный strlen (ASCIIZ).
[[nodiscard]] inline size_t str_len(const char* str) noexcept {
    size_t len = 0;
    while (str[len] != '\0') ++len;
    return len;
}

/// @brief PIC-безопасный stricmp (case-insensitive, ASCII only).
[[nodiscard]] inline int str_icmp(const char* a, const char* b) noexcept {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca < cb ? -1 : 1;
        ++a; ++b;
    }
    return static_cast<int>(*a) - static_cast<int>(*b);
}

// ============================================================================
// Хеширование строк (DJB2 — для динамического API resolution)
// ============================================================================

/// @brief Вычисляет DJB2-хеш строки (compile-time или runtime).
[[nodiscard]] constexpr uint32_t djb2_hash(const char* str) noexcept {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str);
        ++str;
    }
    return hash;
}

/// @brief DJB2-хеш с приведением к lowercase (для имён DLL/функций).
[[nodiscard]] constexpr uint32_t djb2_hash_ci(const char* str) noexcept {
    uint32_t hash = 5381;
    while (*str) {
        char c = *str;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
        ++str;
    }
    return hash;
}

// ============================================================================
// Предвычисленные хеши системных DLL и функций
// ============================================================================

/// @brief Хеш "kernel32.dll" (lowercase).
constexpr uint32_t HASH_KERNEL32_DLL    = djb2_hash_ci("kernel32.dll");

/// @brief Хеш "ntdll.dll" (lowercase).
constexpr uint32_t HASH_NTDLL_DLL       = djb2_hash_ci("ntdll.dll");

/// @brief Хеш "LoadLibraryA".
constexpr uint32_t HASH_LOAD_LIBRARY_A  = djb2_hash("LoadLibraryA");

/// @brief Хеш "GetProcAddress".
constexpr uint32_t HASH_GET_PROC_ADDR   = djb2_hash("GetProcAddress");

/// @brief Хеш "VirtualProtect".
constexpr uint32_t HASH_VIRTUAL_PROTECT = djb2_hash("VirtualProtect");

/// @brief Хеш "VirtualAlloc".
constexpr uint32_t HASH_VIRTUAL_ALLOC   = djb2_hash("VirtualAlloc");

/// @brief Хеш "VirtualFree".
constexpr uint32_t HASH_VIRTUAL_FREE    = djb2_hash("VirtualFree");

// ============================================================================
// Адресная арифметика (PIC-safe)
// ============================================================================

/// @brief Приводит указатель к VA (uint64_t) для x64.
[[nodiscard]] inline uint64_t ptr_to_va(const void* ptr) noexcept {
    return reinterpret_cast<uint64_t>(ptr);
}

/// @brief Приводит VA к указателю.
template <typename T>
[[nodiscard]] inline T* va_to_ptr(uint64_t va) noexcept {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(va));
}

/// @brief Вычисляет указатель со смещением от базы.
template <typename T>
[[nodiscard]] inline T* offset_ptr(void* base, size_t offset) noexcept {
    return reinterpret_cast<T*>(static_cast<uint8_t*>(base) + offset);
}

/// @copydoc offset_ptr
template <typename T>
[[nodiscard]] inline const T* offset_ptr(const void* base, size_t offset) noexcept {
    return reinterpret_cast<const T*>(static_cast<const uint8_t*>(base) + offset);
}

// ============================================================================
// Минимальные PE-структуры для inline-парсинга (без зависимости от pe_types.hpp)
// ============================================================================

#pragma pack(push, 1)

struct MiniDosHeader {
    uint16_t e_magic;       ///< 0x5A4D
    uint8_t  padding[58];
    int32_t  e_lfanew;      ///< Смещение NT-заголовков
};

struct MiniFileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct MiniDataDir {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct MiniOptionalHeader64 {
    uint16_t Magic;             ///< 0x20B для PE32+
    uint8_t  padding1[14];
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint8_t  padding2[16];
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint8_t  padding3[8];
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    MiniDataDir DataDirectory[16];
};

struct MiniNtHeaders64 {
    uint32_t            Signature;
    MiniFileHeader      FileHeader;
    MiniOptionalHeader64 OptionalHeader;
};

struct MiniSectionHeader {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint8_t  padding[12];
    uint32_t Characteristics;
};

struct MiniExportDir {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

struct MiniImportDescriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

#pragma pack(pop)

/// @brief Получает NT-заголовки из базы загрузки PE.
[[nodiscard]] inline const MiniNtHeaders64* get_nt_headers(const void* image_base) noexcept {
    const auto* dos = static_cast<const MiniDosHeader*>(image_base);
    if (dos->e_magic != 0x5A4D) return nullptr;
    return offset_ptr<MiniNtHeaders64>(image_base, static_cast<size_t>(dos->e_lfanew));
}

/// @brief Получает массив заголовков секций.
[[nodiscard]] inline const MiniSectionHeader* get_section_headers(
    const MiniNtHeaders64* nt) noexcept
{
    return offset_ptr<MiniSectionHeader>(
        &nt->OptionalHeader,
        nt->FileHeader.SizeOfOptionalHeader);
}

} // namespace mx::stub::pic
