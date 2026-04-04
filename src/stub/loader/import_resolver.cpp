/**
 * @file import_resolver.cpp
 * @brief [STUB] Динамическое разрешение импортов PE в рантайме.
 *
 * @details Восстанавливает IAT (Import Address Table) защищённого PE:
 *          1. Парсит Import Directory PE-образа в памяти
 *          2. Для каждой импортируемой DLL:
 *             a. Загружает DLL через LdrLoadDll или цепочку PEB→InLoadOrderModuleList
 *             b. Разрешает каждую функцию по имени или ординалу
 *             c. Записывает VA в IAT
 *
 *          Используются два механизма разрешения API:
 *          - Прямой: парсинг Export Directory целевой DLL в памяти
 *          - Fallback: GetProcAddress (если уже разрешён через exports)
 *
 * @note PIC, без CRT/STL. Все строковые операции — через PIC-утилиты.
 *       Для нахождения kernel32.dll и GetProcAddress используется PEB walk.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"

namespace mx::stub::pic {

/// @brief Тип функции LoadLibraryA.
using FnLoadLibraryA = void* (__stdcall*)(const char*);

/// @brief Тип функции GetProcAddress.
using FnGetProcAddress = void* (__stdcall*)(void*, const char*);

/**
 * @brief Находит базу загруженного модуля по DJB2-хешу имени (через PEB).
 *
 * @details Обход InMemoryOrderModuleList в PEB_LDR_DATA.
 *          Для каждого модуля хешируем FullDllName (Unicode→ASCII lowercase).
 *
 * @param name_hash DJB2-хеш имени DLL (lowercase).
 * @return Указатель на базу модуля или nullptr.
 */
void* find_module_by_hash(uint32_t name_hash) noexcept {
#if defined(_MSC_VER) && defined(_M_X64)
    const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (!peb) return nullptr;

    const auto* ldr = *reinterpret_cast<const uint8_t* const*>(peb + 0x18);
    if (!ldr) return nullptr;

    const auto* list_head = ldr + 0x20;
    const auto* flink = *reinterpret_cast<const uint8_t* const*>(list_head);

    const auto* current = flink;
    while (current != list_head) {
        const auto* full_name_buf = *reinterpret_cast<const uint16_t* const*>(current + 0x40 + 8);
        const uint16_t name_len = *reinterpret_cast<const uint16_t*>(current + 0x40);

        if (full_name_buf && name_len > 0) {
            uint32_t hash = 5381;
            const uint32_t char_count = name_len / 2;

            for (uint32_t i = 0; i < char_count; ++i) {
                char c = static_cast<char>(full_name_buf[i] & 0xFF);
                if (c >= 'A' && c <= 'Z') c += 32;
                hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);
            }

            if (hash == name_hash) {
                return *reinterpret_cast<void* const*>(current + 0x20);
            }
        }

        current = *reinterpret_cast<const uint8_t* const*>(current);
    }
#else
    (void)name_hash;
#endif
    return nullptr;
}

/**
 * @brief Находит экспорт в загруженном модуле по DJB2-хешу имени.
 *
 * @param module_base База загруженного модуля.
 * @param func_hash   DJB2-хеш имени функции.
 * @return VA функции или nullptr.
 */
void* find_export_by_hash(void* module_base, uint32_t func_hash) noexcept {
    if (!module_base) return nullptr;

    const auto* base = static_cast<const uint8_t*>(module_base);
    const auto* nt = get_nt_headers(base);
    if (!nt || nt->Signature != 0x00004550) return nullptr;

    constexpr uint32_t EXPORT_IDX = 0;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= EXPORT_IDX) return nullptr;

    const uint32_t export_rva = nt->OptionalHeader.DataDirectory[EXPORT_IDX].VirtualAddress;
    if (export_rva == 0) return nullptr;

    const auto* exp = offset_ptr<MiniExportDir>(base, export_rva);
    const auto* names = offset_ptr<uint32_t>(base, exp->AddressOfNames);
    const auto* ordinals = offset_ptr<uint16_t>(base, exp->AddressOfNameOrdinals);
    const auto* functions = offset_ptr<uint32_t>(base, exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (djb2_hash(name) == func_hash) {
            const uint32_t func_rva = functions[ordinals[i]];
            return const_cast<uint8_t*>(base + func_rva);
        }
    }

    return nullptr;
}

/**
 * @brief Разрешает импорты PE-образа в памяти.
 *
 * @param image_base VA базы загрузки PE.
 * @param config     Конфигурация STUB.
 * @return Количество успешно разрешённых импортов (DLL).
 *
 * @details Алгоритм:
 *          1. Находит kernel32.dll через PEB
 *          2. Извлекает LoadLibraryA и GetProcAddress из kernel32
 *          3. Итерирует Import Directory PE:
 *             - Для каждого дескриптора: LoadLibraryA(dll_name)
 *             - Для каждого thunk: GetProcAddress(module, func_name)
 *             - Записывает результат в IAT
 */
uint32_t resolve_imports(
    uint64_t                   image_base,
    const StubRuntimeConfig*   config) noexcept
{
    (void)config;

    const auto* base = va_to_ptr<uint8_t>(image_base);
    const auto* nt = get_nt_headers(base);
    if (!nt) return 0;

    constexpr uint32_t IMPORT_IDX = 1;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMPORT_IDX) return 0;

    const uint32_t import_rva = nt->OptionalHeader.DataDirectory[IMPORT_IDX].VirtualAddress;
    if (import_rva == 0) return 0;

    void* kernel32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!kernel32) return 0;

    auto load_library = reinterpret_cast<FnLoadLibraryA>(
        find_export_by_hash(kernel32, HASH_LOAD_LIBRARY_A));
    auto get_proc = reinterpret_cast<FnGetProcAddress>(
        find_export_by_hash(kernel32, HASH_GET_PROC_ADDR));

    if (!load_library || !get_proc) return 0;

    const auto* import_desc = offset_ptr<MiniImportDescriptor>(base, import_rva);
    uint32_t resolved_dlls = 0;

    while (import_desc->Name != 0) {
        const char* dll_name = reinterpret_cast<const char*>(base + import_desc->Name);

        void* module = load_library(dll_name);
        if (!module) {
            ++import_desc;
            continue;
        }

        uint32_t ilt_rva = import_desc->OriginalFirstThunk;
        if (ilt_rva == 0) ilt_rva = import_desc->FirstThunk;

        const auto* ilt = offset_ptr<uint64_t>(base, ilt_rva);
        auto* iat = const_cast<uint64_t*>(offset_ptr<uint64_t>(base, import_desc->FirstThunk));

        constexpr uint64_t ORDINAL_FLAG_64 = 0x8000000000000000ULL;

        for (uint32_t idx = 0; ilt[idx] != 0; ++idx) {
            void* func_addr = nullptr;

            if (ilt[idx] & ORDINAL_FLAG_64) {
                const uint16_t ordinal = static_cast<uint16_t>(ilt[idx] & 0xFFFF);
                func_addr = get_proc(module, reinterpret_cast<const char*>(
                    static_cast<uintptr_t>(ordinal)));
            } else {
                const uint32_t hint_rva = static_cast<uint32_t>(ilt[idx]);
                const char* func_name = reinterpret_cast<const char*>(
                    base + hint_rva + 2);
                func_addr = get_proc(module, func_name);
            }

            if (func_addr) {
                iat[idx] = reinterpret_cast<uint64_t>(func_addr);
            }
        }

        ++resolved_dlls;
        ++import_desc;
    }

    return resolved_dlls;
}

} // namespace mx::stub::pic
