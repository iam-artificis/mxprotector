/**
 * @file stub_main.cpp
 * @brief [STUB] Главный загрузчик STUB — точка входа после entry.asm.
 *
 * @details Управляющий модуль STUB runtime. Выполняет полную последовательность
 *          действий для запуска защищённого PE:
 *
 *          1. Инициализация: определение базы образа, нахождение .mxrt
 *          2. Syscall resolution: Hell's Gate / Halo's Gate
 *          3. Расшифровка секций (ChaCha20 / AES-256-CTR)
 *          4. Разрешение импортов (IAT reconstruction)
 *          5. Пересчёт релокаций (если ASLR сместил базу)
 *          6. Стирание PE-заголовков (anti-dump)
 *          7. Установка PAGE_GUARD ловушек (подготовка для Phase 7)
 *          8. Передача управления на OEP (Original Entry Point)
 *
 * @note PIC, без CRT/STL. Вызывается из entry.asm после сохранения контекста.
 *       Все API-вызовы — через indirect syscall или PEB-resolved функции.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"
#include "../syscall/syscall_defs.hpp"

namespace mx::stub::pic {

// Внешние функции (определены в других .cpp файлах STUB)
extern uint32_t resolve_syscalls(SyscallTable& table) noexcept;
extern uint32_t decrypt_sections(uint64_t image_base, const StubRuntimeConfig* config,
                                 const SyscallTable& table) noexcept;
extern uint32_t resolve_imports(uint64_t image_base, const StubRuntimeConfig* config) noexcept;
extern uint32_t fix_relocations(uint64_t image_base, const StubRuntimeConfig* config) noexcept;
extern void erase_pe_headers(uint64_t image_base, const StubRuntimeConfig* config,
                             const SyscallTable& table) noexcept;

/**
 * @brief Определяет базу загрузки текущего PE-образа.
 *
 * @details Два метода:
 *          1. PEB → ImageBaseAddress (PEB offset 0x10)
 *          2. Сканирование вниз от текущего RIP с поиском "MZ" сигнатуры
 *             (backup, если PEB не доступен)
 *
 * @return VA базы загрузки или 0 при ошибке.
 */
static uint64_t get_image_base() noexcept {
#if defined(_MSC_VER) && defined(_M_X64)
    const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    if (peb) {
        const auto base = *reinterpret_cast<const uint64_t*>(peb + 0x10);
        if (base != 0) {
            const auto* dos = reinterpret_cast<const MiniDosHeader*>(base);
            if (dos->e_magic == 0x5A4D) {
                return base;
            }
        }
    }
#endif
    return 0;
}

/**
 * @brief Находит секцию .mxrt в загруженном PE.
 *
 * @param image_base VA базы загрузки.
 * @return Указатель на StubRuntimeConfig или nullptr.
 *
 * @details Итерирует заголовки секций PE, ищет секцию с именем ".mxrt".
 *          Проверяет магическую сигнатуру и версию конфигурации.
 */
static const StubRuntimeConfig* find_mxrt_config(uint64_t image_base) noexcept {
    const auto* base = va_to_ptr<uint8_t>(image_base);
    const auto* nt = get_nt_headers(base);
    if (!nt) return nullptr;

    const auto* sections = get_section_headers(nt);
    const uint16_t num_sections = nt->FileHeader.NumberOfSections;

    for (uint16_t i = 0; i < num_sections; ++i) {
        const auto& sec = sections[i];

        if (sec.Name[0] == '.' && sec.Name[1] == 'm' &&
            sec.Name[2] == 'x' && sec.Name[3] == 'r' &&
            sec.Name[4] == 't' && sec.Name[5] == '\0')
        {
            const auto* config = offset_ptr<StubRuntimeConfig>(base, sec.VirtualAddress);

            if (config->magic == MXRT_MAGIC && config->version == MXRT_VERSION) {
                return config;
            }
        }
    }

    return nullptr;
}

/**
 * @brief Главная функция STUB — выполняет полную последовательность загрузки.
 *
 * @details Вызывается из entry.asm после сохранения регистров.
 *          Выполняет все шаги инициализации и передаёт управление на OEP.
 *
 * @note Возвращает VA Original Entry Point для перехода из entry.asm.
 *       Если возвращает 0 — критическая ошибка (silent corruption).
 */
extern "C" uint64_t stub_main() noexcept {
    const uint64_t image_base = get_image_base();
    if (image_base == 0) return 0;

    const auto* config = find_mxrt_config(image_base);
    if (!config) return 0;

    SyscallTable syscall_table;
    if (has_flag(config->flags, StubFlags::use_syscalls)) {
        resolve_syscalls(syscall_table);
    }

    decrypt_sections(image_base, config, syscall_table);

    if (has_flag(config->flags, StubFlags::resolve_imports)) {
        resolve_imports(image_base, config);
    }

    if (has_flag(config->flags, StubFlags::fix_relocations)) {
        fix_relocations(image_base, config);
    }

    if (has_flag(config->flags, StubFlags::erase_headers) ||
        has_flag(config->flags, StubFlags::encrypt_headers))
    {
        erase_pe_headers(image_base, config, syscall_table);
    }

    return image_base + config->original_entry_rva;
}

} // namespace mx::stub::pic
