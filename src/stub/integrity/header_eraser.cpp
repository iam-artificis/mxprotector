/**
 * @file header_eraser.cpp
 * @brief [STUB] Стирание / шифрование PE-заголовков в рантайме (anti-dump).
 *
 * @details После завершения загрузки (расшифровка, импорты, релокации)
 *          PE-заголовки больше не нужны. Стирание заголовков предотвращает:
 *          - Реконструкцию PE-файла из дампа памяти
 *          - Идентификацию структуры образа инструментами анализа
 *          - Определение OEP, import directory, секций
 *
 *          Два режима (определяются StubFlags):
 *          1. erase_headers: обнуление DOS/NT-заголовков и section headers
 *          2. encrypt_headers: шифрование XOR с рандомным ключом (обратимо,
 *             но без ключа — мусор)
 *
 *          Дополнительно обнуляются:
 *          - DataDirectory entries (Import, Export, Debug, TLS)
 *          - Поле e_lfanew (сбивает парсеры, ищущие NT headers)
 *          - TimeDateStamp (деанонимизация)
 *
 * @note PIC, без CRT/STL. VirtualProtect через indirect syscall.
 *       PAGE_GUARD подготовка: пометка стёртых страниц для Phase 7.
 */

#include "../include/stub_types.hpp"
#include "mxprotector/stub/stub_config.hpp"
#include "../syscall/syscall_defs.hpp"

namespace mx::stub::pic {

/// @brief Indirect syscall (gate.asm). Tail-call трамплин с поддержкой 5+ Nt-аргументов.
extern "C" uint64_t indirect_syscall(
    uint32_t ssn, uint64_t syscall_addr,
    uint64_t arg1, uint64_t arg2,
    uint64_t arg3, uint64_t arg4,
    uint64_t arg5);

namespace {

/// @brief Изменяет защиту памяти через NtProtectVirtualMemory.
uint32_t protect_region(
    const SyscallTable& table,
    void* address,
    uint64_t size,
    uint32_t new_protect) noexcept
{
    const auto& entry = table.get(NtFunction::NtProtectVirtualMemory);
    if (!entry.resolved) return 0xC0000001;

    void* base_addr = address;
    uint64_t region_size = size;
    uint32_t old_protect = 0;

    return static_cast<uint32_t>(indirect_syscall(
        entry.ssn, entry.syscall_addr,
        static_cast<uint64_t>(-1),
        reinterpret_cast<uint64_t>(&base_addr),
        reinterpret_cast<uint64_t>(&region_size),
        static_cast<uint64_t>(new_protect),
        reinterpret_cast<uint64_t>(&old_protect)));
}

/**
 * @brief Генерирует псевдослучайный 8-битный ключ на основе RDTSC.
 * @return Случайный байт.
 */
uint8_t rdtsc_random_byte() noexcept {
#if defined(_MSC_VER)
    return static_cast<uint8_t>(__rdtsc() & 0xFF);
#else
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return static_cast<uint8_t>(lo & 0xFF);
#endif
}

} // anonymous namespace

/**
 * @brief Стирает или шифрует PE-заголовки в памяти.
 *
 * @param image_base  VA базы загрузки образа.
 * @param config      Конфигурация STUB.
 * @param table       Таблица syscall.
 *
 * @details Последовательность:
 *          1. VirtualProtect(headers, PAGE_READWRITE)
 *          2. Обнуление/шифрование:
 *             a. DOS header (кроме e_magic — оставляем "MZ" для минимальной валидности)
 *             b. NT headers (Signature, FileHeader, OptionalHeader)
 *             c. Section headers (все записи)
 *             d. DOS stub (пространство между DOS header и NT headers)
 *          3. VirtualProtect(headers, PAGE_READONLY) — или PAGE_GUARD для Phase 7
 */
void erase_pe_headers(
    uint64_t                    image_base,
    const StubRuntimeConfig*    config,
    const SyscallTable&         table) noexcept
{
    if (!config) return;

    auto* base = va_to_ptr<uint8_t>(image_base);
    const uint32_t header_size = config->header_size;
    if (header_size == 0) return;

    protect_region(table, base, header_size, PAGE_READWRITE);

    const bool should_encrypt = has_flag(config->flags, StubFlags::encrypt_headers);

    if (should_encrypt) {
        const uint8_t xor_key = rdtsc_random_byte() | 0x01;

        auto* dos = reinterpret_cast<MiniDosHeader*>(base);
        const int32_t lfanew = dos->e_lfanew;

        for (uint32_t i = 2; i < static_cast<uint32_t>(lfanew); ++i) {
            base[i] ^= xor_key;
        }

        auto* nt_raw = base + lfanew;
        const auto* nt = reinterpret_cast<const MiniNtHeaders64*>(nt_raw);
        const uint32_t nt_size = sizeof(MiniNtHeaders64);
        const uint32_t section_headers_size =
            nt->FileHeader.NumberOfSections * sizeof(MiniSectionHeader);
        const uint32_t total_nt = nt_size + section_headers_size;

        for (uint32_t i = 0; i < total_nt && (lfanew + i) < header_size; ++i) {
            nt_raw[i] ^= xor_key;
        }

        dos->e_lfanew = 0;
    } else {
        auto* dos = reinterpret_cast<MiniDosHeader*>(base);
        const int32_t lfanew = dos->e_lfanew;

        mem_set(base + 2, 0, static_cast<size_t>(lfanew) - 2);

        auto* nt_raw = base + lfanew;
        const auto* nt = reinterpret_cast<const MiniNtHeaders64*>(nt_raw);
        const uint32_t nt_size = sizeof(MiniNtHeaders64);
        const uint32_t section_headers_size =
            nt->FileHeader.NumberOfSections * sizeof(MiniSectionHeader);
        const uint32_t total_nt = nt_size + section_headers_size;

        mem_set(nt_raw, 0, total_nt);

        dos->e_lfanew = 0;
    }

    uint32_t final_protect = PAGE_READONLY;
    if (has_flag(config->flags, StubFlags::page_guard_trap)) {
        final_protect = PAGE_READONLY | PAGE_GUARD_FLAG;
    }
    protect_region(table, base, header_size, final_protect);
}

} // namespace mx::stub::pic
