/**
 * @file syscall_defs.hpp
 * @brief [STUB] Определения и типы для Syscall Engine (Hell's Gate / Halo's Gate).
 *
 * @details Содержит:
 *          - Структуру SyscallEntry для хранения SSN и адреса syscall-инструкции
 *          - Перечисление NtFunction с идентификаторами системных вызовов
 *          - Таблицу syscall (фиксированный массив для быстрого доступа)
 *          - Вспомогательные типы для indirect syscall dispatch
 *
 * @note Без CRT/STL зависимостей. Все типы inline для PIC.
 *       SSN (System Service Number) извлекается динамически из ntdll.dll.
 */

#pragma once

#include <cstdint>

namespace mx::stub::pic {

// ============================================================================
// Идентификаторы Nt* функций, используемых STUB
// ============================================================================

/**
 * @brief Перечисление Nt* функций для syscall-таблицы.
 *
 * @details Каждый элемент соответствует одной Nt*-функции, которую STUB
 *          вызывает через indirect syscall. SSN разрешается динамически
 *          из ntdll.dll при инициализации STUB.
 */
enum class NtFunction : uint32_t {
    NtAllocateVirtualMemory  = 0,
    NtProtectVirtualMemory   = 1,
    NtFreeVirtualMemory      = 2,
    NtQueryInformationProcess = 3,
    NtQuerySystemInformation = 4,
    NtGetContextThread       = 5,
    NtSetInformationThread   = 6,
    NtClose                  = 7,
    NtDelayExecution         = 8,
    NtQueryPerformanceCounter = 9,
    nt_function_count         = 10
};

/**
 * @brief Запись в таблице syscall: SSN + адрес syscall-инструкции.
 *
 * @details SSN — номер системного вызова (mov eax, SSN).
 *          syscall_addr — адрес легитимной `syscall; ret` внутри ntdll.dll.
 *          Indirect syscall: вместо `syscall` в нашем коде, выполняем
 *          `jmp [syscall_addr]` → вызов из тела ntdll → чистый call stack.
 */
struct SyscallEntry {
    uint32_t  ssn;           ///< System Service Number
    uint64_t  syscall_addr;  ///< VA `syscall; ret` внутри ntdll.dll
    bool      resolved;      ///< true если SSN успешно разрешён
};

/// @brief Максимальное количество syscall-записей.
constexpr uint32_t MAX_SYSCALL_ENTRIES = static_cast<uint32_t>(NtFunction::nt_function_count);

/**
 * @brief Таблица syscall (размещается в стеке STUB, не в глобалах).
 */
struct SyscallTable {
    SyscallEntry entries[MAX_SYSCALL_ENTRIES];

    /// @brief Инициализация нулями.
    void clear() noexcept {
        for (auto& e : entries) {
            e.ssn = 0;
            e.syscall_addr = 0;
            e.resolved = false;
        }
    }

    /// @brief Доступ к записи по NtFunction.
    [[nodiscard]] SyscallEntry& get(NtFunction func) noexcept {
        return entries[static_cast<uint32_t>(func)];
    }

    /// @brief Константный доступ.
    [[nodiscard]] const SyscallEntry& get(NtFunction func) const noexcept {
        return entries[static_cast<uint32_t>(func)];
    }
};

// ============================================================================
// Предвычисленные хеши Nt* функций (DJB2)
// ============================================================================

constexpr uint32_t HASH_NT_ALLOCATE_VIRTUAL_MEMORY  = djb2_hash("NtAllocateVirtualMemory");
constexpr uint32_t HASH_NT_PROTECT_VIRTUAL_MEMORY   = djb2_hash("NtProtectVirtualMemory");
constexpr uint32_t HASH_NT_FREE_VIRTUAL_MEMORY      = djb2_hash("NtFreeVirtualMemory");
constexpr uint32_t HASH_NT_QUERY_INFORMATION_PROCESS = djb2_hash("NtQueryInformationProcess");
constexpr uint32_t HASH_NT_QUERY_SYSTEM_INFORMATION = djb2_hash("NtQuerySystemInformation");
constexpr uint32_t HASH_NT_GET_CONTEXT_THREAD       = djb2_hash("NtGetContextThread");
constexpr uint32_t HASH_NT_SET_INFORMATION_THREAD   = djb2_hash("NtSetInformationThread");
constexpr uint32_t HASH_NT_CLOSE                    = djb2_hash("NtClose");
constexpr uint32_t HASH_NT_DELAY_EXECUTION          = djb2_hash("NtDelayExecution");
constexpr uint32_t HASH_NT_QUERY_PERFORMANCE_COUNTER = djb2_hash("NtQueryPerformanceCounter");

/**
 * @brief Маппинг хеша функции → индекс NtFunction.
 *
 * @details Используется при парсинге экспортов ntdll.dll:
 *          для каждого экспорта вычисляем DJB2-хеш имени и ищем в этой таблице.
 */
struct NtFunctionHashEntry {
    uint32_t   hash;
    NtFunction func;
};

/// @brief Таблица маппинга хеш → NtFunction.
constexpr NtFunctionHashEntry NT_FUNCTION_HASHES[] = {
    { HASH_NT_ALLOCATE_VIRTUAL_MEMORY,   NtFunction::NtAllocateVirtualMemory },
    { HASH_NT_PROTECT_VIRTUAL_MEMORY,    NtFunction::NtProtectVirtualMemory },
    { HASH_NT_FREE_VIRTUAL_MEMORY,       NtFunction::NtFreeVirtualMemory },
    { HASH_NT_QUERY_INFORMATION_PROCESS, NtFunction::NtQueryInformationProcess },
    { HASH_NT_QUERY_SYSTEM_INFORMATION,  NtFunction::NtQuerySystemInformation },
    { HASH_NT_GET_CONTEXT_THREAD,        NtFunction::NtGetContextThread },
    { HASH_NT_SET_INFORMATION_THREAD,    NtFunction::NtSetInformationThread },
    { HASH_NT_CLOSE,                     NtFunction::NtClose },
    { HASH_NT_DELAY_EXECUTION,           NtFunction::NtDelayExecution },
    { HASH_NT_QUERY_PERFORMANCE_COUNTER, NtFunction::NtQueryPerformanceCounter },
};

constexpr uint32_t NT_FUNCTION_HASH_COUNT =
    sizeof(NT_FUNCTION_HASHES) / sizeof(NT_FUNCTION_HASHES[0]);

// ============================================================================
// Типы для VirtualProtect (NtProtectVirtualMemory)
// ============================================================================

constexpr uint32_t PAGE_EXECUTE_READ       = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE  = 0x40;
constexpr uint32_t PAGE_READWRITE          = 0x04;
constexpr uint32_t PAGE_READONLY           = 0x02;
constexpr uint32_t PAGE_GUARD_FLAG         = 0x100;

constexpr uint32_t MEM_COMMIT  = 0x00001000;
constexpr uint32_t MEM_RESERVE = 0x00002000;
constexpr uint32_t MEM_RELEASE = 0x00008000;

} // namespace mx::stub::pic
