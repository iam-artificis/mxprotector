/**
 * @file markers.hpp
 * @brief [SDK] Макросы-маркеры для разметки регионов кода, подлежащих защите.
 *
 * @details Формат маркера — 8-байтная сигнатура: "MX_PROT" (7 байт, big-endian
 *          ASCII) + 1 байт MarkerType в старшем байте little-endian uint64.
 *          Каждый тип маркера — уникальный 64-бит константа, что гарантирует
 *          MSVC невозможность shared-load между разными маркерами (каждый
 *          инлайн MX_VM_BEGIN/END генерирует свой `mov rax, imm64`).
 */

#pragma once

#include <cstdint>

namespace mx::sdk {

enum MarkerTypeId : uint8_t {
    VM_BEGIN        = 0,
    VM_END          = 1,
    MUTATE_BEGIN    = 2,
    MUTATE_END      = 3,
    OBFUSCATE_BEGIN = 4,
    OBFUSCATE_END   = 5,
    GUARD_BEGIN     = 6,
    GUARD_END       = 7
};

/// 7-байтовый префикс магии "MX_PROT" в little-endian: 0x??_54_4F_52_50_5F_58_4D
constexpr uint64_t MARKER_PREFIX = 0x00544F52505F584DULL;

/// Собирает полный 64-бит маркер по типу.
constexpr uint64_t make_marker_constant(uint8_t type) noexcept {
    return MARKER_PREFIX | (static_cast<uint64_t>(type) << 56);
}

/**
 * @brief Встраивает 8-байтовый маркер в инструкционный поток.
 *
 * Параметризуется типом маркера как non-type template parameter, чтобы
 * каждый тип имел свой уникальный constexpr imm64 → MSVC не сможет
 * коалесцировать две разные константы в один shared-load.
 */
template <uint8_t MarkerType>
#if defined(_MSC_VER)
__forceinline void emit_marker_t() {
#else
__attribute__((always_inline)) inline void emit_marker_t() {
#endif
    volatile uint64_t magic = make_marker_constant(MarkerType);
    (void)magic;
}

} // namespace mx::sdk

// ============================================================================
// Макросы-маркеры для пользовательского кода
// ============================================================================

#define MX_VM_BEGIN         ::mx::sdk::emit_marker_t<::mx::sdk::VM_BEGIN>();
#define MX_VM_END           ::mx::sdk::emit_marker_t<::mx::sdk::VM_END>();
#define MX_MUTATE_BEGIN     ::mx::sdk::emit_marker_t<::mx::sdk::MUTATE_BEGIN>();
#define MX_MUTATE_END       ::mx::sdk::emit_marker_t<::mx::sdk::MUTATE_END>();
#define MX_OBFUSCATE_BEGIN  ::mx::sdk::emit_marker_t<::mx::sdk::OBFUSCATE_BEGIN>();
#define MX_OBFUSCATE_END    ::mx::sdk::emit_marker_t<::mx::sdk::OBFUSCATE_END>();

/**
 * @brief Runtime-guard блок: код между MX_GUARD_BEGIN и MX_GUARD_END
 *        помещается builder'ом на выделенные 4K-страницы в отдельной
 *        секции и шифруется at-rest. При первом вызове VEH на INT3
 *        расшифровывает соответствующую страницу, исполняет тело
 *        блока, затем шифрует её обратно.
 *
 * ## Контракт использования
 *
 *   * Тело блока должно быть структурным straight-line регионом.
 *     РАЗРЕШЕНО: арифметика, вызовы других функций, циклы целиком
 *     внутри блока, условные переходы целиком внутри блока.
 *     ЗАПРЕЩЕНО:
 *       - `return`, `break`, `continue`, `goto` пересекающие
 *         границу блока
 *       - любой `throw` внутри блока (C++ исключение поднятое в
 *         теле не будет корректно раскручено — у релоцированной
 *         страницы нет `.pdata` записи, и unwinder упрётся в
 *         synthetic frame)
 *       - setjmp/longjmp через границу блока
 *     Если вам нужно вернуть ошибку из защищённого кода, сохраните
 *     её в переменную в теле блока и обработайте/выбросите ПОСЛЕ
 *     MX_GUARD_END.
 *
 *   * Размер тела — порядка десятков-сотен байт (одна 4K страница
 *     за вычетом двух 5-байтных int3+tag окон, т.е. ~4086 байт).
 *     Большие тела отбрасываются GuardPass'ом с предупреждением.
 *
 *   * MX_GUARD блок нельзя вкладывать ни внутрь MX_VM, ни внутрь
 *     MX_MUTATE, ни внутрь другого MX_GUARD. Скан маркеров
 *     корректно обрабатывает вложенность только парных начал/
 *     концов, а семантика конфликтов между passes не определена.
 *
 *   * MX_GUARD требует `--packer` — VEH handler инсталлируется
 *     через TLS callback из packer stub'а. GuardPass отбрасывает
 *     сборку с понятной ошибкой, если packer отключён.
 *
 *   * Исключения брошенные СНАРУЖИ блока (в окружающем коде
 *     защищённого бинаря) работают нормально. Runtime-guards и
 *     стандартный SEH unwinder не мешают друг другу — VEH
 *     фильтрует только STATUS_BREAKPOINT и возвращает
 *     CONTINUE_SEARCH для всех остальных кодов исключений.
 *
 * ## Гарантии runtime защиты
 *
 *   * At-rest: тело зашифровано XOR-шифром per-guard 32-байтовым
 *     ключом. Статический дамп `.exe`/`.dll` показывает
 *     шифротекст.
 *   * In-use: тело расшифровано плэйнтекстом ТОЛЬКО пока поток
 *     активно исполняет код внутри блока. Последний поток на
 *     выходе шифрует обратно (concurrent-thread ref-counting
 *     через LOCK XADD).
 *   * Concurrent-thread race: НЕ защищается. Пока поток A внутри
 *     блока, поток B в том же процессе может прочитать
 *     расшифрованные байты — предотвратить это в user-mode
 *     невозможно без kernel-mode thread-private mappings.
 *   * Anti-debug: VEH handler на каждом guard int3 проверяет
 *     CONTEXT.Dr0..Dr3. Любой non-zero hardware breakpoint →
 *     bailout без расшифровки, процесс падает на неподхваченном
 *     int3.
 */
#define MX_GUARD_BEGIN      ::mx::sdk::emit_marker_t<::mx::sdk::GUARD_BEGIN>();
#define MX_GUARD_END        ::mx::sdk::emit_marker_t<::mx::sdk::GUARD_END>();
