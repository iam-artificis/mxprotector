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
 * Ограничения (Commit 1 — только SDK-side, builder-side защита
 * будет добавлена следующими коммитами):
 *
 *   * Тело блока должно быть структурным callable-подобным регионом:
 *     никаких early-return, exception, goto через границу блока.
 *   * Размер тела — порядка десятков-сотен байт (одна 4K страница).
 *   * Тело не должно разделяться с другим кодом по страницам —
 *     builder сам выносит его на свою выровненную страницу.
 */
#define MX_GUARD_BEGIN      ::mx::sdk::emit_marker_t<::mx::sdk::GUARD_BEGIN>();
#define MX_GUARD_END        ::mx::sdk::emit_marker_t<::mx::sdk::GUARD_END>();
