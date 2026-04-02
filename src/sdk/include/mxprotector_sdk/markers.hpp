/**
 * @file markers.hpp
 * @brief [SDK] Макросы-маркеры для разметки регионов кода, подлежащих защите.
 *
 * @details Пользователь размечает участки кода макросами MX_VM_BEGIN/MX_VM_END,
 *          MX_MUTATE_BEGIN/MX_MUTATE_END, MX_OBFUSCATE_BEGIN/MX_OBFUSCATE_END.
 *          Builder (MarkerScanner) находит соответствующие паттерны в бинарнике
 *          и применяет соответствующие проходы защиты к маркированным регионам.
 *
 *          Маркер — это inline-функция, генерирующая детерминированную
 *          последовательность байтов: 8-байтный magic + 1-байтный тип маркера.
 *          Реализована через volatile-запись, чтобы компилятор не удалил маркер.
 *
 * @note Маркеры не влияют на выполнение до обработки Builder'ом.
 *       После защиты маркерные байты заменяются NOP'ами или кодом прохода.
 *
 * @par Пример использования:
 * @code
 * void sensitive_function() {
 *     MX_VM_BEGIN
 *     // Этот код будет виртуализирован
 *     decrypt_license_key();
 *     MX_VM_END
 * }
 * @endcode
 */

#pragma once

#include <cstdint>

namespace mx::sdk {

/**
 * @brief Magic-сигнатура маркера (8 байт): "MX_PROT\0" = 0x4D585F50524F5400.
 * @note Выбрана так, чтобы минимизировать вероятность ложных срабатываний.
 */
constexpr uint64_t MARKER_MAGIC = 0x00544F52505F584D; // little-endian "MX_PROT\0"

/**
 * @brief Типы маркеров, совпадающие с mx::MarkerType.
 */
enum MarkerTypeId : uint8_t {
    VM_BEGIN        = 0,
    VM_END          = 1,
    MUTATE_BEGIN    = 2,
    MUTATE_END      = 3,
    OBFUSCATE_BEGIN = 4,
    OBFUSCATE_END   = 5
};

/**
 * @brief Встраивает маркерную последовательность в поток инструкций.
 *
 * @details Генерирует 9 байт: magic (8) + marker_type (1).
 *          Использует volatile для предотвращения оптимизации компилятором.
 *          __forceinline гарантирует инлайнинг (маркер должен быть в потоке кода).
 *
 * @param marker_type Тип маркера (MarkerTypeId).
 */
#if defined(_MSC_VER)
__forceinline void emit_marker(uint8_t marker_type) {
    volatile uint64_t magic = MARKER_MAGIC;
    volatile uint8_t type = marker_type;
    (void)magic;
    (void)type;
}
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline)) inline void emit_marker(uint8_t marker_type) {
    volatile uint64_t magic = MARKER_MAGIC;
    volatile uint8_t type = marker_type;
    (void)magic;
    (void)type;
}
#endif

} // namespace mx::sdk

// ============================================================================
// Макросы-маркеры для использования в пользовательском коде
// ============================================================================

/// @brief Начало региона виртуализации (код будет транслирован в VM bytecode).
#define MX_VM_BEGIN         ::mx::sdk::emit_marker(::mx::sdk::VM_BEGIN);

/// @brief Конец региона виртуализации.
#define MX_VM_END           ::mx::sdk::emit_marker(::mx::sdk::VM_END);

/// @brief Начало региона мутации (инструкции будут заменены эквивалентными).
#define MX_MUTATE_BEGIN     ::mx::sdk::emit_marker(::mx::sdk::MUTATE_BEGIN);

/// @brief Конец региона мутации.
#define MX_MUTATE_END       ::mx::sdk::emit_marker(::mx::sdk::MUTATE_END);

/// @brief Начало региона обфускации (opaque predicates, MBA, bogus flow).
#define MX_OBFUSCATE_BEGIN  ::mx::sdk::emit_marker(::mx::sdk::OBFUSCATE_BEGIN);

/// @brief Конец региона обфускации.
#define MX_OBFUSCATE_END    ::mx::sdk::emit_marker(::mx::sdk::OBFUSCATE_END);
