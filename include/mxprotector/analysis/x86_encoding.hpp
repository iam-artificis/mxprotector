/**
 * @file x86_encoding.hpp
 * @brief [BUILDER] Утилиты для анализа и генерации байтов x86/x64 инструкций.
 *
 * @details Предоставляет inline-функции для работы с байтовым представлением
 *          x86/x64 инструкций: определение префиксов, разбор ModR/M, генерация
 *          multi-byte NOP. Используется модулями мутации и обфускации для
 *          безопасной модификации машинного кода на уровне байтов.
 *
 * @note Все функции работают с сырыми байтами и не зависят от Zydis.
 *       Корректность гарантируется для x86-64 (long mode) инструкций.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::x86 {

// ============================================================================
// Идентификаторы регистров x86/x64
// ============================================================================

/// @brief 4-битные идентификаторы регистров общего назначения x86/x64.
enum class Reg : uint8_t {
    rax = 0,  rcx = 1,  rdx = 2,  rbx = 3,
    rsp = 4,  rbp = 5,  rsi = 6,  rdi = 7,
    r8  = 8,  r9  = 9,  r10 = 10, r11 = 11,
    r12 = 12, r13 = 13, r14 = 14, r15 = 15
};

// ============================================================================
// Определение префиксов
// ============================================================================

/**
 * @brief Проверяет, является ли байт legacy-префиксом x86.
 * @param byte Байт для проверки.
 * @return true если это legacy-префикс (LOCK, REP, сегментный, 66h, 67h).
 */
[[nodiscard]] inline constexpr bool is_legacy_prefix(uint8_t byte) noexcept {
    switch (byte) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26:
        case 0x64: case 0x65:
        case 0x66: case 0x67:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Проверяет, является ли байт REX-префиксом (0x40–0x4F).
 * @param byte Байт для проверки.
 * @return true если это REX-префикс.
 */
[[nodiscard]] inline constexpr bool is_rex(uint8_t byte) noexcept {
    return (byte & 0xF0) == 0x40;
}

/// @brief REX.W бит — 64-битный размер операнда.
[[nodiscard]] inline constexpr bool rex_w(uint8_t rex) noexcept { return (rex & 0x08) != 0; }

/// @brief REX.R бит — расширение поля reg в ModR/M.
[[nodiscard]] inline constexpr bool rex_r(uint8_t rex) noexcept { return (rex & 0x04) != 0; }

/// @brief REX.X бит — расширение поля index в SIB.
[[nodiscard]] inline constexpr bool rex_x(uint8_t rex) noexcept { return (rex & 0x02) != 0; }

/// @brief REX.B бит — расширение поля rm в ModR/M или base в SIB.
[[nodiscard]] inline constexpr bool rex_b(uint8_t rex) noexcept { return (rex & 0x01) != 0; }

// ============================================================================
// Разбор ModR/M
// ============================================================================

/// @brief Извлекает поле mod (биты 7:6) из байта ModR/M.
[[nodiscard]] inline constexpr uint8_t modrm_mod(uint8_t modrm) noexcept {
    return (modrm >> 6) & 0x03;
}

/// @brief Извлекает поле reg (биты 5:3) из байта ModR/M.
[[nodiscard]] inline constexpr uint8_t modrm_reg(uint8_t modrm) noexcept {
    return (modrm >> 3) & 0x07;
}

/// @brief Извлекает поле rm (биты 2:0) из байта ModR/M.
[[nodiscard]] inline constexpr uint8_t modrm_rm(uint8_t modrm) noexcept {
    return modrm & 0x07;
}

/**
 * @brief Собирает байт ModR/M из полей mod, reg, rm.
 * @param mod Поле mod (0–3).
 * @param reg Поле reg (0–7).
 * @param rm Поле rm (0–7).
 * @return Собранный байт ModR/M.
 */
[[nodiscard]] inline constexpr uint8_t make_modrm(uint8_t mod, uint8_t reg, uint8_t rm) noexcept {
    return static_cast<uint8_t>((mod << 6) | ((reg & 0x07) << 3) | (rm & 0x07));
}

// ============================================================================
// Навигация по байтам инструкции
// ============================================================================

/**
 * @brief Находит смещение opcode-байта (после legacy-префиксов и REX).
 * @param bytes Сырые байты инструкции.
 * @return Смещение первого байта opcode от начала инструкции.
 */
[[nodiscard]] inline uint8_t find_opcode_offset(ByteView bytes) noexcept {
    uint8_t pos = 0;
    while (pos < bytes.size() && is_legacy_prefix(bytes[pos])) {
        ++pos;
    }
    if (pos < bytes.size() && is_rex(bytes[pos])) {
        ++pos;
    }
    return pos;
}

/**
 * @brief Находит REX-байт в инструкции.
 * @param bytes Сырые байты инструкции.
 * @return REX-байт или 0, если REX отсутствует.
 */
[[nodiscard]] inline uint8_t find_rex(ByteView bytes) noexcept {
    uint8_t pos = 0;
    while (pos < bytes.size() && is_legacy_prefix(bytes[pos])) {
        ++pos;
    }
    if (pos < bytes.size() && is_rex(bytes[pos])) {
        return bytes[pos];
    }
    return 0;
}

/**
 * @brief Проверяет, что инструкция имеет форму «регистр-регистр» (mod=3 в ModR/M).
 * @param bytes Сырые байты инструкции.
 * @return true если mod == 3 в байте ModR/M (операнд сразу после opcode).
 *
 * @note Предполагает, что opcode — однобайтовый и за ним следует ModR/M.
 */
[[nodiscard]] inline bool is_modrm_reg_reg(ByteView bytes) noexcept {
    const uint8_t modrm_off = find_opcode_offset(bytes) + 1;
    if (modrm_off >= bytes.size()) return false;
    return modrm_mod(bytes[modrm_off]) == 3;
}

/**
 * @brief Возвращает полный 4-битный ID регистра из поля reg (с учётом REX.R).
 * @param bytes Сырые байты инструкции.
 * @return 4-битный ID регистра [0..15].
 */
[[nodiscard]] inline uint8_t get_full_reg(ByteView bytes) noexcept {
    const uint8_t modrm_off = find_opcode_offset(bytes) + 1;
    if (modrm_off >= bytes.size()) return 0;
    uint8_t reg = modrm_reg(bytes[modrm_off]);
    const uint8_t rex = find_rex(bytes);
    if (rex != 0 && rex_r(rex)) {
        reg |= 8;
    }
    return reg;
}

/**
 * @brief Возвращает полный 4-битный ID регистра из поля rm (с учётом REX.B).
 * @param bytes Сырые байты инструкции.
 * @return 4-битный ID регистра [0..15].
 */
[[nodiscard]] inline uint8_t get_full_rm(ByteView bytes) noexcept {
    const uint8_t modrm_off = find_opcode_offset(bytes) + 1;
    if (modrm_off >= bytes.size()) return 0;
    uint8_t rm = modrm_rm(bytes[modrm_off]);
    const uint8_t rex = find_rex(bytes);
    if (rex != 0 && rex_b(rex)) {
        rm |= 8;
    }
    return rm;
}

/**
 * @brief Проверяет, что оба операнда инструкции — один и тот же регистр.
 * @param bytes Сырые байты инструкции.
 * @return true если mod=3 и reg==rm (с учётом REX.R==REX.B).
 */
[[nodiscard]] inline bool is_same_reg_operands(ByteView bytes) noexcept {
    if (!is_modrm_reg_reg(bytes)) return false;
    return get_full_reg(bytes) == get_full_rm(bytes);
}

// ============================================================================
// Генерация NOP-инструкций
// ============================================================================

/**
 * @brief Генерирует multi-byte NOP заданной длины (1–15 байт).
 * @param length Длина NOP в байтах (0 возвращает пустой буфер).
 * @return Буфер с NOP-инструкцией указанной длины.
 *
 * @details Использует формы NOP, рекомендованные Intel (SDM Table 4-12):
 *          1B: 90
 *          2B: 66 90
 *          3B: 0F 1F 00
 *          4B: 0F 1F 40 00
 *          ...
 *          9B: 66 0F 1F 84 00 00 00 00 00
 */
[[nodiscard]] inline ByteBuffer make_nop(uint8_t length) {
    switch (length) {
        case 0:  return {};
        case 1:  return {0x90};
        case 2:  return {0x66, 0x90};
        case 3:  return {0x0F, 0x1F, 0x00};
        case 4:  return {0x0F, 0x1F, 0x40, 0x00};
        case 5:  return {0x0F, 0x1F, 0x44, 0x00, 0x00};
        case 6:  return {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00};
        case 7:  return {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00};
        case 8:  return {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
        case 9:  return {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};
        default: {
            ByteBuffer result;
            result.reserve(length);
            uint8_t remaining = length;
            while (remaining > 0) {
                const uint8_t nop_len = (remaining >= 9) ? uint8_t{9} : remaining;
                auto nop = make_nop(nop_len);
                result.insert(result.end(), nop.begin(), nop.end());
                remaining -= nop_len;
            }
            return result;
        }
    }
}

/**
 * @brief Генерирует NOP-заполнение точно заданной длины.
 * @param size Суммарная длина в байтах.
 * @return Буфер NOP-инструкций суммарной длиной size.
 */
[[nodiscard]] inline ByteBuffer make_nop_padding(size_t size) {
    return make_nop(static_cast<uint8_t>(size > 15 ? 15 : size));
}

/**
 * @brief Меняет местами REX.R и REX.B биты.
 * @param rex Исходный REX-байт.
 * @return REX-байт с поменянными R и B.
 */
[[nodiscard]] inline constexpr uint8_t swap_rex_rb(uint8_t rex) noexcept {
    const uint8_t r_bit = (rex >> 2) & 1;
    const uint8_t b_bit = rex & 1;
    return static_cast<uint8_t>((rex & 0xFA) | (b_bit << 2) | r_bit);
}

} // namespace mx::x86
