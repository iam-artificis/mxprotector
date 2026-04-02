/**
 * @file register_reassignment.cpp
 * @brief [BUILDER] Переназначение регистров в пределах базового блока.
 *
 * @details Реализует базовое переназначение регистров: для каждой инструкции
 *          в буфере кода, если оба операнда — регистры (mod=3 в ModR/M),
 *          случайно меняет кодирование на альтернативную форму (direction flip).
 *          Полноценное переназначение (с liveness analysis) запланировано на Phase 4.
 *
 * @note Текущая реализация — «лёгкое» переназначение через direction bit flip
 *       для reg-reg инструкций. Не изменяет семантику, только кодирование.
 *       Безопасно для всех reg-reg операций.
 */

#include "mxprotector/protection/mutation/mutation_engine.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <cstring>

namespace mx {

namespace {

/// @brief Множество opcodes, поддерживающих direction flip (бит 1 = direction).
constexpr bool supports_direction_flip(uint8_t opcode) noexcept {
    switch (opcode) {
        case 0x01: case 0x03:
        case 0x09: case 0x0B:
        case 0x11: case 0x13:
        case 0x19: case 0x1B:
        case 0x21: case 0x23:
        case 0x29: case 0x2B:
        case 0x31: case 0x33:
        case 0x39: case 0x3B:
        case 0x89: case 0x8B:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Применяет direction flip к одной инструкции in-place.
 * @param insn_bytes Буфер с байтами инструкции (модифицируется).
 * @param length Длина инструкции.
 * @return true если flip был применён.
 */
bool apply_direction_flip_inplace(uint8_t* insn_bytes, uint8_t length) {
    if (length < 2) return false;

    ByteView view(insn_bytes, length);
    if (!x86::is_modrm_reg_reg(view)) return false;

    const uint8_t op_off = x86::find_opcode_offset(view);
    if (op_off + 1 >= length) return false;

    const uint8_t opcode = insn_bytes[op_off];
    if (!supports_direction_flip(opcode)) return false;

    insn_bytes[op_off] = opcode ^ 0x02;

    const uint8_t modrm_off = op_off + 1;
    const uint8_t old_modrm = insn_bytes[modrm_off];
    const uint8_t old_reg = x86::modrm_reg(old_modrm);
    const uint8_t old_rm = x86::modrm_rm(old_modrm);
    insn_bytes[modrm_off] = x86::make_modrm(3, old_rm, old_reg);

    uint8_t prefix_off = 0;
    while (prefix_off < op_off && x86::is_legacy_prefix(insn_bytes[prefix_off])) {
        ++prefix_off;
    }
    if (prefix_off < op_off && x86::is_rex(insn_bytes[prefix_off])) {
        insn_bytes[prefix_off] = x86::swap_rex_rb(insn_bytes[prefix_off]);
    }

    return true;
}

} // anonymous namespace

} // namespace mx
