/**
 * @file constant_unfolding.cpp
 * @brief [BUILDER] Реализация декомпозиции констант (constant unfolding).
 *
 * @details Заменяет инструкции MOV reg, imm32 на последовательности из 2–3
 *          инструкций, вычисляющих ту же константу:
 *          - XOR: mov reg, A; xor reg, B     (A ^ B == value)
 *          - ADD: mov reg, A; add reg, B     (A + B == value)
 *          - SUB: mov reg, A; sub reg, B     (A - B == value)
 *          - Multi-step: mov reg, A; xor reg, B; add reg, C
 *
 *          Части A, B, C генерируются случайно при каждом вызове.
 *
 * @note Поддерживает только 32-битные immediate (mov r32, imm32 и mov r64, imm32).
 *       64-битные immediate (mov r64, imm64) не поддерживаются в Phase 2.
 */

#include "mxprotector/protection/obfuscation/constant_unfolding.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx {

// ============================================================================
// can_unfold — проверка применимости
// ============================================================================

bool ConstantUnfolder::can_unfold(const analysis::Instruction& insn) const {
    if (insn.mnemonic() != "mov") return false;
    if (insn.length() < 5) return false;

    const auto bytes = insn.raw_bytes();
    const uint8_t op_off = x86::find_opcode_offset(bytes);
    if (op_off >= bytes.size()) return false;

    const uint8_t op = bytes[op_off];

    if (op >= 0xB8 && op <= 0xBF) {
        const uint8_t rex = x86::find_rex(bytes);
        if (rex != 0 && x86::rex_w(rex)) return false;

        uint32_t imm = 0;
        for (uint8_t i = 0; i < 4 && (op_off + 1 + i) < bytes.size(); ++i) {
            imm |= static_cast<uint32_t>(bytes[op_off + 1 + i]) << (i * 8);
        }
        return imm != 0;
    }

    return false;
}

// ============================================================================
// unfold — декомпозиция для конкретной инструкции
// ============================================================================

UnfoldedConstant ConstantUnfolder::unfold(
    const analysis::Instruction& insn, Randomizer& rng) const
{
    if (!can_unfold(insn)) return {};

    const auto bytes = insn.raw_bytes();
    const uint8_t op_off = x86::find_opcode_offset(bytes);
    const uint8_t op = bytes[op_off];

    uint8_t reg_3bit = op - 0xB8;
    const uint8_t rex = x86::find_rex(bytes);
    uint8_t reg_id = reg_3bit;
    if (rex != 0 && x86::rex_b(rex)) {
        reg_id |= 8;
    }

    uint32_t imm = 0;
    for (uint8_t i = 0; i < 4 && (op_off + 1 + i) < bytes.size(); ++i) {
        imm |= static_cast<uint32_t>(bytes[op_off + 1 + i]) << (i * 8);
    }

    return unfold_imm32(reg_id, imm, rng);
}

// ============================================================================
// unfold_imm32 — декомпозиция 32-битной константы
// ============================================================================

UnfoldedConstant ConstantUnfolder::unfold_imm32(
    uint8_t reg_id, uint32_t value, Randomizer& rng) const
{
    const uint32_t method = rng.next_range(0, 3);

    switch (method) {
        case 0:  return gen_xor_decomposition(reg_id, value, rng);
        case 1:  return gen_add_decomposition(reg_id, value, rng);
        case 2:  return gen_sub_decomposition(reg_id, value, rng);
        default: return gen_multi_step(reg_id, value, rng);
    }
}

// ============================================================================
// Вспомогательная функция: emit MOV r32, imm32
// ============================================================================

namespace {

void emit_mov_r32_imm32(ByteBuffer& out, uint8_t reg_id, uint32_t imm) {
    const uint8_t reg_3bit = reg_id & 0x07;
    const bool extended = (reg_id & 0x08) != 0;

    if (extended) {
        out.push_back(0x41);
    }

    out.push_back(static_cast<uint8_t>(0xB8 + reg_3bit));
    out.push_back(static_cast<uint8_t>(imm & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 24) & 0xFF));
}

void emit_group1_r32_imm32(ByteBuffer& out, uint8_t reg_id, uint8_t op_ext, uint32_t imm) {
    const uint8_t reg_3bit = reg_id & 0x07;
    const bool extended = (reg_id & 0x08) != 0;

    if (extended) {
        out.push_back(0x41);
    }

    out.push_back(0x81);
    out.push_back(x86::make_modrm(3, op_ext, reg_3bit));
    out.push_back(static_cast<uint8_t>(imm & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((imm >> 24) & 0xFF));
}

} // anonymous namespace

// ============================================================================
// gen_xor_decomposition — mov reg, A; xor reg, B (A^B == value)
// ============================================================================

UnfoldedConstant ConstantUnfolder::gen_xor_decomposition(
    uint8_t reg_id, uint32_t value, Randomizer& rng) const
{
    const uint32_t a = rng.next_u32();
    const uint32_t b = a ^ value;

    ByteBuffer code;
    code.reserve(16);

    emit_mov_r32_imm32(code, reg_id, a);
    emit_group1_r32_imm32(code, reg_id, 6, b);

    UnfoldedConstant result;
    result.code = std::move(code);
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.instruction_count = 2;
    return result;
}

// ============================================================================
// gen_add_decomposition — mov reg, A; add reg, B (A+B == value)
// ============================================================================

UnfoldedConstant ConstantUnfolder::gen_add_decomposition(
    uint8_t reg_id, uint32_t value, Randomizer& rng) const
{
    const uint32_t a = rng.next_u32();
    const uint32_t b = value - a;

    ByteBuffer code;
    code.reserve(16);

    emit_mov_r32_imm32(code, reg_id, a);
    emit_group1_r32_imm32(code, reg_id, 0, b);

    UnfoldedConstant result;
    result.code = std::move(code);
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.instruction_count = 2;
    return result;
}

// ============================================================================
// gen_sub_decomposition — mov reg, A; sub reg, B (A-B == value)
// ============================================================================

UnfoldedConstant ConstantUnfolder::gen_sub_decomposition(
    uint8_t reg_id, uint32_t value, Randomizer& rng) const
{
    const uint32_t a = rng.next_u32();
    const uint32_t b = a - value;

    ByteBuffer code;
    code.reserve(16);

    emit_mov_r32_imm32(code, reg_id, a);
    emit_group1_r32_imm32(code, reg_id, 5, b);

    UnfoldedConstant result;
    result.code = std::move(code);
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.instruction_count = 2;
    return result;
}

// ============================================================================
// gen_multi_step — mov reg, A; xor reg, B; add reg, C ((A^B)+C == value)
// ============================================================================

UnfoldedConstant ConstantUnfolder::gen_multi_step(
    uint8_t reg_id, uint32_t value, Randomizer& rng) const
{
    const uint32_t c = rng.next_u32();
    const uint32_t xor_result = value - c;
    const uint32_t a = rng.next_u32();
    const uint32_t b = a ^ xor_result;

    ByteBuffer code;
    code.reserve(24);

    emit_mov_r32_imm32(code, reg_id, a);
    emit_group1_r32_imm32(code, reg_id, 6, b);
    emit_group1_r32_imm32(code, reg_id, 0, c);

    UnfoldedConstant result;
    result.code = std::move(code);
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.instruction_count = 3;
    return result;
}

} // namespace mx
