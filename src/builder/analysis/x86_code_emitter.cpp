/**
 * @file x86_code_emitter.cpp
 * @brief [BUILDER] Реализация X86CodeEmitter — структурированный x86/x64 кодогенератор.
 *
 * @details Генерирует корректный машинный код x86/x64 из типизированных параметров.
 *          Поддерживает все основные инструкции, необходимые для CFF, MBA и мутации.
 *          Автоматическое разрешение label'ов при финализации (build()).
 */

#include "mxprotector/analysis/assembler.hpp"

#include <algorithm>
#include <cstring>
#include <format>

namespace mx::analysis {

X86CodeEmitter::X86CodeEmitter(bool is_64bit)
    : is_64bit_(is_64bit)
{
    code_.reserve(256);
}

void X86CodeEmitter::clear() {
    code_.clear();
    label_bindings_.clear();
    fixups_.clear();
    next_label_id_ = 1;
}

void X86CodeEmitter::emit_byte(uint8_t b) { code_.push_back(b); }

void X86CodeEmitter::emit_word(uint16_t w) {
    code_.push_back(static_cast<uint8_t>(w & 0xFF));
    code_.push_back(static_cast<uint8_t>((w >> 8) & 0xFF));
}

void X86CodeEmitter::emit_dword(uint32_t d) {
    code_.push_back(static_cast<uint8_t>(d & 0xFF));
    code_.push_back(static_cast<uint8_t>((d >> 8) & 0xFF));
    code_.push_back(static_cast<uint8_t>((d >> 16) & 0xFF));
    code_.push_back(static_cast<uint8_t>((d >> 24) & 0xFF));
}

void X86CodeEmitter::emit_qword(uint64_t q) {
    emit_dword(static_cast<uint32_t>(q & 0xFFFFFFFF));
    emit_dword(static_cast<uint32_t>((q >> 32) & 0xFFFFFFFF));
}

void X86CodeEmitter::emit_rex(bool w, bool r, bool x, bool b) {
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    emit_byte(rex);
}

void X86CodeEmitter::emit_rex_if_needed(bool force_w, x86::Reg reg, x86::Reg rm) {
    const bool r_ext = static_cast<uint8_t>(reg) >= 8;
    const bool b_ext = static_cast<uint8_t>(rm) >= 8;
    const bool w = is_64bit_ && force_w;

    if (w || r_ext || b_ext) {
        emit_rex(w, r_ext, false, b_ext);
    }
}

void X86CodeEmitter::emit_modrm_reg_reg(uint8_t reg_field, x86::Reg rm) {
    const uint8_t rm_3bit = static_cast<uint8_t>(rm) & 0x07;
    emit_byte(x86::make_modrm(3, reg_field & 0x07, rm_3bit));
}

void X86CodeEmitter::emit_mem_operand(uint8_t reg_field, MemOperand mem) {
    const uint8_t base_3bit = static_cast<uint8_t>(mem.base) & 0x07;
    const bool needs_sib = (base_3bit == 4);

    if (mem.disp == 0 && base_3bit != 5) {
        emit_byte(x86::make_modrm(0, reg_field & 0x07, needs_sib ? 4 : base_3bit));
        if (needs_sib) {
            emit_byte(0x24);
        }
    } else if (mem.disp >= -128 && mem.disp <= 127) {
        emit_byte(x86::make_modrm(1, reg_field & 0x07, needs_sib ? 4 : base_3bit));
        if (needs_sib) {
            emit_byte(0x24);
        }
        emit_byte(static_cast<uint8_t>(static_cast<int8_t>(mem.disp)));
    } else {
        emit_byte(x86::make_modrm(2, reg_field & 0x07, needs_sib ? 4 : base_3bit));
        if (needs_sib) {
            emit_byte(0x24);
        }
        emit_dword(static_cast<uint32_t>(mem.disp));
    }
}

// ============================================================================
// Labels
// ============================================================================

Label X86CodeEmitter::create_label() {
    return Label{next_label_id_++};
}

X86CodeEmitter& X86CodeEmitter::bind_label(Label label) {
    label_bindings_.emplace_back(label, code_.size());
    return *this;
}

// ============================================================================
// Data Movement
// ============================================================================

X86CodeEmitter& X86CodeEmitter::mov(x86::Reg dst, uint64_t imm) {
    const uint8_t dst_3bit = static_cast<uint8_t>(dst) & 0x07;
    const bool dst_ext = static_cast<uint8_t>(dst) >= 8;

    if (is_64bit_ && imm > 0xFFFFFFFF) {
        emit_rex(true, false, false, dst_ext);
        emit_byte(0xB8 + dst_3bit);
        emit_qword(imm);
    } else {
        if (is_64bit_) {
            emit_rex(true, false, false, dst_ext);
        } else if (dst_ext) {
            emit_rex(false, false, false, true);
        }
        emit_byte(0xC7);
        emit_modrm_reg_reg(0, dst);
        emit_dword(static_cast<uint32_t>(imm));
    }
    return *this;
}

X86CodeEmitter& X86CodeEmitter::mov(x86::Reg dst, x86::Reg src) {
    emit_rex_if_needed(true, src, dst);
    emit_byte(0x89);
    emit_modrm_reg_reg(static_cast<uint8_t>(src) & 0x07, dst);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::mov(x86::Reg dst, MemOperand src) {
    const bool dst_ext = static_cast<uint8_t>(dst) >= 8;
    const bool base_ext = static_cast<uint8_t>(src.base) >= 8;
    if (is_64bit_ || dst_ext || base_ext) {
        emit_rex(is_64bit_, dst_ext, false, base_ext);
    }
    emit_byte(0x8B);
    emit_mem_operand(static_cast<uint8_t>(dst) & 0x07, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::mov(MemOperand dst, x86::Reg src) {
    const bool src_ext = static_cast<uint8_t>(src) >= 8;
    const bool base_ext = static_cast<uint8_t>(dst.base) >= 8;
    if (is_64bit_ || src_ext || base_ext) {
        emit_rex(is_64bit_, src_ext, false, base_ext);
    }
    emit_byte(0x89);
    emit_mem_operand(static_cast<uint8_t>(src) & 0x07, dst);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::mov(MemOperand dst, uint32_t imm) {
    const bool base_ext = static_cast<uint8_t>(dst.base) >= 8;
    if (is_64bit_ || base_ext) {
        emit_rex(is_64bit_, false, false, base_ext);
    }
    emit_byte(0xC7);
    emit_mem_operand(0, dst);
    emit_dword(imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::lea(x86::Reg dst, MemOperand src) {
    const bool dst_ext = static_cast<uint8_t>(dst) >= 8;
    const bool base_ext = static_cast<uint8_t>(src.base) >= 8;
    if (is_64bit_ || dst_ext || base_ext) {
        emit_rex(is_64bit_, dst_ext, false, base_ext);
    }
    emit_byte(0x8D);
    emit_mem_operand(static_cast<uint8_t>(dst) & 0x07, src);
    return *this;
}

// ============================================================================
// ALU helpers
// ============================================================================

void X86CodeEmitter::emit_alu_reg_imm(uint8_t alu_op, x86::Reg dst, int32_t imm) {
    const bool dst_ext = static_cast<uint8_t>(dst) >= 8;

    if (is_64bit_ || dst_ext) {
        emit_rex(is_64bit_, false, false, dst_ext);
    }

    if (imm >= -128 && imm <= 127) {
        emit_byte(0x83);
        emit_modrm_reg_reg(alu_op, dst);
        emit_byte(static_cast<uint8_t>(static_cast<int8_t>(imm)));
    } else {
        emit_byte(0x81);
        emit_modrm_reg_reg(alu_op, dst);
        emit_dword(static_cast<uint32_t>(imm));
    }
}

void X86CodeEmitter::emit_alu_reg_reg(uint8_t opcode_rm_r, x86::Reg dst, x86::Reg src) {
    emit_rex_if_needed(true, src, dst);
    emit_byte(opcode_rm_r);
    emit_modrm_reg_reg(static_cast<uint8_t>(src) & 0x07, dst);
}

void X86CodeEmitter::emit_unary_reg(uint8_t reg_field, x86::Reg operand) {
    const bool ext = static_cast<uint8_t>(operand) >= 8;
    if (is_64bit_ || ext) {
        emit_rex(is_64bit_, false, false, ext);
    }
    emit_byte(0xF7);
    emit_modrm_reg_reg(reg_field, operand);
}

// ============================================================================
// Arithmetic
// ============================================================================

X86CodeEmitter& X86CodeEmitter::add(x86::Reg dst, int32_t imm) {
    emit_alu_reg_imm(0, dst, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::add(x86::Reg dst, x86::Reg src) {
    emit_alu_reg_reg(0x01, dst, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::sub(x86::Reg dst, int32_t imm) {
    emit_alu_reg_imm(5, dst, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::sub(x86::Reg dst, x86::Reg src) {
    emit_alu_reg_reg(0x29, dst, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::imul(x86::Reg dst, x86::Reg src, int32_t imm) {
    const bool dst_ext = static_cast<uint8_t>(dst) >= 8;
    const bool src_ext = static_cast<uint8_t>(src) >= 8;

    if (is_64bit_ || dst_ext || src_ext) {
        emit_rex(is_64bit_, dst_ext, false, src_ext);
    }

    if (imm >= -128 && imm <= 127) {
        emit_byte(0x6B);
        emit_modrm_reg_reg(static_cast<uint8_t>(dst) & 0x07, src);
        emit_byte(static_cast<uint8_t>(static_cast<int8_t>(imm)));
    } else {
        emit_byte(0x69);
        emit_modrm_reg_reg(static_cast<uint8_t>(dst) & 0x07, src);
        emit_dword(static_cast<uint32_t>(imm));
    }
    return *this;
}

// ============================================================================
// Bitwise
// ============================================================================

X86CodeEmitter& X86CodeEmitter::xor_(x86::Reg dst, int32_t imm) {
    emit_alu_reg_imm(6, dst, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::xor_(x86::Reg dst, x86::Reg src) {
    emit_alu_reg_reg(0x31, dst, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::and_(x86::Reg dst, int32_t imm) {
    emit_alu_reg_imm(4, dst, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::and_(x86::Reg dst, x86::Reg src) {
    emit_alu_reg_reg(0x21, dst, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::or_(x86::Reg dst, int32_t imm) {
    emit_alu_reg_imm(1, dst, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::or_(x86::Reg dst, x86::Reg src) {
    emit_alu_reg_reg(0x09, dst, src);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::not_(x86::Reg operand) {
    emit_unary_reg(2, operand);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::neg(x86::Reg operand) {
    emit_unary_reg(3, operand);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::shl(x86::Reg dst, uint8_t count) {
    const bool ext = static_cast<uint8_t>(dst) >= 8;
    if (is_64bit_ || ext) {
        emit_rex(is_64bit_, false, false, ext);
    }
    if (count == 1) {
        emit_byte(0xD1);
        emit_modrm_reg_reg(4, dst);
    } else {
        emit_byte(0xC1);
        emit_modrm_reg_reg(4, dst);
        emit_byte(count);
    }
    return *this;
}

X86CodeEmitter& X86CodeEmitter::shr(x86::Reg dst, uint8_t count) {
    const bool ext = static_cast<uint8_t>(dst) >= 8;
    if (is_64bit_ || ext) {
        emit_rex(is_64bit_, false, false, ext);
    }
    if (count == 1) {
        emit_byte(0xD1);
        emit_modrm_reg_reg(5, dst);
    } else {
        emit_byte(0xC1);
        emit_modrm_reg_reg(5, dst);
        emit_byte(count);
    }
    return *this;
}

X86CodeEmitter& X86CodeEmitter::rol(x86::Reg dst, uint8_t count) {
    const bool ext = static_cast<uint8_t>(dst) >= 8;
    if (is_64bit_ || ext) {
        emit_rex(is_64bit_, false, false, ext);
    }
    if (count == 1) {
        emit_byte(0xD1);
        emit_modrm_reg_reg(0, dst);
    } else {
        emit_byte(0xC1);
        emit_modrm_reg_reg(0, dst);
        emit_byte(count);
    }
    return *this;
}

X86CodeEmitter& X86CodeEmitter::ror(x86::Reg dst, uint8_t count) {
    const bool ext = static_cast<uint8_t>(dst) >= 8;
    if (is_64bit_ || ext) {
        emit_rex(is_64bit_, false, false, ext);
    }
    if (count == 1) {
        emit_byte(0xD1);
        emit_modrm_reg_reg(1, dst);
    } else {
        emit_byte(0xC1);
        emit_modrm_reg_reg(1, dst);
        emit_byte(count);
    }
    return *this;
}

// ============================================================================
// Comparison / Test
// ============================================================================

X86CodeEmitter& X86CodeEmitter::cmp(x86::Reg lhs, int32_t imm) {
    emit_alu_reg_imm(7, lhs, imm);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::cmp(x86::Reg lhs, x86::Reg rhs) {
    emit_alu_reg_reg(0x39, lhs, rhs);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::cmp(MemOperand lhs, int32_t imm) {
    const bool base_ext = static_cast<uint8_t>(lhs.base) >= 8;
    if (is_64bit_ || base_ext) {
        emit_rex(is_64bit_, false, false, base_ext);
    }
    if (imm >= -128 && imm <= 127) {
        emit_byte(0x83);
        emit_mem_operand(7, lhs);
        emit_byte(static_cast<uint8_t>(static_cast<int8_t>(imm)));
    } else {
        emit_byte(0x81);
        emit_mem_operand(7, lhs);
        emit_dword(static_cast<uint32_t>(imm));
    }
    return *this;
}

X86CodeEmitter& X86CodeEmitter::test(x86::Reg lhs, x86::Reg rhs) {
    emit_alu_reg_reg(0x85, lhs, rhs);
    return *this;
}

// ============================================================================
// Control Flow
// ============================================================================

X86CodeEmitter& X86CodeEmitter::jmp(Label target) {
    emit_byte(0xE9);
    fixups_.push_back({target, code_.size(), code_.size() + 4, false});
    emit_dword(0);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::jmp(int32_t rel32) {
    emit_byte(0xE9);
    emit_dword(static_cast<uint32_t>(rel32));
    return *this;
}

X86CodeEmitter& X86CodeEmitter::jcc(ConditionCode cc, Label target) {
    emit_byte(0x0F);
    emit_byte(0x80 + static_cast<uint8_t>(cc));
    fixups_.push_back({target, code_.size(), code_.size() + 4, false});
    emit_dword(0);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::jcc(ConditionCode cc, int32_t rel32) {
    emit_byte(0x0F);
    emit_byte(0x80 + static_cast<uint8_t>(cc));
    emit_dword(static_cast<uint32_t>(rel32));
    return *this;
}

X86CodeEmitter& X86CodeEmitter::call(int32_t rel32) {
    emit_byte(0xE8);
    emit_dword(static_cast<uint32_t>(rel32));
    return *this;
}

X86CodeEmitter& X86CodeEmitter::ret() {
    emit_byte(0xC3);
    return *this;
}

// ============================================================================
// Stack
// ============================================================================

X86CodeEmitter& X86CodeEmitter::push(x86::Reg reg) {
    const uint8_t reg_val = static_cast<uint8_t>(reg);
    if (reg_val >= 8) {
        emit_rex(false, false, false, true);
    }
    emit_byte(0x50 + (reg_val & 0x07));
    return *this;
}

X86CodeEmitter& X86CodeEmitter::pop(x86::Reg reg) {
    const uint8_t reg_val = static_cast<uint8_t>(reg);
    if (reg_val >= 8) {
        emit_rex(false, false, false, true);
    }
    emit_byte(0x58 + (reg_val & 0x07));
    return *this;
}

X86CodeEmitter& X86CodeEmitter::push_imm(int32_t imm) {
    if (imm >= -128 && imm <= 127) {
        emit_byte(0x6A);
        emit_byte(static_cast<uint8_t>(static_cast<int8_t>(imm)));
    } else {
        emit_byte(0x68);
        emit_dword(static_cast<uint32_t>(imm));
    }
    return *this;
}

// ============================================================================
// Misc
// ============================================================================

X86CodeEmitter& X86CodeEmitter::nop(uint8_t count) {
    auto nop_bytes = x86::make_nop(count);
    code_.insert(code_.end(), nop_bytes.begin(), nop_bytes.end());
    return *this;
}

X86CodeEmitter& X86CodeEmitter::int3() {
    emit_byte(0xCC);
    return *this;
}

X86CodeEmitter& X86CodeEmitter::raw(ByteView bytes) {
    code_.insert(code_.end(), bytes.begin(), bytes.end());
    return *this;
}

// ============================================================================
// Finalization
// ============================================================================

MxResult<ByteBuffer> X86CodeEmitter::build() {
    for (auto& fixup : fixups_) {
        const auto it = std::ranges::find_if(label_bindings_,
            [&](const auto& pair) { return pair.first == fixup.label; });

        if (it == label_bindings_.end()) {
            return std::unexpected(MxError(
                ErrorCategory::protection, 0,
                std::format("Unresolved label #{}", fixup.label.id)));
        }

        const auto target_offset = static_cast<int64_t>(it->second);
        const auto instruction_end = static_cast<int64_t>(fixup.instruction_end);
        const auto rel = static_cast<int32_t>(target_offset - instruction_end);

        std::memcpy(code_.data() + fixup.patch_offset, &rel, sizeof(int32_t));
    }

    return code_;
}

} // namespace mx::analysis
