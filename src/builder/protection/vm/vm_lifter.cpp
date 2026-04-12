/**
 * @file vm_lifter.cpp
 * @brief [BUILDER] Реализация VmLifter — x64 → VM bytecode.
 */

#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <Zydis/Zydis.h>

#include <format>

namespace mx::vm {

namespace {

/**
 * @brief Маппинг ZydisRegister → VM reg index (0..15).
 * Возвращает -1 если регистр не GPR (не 64-бит / не 32-бит / не 16-бит / не 8-бит GPR).
 */
int vm_reg_from_zydis(ZydisRegister reg) {
    const auto enclosing = ZydisRegisterGetLargestEnclosing(
        ZYDIS_MACHINE_MODE_LONG_64, reg);
    switch (enclosing) {
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RCX: return 1;
        case ZYDIS_REGISTER_RDX: return 2;
        case ZYDIS_REGISTER_RBX: return 3;
        case ZYDIS_REGISTER_RSP: return 4;
        case ZYDIS_REGISTER_RBP: return 5;
        case ZYDIS_REGISTER_RSI: return 6;
        case ZYDIS_REGISTER_RDI: return 7;
        case ZYDIS_REGISTER_R8:  return 8;
        case ZYDIS_REGISTER_R9:  return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default: return -1;
    }
}

bool uses_rsp_or_rbp_or_rip(const ZydisDecodedInstruction& insn,
                            const ZydisDecodedOperand* operands)
{
    for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
        const auto& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const int v = vm_reg_from_zydis(op.reg.value);
            if (v == 4 || v == 5) return true; // RSP or RBP
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.mem.base == ZYDIS_REGISTER_RIP) return true;
            const int b = vm_reg_from_zydis(op.mem.base);
            if (b == 4 || b == 5) return true;
            const int idx = vm_reg_from_zydis(op.mem.index);
            if (idx == 4 || idx == 5) return true;
        }
    }
    return false;
}

/**
 * @brief Мягкая проверка: допустимо ли принимать инструкцию как native,
 *        разрешая RSP/RBP-относительную адресацию (native handler
 *        выравнивает rsp обратно к фрейму caller'а для выполнения).
 *        Всё равно запрещаем:
 *          - RIP-relative (ссылка сломается после переноса в другую секцию)
 *          - RSP/RBP как явный операнд-регистр (push/pop/и т.д.)
 *          - index-регистр = RSP/RBP (редкость, но сбивает эмуляцию фрейма)
 */
bool uses_rip_or_rsp_rbp_as_reg(const ZydisDecodedInstruction& insn,
                                 const ZydisDecodedOperand* operands)
{
    for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
        const auto& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const int v = vm_reg_from_zydis(op.reg.value);
            if (v == 4 || v == 5) return true; // RSP/RBP как explicit операнд
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.mem.base == ZYDIS_REGISTER_RIP) return true;
            const int idx = vm_reg_from_zydis(op.mem.index);
            if (idx == 4 || idx == 5) return true;
        }
    }
    return false;
}

/**
 * @brief Пытается выделить 64-битные reg-reg / reg-imm формы для generic VM ops.
 * @note Работает только с формами mod=3 (два регистра) и reg-imm.
 *       Memory-форм не поддерживает в generic (будут native escape).
 */
bool extract_generic_op(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand* operands,
    VmInstruction& out)
{
    // Ожидаем 64-битные операнды (operand_size = 64 bits)
    if (insn.operand_width != 64) return false;

    // Оба операнда должны быть либо REG, либо IMM/REG
    if (insn.operand_count_visible < 2 && insn.mnemonic != ZYDIS_MNEMONIC_NOT
        && insn.mnemonic != ZYDIS_MNEMONIC_NEG) return false;

    const auto get_reg = [&](ZyanU8 idx) -> int {
        if (operands[idx].type != ZYDIS_OPERAND_TYPE_REGISTER) return -1;
        return vm_reg_from_zydis(operands[idx].reg.value);
    };

    // MOV / ADD / SUB / XOR / AND / OR / IMUL
    switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_MOV: {
            const int dst = get_reg(0);
            if (dst < 0 || dst == 4 || dst == 5) return false;
            if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                const int src = vm_reg_from_zydis(operands[1].reg.value);
                if (src < 0 || src == 4 || src == 5) return false;
                out.op = VmOp::mov_rr;
                out.dst = static_cast<uint8_t>(dst);
                out.src = static_cast<uint8_t>(src);
                return true;
            }
            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                const uint64_t imm = operands[1].imm.value.u;
                out.dst = static_cast<uint8_t>(dst);
                // 32-bit sign-extended form if fits
                const int64_t simm = operands[1].imm.value.s;
                if (simm >= INT32_MIN && simm <= INT32_MAX) {
                    out.op = VmOp::mov_ri32;
                    out.imm32 = static_cast<int32_t>(simm);
                } else {
                    out.op = VmOp::mov_ri64;
                    out.imm64 = imm;
                }
                return true;
            }
            return false;
        }
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_IMUL: {
            const int dst = get_reg(0);
            if (dst < 0 || dst == 4 || dst == 5) return false;

            if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                const int src = vm_reg_from_zydis(operands[1].reg.value);
                if (src < 0 || src == 4 || src == 5) return false;
                out.dst = static_cast<uint8_t>(dst);
                out.src = static_cast<uint8_t>(src);
                switch (insn.mnemonic) {
                    case ZYDIS_MNEMONIC_ADD:  out.op = VmOp::add_rr;  break;
                    case ZYDIS_MNEMONIC_SUB:  out.op = VmOp::sub_rr;  break;
                    case ZYDIS_MNEMONIC_XOR:  out.op = VmOp::xor_rr;  break;
                    case ZYDIS_MNEMONIC_AND:  out.op = VmOp::and_rr;  break;
                    case ZYDIS_MNEMONIC_OR:   out.op = VmOp::or_rr;   break;
                    case ZYDIS_MNEMONIC_IMUL: out.op = VmOp::imul_rr; break;
                    default: return false;
                }
                return true;
            }

            if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                const int64_t simm = operands[1].imm.value.s;
                if (simm < INT32_MIN || simm > INT32_MAX) return false;
                out.dst = static_cast<uint8_t>(dst);
                out.imm32 = static_cast<int32_t>(simm);
                switch (insn.mnemonic) {
                    case ZYDIS_MNEMONIC_ADD: out.op = VmOp::add_ri32; break;
                    case ZYDIS_MNEMONIC_SUB: out.op = VmOp::sub_ri32; break;
                    case ZYDIS_MNEMONIC_XOR: out.op = VmOp::xor_ri32; break;
                    case ZYDIS_MNEMONIC_AND: out.op = VmOp::and_ri32; break;
                    case ZYDIS_MNEMONIC_OR:  out.op = VmOp::or_ri32;  break;
                    case ZYDIS_MNEMONIC_IMUL: return false; // IMUL_RI three-operand; skip for now
                    default: return false;
                }
                return true;
            }
            return false;
        }
        case ZYDIS_MNEMONIC_NOT:
        case ZYDIS_MNEMONIC_NEG: {
            const int dst = get_reg(0);
            if (dst < 0 || dst == 4 || dst == 5) return false;
            out.dst = static_cast<uint8_t>(dst);
            out.op = (insn.mnemonic == ZYDIS_MNEMONIC_NOT) ? VmOp::not_r : VmOp::neg_r;
            return true;
        }
        case ZYDIS_MNEMONIC_SHL:
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_SAR:
        case ZYDIS_MNEMONIC_ROL:
        case ZYDIS_MNEMONIC_ROR: {
            const int dst = get_reg(0);
            if (dst < 0 || dst == 4 || dst == 5) return false;
            if (operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
            const uint64_t cnt = operands[1].imm.value.u & 0x3F;
            out.dst = static_cast<uint8_t>(dst);
            out.shift_count = static_cast<uint8_t>(cnt);
            switch (insn.mnemonic) {
                case ZYDIS_MNEMONIC_SHL: out.op = VmOp::shl_ri; break;
                case ZYDIS_MNEMONIC_SHR: out.op = VmOp::shr_ri; break;
                case ZYDIS_MNEMONIC_SAR: out.op = VmOp::sar_ri; break;
                case ZYDIS_MNEMONIC_ROL: out.op = VmOp::rol_ri; break;
                case ZYDIS_MNEMONIC_ROR: out.op = VmOp::ror_ri; break;
                default: return false;
            }
            return true;
        }
        default:
            return false;
    }
}

} // anonymous namespace

bool VmLifter::is_safe_for_native(const analysis::Instruction& insn) {
    // Ветвления / стэковые / возврат — отклонить
    if (insn.is_branch() || insn.is_call() || insn.is_return()) return false;
    const auto m = insn.mnemonic();
    if (m == "push" || m == "pop" || m == "pushfq" || m == "popfq") return false;
    if (m == "leave" || m == "enter") return false;
    if (m == "syscall" || m == "int" || m == "iret") return false;

    // Повторно декодируем через Zydis чтобы проверить RIP/RSP/RBP
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction zy_insn{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    const auto raw = insn.raw_bytes();
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder, raw.data(), raw.size(), &zy_insn, operands))) {
        return false;
    }

    // Разрешаем [rsp|rbp + disp] memory operand в native — handler вернёт rsp
    // обратно к caller-фрейму на время выполнения native bytes.
    if (uses_rip_or_rsp_rbp_as_reg(zy_insn, operands)) return false;
    return true;
}

bool VmLifter::try_lift_generic(
    const analysis::Instruction& insn,
    VmInstruction& out)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction zy_insn{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

    const auto raw = insn.raw_bytes();
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder, raw.data(), raw.size(), &zy_insn, operands))) {
        return false;
    }

    if (uses_rsp_or_rbp_or_rip(zy_insn, operands)) return false;
    return extract_generic_op(zy_insn, operands, out);
}

MxResult<std::pair<std::vector<VmInstruction>, LiftReport>>
VmLifter::lift(ByteView code, Va base_va)
{
    LiftReport report;
    std::vector<VmInstruction> out;

    auto decode_result = disasm_.decode_buffer(code, base_va);
    if (!decode_result) {
        return std::unexpected(decode_result.error());
    }

    const auto& insns = *decode_result;
    if (insns.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "VmLifter: пустой регион"));
    }

    for (const auto& insn : insns) {
        ++report.total_insns;
        report.total_bytes += insn.length();

        // Блокирующие конструкции — отказ от лифтинга всего региона
        if (insn.is_branch() || insn.is_call() || insn.is_return()) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format(
                    "VmLifter: регион содержит control-flow '{}' по VA 0x{:016X}",
                    insn.to_string(), insn.address())));
        }
        const auto m = insn.mnemonic();
        if (m == "push" || m == "pop" || m == "pushfq" || m == "popfq" ||
            m == "leave" || m == "enter" || m == "syscall" || m == "int") {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format(
                    "VmLifter: регион содержит стэковую/системную инструкцию '{}' по VA 0x{:016X}",
                    insn.to_string(), insn.address())));
        }

        VmInstruction vi;
        vi.original_va = insn.address();

        if (try_lift_generic(insn, vi)) {
            out.push_back(std::move(vi));
            ++report.generic_ops;
            continue;
        }

        if (!is_safe_for_native(insn)) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format(
                    "VmLifter: инструкция '{}' по VA 0x{:016X} небезопасна "
                    "для native escape (RSP/RBP/RIP-relative)",
                    insn.to_string(), insn.address())));
        }

        vi.op = VmOp::native;
        vi.native_bytes.assign(insn.raw_bytes().begin(), insn.raw_bytes().end());
        out.push_back(std::move(vi));
        ++report.native_ops;
    }

    return std::make_pair(std::move(out), report);
}

} // namespace mx::vm
