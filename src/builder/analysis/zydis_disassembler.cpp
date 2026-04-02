/**
 * @file zydis_disassembler.cpp
 * @brief [BUILDER] Реализация дизассемблера на базе Zydis (ZydisDecoder + ZydisFormatter).
 *
 * @details Содержит полную реализацию ZydisDisassembler через PIMPL-идиому.
 *          Внутренний класс Impl хранит ZydisDecoder и ZydisFormatter,
 *          выполняет декодирование инструкций и классификацию (ветвления,
 *          вызовы, возвраты, безусловные переходы).
 *          Вычисляет абсолютные целевые адреса для переходов и вызовов.
 *
 * @note Заголовок Zydis/Zydis.h включается ТОЛЬКО в этом .cpp,
 *       благодаря PIMPL детали Zydis не утекают в публичный API.
 */

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/core/result.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstring>
#include <format>

namespace mx::analysis {

// ============================================================================
// PIMPL — внутренняя реализация ZydisDisassembler
// ============================================================================

/**
 * @brief Внутренняя реализация ZydisDisassembler (PIMPL).
 *
 * @details Хранит инициализированные объекты ZydisDecoder и ZydisFormatter.
 *          Предоставляет методы decode_single для декодирования одной инструкции
 *          и вспомогательные функции для классификации инструкций.
 */
struct ZydisDisassembler::Impl {
    ZydisDecoder    decoder{};    ///< Декодер Zydis
    ZydisFormatter  formatter{};  ///< Форматировщик Zydis
    Architecture    arch;         ///< Целевая архитектура

    /**
     * @brief Инициализирует декодер и форматировщик под заданную архитектуру.
     * @param architecture Архитектура (x86 или x64).
     */
    explicit Impl(Architecture architecture) : arch(architecture) {
        const auto machine_mode = (arch == Architecture::x64)
            ? ZYDIS_MACHINE_MODE_LONG_64
            : ZYDIS_MACHINE_MODE_LONG_COMPAT_32;

        const auto stack_width = (arch == Architecture::x64)
            ? ZYDIS_STACK_WIDTH_64
            : ZYDIS_STACK_WIDTH_32;

        ZydisDecoderInit(&decoder, machine_mode, stack_width);
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    }

    /**
     * @brief Декодирует одну инструкцию и создаёт объект Instruction.
     * @param code Буфер машинного кода.
     * @param address Виртуальный адрес первого байта.
     * @return Instruction или ошибка декодирования.
     */
    MxResult<Instruction> decode_single(ByteView code, Va address) {
        if (code.empty()) {
            return std::unexpected(MxError(
                DisasmErrorCode::buffer_too_small,
                "Буфер для декодирования пуст"));
        }

        ZydisDecodedInstruction zydis_insn{};
        ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};

        const auto status = ZydisDecoderDecodeFull(
            &decoder,
            code.data(),
            code.size(),
            &zydis_insn,
            operands);

        if (!ZYAN_SUCCESS(status)) {
            return std::unexpected(MxError(
                DisasmErrorCode::invalid_instruction,
                std::format("Невалидная инструкция по адресу 0x{:016X}", address)));
        }

        const uint8_t insn_length = static_cast<uint8_t>(zydis_insn.length);

        ByteBuffer raw_bytes(code.begin(), code.begin() + insn_length);

        const auto* mnemonic_str = ZydisMnemonicGetString(zydis_insn.mnemonic);
        std::string mnemonic(mnemonic_str ? mnemonic_str : "");
        std::ranges::transform(mnemonic, mnemonic.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        char format_buf[256]{};
        ZydisFormatterFormatInstruction(
            &formatter,
            &zydis_insn,
            operands,
            zydis_insn.operand_count_visible,
            format_buf,
            sizeof(format_buf),
            address,
            ZYAN_NULL);

        std::string full_text(format_buf);
        std::string operands_text;
        if (const auto space_pos = full_text.find(' '); space_pos != std::string::npos) {
            operands_text = full_text.substr(space_pos + 1);
        }

        const bool is_branch = is_branch_category(zydis_insn);
        const bool is_cond   = is_conditional_branch_category(zydis_insn);
        const bool is_call_f = (zydis_insn.meta.category == ZYDIS_CATEGORY_CALL);
        const bool is_ret    = (zydis_insn.meta.category == ZYDIS_CATEGORY_RET);
        const bool is_uncond = is_unconditional_jump_category(zydis_insn);

        std::vector<Va> targets;
        if (is_branch && !is_ret) {
            compute_branch_targets(zydis_insn, operands, address, targets);
        }

        return Instruction(
            address,
            insn_length,
            std::move(raw_bytes),
            std::move(mnemonic),
            std::move(operands_text),
            is_branch,
            is_cond,
            is_call_f,
            is_ret,
            is_uncond,
            std::move(targets));
    }

private:
    /**
     * @brief Проверяет, является ли инструкция ветвлением любого типа.
     * @param insn Декодированная инструкция Zydis.
     * @return true если jmp/jcc/call/ret.
     */
    static bool is_branch_category(const ZydisDecodedInstruction& insn) noexcept {
        switch (insn.meta.category) {
            case ZYDIS_CATEGORY_UNCOND_BR:
            case ZYDIS_CATEGORY_COND_BR:
            case ZYDIS_CATEGORY_CALL:
            case ZYDIS_CATEGORY_RET:
                return true;
            default:
                return false;
        }
    }

    /**
     * @brief Проверяет, является ли инструкция условным переходом (jcc).
     * @param insn Декодированная инструкция Zydis.
     * @return true для условных переходов.
     */
    static bool is_conditional_branch_category(const ZydisDecodedInstruction& insn) noexcept {
        return insn.meta.category == ZYDIS_CATEGORY_COND_BR;
    }

    /**
     * @brief Проверяет, является ли инструкция безусловным переходом (jmp).
     * @param insn Декодированная инструкция Zydis.
     * @return true для безусловных переходов (не call, не ret).
     */
    static bool is_unconditional_jump_category(const ZydisDecodedInstruction& insn) noexcept {
        return insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    }

    /**
     * @brief Вычисляет абсолютные целевые адреса для ветвящейся инструкции.
     * @param insn Декодированная инструкция Zydis.
     * @param operands Массив операндов.
     * @param runtime_address Адрес инструкции в runtime.
     * @param out_targets Выходной вектор целевых адресов.
     */
    static void compute_branch_targets(
        const ZydisDecodedInstruction& insn,
        const ZydisDecodedOperand* operands,
        Va runtime_address,
        std::vector<Va>& out_targets)
    {
        for (ZyanU8 i = 0; i < insn.operand_count_visible; ++i) {
            const auto& op = operands[i];

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                ZyanU64 absolute_target = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, runtime_address, &absolute_target))) {
                    out_targets.push_back(static_cast<Va>(absolute_target));
                }
            } else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !op.imm.is_relative) {
                out_targets.push_back(static_cast<Va>(
                    op.imm.is_signed ? static_cast<uint64_t>(op.imm.value.s) : op.imm.value.u));
            }
        }
    }
};

// ============================================================================
// Реализация публичных методов ZydisDisassembler
// ============================================================================

ZydisDisassembler::ZydisDisassembler(Architecture arch)
    : impl_(std::make_unique<Impl>(arch))
{}

ZydisDisassembler::~ZydisDisassembler() = default;

ZydisDisassembler::ZydisDisassembler(ZydisDisassembler&&) noexcept = default;
ZydisDisassembler& ZydisDisassembler::operator=(ZydisDisassembler&&) noexcept = default;

MxResult<Instruction> ZydisDisassembler::decode_one(ByteView code, Va address) {
    return impl_->decode_single(code, address);
}

MxResult<std::vector<Instruction>> ZydisDisassembler::decode_buffer(
    ByteView code, Va address, size_t max_instructions)
{
    std::vector<Instruction> result;
    size_t offset = 0;

    while (offset < code.size()) {
        if (max_instructions > 0 && result.size() >= max_instructions) {
            break;
        }

        const ByteView remaining{code.data() + offset, code.size() - offset};
        const Va current_address = address + offset;

        auto insn_result = impl_->decode_single(remaining, current_address);
        if (!insn_result) {
            if (result.empty()) {
                return std::unexpected(insn_result.error());
            }
            break;
        }

        offset += insn_result->length();
        result.push_back(std::move(*insn_result));
    }

    return result;
}

Architecture ZydisDisassembler::architecture() const noexcept {
    return impl_->arch;
}

} // namespace mx::analysis
