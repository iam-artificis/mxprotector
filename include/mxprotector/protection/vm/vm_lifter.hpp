/**
 * @file vm_lifter.hpp
 * @brief [BUILDER] Лифтер x64 → VM bytecode.
 *
 * Декодирует последовательность x64 инструкций через IDisassembler и
 * переводит их в VmInstruction. Для распознанных форм (mov/add/sub/xor/...)
 * эмитит generic VM ops. Для всего остального — VmOp::native с сырыми байтами.
 *
 * Отказывается лифтить регион, если:
 *   - содержит CALL/RET/JMP/JCC (изменяют control flow)
 *   - содержит PUSH/POP (модифицируют RSP)
 *   - содержит операции с RSP/RBP (стэковые фреймы) — для generic ops
 *   - содержит RIP-relative memory operand (после переноса ссылка сломается)
 *
 * Native escape используется для допустимых, но сложных инструкций (например,
 * mov reg, [reg+disp] для не-RSP/RBP/RIP баз, multi-byte NOPs и т.п.).
 */

#pragma once

#include <string>
#include <vector>

#include "mxprotector/analysis/disassembler.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"

namespace mx::vm {

struct LiftReport {
    uint32_t generic_ops = 0;      ///< сколько распознанных VM ops
    uint32_t native_ops  = 0;      ///< сколько native escape ops
    uint32_t total_insns = 0;
    uint32_t total_bytes = 0;
};

class VmLifter final {
public:
    explicit VmLifter(analysis::IDisassembler& disasm) noexcept
        : disasm_(disasm)
    {}

    /**
     * @brief Лифтит регион x64 машинного кода в последовательность VM инструкций.
     *
     * @param code       Сырые байты региона.
     * @param base_va    Виртуальный адрес начала региона (для диагностики).
     * @return Пара: вектор VM-инструкций (без финального VmOp::exit) + отчёт.
     *         Ошибка если регион содержит запрещённые конструкции.
     */
    [[nodiscard]] MxResult<std::pair<std::vector<VmInstruction>, LiftReport>>
    lift(ByteView code, Va base_va);

private:
    analysis::IDisassembler& disasm_;

    /**
     * @brief Пытается распознать инструкцию как конкретный VmOp с операндами.
     * @return true если удалось, false → caller fallback на native escape.
     */
    [[nodiscard]] bool try_lift_generic(
        const analysis::Instruction& insn,
        VmInstruction& out);

    /**
     * @brief Проверяет, допустима ли инструкция для native escape
     * (никаких RIP-relative, никаких стэковых операций).
     */
    [[nodiscard]] bool is_safe_for_native(const analysis::Instruction& insn);
};

} // namespace mx::vm
