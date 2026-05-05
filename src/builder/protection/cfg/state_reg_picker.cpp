/**
 * @file state_reg_picker.cpp
 * @brief Zydis-based scan for unused state-variable candidates.
 */

#include "mxprotector/protection/cfg/state_reg_picker.hpp"

#include <optional>

#include <Zydis/Zydis.h>

namespace mx::cff {

namespace {

/// Return true if any operand of any instruction in `code` references the
/// largest-enclosing register of `reg` (so matching `r10d` also matches
/// `r10`, `r10w`, `r10b`).
[[nodiscard]] bool code_uses_register(ByteView code, ZydisRegister reg) noexcept {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const auto matches = [reg](ZydisRegister r) {
        return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r) ==
               ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    };

    size_t offset = 0;
    while (offset < code.size()) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + offset, code.size() - offset,
                &insn, operands))) {
            ++offset;
            continue;
        }

        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                matches(operands[i].reg.value)) {
                return true;
            }
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (matches(operands[i].mem.base) ||
                    matches(operands[i].mem.index)) {
                    return true;
                }
            }
        }

        offset += insn.length;
    }
    return false;
}

} // namespace

std::optional<x86::Reg> select_state_register(ByteView func_code) noexcept {
    struct Candidate {
        x86::Reg      mx_reg;
        ZydisRegister zy_reg;
    };

    // Order matters: we return the first unused candidate, so earlier
    // entries have priority. Both `r10` and `r11` are volatile under the
    // Win64 ABI and rarely touched by MSVC function bodies.
    static constexpr Candidate candidates[] = {
        {x86::Reg::r10, ZYDIS_REGISTER_R10},
        {x86::Reg::r11, ZYDIS_REGISTER_R11},
    };

    for (const auto& [mx_reg, zy_reg] : candidates) {
        if (!code_uses_register(func_code, zy_reg)) {
            return mx_reg;
        }
    }
    return std::nullopt;
}

} // namespace mx::cff
