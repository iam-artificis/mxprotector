/**
 * @file stolen_bytes.cpp
 * @brief OEP stolen-bytes planner implementation — see stolen_bytes.hpp.
 */

#include "mxprotector/protection/packer/stolen_bytes.hpp"

#include <Zydis/Zydis.h>

#include <cstring>

namespace mx::packer {

StolenPlan plan_stolen_bytes(ByteView text_bytes,
                             uint32_t oep_offset_in_text,
                             Rva      oep_rva)
{
    StolenPlan result;
    if (oep_offset_in_text >= text_bytes.size()) return result;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    size_t pos = oep_offset_in_text;
    while (result.size < kMinStolenBytes) {
        if (pos >= text_bytes.size()) {
            result.size = 0;
            result.relocs.clear();
            return result;
        }
        const size_t remain = text_bytes.size() - pos;

        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, text_bytes.data() + pos, remain, &insn, operands))) {
            return {};
        }

        // Reject branches/ret outright — they leave the stolen sequence.
        if (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_RET) {
            return {};
        }

        // RIP-relative memory references break when we move the bytes.
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                op.mem.base == ZYDIS_REGISTER_RIP) {
                return {};
            }
        }

        // CALL rel32 — record a fix-up so the absolute target survives.
        if (insn.meta.category == ZYDIS_CATEGORY_CALL) {
            // Only the rel32 form (E8 rel32) is supported here. Indirect
            // calls (FF /2) would need a different encoding change.
            if (insn.length != 5 || text_bytes[pos] != 0xE8) return {};

            int32_t rel32 = 0;
            std::memcpy(&rel32, text_bytes.data() + pos + 1, 4);
            const Rva target_rva = static_cast<Rva>(
                static_cast<int64_t>(oep_rva) +
                static_cast<int64_t>(pos - oep_offset_in_text) +
                5 + rel32);

            StolenReloc r{};
            r.offset_in_stolen    = result.size + 1;
            r.instr_end_in_stolen = result.size + 5;
            r.original_target_rva = target_rva;
            result.relocs.push_back(r);
        }

        pos += insn.length;
        result.size += insn.length;
        if (result.size > kMaxStolenBytes) return {};
    }
    return result;
}

} // namespace mx::packer
