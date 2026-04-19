/**
 * @file cff_relocation_fixup.cpp
 * @brief Zydis-driven rel32/disp32 rewriter for relocated basic blocks.
 */

#include "mxprotector/protection/cfg/cff_relocation_fixup.hpp"

#include <Zydis/Zydis.h>

#include <cstring>

namespace mx::cff {

void apply_relocation_fixups(ByteBuffer&              section_data,
                             const CffTrampolineEntry& trampoline,
                             Rva                      section_rva,
                             Va                       image_base)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (const auto& bp : trampoline.block_placements) {
        if (bp.code_size == 0 || bp.original_va == 0) continue;

        const uint32_t abs_offset = trampoline.section_offset + bp.output_offset;
        if (abs_offset + bp.code_size > section_data.size()) continue;

        const Rva     original_block_rva = static_cast<Rva>(bp.original_va - image_base);
        const Rva     new_block_rva      = section_rva + abs_offset;
        const auto    delta              = static_cast<int64_t>(new_block_rva)
                                         - static_cast<int64_t>(original_block_rva);

        size_t offset = 0;
        while (offset < bp.code_size) {
            ZydisDecodedInstruction insn{};
            ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};

            const uint8_t* insn_ptr  = section_data.data() + abs_offset + offset;
            const size_t   remaining = bp.code_size - offset;

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    &decoder, insn_ptr, remaining, &insn, operands))) {
                ++offset;
                continue;
            }

            const uint32_t insn_file_base = abs_offset + static_cast<uint32_t>(offset);

            // RIP-relative memory operand ([rip+disp32]): LEA, MOV, CMP,
            // CALL [rip+...], etc.
            if (insn.raw.disp.size == 32) {
                bool has_rip_mem = false;
                for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
                    if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                        has_rip_mem = true;
                        break;
                    }
                }

                if (has_rip_mem) {
                    const uint32_t disp_off = insn_file_base + insn.raw.disp.offset;
                    if (disp_off + 4 <= section_data.size()) {
                        int32_t old_disp = 0;
                        std::memcpy(&old_disp, section_data.data() + disp_off, 4);
                        const auto new_disp = static_cast<int32_t>(old_disp - delta);
                        std::memcpy(section_data.data() + disp_off, &new_disp, 4);
                    }
                }
            }

            // Immediate relative operand (CALL rel32, JMP rel32)
            for (ZyanU8 i = 0; i < insn.operand_count_visible; ++i) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    operands[i].imm.is_relative &&
                    insn.raw.imm[0].size == 32) {

                    const uint32_t imm_off = insn_file_base + insn.raw.imm[0].offset;
                    if (imm_off + 4 <= section_data.size()) {
                        int32_t old_rel = 0;
                        std::memcpy(&old_rel, section_data.data() + imm_off, 4);
                        const auto new_rel = static_cast<int32_t>(old_rel - delta);
                        std::memcpy(section_data.data() + imm_off, &new_rel, 4);
                    }
                    break;
                }
            }

            offset += insn.length;
        }
    }
}

} // namespace mx::cff
