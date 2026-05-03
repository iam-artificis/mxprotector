/**
 * @file code_reference_scanner.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/pe/chaos/code_reference_scanner.hpp"

#include <Zydis/Zydis.h>

namespace mx::pe::chaos {

namespace {

/// Convert Zydis displacement size in bits to our reference width.
/// Zydis only ever uses 8 or 32 bits for the slot widths the chaos
/// pipeline cares about. 16-bit displacements (rare in x64) are
/// reported as zero — the caller skips them.
[[nodiscard]] ReferenceWidth width_from_bits(std::uint8_t bits) noexcept {
    switch (bits) {
        case 8:  return ReferenceWidth::byte1;
        case 32: return ReferenceWidth::byte4;
        default: return ReferenceWidth::byte4; // sentinel; caller checks bits
    }
}

/// `true` when any memory operand in the visible operand list uses
/// `RIP` as its base — i.e. the instruction has a `[RIP+disp]` slot.
[[nodiscard]] bool has_rip_relative_operand(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     operands) noexcept
{
    for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
        const auto& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            op.mem.base == ZYDIS_REGISTER_RIP)
        {
            return true;
        }
    }
    return false;
}

/// Append a relative-immediate (branch) reference if the slot's
/// width is one of the supported sizes (8 or 32 bits).
void emit_branch_reference(
    const ZydisDecodedInstruction& insn,
    Rva                            inst_rva,
    const ZydisDecodedOperand&     op,
    std::uint8_t                   raw_imm_index,
    ReferenceTable&                table)
{
    const auto& raw = insn.raw.imm[raw_imm_index];
    if (raw.size != 8 && raw.size != 32) return;

    const Rva slot_rva  = static_cast<Rva>(inst_rva + raw.offset);
    const Rva next_inst = static_cast<Rva>(inst_rva + insn.length);
    const std::int64_t disp = op.imm.value.s;
    const Rva target_rva = static_cast<Rva>(
        static_cast<std::int64_t>(next_inst) + disp);

    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = width_from_bits(raw.size),
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_branch_or_call,
    });
}

/// Append a RIP-relative-memory reference. Only 32-bit displacements
/// participate — Zydis encodes RIP-rel only with disp32 in long mode.
void emit_rip_relative_reference(
    const ZydisDecodedInstruction& insn,
    Rva                            inst_rva,
    ReferenceTable&                table)
{
    const auto& disp = insn.raw.disp;
    if (disp.size != 32) return;

    const Rva slot_rva  = static_cast<Rva>(inst_rva + disp.offset);
    const Rva next_inst = static_cast<Rva>(inst_rva + insn.length);
    const Rva target_rva = static_cast<Rva>(
        static_cast<std::int64_t>(next_inst) + disp.value);

    table.add(Reference{
        .location_rva = slot_rva,
        .target_rva   = target_rva,
        .width        = ReferenceWidth::byte4,
        .encoding     = ReferenceEncoding::rel,
        .origin       = ReferenceOrigin::code_rip_relative,
    });
}

} // anonymous namespace

struct CodeReferenceScanner::Impl {
    ZydisDecoder decoder{};

    Impl() {
        ZydisDecoderInit(&decoder,
                         ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64);
    }

    [[nodiscard]] std::uint32_t scan(
        ByteView code,
        Rva      base_rva,
        ReferenceTable& table)
    {
        std::uint32_t errors = 0;
        std::size_t   offset = 0;

        while (offset < code.size()) {
            ZydisDecodedInstruction insn{};
            ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};

            const auto status = ZydisDecoderDecodeFull(
                &decoder,
                code.data() + offset,
                code.size() - offset,
                &insn,
                ops);

            if (!ZYAN_SUCCESS(status)) {
                ++errors;
                ++offset;
                continue;
            }

            const Rva inst_rva = static_cast<Rva>(base_rva + offset);

            // Branch immediates. Iterate visible operands so we can
            // pick up `imm.value.s` for the signed displacement;
            // each relative immediate corresponds to `raw.imm[i]`
            // (i = 0 or 1) — most instructions have at most one.
            std::uint8_t raw_imm_idx = 0;
            for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
                const auto& op = ops[i];
                if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE) continue;
                if (!op.imm.is_relative) {
                    if (insn.raw.imm[raw_imm_idx].size > 0) ++raw_imm_idx;
                    continue;
                }
                if (raw_imm_idx >= 2) continue;
                emit_branch_reference(insn, inst_rva, op, raw_imm_idx, table);
                if (insn.raw.imm[raw_imm_idx].size > 0) ++raw_imm_idx;
            }

            // RIP-relative memory operand.
            if (insn.raw.disp.size > 0 &&
                has_rip_relative_operand(insn, ops))
            {
                emit_rip_relative_reference(insn, inst_rva, table);
            }

            offset += insn.length;
        }

        return errors;
    }
};

CodeReferenceScanner::CodeReferenceScanner()
    : impl_(std::make_unique<Impl>()) {}

CodeReferenceScanner::~CodeReferenceScanner() = default;

CodeReferenceScanner::CodeReferenceScanner(CodeReferenceScanner&&) noexcept = default;
CodeReferenceScanner& CodeReferenceScanner::operator=(CodeReferenceScanner&&) noexcept = default;

std::uint32_t CodeReferenceScanner::scan(
    ByteView code, Rva base_rva, ReferenceTable& table)
{
    return impl_->scan(code, base_rva, table);
}

} // namespace mx::pe::chaos
