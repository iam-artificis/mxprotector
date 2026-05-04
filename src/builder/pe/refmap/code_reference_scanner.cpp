/**
 * @file code_reference_scanner.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/pe/refmap/code_reference_scanner.hpp"

#include <algorithm>
#include <vector>

#include <Zydis/Zydis.h>

namespace mx::pe::refmap {

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

/// Sorted list of `[begin_rva, end_rva)` byte ranges inside the
/// scanned buffer that are data, not instructions. Caller passes
/// these as `pe::DataRegion`s; the scanner converts them into this
/// internal form once at the start of `scan` and binary-searches
/// per cursor position.
struct ScanSkipRange {
    Rva begin;
    Rva end;
};

[[nodiscard]] std::vector<ScanSkipRange> build_skip_ranges(
    std::span<const DataRegion> regions,
    Rva                         base_rva,
    std::size_t                 code_size)
{
    std::vector<ScanSkipRange> out;
    out.reserve(regions.size());
    const Rva code_end = static_cast<Rva>(base_rva + code_size);
    for (const auto& dr : regions) {
        if (dr.size == 0) continue;
        const Rva b = dr.begin_rva;
        const Rva e = static_cast<Rva>(dr.begin_rva + dr.size);
        if (e <= base_rva || b >= code_end) continue;
        const Rva clamped_b = std::max(b, base_rva);
        const Rva clamped_e = std::min(e, code_end);
        if (clamped_b >= clamped_e) continue;
        out.push_back(ScanSkipRange{clamped_b, clamped_e});
    }
    std::sort(out.begin(), out.end(),
        [](const ScanSkipRange& a, const ScanSkipRange& b) {
            return a.begin < b.begin;
        });
    return out;
}

/// Returns the end-RVA of the skip range containing `rva`, or 0 if
/// `rva` is not in any skip range. Skip ranges are sorted; the
/// search is `O(log N)` per query.
[[nodiscard]] Rva skip_range_end_for(
    const std::vector<ScanSkipRange>& ranges, Rva rva) noexcept
{
    auto it = std::lower_bound(
        ranges.begin(), ranges.end(), rva,
        [](const ScanSkipRange& r, Rva v) {
            return r.end <= v;
        });
    if (it == ranges.end()) return 0;
    if (rva >= it->begin && rva < it->end) return it->end;
    return 0;
}

struct CodeReferenceScanner::Impl {
    ZydisDecoder decoder{};

    Impl() {
        ZydisDecoderInit(&decoder,
                         ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64);
    }

    [[nodiscard]] std::uint32_t scan(
        ByteView                     code,
        Rva                          base_rva,
        std::span<const DataRegion>  data_regions,
        ReferenceTable&              table)
    {
        const auto skip_ranges = build_skip_ranges(
            data_regions, base_rva, code.size());

        std::uint32_t errors = 0;
        std::size_t   offset = 0;

        while (offset < code.size()) {
            const Rva cursor_rva =
                static_cast<Rva>(base_rva + offset);

            // Skip data regions in one jump so the decoder resyncs
            // to instruction boundaries on the far side.
            if (const Rva skip_end = skip_range_end_for(
                    skip_ranges, cursor_rva); skip_end != 0)
            {
                offset = static_cast<std::size_t>(skip_end - base_rva);
                if (offset >= code.size()) break;
                continue;
            }

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

            // If the decoded instruction overlaps a data region,
            // honour the data range and skip — Zydis will have
            // happily produced something even though those bytes
            // are not instructions.
            const Rva insn_end = static_cast<Rva>(
                cursor_rva + insn.length);
            if (skip_range_end_for(skip_ranges, cursor_rva) != 0 ||
                skip_range_end_for(skip_ranges, insn_end - 1) != 0)
            {
                // Re-check after decoding — covers the case where a
                // multi-byte instruction *crosses into* a skip
                // range. Round the cursor to the range's end.
                Rva jump_to = 0;
                for (const auto& r : skip_ranges) {
                    if (r.begin >= cursor_rva && r.begin < insn_end) {
                        jump_to = r.end;
                        break;
                    }
                }
                if (jump_to != 0) {
                    offset = static_cast<std::size_t>(jump_to - base_rva);
                    if (offset >= code.size()) break;
                    continue;
                }
            }

            const Rva inst_rva = cursor_rva;

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
    ByteView                     code,
    Rva                          base_rva,
    std::span<const DataRegion>  data_regions,
    ReferenceTable&              table)
{
    return impl_->scan(code, base_rva, data_regions, table);
}

std::uint32_t CodeReferenceScanner::scan(
    ByteView code, Rva base_rva, ReferenceTable& table)
{
    return impl_->scan(code, base_rva,
                       std::span<const DataRegion>{},
                       table);
}

} // namespace mx::pe::refmap
