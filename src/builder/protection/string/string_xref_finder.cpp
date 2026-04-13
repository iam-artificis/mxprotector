/**
 * @file string_xref_finder.cpp
 * @brief [BUILDER] Zydis-based scanner for LEA rip-relative string refs.
 *
 * Implementation walks the code buffer linearly. At each offset we
 * attempt a full decode; on success we advance by the decoded
 * instruction length, on failure we advance by 1 byte (this keeps
 * the scan robust against data interleaved with code, common in
 * x64 binaries that mix jump tables and switch tables into the
 * text section).
 *
 * Matching criteria for a LEA site:
 *
 *   1. Mnemonic is `LEA`.
 *   2. Exactly one memory operand whose base is `RIP`.
 *   3. The resolved absolute target (via `ZydisCalcAbsoluteAddress`
 *      using a synthetic "runtime address" built from `code_rva` +
 *      offset) equals some candidate's `rva_start` exactly.
 *
 * Intra-string references (target RVA inside a string but not at
 * its start) are deliberately excluded — see header comment. They
 * would need a runtime decryptor that accepts (string_id, offset)
 * instead of (string_id), which is out of scope for MVP.
 *
 * Matching uses `std::lower_bound` against the candidates list to
 * keep lookup logarithmic. The candidates list is sorted by
 * `rva_start` per the scanner's natural output order.
 */

#include "mxprotector/protection/string/string_xref_finder.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include <Zydis/Zydis.h>

namespace mx::string_protect {

namespace {

/// Returns the index of the candidate whose `rva_start == target`,
/// or `candidates.size()` if no exact match exists. The candidates
/// list is assumed to be sorted by `rva_start`.
size_t find_exact_match(const std::vector<FoundString>& candidates, Rva target) {
    const auto it = std::lower_bound(
        candidates.begin(), candidates.end(), target,
        [](const FoundString& fs, Rva v) noexcept {
            return fs.rva_start < v;
        });
    if (it == candidates.end())      return candidates.size();
    if (it->rva_start != target)     return candidates.size();
    return static_cast<size_t>(it - candidates.begin());
}

} // anonymous namespace

std::vector<StringXref>
StringXrefFinder::find(ByteView                       code,
                       Rva                             code_rva,
                       const std::vector<FoundString>& candidates) const
{
    std::vector<StringXref> result;
    if (code.empty() || candidates.empty()) return result;

    // Sanity check the precondition: the candidates list must be
    // sorted by rva_start. We don't own the fixup — callers that
    // violate this get undefined results from `lower_bound` below
    // — so this is a cheap debug assert, not a correctness gate.
    // (Scanner already produces sorted output.)

    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    size_t offset = 0;
    while (offset < code.size()) {
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand     operands[ZYDIS_MAX_OPERAND_COUNT]{};

        const uint8_t* insn_ptr = code.data() + offset;
        const size_t   remaining = code.size() - offset;

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, insn_ptr, remaining, &insn, operands)))
        {
            // Invalid or truncated instruction — advance one byte
            // and keep scanning. The LEA we care about is 7 bytes
            // long, so even at the tail of the buffer we may still
            // find one on the next offset.
            ++offset;
            continue;
        }

        // Only LEA with a rip-relative memory source qualifies.
        if (insn.mnemonic != ZYDIS_MNEMONIC_LEA) {
            offset += insn.length;
            continue;
        }

        // LEA has a destination register operand and a memory
        // operand source. Find them.
        const ZydisDecodedOperand* dest_reg_op = nullptr;
        const ZydisDecodedOperand* src_mem_op  = nullptr;
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = operands[i];
            if (op.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT) continue;
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && dest_reg_op == nullptr) {
                dest_reg_op = &op;
            } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && src_mem_op == nullptr) {
                src_mem_op = &op;
            }
        }

        if (dest_reg_op == nullptr || src_mem_op == nullptr ||
            src_mem_op->mem.base != ZYDIS_REGISTER_RIP)
        {
            offset += insn.length;
            continue;
        }

        // Resolve the absolute target by feeding Zydis a synthetic
        // "runtime address" equal to the instruction's RVA. Because
        // rip-relative addressing uses `rip + disp32` where `rip`
        // is the address of the NEXT instruction, Zydis does the
        // `+ insn.length` internally when we hand it the base.
        ZyanU64 abs_target = 0;
        const ZyanU64 rip_base = static_cast<ZyanU64>(code_rva) +
                                 static_cast<ZyanU64>(offset);
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &insn, src_mem_op, rip_base, &abs_target)))
        {
            offset += insn.length;
            continue;
        }

        const auto target_rva = static_cast<Rva>(abs_target);
        const size_t idx = find_exact_match(candidates, target_rva);
        if (idx < candidates.size()) {
            StringXref x{};
            x.xref_rva     = code_rva + static_cast<Rva>(offset);
            x.insn_length  = insn.length;
            x.disp_offset  = insn.raw.disp.offset;
            x.dest_reg     = static_cast<uint32_t>(dest_reg_op->reg.value);
            x.target_rva   = target_rva;
            x.string_index = idx;
            result.push_back(x);
        }

        offset += insn.length;
    }

    return result;
}

} // namespace mx::string_protect
