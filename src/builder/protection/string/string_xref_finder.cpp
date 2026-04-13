/**
 * @file string_xref_finder.cpp
 * @brief [BUILDER] Byte-pattern scanner for LEA rip-relative string refs.
 *
 * The earlier implementation walked the code buffer with Zydis in a
 * linear-decode loop. That works fine in a clean `.text` section but
 * desynchronises the moment it hits a CFF trampoline section (where
 * real instructions are interleaved with dispatcher tables, MBA
 * transitions, and state-machine prologues that don't decode as a
 * single stream). A single decoded "instruction" whose length
 * straddles a real LEA silently skips past it.
 *
 * Since we only care about one specific instruction form —
 * `LEA r64, [rip + disp32]`, which has a fixed 7-byte encoding —
 * we can match it directly at every byte offset instead of trying
 * to decode the surrounding context. This is both faster and
 * immune to decoder desync.
 *
 * Encoding of `lea r64, [rip + disp32]`:
 *
 *   [REX]   0100 W R X B      W=1 always; R selects low/ext reg;
 *                             X and B are unused for rip-rel and
 *                             the emitters we care about leave
 *                             them zero (0x48 for rax..rdi,
 *                             0x4C for r8..r15)
 *   [op]    0x8D              LEA
 *   [ModRM] 00 <reg3> 101     mod=00, rm=101 → rip+disp32;
 *                             reg field holds the low 3 bits of
 *                             the destination register
 *   [disp32] little-endian signed 32-bit displacement
 *
 * Matching criteria:
 *   1. byte[0] ∈ {0x48, 0x4C}
 *   2. byte[1] == 0x8D
 *   3. byte[2] & 0xC7 == 0x05  (mod=00, rm=101)
 *   4. resolved target RVA (= lea_rva + 7 + disp32) equals some
 *      candidate's `rva_start` exactly.
 *
 * Intra-string references (target RVA inside a string but not at
 * its start) are deliberately excluded — see header comment.
 *
 * False-positive analysis: the LEA byte pattern has probability
 * ~9.4e-7 per random offset, and among those only the ones that
 * happen to point exactly at one of a few hundred candidate RVAs
 * matter. Expected false positives in a 100KB section: ~4.4e-9.
 * In practice, the pattern is rare enough that confusing a data
 * table for an LEA site requires deliberate construction.
 *
 * rsp (encoding 4) as LEA destination is silently rejected —
 * `lea rsp, [rip+d]` is legal but our trampoline emitter refuses
 * it, and this way we don't pollute the caller with a filter.
 */

#include "mxprotector/protection/string/string_xref_finder.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

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
    if (code.size() < 7 || candidates.empty()) return result;

    // Scan every byte offset. The LEA form we care about is a fixed
    // 7 bytes, so offsets past `code.size() - 7` can't hold one.
    const size_t end = code.size() - 7 + 1;
    for (size_t off = 0; off < end; ++off) {
        const uint8_t rex = code[off];
        // REX.W = 1 always (64-bit operand). REX.R chooses low vs.
        // extended dest register. REX.X / REX.B are ignored for
        // rip-relative addressing — we accept only the canonical
        // 0x48 / 0x4C values that the MSVC and clang codegens
        // actually emit. Other values (0x49, 0x4D, etc.) are
        // vanishingly rare for this instruction form.
        if (rex != 0x48 && rex != 0x4C) continue;
        if (code[off + 1] != 0x8D)      continue;

        const uint8_t modrm = code[off + 2];
        // mod=00 (top 2 bits = 00), rm=101 (low 3 bits = 101).
        // Mask out the middle `reg` field and compare.
        if ((modrm & 0xC7) != 0x05) continue;

        // Decode the destination register. REX.R extends the `reg`
        // field from 3 bits to 4 bits. Reject rsp (encoding 4) as
        // a destination.
        const uint8_t rex_r     = (rex >> 2) & 1;
        const uint8_t reg_low3  = (modrm >> 3) & 7;
        const uint8_t gpr       = static_cast<uint8_t>((rex_r << 3) | reg_low3);
        if (gpr == 4 /* rsp */) continue;

        // Read the signed 32-bit displacement.
        int32_t disp32 = 0;
        std::memcpy(&disp32, code.data() + off + 3, 4);

        // Resolve the target RVA. rip-relative addressing uses the
        // RVA of the NEXT instruction as the base, which for a
        // 7-byte LEA is `lea_rva + 7`.
        const Rva lea_rva    = code_rva + static_cast<Rva>(off);
        const int64_t rip_after = static_cast<int64_t>(lea_rva) + 7;
        const int64_t target64  = rip_after + static_cast<int64_t>(disp32);
        if (target64 < 0 || target64 > 0xFFFFFFFFLL) continue;
        const Rva target_rva = static_cast<Rva>(target64);

        // Must hit the exact start of one of the candidates.
        const size_t idx = find_exact_match(candidates, target_rva);
        if (idx >= candidates.size()) continue;

        // Translate the 0..15 AMD64 GPR index into the Zydis enum
        // value the downstream pass expects. The AMD64 ordering
        // (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10,
        //  r11, r12, r13, r14, r15) matches Zydis's `RAX+k` layout
        // one-for-one, so a simple add is correct.
        const uint32_t zydis_reg =
            static_cast<uint32_t>(ZYDIS_REGISTER_RAX) + gpr;

        StringXref x{};
        x.xref_rva     = lea_rva;
        x.insn_length  = 7;
        x.disp_offset  = 3;
        x.dest_reg     = zydis_reg;
        x.target_rva   = target_rva;
        x.string_index = idx;
        result.push_back(x);
    }

    return result;
}

} // namespace mx::string_protect
