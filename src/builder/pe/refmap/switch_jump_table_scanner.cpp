/**
 * @file switch_jump_table_scanner.cpp
 * @brief Implementation — see header.
 *
 * Phase split:
 *   1. `find_dispatcher_jt_bases` walks every code section, decodes
 *      with Zydis, and accumulates the JT-base RVA of every
 *      `mov r32 / movsxd r64 + add r64, base + jmp r64` triple.
 *   2. `walk_jumptable_entries` walks 4-byte slots starting at each
 *      base, emitting one reference per slot whose value falls in
 *      a code section's virtual range.
 *
 * The two phases are kept in anonymous helpers so the public
 * `scan` method reads top-down: discover, then emit.
 */

#include "mxprotector/pe/refmap/switch_jump_table_scanner.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>

#include <Zydis/Zydis.h>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::refmap {

namespace {

/// Defensive cap on entries per single jump table. MSVC switches
/// rarely emit more than 64 cases; 1024 is a generous ceiling
/// that still terminates a runaway walk before it sweeps an entire
/// `.rdata`.
constexpr std::uint32_t kMaxEntriesPerTable = 1024;

/// Captured JT-base RVA for one detected dispatcher.
struct DispatcherSite {
    Rva jt_base_rva;        ///< Displacement extracted from the MOV.
    Rva dispatcher_rva;     ///< RVA of the MOV instruction (diagnostics).
};

/// Pattern-match the second instruction of the dispatcher triple.
///
/// Returns `true` when `insn` is `add r64, r64` whose destination
/// equals `expected_dest` and whose source equals `expected_src`.
[[nodiscard]] bool is_add_dest_src(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    ZydisRegister                  expected_dest,
    ZydisRegister                  expected_src) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_ADD)        return false;
    if (insn.operand_count_visible < 2)             return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    if (ops[0].reg.value != expected_dest)          return false;
    if (ops[1].reg.value != expected_src)           return false;
    return true;
}

/// Pattern-match the third instruction of the dispatcher triple.
///
/// Returns `true` when `insn` is `jmp r64` whose register operand
/// equals `expected_reg`.
[[nodiscard]] bool is_jmp_reg(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    ZydisRegister                  expected_reg) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_JMP)        return false;
    if (insn.operand_count_visible < 1)             return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    if (ops[0].reg.value != expected_reg)           return false;
    return true;
}

/// True when `reg` names a 32-bit GPR. The scanner only wants the
/// `mov r32, [..]` form, where the destination zero-extends to the
/// matching r64.
[[nodiscard]] bool is_gpr32(ZydisRegister reg) noexcept {
    return reg >= ZYDIS_REGISTER_EAX && reg <= ZYDIS_REGISTER_R15D;
}

/// True when `reg` names a 64-bit GPR.
[[nodiscard]] bool is_gpr64(ZydisRegister reg) noexcept {
    return reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15;
}

/// Promote a 32-bit GPR to its 64-bit counterpart, so callers can
/// compare against the destination of the subsequent `add` and `jmp`.
[[nodiscard]] ZydisRegister widen_to_64(ZydisRegister r32) noexcept {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r32);
}

/// Pattern-match the first instruction of the dispatcher triple.
///
/// Captures `(dest_reg32, base_reg64, disp32)` for either
/// `mov r32, dword ptr [base + idx*4 + disp32]` or
/// `movsxd r64, dword ptr [base + idx*4 + disp32]`.
struct LoadInstr {
    ZydisRegister dest_reg64;
    ZydisRegister base_reg64;
    std::int64_t  disp32;
};

[[nodiscard]] bool match_jt_load(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    LoadInstr&                     out) noexcept
{
    const bool is_mov    = insn.mnemonic == ZYDIS_MNEMONIC_MOV;
    const bool is_movsxd = insn.mnemonic == ZYDIS_MNEMONIC_MOVSXD;
    if (!is_mov && !is_movsxd) return false;
    if (insn.operand_count_visible < 2)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY)   return false;

    const auto& mem = ops[1].mem;
    if (mem.scale != 4)                              return false;
    if (mem.base  == ZYDIS_REGISTER_NONE)            return false;
    if (mem.index == ZYDIS_REGISTER_NONE)            return false;
    if (insn.raw.disp.size != 32)                    return false;
    if (insn.raw.disp.value <= 0)                    return false;

    if (is_mov) {
        // `mov r32, [..]` zero-extends to r64.
        if (!is_gpr32(ops[0].reg.value))             return false;
        if (ops[1].size != 32)                       return false;
        out.dest_reg64 = widen_to_64(ops[0].reg.value);
    } else {
        // `movsxd r64, [..]` sign-extends a 32-bit memory operand.
        if (!is_gpr64(ops[0].reg.value))             return false;
        if (ops[1].size != 32)                       return false;
        out.dest_reg64 = ops[0].reg.value;
    }

    out.base_reg64 = mem.base;
    out.disp32     = insn.raw.disp.value;
    return true;
}

/// Decode `code` looking for the three-instruction MSVC dispatcher
/// pattern. Each match contributes one `DispatcherSite` whose
/// `jt_base_rva` is the captured displacement.
void scan_section_for_dispatchers(
    ZydisDecoder&               decoder,
    ByteView                    code,
    Rva                         base_rva,
    std::vector<DispatcherSite>& out)
{
    std::size_t offset = 0;
    while (offset < code.size()) {
        ZydisDecodedInstruction i1{};
        ZydisDecodedOperand     o1[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + offset, code.size() - offset,
                &i1, o1)))
        {
            ++offset;
            continue;
        }

        LoadInstr load{};
        if (!match_jt_load(i1, o1, load)) {
            offset += i1.length;
            continue;
        }

        const std::size_t off2 = offset + i1.length;
        if (off2 >= code.size()) break;

        ZydisDecodedInstruction i2{};
        ZydisDecodedOperand     o2[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + off2, code.size() - off2,
                &i2, o2)) ||
            !is_add_dest_src(i2, o2, load.dest_reg64, load.base_reg64))
        {
            offset += i1.length;
            continue;
        }

        const std::size_t off3 = off2 + i2.length;
        if (off3 >= code.size()) break;

        ZydisDecodedInstruction i3{};
        ZydisDecodedOperand     o3[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, code.data() + off3, code.size() - off3,
                &i3, o3)) ||
            !is_jmp_reg(i3, o3, load.dest_reg64))
        {
            offset += i1.length;
            continue;
        }

        out.push_back(DispatcherSite{
            .jt_base_rva    = static_cast<Rva>(load.disp32),
            .dispatcher_rva = static_cast<Rva>(base_rva + offset),
        });
        offset += i1.length;
    }
}

/// True when `target_rva` lands inside any code (executable) section's
/// `[virtual_address, virtual_address + virtual_size)` range.
[[nodiscard]] bool is_code_rva(
    const PeImage& image, Rva target_rva) noexcept
{
    for (const auto& s : image.sections()) {
        if (!s.is_code()) continue;
        if (target_rva >= s.virtual_address &&
            target_rva <  s.virtual_address + s.virtual_size)
        {
            return true;
        }
    }
    return false;
}

/// Read four little-endian bytes from `image` at `rva`. Returns
/// `false` if the read crosses a section boundary.
[[nodiscard]] bool read_u32(
    const PeImage& image, Rva rva, std::uint32_t& out) noexcept
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return false;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return false;
    std::memcpy(&out, sec->data.data() + off, sizeof(out));
    return true;
}

/// Walk JT entries forward from `jt_base_rva`. Stops at the first
/// non-code-RVA, at `next_jt_base` (when set), or after
/// `kMaxEntriesPerTable` entries — whichever comes first.
void walk_jumptable_entries(
    const PeImage&  image,
    Rva             jt_base_rva,
    Rva             next_jt_base,
    ReferenceTable& table)
{
    for (std::uint32_t i = 0; i < kMaxEntriesPerTable; ++i) {
        const Rva slot_rva = static_cast<Rva>(jt_base_rva + i * 4);
        if (next_jt_base != 0 && slot_rva >= next_jt_base) return;

        std::uint32_t entry = 0;
        if (!read_u32(image, slot_rva, entry)) return;
        if (!is_code_rva(image, static_cast<Rva>(entry))) return;

        table.add(Reference{
            .location_rva = slot_rva,
            .target_rva   = static_cast<Rva>(entry),
            .width        = ReferenceWidth::byte4,
            .encoding     = ReferenceEncoding::rva,
            .origin       = ReferenceOrigin::switch_jump_table_entry,
        });
    }
}

/// Find every dispatcher pattern in every code section and produce a
/// deduped, sorted list of JT-base RVAs.
[[nodiscard]] std::vector<Rva> find_dispatcher_jt_bases(
    const PeImage& image)
{
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    std::vector<DispatcherSite> sites;
    sites.reserve(64);
    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        const auto code_view = ByteView{
            sec.data.data(),
            std::min(sec.data.size(),
                     static_cast<std::size_t>(sec.virtual_size))};
        scan_section_for_dispatchers(
            decoder, code_view, sec.virtual_address, sites);
    }

    std::vector<Rva> bases;
    bases.reserve(sites.size());
    std::unordered_set<Rva> seen;
    seen.reserve(sites.size());
    for (const auto& s : sites) {
        if (seen.insert(s.jt_base_rva).second) {
            bases.push_back(s.jt_base_rva);
        }
    }
    std::sort(bases.begin(), bases.end());
    return bases;
}

} // anonymous namespace

void SwitchJumpTableScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    const auto bases = find_dispatcher_jt_bases(image);
    for (std::size_t i = 0; i < bases.size(); ++i) {
        const Rva next = (i + 1 < bases.size()) ? bases[i + 1] : 0;
        walk_jumptable_entries(image, bases[i], next, table);
    }
}

} // namespace mx::pe::refmap
