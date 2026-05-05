/**
 * @file mba_alu_rr_decoder.cpp
 * @brief Implementation — see header.
 *
 * Each encoding is identified by its primary opcode byte; the
 * direction (rm-r vs r-rm) is folded into a (op, swap) pair that
 * normalises (dst, src) regardless of which encoding the compiler
 * chose. The "rm-r" encoding (`01`/`09`/...) puts the destination
 * in modrm.rm; the "r-rm" encoding (`03`/`0B`/...) swaps roles.
 * Both decode to the same `AluRrView`.
 */

#include "mxprotector/protection/mutation/mba/mba_alu_rr_decoder.hpp"

#include <array>

namespace mx::mutation::mba {

namespace {

struct OpcodeMap {
    std::uint8_t opcode;   ///< The byte after the optional REX prefix.
    AluImm32Op   op;       ///< Normalised ALU op.
    bool         swap;     ///< `true` if dst is reg, src is rm.
};

/// Five group-1 ALU ops × two encoding directions = ten table entries.
/// `swap == false` matches the rm-r forms (modrm.rm is the dst);
/// `swap == true` matches the r-rm forms (modrm.reg is the dst).
constexpr std::array<OpcodeMap, 10> kAluRrOpcodes = {{
    {0x01, AluImm32Op::add,  false},
    {0x03, AluImm32Op::add,  true },
    {0x09, AluImm32Op::or_,  false},
    {0x0B, AluImm32Op::or_,  true },
    {0x21, AluImm32Op::and_, false},
    {0x23, AluImm32Op::and_, true },
    {0x29, AluImm32Op::sub,  false},
    {0x2B, AluImm32Op::sub,  true },
    {0x31, AluImm32Op::xor_, false},
    {0x33, AluImm32Op::xor_, true },
}};

[[nodiscard]] const OpcodeMap* lookup_opcode(std::uint8_t op) noexcept {
    for (const auto& entry : kAluRrOpcodes) {
        if (entry.opcode == op) return &entry;
    }
    return nullptr;
}

} // namespace

std::optional<AluRrView> decode_alu_rr(
    const analysis::Instruction& insn,
    std::optional<AluImm32Op>    expected_op) noexcept
{
    const auto bytes = insn.raw_bytes();
    // Two bytes minimum (no REX): opcode + ModR/M. Three with REX.
    if (bytes.size() < 2) return std::nullopt;

    std::size_t cursor = 0;

    // No legacy prefixes — the 0x66 operand-size override toggles
    // 16-bit ALU which we don't target, and segment overrides aren't
    // a valid prefix on the r-r forms.
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    bool rex_w = false;
    bool rex_r = false;
    bool rex_b = false;
    if (x86::is_rex(bytes[cursor])) {
        rex_w = x86::rex_w(bytes[cursor]);
        rex_r = x86::rex_r(bytes[cursor]);
        rex_b = x86::rex_b(bytes[cursor]);
        ++cursor;
    }

    if (cursor + 1 >= bytes.size()) return std::nullopt;

    const auto* opcode_entry = lookup_opcode(bytes[cursor]);
    if (opcode_entry == nullptr) return std::nullopt;
    if (expected_op && *expected_op != opcode_entry->op) return std::nullopt;
    ++cursor;

    const std::uint8_t modrm = bytes[cursor];
    if (x86::modrm_mod(modrm) != 3) return std::nullopt;

    std::uint8_t reg_id_reg = x86::modrm_reg(modrm);
    std::uint8_t reg_id_rm  = x86::modrm_rm(modrm);
    if (rex_r) reg_id_reg |= 0x08;
    if (rex_b) reg_id_rm  |= 0x08;

    AluRrView view{};
    view.op       = opcode_entry->op;
    view.is_64bit = rex_w;
    if (opcode_entry->swap) {
        view.dst = static_cast<x86::Reg>(reg_id_reg);
        view.src = static_cast<x86::Reg>(reg_id_rm);
    } else {
        view.dst = static_cast<x86::Reg>(reg_id_rm);
        view.src = static_cast<x86::Reg>(reg_id_reg);
    }

    // Reject same-register sites: `xor r, r` zeroing, `or r, r`
    // testing, etc. Rewriting these with MBA is wasteful and the
    // value being produced (zero, or the unchanged operand) is
    // structurally known to any reasonable solver regardless of
    // body shape.
    if (view.dst == view.src) return std::nullopt;

    // Reject rsp on either side of the r-r form. The r-r affine
    // body wraps three scratches in push/pop and reads `view.dst` /
    // `view.src` inside that wrap — if either operand is rsp, the
    // body sees rsp at the wrong stack-frame depth (24 bytes off)
    // and writes back a wrong value. Compilers very rarely emit
    // ALU r-r against rsp anyway; the gate's coverage cost is
    // negligible and it removes a whole class of segfaults.
    if (view.dst == x86::Reg::rsp || view.src == x86::Reg::rsp) {
        return std::nullopt;
    }

    return view;
}

} // namespace mx::mutation::mba
