/**
 * @file mov_imm_decoder.cpp
 * @brief Implementation — see header.
 *
 * Single byte-walk, branch-free per byte. The decoder does not
 * call into Zydis: MBA matching has to run on synthetic
 * instructions in unit tests too, where the test harness builds a
 * `mx::analysis::Instruction` from raw bytes without booting up
 * the full disassembler stack.
 */

#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

std::optional<MovR32Imm32View> decode_mov_r32_imm32(
    const analysis::Instruction& insn) noexcept
{
    const auto bytes = insn.raw_bytes();
    if (bytes.size() < 5) return std::nullopt;

    std::size_t cursor = 0;
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    bool rex_b = false;
    if (x86::is_rex(bytes[cursor])) {
        // REX.W means the encoding becomes `48 C7 C0 id` — out of
        // scope (sign-extended imm32, different semantic). Only
        // accept REX with W=0 for the extended low-3-bit register.
        if (x86::rex_w(bytes[cursor])) return std::nullopt;
        rex_b = x86::rex_b(bytes[cursor]);
        ++cursor;
    }

    if (cursor >= bytes.size()) return std::nullopt;
    const std::uint8_t op = bytes[cursor];
    if (op < 0xB8 || op > 0xBF) return std::nullopt;
    ++cursor;

    if (cursor + 4 > bytes.size()) return std::nullopt;

    std::uint32_t imm = 0;
    for (std::uint8_t i = 0; i < 4; ++i) {
        imm |= static_cast<std::uint32_t>(bytes[cursor + i]) << (i * 8);
    }
    if (imm == 0) return std::nullopt; // zeroing is a different idiom

    std::uint8_t reg_id = static_cast<std::uint8_t>(op - 0xB8);
    if (rex_b) reg_id |= 0x08;

    MovR32Imm32View view{};
    view.dst = static_cast<x86::Reg>(reg_id);
    view.imm = imm;
    return view;
}

} // namespace mx::mutation::mba
