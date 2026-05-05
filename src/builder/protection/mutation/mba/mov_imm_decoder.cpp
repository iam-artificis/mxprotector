/**
 * @file mov_imm_decoder.cpp
 * @brief Implementation — see header.
 *
 * Both decoders walk the byte stream once with no Zydis call: MBA
 * matching has to run on synthetic instructions in unit tests too,
 * where the test harness builds an `mx::analysis::Instruction` from
 * raw bytes without booting up the full disassembler stack.
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
        // REX.W takes the encoding into 64-bit imm-iq territory —
        // handled by `decode_mov_r64_imm64`. Only accept REX with
        // W=0 here, with optional B for the extended low-3-bit
        // register id.
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

std::optional<MovR64Imm64View> decode_mov_r64_imm64(
    const analysis::Instruction& insn) noexcept
{
    const auto bytes = insn.raw_bytes();
    // REX (1) + opcode (1) + iq (8) = 10 bytes minimum.
    if (bytes.size() < 10) return std::nullopt;

    std::size_t cursor = 0;
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    // The 10-byte form is `REX.W [.B] B8+rd iq`. REX is mandatory
    // here — without REX.W the opcode is a 32-bit `mov r32, imm32`
    // (handled by the other decoder). REX.X / REX.R must be 0
    // because `B8+rd` does not have a ModR/M byte.
    if (!x86::is_rex(bytes[cursor])) return std::nullopt;
    if (!x86::rex_w(bytes[cursor])) return std::nullopt;
    const bool rex_b = x86::rex_b(bytes[cursor]);
    ++cursor;

    if (cursor >= bytes.size()) return std::nullopt;
    const std::uint8_t op = bytes[cursor];
    if (op < 0xB8 || op > 0xBF) return std::nullopt;
    ++cursor;

    if (cursor + 8 > bytes.size()) return std::nullopt;

    std::uint64_t imm = 0;
    for (std::uint8_t i = 0; i < 8; ++i) {
        imm |= static_cast<std::uint64_t>(bytes[cursor + i]) << (i * 8);
    }
    // A `mov r64, 0` site is suspect for the same reason as the
    // 32-bit case (canonical zero-init is `xor`); skip it.
    if (imm == 0) return std::nullopt;

    std::uint8_t reg_id = static_cast<std::uint8_t>(op - 0xB8);
    if (rex_b) reg_id |= 0x08;

    MovR64Imm64View view{};
    view.dst = static_cast<x86::Reg>(reg_id);
    view.imm = imm;
    return view;
}

} // namespace mx::mutation::mba
