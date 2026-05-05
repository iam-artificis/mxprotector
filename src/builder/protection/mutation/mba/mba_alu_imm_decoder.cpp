/**
 * @file mba_alu_imm_decoder.cpp
 * @brief Implementation — see header.
 *
 * Single byte-walk, branch-free per byte. The decoder does **not**
 * call into Zydis: imm32 MBA matching has to run on synthetic
 * instructions in unit tests too, where the test harness builds a
 * `mx::analysis::Instruction` from raw bytes without booting up the
 * full disassembler stack.
 */

#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"

#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::mutation::mba {

namespace {

/// True if `op` is one of the five group-1 ALU ops we cover. Keeps
/// the decoder rejecting CMP (`/7`) and the unused `/2`/`/3`
/// (ADC/SBB) — those have different semantics that no shipped
/// rewriter handles, so accepting them here would silently route
/// foreign instructions to the wrong family.
[[nodiscard]] bool is_supported_op(std::uint8_t reg_field) noexcept {
    switch (reg_field) {
        case 0: case 1: case 4: case 5: case 6:
            return true;
        default:
            return false;
    }
}

} // namespace

std::optional<AluImm32View> decode_alu_imm32(
    const analysis::Instruction& insn,
    std::optional<AluImm32Op>    expected_op) noexcept
{
    const auto bytes = insn.raw_bytes();
    if (bytes.size() < 6) return std::nullopt;

    std::size_t cursor = 0;

    // Reject any legacy prefix — `66h` would change operand size to
    // 16-bit (we only target 32/64-bit shapes), and segment / lock
    // prefixes mark either thread-local or atomic ops both of
    // which fall outside the rewriter's flag-preserving guarantees.
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    bool          rex_w     = false;
    bool          rex_b     = false;
    if (x86::is_rex(bytes[cursor])) {
        rex_w = x86::rex_w(bytes[cursor]);
        rex_b = x86::rex_b(bytes[cursor]);
        ++cursor;
    }

    if (cursor >= bytes.size() || bytes[cursor] != 0x81) {
        return std::nullopt;
    }
    ++cursor;

    if (cursor >= bytes.size()) return std::nullopt;
    const std::uint8_t modrm = bytes[cursor++];
    if (x86::modrm_mod(modrm) != 3) return std::nullopt;

    const std::uint8_t reg_field = x86::modrm_reg(modrm);
    if (!is_supported_op(reg_field)) return std::nullopt;

    const auto decoded_op = static_cast<AluImm32Op>(reg_field);
    if (expected_op && *expected_op != decoded_op) return std::nullopt;

    if (cursor + 4 > bytes.size()) return std::nullopt;

    std::uint32_t imm = 0;
    for (std::uint8_t i = 0; i < 4; ++i) {
        imm |= static_cast<std::uint32_t>(bytes[cursor + i]) << (i * 8);
    }

    std::uint8_t reg_id = x86::modrm_rm(modrm);
    if (rex_b) reg_id |= 0x08;

    AluImm32View view{};
    view.op       = decoded_op;
    view.dst      = static_cast<x86::Reg>(reg_id);
    view.imm      = imm;
    view.is_64bit = rex_w;
    return view;
}

} // namespace mx::mutation::mba
