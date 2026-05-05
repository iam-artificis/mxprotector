/**
 * @file mba_unary_decoder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"

namespace mx::mutation::mba {

std::optional<UnaryView> decode_unary(
    const analysis::Instruction& insn,
    std::optional<UnaryOp>       expected_op) noexcept
{
    const auto bytes = insn.raw_bytes();
    if (bytes.size() < 2) return std::nullopt;

    std::size_t cursor = 0;
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    bool rex_w = false;
    bool rex_b = false;
    if (x86::is_rex(bytes[cursor])) {
        rex_w = x86::rex_w(bytes[cursor]);
        rex_b = x86::rex_b(bytes[cursor]);
        ++cursor;
    }

    if (cursor + 1 >= bytes.size()) return std::nullopt;
    if (bytes[cursor] != 0xF7) return std::nullopt;
    ++cursor;

    const std::uint8_t modrm = bytes[cursor];
    if (x86::modrm_mod(modrm) != 3) return std::nullopt;

    const std::uint8_t reg_field = x86::modrm_reg(modrm);
    if (reg_field != static_cast<std::uint8_t>(UnaryOp::not_) &&
        reg_field != static_cast<std::uint8_t>(UnaryOp::neg))
    {
        return std::nullopt;
    }
    const auto op = static_cast<UnaryOp>(reg_field);
    if (expected_op && *expected_op != op) return std::nullopt;

    std::uint8_t reg_id = x86::modrm_rm(modrm);
    if (rex_b) reg_id |= 0x08;

    const auto dst_reg = static_cast<x86::Reg>(reg_id);
    // Reject rsp — the deep-chain unary shapes wrap their work in
    // `push scratch ... pop scratch`, which corrupts the body's view
    // of `dst` if `dst == rsp`. The single-shape unary rewriters
    // (twocomplement, xor-cancel, not-add1) would tolerate rsp, but
    // gating once at the decoder is cleaner than gating per-shape;
    // `not rsp` / `neg rsp` are essentially never emitted by
    // compilers, so the coverage loss is nil.
    if (dst_reg == x86::Reg::rsp) return std::nullopt;

    UnaryView view{};
    view.op       = op;
    view.dst      = dst_reg;
    view.is_64bit = rex_w;
    return view;
}

} // namespace mx::mutation::mba
