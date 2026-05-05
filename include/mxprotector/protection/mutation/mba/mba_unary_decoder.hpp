/**
 * @file mba_unary_decoder.hpp
 * @brief Shared decoder for `[REX] F7 /2` (NOT) and `[REX] F7 /3` (NEG)
 *        with `mod = 3`.
 *
 * Targets the unary group-3 forms:
 *
 *     F7 /2    NOT r/m32      [REX.W] F7 /2    NOT r/m64
 *     F7 /3    NEG r/m32      [REX.W] F7 /3    NEG r/m64
 *
 * Memory operands (`mod < 3`) are out of scope: an MBA body that
 * reads the operand multiple times would have to spill the memory
 * value first, which is a different problem from the register-only
 * case. Skip until that warrants its own rewriter family.
 *
 * Length: 2 bytes (no REX) or 3 bytes (with REX). Below the 5-byte
 * JMP rel32 redirect threshold — relies on the engine's multi-
 * instruction redirect (Phase 11) to widen the slot.
 */

#pragma once

#include <cstdint>
#include <optional>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::mutation::mba {

/// Selector for the two group-3 unary forms we target.
enum class UnaryOp : std::uint8_t {
    not_ = 2,  ///< `F7 /2` — NOT r/m
    neg  = 3,  ///< `F7 /3` — NEG r/m
};

/// Decoded view of a `[REX] F7 /<2|3>` register-only instruction.
struct UnaryView {
    UnaryOp  op;
    x86::Reg dst;
    bool     is_64bit;
};

/// Try to decode `insn` as one of the unary forms. Returns
/// `std::nullopt` for any other shape (memory operands, foreign
/// `/<reg>` extensions, etc.). When `expected_op` is provided, also
/// requires the decoded op to match — lets each per-shape rewriter
/// skip the foreign opcode without re-implementing the byte walk.
[[nodiscard]] std::optional<UnaryView> decode_unary(
    const analysis::Instruction& insn,
    std::optional<UnaryOp>       expected_op = std::nullopt) noexcept;

} // namespace mx::mutation::mba
