/**
 * @file mba_alu_rr_decoder.hpp
 * @brief Shared decoder for ALU r-r (register-register) ALU encodings.
 *
 * Targets the group-1 ALU r-r forms with `mod = 3`:
 *
 *     01 /r  ADD r/m, r       03 /r  ADD r, r/m
 *     09 /r  OR  r/m, r       0B /r  OR  r, r/m
 *     21 /r  AND r/m, r       23 /r  AND r, r/m
 *     29 /r  SUB r/m, r       2B /r  SUB r, r/m
 *     31 /r  XOR r/m, r       33 /r  XOR r, r/m
 *
 * Each op has two encoding directions distinguished by which modrm
 * field carries the destination — `01 /r` puts dst in rm, `03 /r`
 * puts dst in reg, but the runtime semantics are the same:
 * `dst <op>= src`. Both encodings collapse to a single `AluRrView`
 * with the destination and source already normalised.
 *
 * Memory operands (`mod < 3`) are out of scope: MBA bodies need to
 * read both operands repeatedly into scratch registers, which is a
 * different problem (would need to spill the memory operand once
 * and re-read from the spill). Skip until that warrants its own
 * rewriter family.
 *
 * Same-register sites (`dst == src`) are also rejected. They encode
 * canonical idioms like `xor r, r` (zero), `or r, r` (test), and
 * `sub r, r` (zero) that hand-tuned compilers and pattern matchers
 * recognise; rewriting them with MBA produces wasteful code without
 * defeat upside, since the value being clobbered is structurally
 * known to the solver regardless of the body shape.
 *
 * Length: 2 bytes (no REX) or 3 bytes (with REX). Both shorter than
 * the 5-byte JMP rel32 redirect threshold — relies on the engine's
 * multi-instruction redirect to widen the slot at substitution time.
 */

#pragma once

#include <cstdint>
#include <optional>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"

namespace mx::mutation::mba {

/**
 * @brief Decoded view of one of the ten r-r ALU encodings.
 *
 * `op`        — normalised ALU op (`AluImm32Op` is reused so the
 *               affine emitter sees the same enum across imm and
 *               r-r decoders).
 * `dst`/`src` — full 4-bit register ids (REX.R/REX.B already
 *               folded in). Always different — same-register sites
 *               are rejected by the decoder.
 * `is_64bit`  — `true` when REX.W is set, picking the 64-bit
 *               operand-size for the body.
 */
struct AluRrView {
    AluImm32Op op;
    x86::Reg   dst;
    x86::Reg   src;
    bool       is_64bit;
};

/// Try to decode `insn` as one of the r-r ALU encodings listed
/// above. Returns `std::nullopt` if the bytes don't match the
/// pattern, the operand has memory addressing (`mod < 3`), or the
/// two operands alias the same register.
[[nodiscard]] std::optional<AluRrView> decode_alu_rr(
    const analysis::Instruction& insn,
    std::optional<AluImm32Op>    expected_op = std::nullopt) noexcept;

} // namespace mx::mutation::mba
