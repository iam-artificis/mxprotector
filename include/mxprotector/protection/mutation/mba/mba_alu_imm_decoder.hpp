/**
 * @file mba_alu_imm_decoder.hpp
 * @brief Shared decoder for `81 /<op> id` (group-1 ALU r/m, imm32).
 *
 * Every imm32 MBA rewriter (ADD, SUB, XOR, OR, AND) needs to
 * recognise the same encoding family and pull out the same fields:
 *
 *   * destination 4-bit register id (REX.B-aware),
 *   * sign-extended-to-64-bit (or zero-extended-to-32-bit)
 *     immediate,
 *   * 64-bit vs 32-bit operand size (REX.W).
 *
 * Hoisting that into a single helper keeps the per-family rewriters
 * focused on their identity and avoids five copies of identical
 * byte-walking logic. The helper is byte-only (no Zydis dependency)
 * so unit tests can exercise rewriters with hand-crafted opcodes.
 *
 * Encoding reference (Intel SDM §2.1):
 *
 *   * `[REX.W|REX.B] 81 /op id` — group-1 ALU r/m32 or r/m64, imm32
 *     where `op` is the ModR/M.reg field:
 *       0=ADD, 1=OR, 4=AND, 5=SUB, 6=XOR (we cover all five).
 *
 *   * `[REX.W] {05|0D|25|2D|35} id` — EAX/RAX-only short forms
 *     (5 bytes without REX, 6 with REX.W). Same five ops, no
 *     ModR/M; destination is hardcoded to RAX/EAX. Compilers emit
 *     these aggressively for syscall-arg setup, indexing into
 *     globals, and any RAX-bound arithmetic with a non-imm8 K.
 *     They are exactly 5 bytes — fits the `JMP rel32` redirect
 *     boundary, so the engine can route them through the overflow
 *     sink alongside the general `81 /op id` form.
 *
 * Smaller forms (`83 /op ib`, 4 bytes max — too short for the
 * 5-byte `JMP rel32` redirect) remain out of scope. Adding them
 * would require a multi-instruction redirect mechanism; that's a
 * roadmap item, not a decoder extension.
 */

#pragma once

#include <cstdint>
#include <optional>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::mutation::mba {

/**
 * @brief ModR/M.reg slot of the group-1 ALU encoding family.
 *
 * Mirrors the Intel-SDM mnemonics. Values are the exact bit
 * pattern stored in `ModR/M[5:3]` for the `81 /op id` form.
 */
enum class AluImm32Op : std::uint8_t {
    add = 0,
    or_ = 1,
    and_ = 4,
    sub = 5,
    xor_ = 6,
};

/**
 * @brief Decoded view of a `[REX] 81 /op id` instruction.
 *
 * `dst` carries the full 4-bit register id (REX.B already folded
 * in). `imm` is the raw 32-bit immediate, sign-extended interpretation
 * is the caller's choice. `is_64bit` is `true` when REX.W is set;
 * the rewriter uses it to pick between 32-bit and 64-bit working
 * registers in the body.
 */
struct AluImm32View {
    AluImm32Op    op;
    x86::Reg      dst;
    std::uint32_t imm;
    bool          is_64bit;
};

/**
 * @brief Try to decode `insn` as one of the imm32 ALU encodings.
 *
 * Accepts two encoding shapes:
 *   * `[REX] 81 /op id` — general r/m32 or r/m64, any GPR dst.
 *   * `[REX.W] {05|0D|25|2D|35} id` — EAX/RAX-only short form.
 *
 * Returns `std::nullopt` when:
 *   * length is < 5 (no room for any imm32 ALU encoding),
 *   * any legacy prefix is present (the rewriter family does not
 *     target `66h` operand-size or segment-prefixed variants),
 *   * the opcode is neither `0x81` nor a recognised short-form
 *     opcode,
 *   * for `0x81`: ModR/M `mod` field is not 3 (memory operand) or
 *     `reg` field is not one of {0, 1, 4, 5, 6}.
 *
 * @param insn       Instruction to inspect.
 * @param expected_op If set, also requires the decoded op to match.
 *                    Lets each per-family rewriter skip foreign ops
 *                    without re-implementing the byte walk.
 */
[[nodiscard]] std::optional<AluImm32View> decode_alu_imm32(
    const analysis::Instruction& insn,
    std::optional<AluImm32Op>    expected_op = std::nullopt) noexcept;

} // namespace mx::mutation::mba
