/**
 * @file mov_imm_decoder.hpp
 * @brief Shared decoder for `[REX.B] B8+rd id` (`mov r32, imm32`).
 *
 * Every MOV-imm32 MBA rewriter (modular-inverse, xor-blind,
 * rotate-blind) needs to recognise the same encoding family and
 * pull out the same fields:
 *
 *   * destination 4-bit register id (REX.B-aware),
 *   * raw 32-bit immediate.
 *
 * Hoisting that into a shared helper keeps the per-shape rewriters
 * focused on their identity. The helper is byte-only (no Zydis
 * dependency) so unit tests can exercise rewriters with hand-
 * crafted opcodes.
 *
 * Encoding reference (Intel SDM §3.2):
 *
 *   * `[REX.B] B8+rd id` — MOV r32, imm32 (5 or 6 bytes). Zero-
 *     extends the imm32 into the full 64-bit register.
 *
 * The 7-byte REX.W form (`48 C7 C0 id`) is intentionally rejected:
 * its semantics are *sign-extended* imm32, which inverts the
 * value's high bits when the imm has a 1 in bit 31. None of the
 * shipped MOV-imm rewriters preserve that sign-extension correctly
 * yet — adding it cleanly would mean a new view + a new emit path
 * per shape.
 *
 * Why we reject `imm == 0`: the canonical zero-init idiom is
 * `xor reg, reg` (2 bytes), not `mov reg, 0` (5 bytes). Compilers
 * that emit the 5-byte form are usually doing it for an indirect
 * reason (alignment, signing); MBA-rewriting the zero case has no
 * defeat upside and risks colliding with that intent.
 */

#pragma once

#include <cstdint>
#include <optional>

#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx::mutation::mba {

/// Decoded view of a `[REX.B] B8+rd id` instruction.
struct MovR32Imm32View {
    x86::Reg      dst;
    std::uint32_t imm;
};

/// Try to decode `insn` as `[REX.B] B8+rd id`. Returns
/// `std::nullopt` for any other shape, including REX.W variants
/// (sign-extended imm32 — out of scope) and `imm == 0` (covered
/// above).
[[nodiscard]] std::optional<MovR32Imm32View> decode_mov_r32_imm32(
    const analysis::Instruction& insn) noexcept;

} // namespace mx::mutation::mba
