/**
 * @file mov_imm_decoder.hpp
 * @brief Shared decoders for `mov r, imm` MBA-relevant encodings.
 *
 * Two distinct `mov`-imm shapes feed the MBA rewriter set. They
 * share register-extension semantics (REX.B promotes the low-3-bit
 * register id to r8..r15) but differ in immediate width:
 *
 *   * `[REX.B] B8+rd id` — `mov r32, imm32` (5/6 bytes). Zero-
 *     extends the imm32 into the full 64-bit register.
 *   * `[REX.W (.B)] B8+rd iq` — `mov r64, imm64` (10/11 bytes).
 *     Full 64-bit immediate, no extension.
 *
 * Hoisting decoder logic into shared helpers keeps each per-shape
 * rewriter focused on its identity. The helpers are byte-only (no
 * Zydis dependency) so unit tests can exercise rewriters with
 * hand-crafted opcodes.
 *
 * Encoding reference: Intel SDM §3.2 (MOV — Move).
 *
 * The 7-byte REX.W form (`48 C7 C0 id`) is intentionally excluded
 * from both decoders: its semantics are *sign-extended* imm32, which
 * inverts the value's high bits when the imm has a 1 in bit 31. None
 * of the shipped MOV-imm rewriters preserve that sign-extension
 * correctly, and adding it cleanly would mean a third view + a third
 * emit path per shape with little defeat upside (compilers reach for
 * the 5-byte `B8 id` form for positive 32-bit constants and the
 * 10-byte `48 B8 iq` form whenever a 64-bit constant is needed).
 *
 * Why we reject `imm == 0`: the canonical zero-init idiom is
 * `xor reg, reg` (2 bytes), not `mov reg, 0`. Compilers that emit
 * the longer form are usually doing it for an indirect reason
 * (alignment, signing); MBA-rewriting the zero case has no defeat
 * upside and risks colliding with that intent.
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

/// Decoded view of a `[REX.W (.B)] B8+rd iq` instruction.
/// `dst` honours REX.B for the low 3 bits + REX.W for the operand
/// size. `imm` is the raw 64-bit immediate exactly as encoded — no
/// sign- or zero-extension applied (the encoded value is already
/// the runtime value).
struct MovR64Imm64View {
    x86::Reg      dst;
    std::uint64_t imm;
};

/// Try to decode `insn` as `[REX.B] B8+rd id`. Returns
/// `std::nullopt` for any other shape, including REX.W variants
/// (the 10-byte `mov r64, imm64` belongs to `decode_mov_r64_imm64`)
/// and `imm == 0` (covered above).
[[nodiscard]] std::optional<MovR32Imm32View> decode_mov_r32_imm32(
    const analysis::Instruction& insn) noexcept;

/// Try to decode `insn` as `[REX.W (.B)] B8+rd iq`. Returns
/// `std::nullopt` for any other shape, including the 5/6-byte
/// `mov r32, imm32` form (handled by `decode_mov_r32_imm32`),
/// the 7-byte `48 C7 C0 id` sign-extended form, and `imm == 0`.
[[nodiscard]] std::optional<MovR64Imm64View> decode_mov_r64_imm64(
    const analysis::Instruction& insn) noexcept;

} // namespace mx::mutation::mba
