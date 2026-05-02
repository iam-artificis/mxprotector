/**
 * @file jmp_emit.hpp
 * @brief x86_64 `JMP rel32` encoder helpers used by the mutation
 *        overflow sinks.
 *
 * Centralises the byte-level encoding of a `JMP rel32` (opcode `0xE9`
 * followed by a 32-bit signed displacement relative to the byte after
 * the JMP). Both expansion sinks emit a JMP-back at the tail of the
 * planted body; the mutation engine emits a JMP-out at the original
 * site. Keeping the encoding in one place stops drift and gives a
 * single test surface.
 *
 * Why a free helper rather than the existing `x86_code_emitter`: the
 * code emitter is built around higher-level instruction synthesis and
 * register allocation. We need a 5-byte literal and the rel32 math —
 * a small fixed-shape op that does not justify reaching into the
 * heavier emitter.
 */

#pragma once

#include <array>
#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::mutation::overflow {

/// `JMP rel32` is 1 byte of opcode + 4 bytes of signed displacement.
inline constexpr std::uint32_t kJmpRel32Size = 5;

/**
 * @brief Compute the `rel32` displacement for a JMP from `from_rva`
 *        to `to_rva`.
 *
 * The displacement is `to_rva - (from_rva + kJmpRel32Size)` because
 * x86 rel32 is relative to the byte after the JMP. Returns the raw
 * 32-bit value; the caller is responsible for verifying the underlying
 * 64-bit delta fits in `int32_t` if reachability matters (mutation
 * sites and overflow sections live in the same PE image, so the
 * delta is bounded by the image size — fits trivially).
 */
[[nodiscard]] std::int32_t compute_rel32(
    Rva from_rva, Rva to_rva) noexcept;

/**
 * @brief Encode a `JMP rel32` from `from_rva` to `to_rva`.
 *
 * @return The 5 bytes of the encoded JMP, ready to copy into a
 *         section buffer. `bytes[0]` is the `0xE9` opcode; `bytes[1..]`
 *         is the little-endian signed `rel32` from `compute_rel32`.
 */
[[nodiscard]] std::array<std::uint8_t, kJmpRel32Size> encode_jmp_rel32(
    Rva from_rva, Rva to_rva) noexcept;

} // namespace mx::mutation::overflow
