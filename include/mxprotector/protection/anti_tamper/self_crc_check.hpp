/**
 * @file self_crc_check.hpp
 * @brief [BUILDER] Post-hoc finaliser for Self-CRC placeholder bytes.
 *
 * See `self_crc_check.cpp` / `check.hpp` for the rationale. This
 * header exposes just the single entry point the X64 backend uses:
 * after it has finished applying all rel32 / imm32 patches to the
 * entry stub, it calls `finalize_self_crc_patches` to compute the
 * real CRC32C over each recorded range and write it into the
 * placeholder the Self-CRC check emitted.
 */

#pragma once

#include <cstdint>
#include <span>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_tamper/check.hpp"

namespace mx::anti_tamper {

/// CRC32C (Castagnoli, reflected, init=0xFFFFFFFF, final xor=0xFFFFFFFF).
/// Matches exactly what the emitted runtime loop with the x86
/// `crc32` instruction computes.
[[nodiscard]] uint32_t crc32c_sw(const uint8_t* data, size_t len) noexcept;

/// Walks each record, computes CRC32C over the final bytes of
/// `e.buf[r.range_start .. r.range_start + r.length)`, and writes
/// it little-endian at `r.placeholder_offset`. Must be called AFTER
/// every other patch that can modify bytes in the range.
void finalize_self_crc_patches(
    RawEmitter& e,
    std::span<const SelfCrcPatchRecord> patches) noexcept;

} // namespace mx::anti_tamper
