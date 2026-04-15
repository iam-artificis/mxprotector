/**
 * @file stolen_bytes.hpp
 * @brief OEP-prologue stolen-bytes planner for the packer.
 *
 * The packer replaces the original entry point (OEP) with a jump to
 * its own stub. To make simple "set a breakpoint on OEP" workflows
 * useless we also STEAL a chunk of the original OEP prologue into the
 * stub: after the stub finishes decrypting sections, it executes the
 * stolen instructions inline and jumps to `OEP + stolen_size`, so the
 * real entry point has no byte left in place to break on.
 *
 * This module handles the build-time planning part: walk whole x64
 * instructions starting at the OEP, pick the first `N ≥ kMinStolenBytes`
 * that are safe to relocate, and record the per-instruction metadata
 * the stub assembler needs to patch CALL rel32 targets after the move.
 *
 * A sequence is considered safe only if every stolen instruction is:
 *   * not a branch (`JMP`/`JCC`) — a taken branch would leave the
 *     stolen block with no way back,
 *   * not a `RET` — ends the OEP sequence entirely,
 *   * free of RIP-relative memory operands — the displacement would
 *     silently break when the bytes move,
 *   * and, if it's a `CALL rel32`, we record a fix-up record so the
 *     rel32 can be rewritten to the original absolute target.
 *
 * If the scanner can't find a safe `kMinStolenBytes`-long run, it
 * returns an empty plan and the caller gives up on stealing for this
 * build — the stub still runs, it just jumps straight back to the
 * unchanged OEP.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::packer {

/// Minimum number of bytes the scanner must collect before returning a
/// non-empty plan. Below this we consider the steal "not worth it"
/// because a reverser can just ignore the tiny missing prefix.
constexpr uint32_t kMinStolenBytes = 10;

/// Upper bound on stolen bytes — prevents extracting so much code that
/// the stub grows unreasonably or the safety checks become fragile.
constexpr uint32_t kMaxStolenBytes = 64;

/**
 * @brief One rel32 fix-up inside the stolen-bytes payload.
 *
 * The rel32 target at `offset_in_stolen` was originally
 * `original_target_rva`; after the bytes move into the stub the 4-byte
 * rel32 at `offset_in_stolen` must be rewritten to keep pointing at
 * that RVA. Currently only CALL rel32 (opcode `0xE8`) is tracked.
 */
struct StolenReloc {
    uint32_t offset_in_stolen;    ///< offset of rel32 within stolen_bytes
    uint32_t instr_end_in_stolen; ///< byte just after the full instruction
    Rva      original_target_rva; ///< absolute target RVA (stays constant)
};

/**
 * @brief Result of `plan_stolen_bytes`.
 *
 * `size == 0` means planning failed (no safe prologue found or an
 * unsupported instruction was encountered); callers should treat that
 * as "skip the steal step and jump straight to the original OEP".
 */
struct StolenPlan {
    uint32_t                 size = 0;
    std::vector<StolenReloc> relocs;
};

/**
 * @brief Scan the OEP prologue for instructions that can be safely
 *        relocated into the packer stub.
 *
 * @param text_bytes          Raw bytes of the section that holds the OEP.
 * @param oep_offset_in_text  Byte offset of the OEP inside `text_bytes`.
 * @param oep_rva             RVA of the OEP in the source PE — used to
 *                            convert CALL rel32 targets to absolute
 *                            RVAs in `StolenReloc::original_target_rva`.
 *
 * @return A plan whose `size` member is `≥ kMinStolenBytes` and
 *         `≤ kMaxStolenBytes` on success, or `0` on failure.
 */
[[nodiscard]] StolenPlan plan_stolen_bytes(ByteView text_bytes,
                                           uint32_t oep_offset_in_text,
                                           Rva      oep_rva);

} // namespace mx::packer
