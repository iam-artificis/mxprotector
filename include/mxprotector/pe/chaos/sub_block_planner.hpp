/**
 * @file sub_block_planner.hpp
 * @brief Walk `.pdata` and split each function into one or more
 *        `(start, end)` sub-blocks at clean unconditional-terminator
 *        boundaries (B.4.23 / B.4.23.1 — shared helper).
 *
 * `BasicBlockAtomSource` (the chaos atom source) and
 * `PdataChainEmitter` (the chained `.pdata` + `.mxchain` builder)
 * BOTH need the same split list to stay consistent: every atom the
 * source emits must have a matching `RUNTIME_FUNCTION` entry the
 * emitter writes to `.mxpdat`. Putting the split in one helper is
 * the SOLID-clean way to keep both views in lockstep.
 *
 * The split policy mirrors `BasicBlockAtomSource`'s in-file logic:
 *
 *   * Each sub-block ends with an unconditional control transfer
 *     (`RET` / `JMP <rel/r/m>`). Conditional branches (`JCC`) and
 *     interrupts (`INT 3`) are NEVER terminators — their fall-
 *     through edge needs slack-after fixup that the basic-block
 *     atom source does not yet plan for.
 *   * The byte AFTER the terminator must be `kSplitAlignment`-
 *     aligned (4 bytes — same as the chaos planner's chunk
 *     granularity). Otherwise the planner would pin the resulting
 *     atom for boundary mismatch and the split is wasted.
 *   * The trailing sub-block of every function extends across any
 *     `0xCC` (`INT 3`) padding that follows the function's
 *     `EndAddress`, up to the next 8-aligned RVA — same head/tail
 *     absorption `FunctionAtomSource` performs.
 *
 * Functions that yield zero usable splits collapse to one sub-block
 * covering the whole `[BeginAddress, EndAddress)` plus tail
 * padding — identical to the function-atom output.
 *
 * SOLID:
 *   * SRP — exactly one task: produce the sub-block list. PE-format
 *     parsing, atom emission, and `.pdata` rewriting are downstream
 *     concerns.
 *   * OCP — new terminator classes plug into
 *     `is_unconditional_terminator()` (a separate helper); split
 *     policy stays in this file.
 *
 * Threading: stateless. The Zydis decoder is local to the call.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx {
class PeImage;
} // namespace mx

namespace mx::pe::chaos {

/**
 * @brief One sub-block produced by the planner.
 *
 *   * `function_index` — 0-based index of the parent `RUNTIME_FUNCTION`
 *     entry in the original `.pdata`. Two sub-blocks with the same
 *     index share a function and an UNWIND_INFO.
 *   * `start_rva`, `size` — half-open byte range of this sub-block,
 *     including any leading head / trailing tail INT3 padding the
 *     planner absorbed.
 *   * `is_first` — `true` when this sub-block contains the function's
 *     original `BeginAddress`. Exactly one sub-block per function
 *     has this set.
 *   * `is_last` — `true` when this sub-block contains the function's
 *     original `EndAddress - 1` byte. Exactly one sub-block per
 *     function has this set.
 *
 * For functions that yield no usable splits, `is_first` and
 * `is_last` are both `true` on the single emitted sub-block.
 */
struct SubBlock {
    std::uint32_t function_index = 0;
    Rva           start_rva      = 0;
    std::uint32_t size           = 0;
    bool          is_first       = false;
    bool          is_last        = false;

    /// Half-open end RVA of this sub-block.
    [[nodiscard]] constexpr Rva end_rva() const noexcept {
        return static_cast<Rva>(start_rva + size);
    }
};

/**
 * @brief Boundary alignment for sub-block splits. Must equal the
 *        chaos planner's `kChunkAlignment` so the resulting atoms
 *        clear the alignment-mismatch pin filter.
 */
inline constexpr std::uint32_t kSubBlockSplitAlignment = 4;

/**
 * @brief Trailing-INT3 absorption alignment for the LAST sub-block
 *        per function. Mirrors `FunctionAtomSource::kBoundaryAlignment`
 *        so a function whose `EndAddress` has trailing `0xCC` filler
 *        ends on an 8-aligned RVA, keeping every naturally-aligned
 *        8-byte value in one chunk.
 */
inline constexpr std::uint32_t kSubBlockFunctionEndAlignment = 8;

/**
 * @brief Walk every `.pdata` `RUNTIME_FUNCTION` and emit one or more
 *        sub-blocks per function. Returns an empty vector when the
 *        image is not 64-bit, when `.pdata` is missing, or when the
 *        directory walk hits a malformed entry past the first valid
 *        one.
 */
[[nodiscard]] std::vector<SubBlock> plan_sub_blocks(const PeImage& image);

} // namespace mx::pe::chaos
