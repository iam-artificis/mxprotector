/**
 * @file padding_filler.hpp
 * @brief Dead-padding scanner + filler. Extracted from
 *        `mutation_pass.cpp` (R3.3) so the padding-detection /
 *        opaque-predicate-injection logic lives separately from the
 *        substitution-driven `MutationEngine`.
 *
 * Two distinct concerns share a translation unit before R3.3:
 *
 *   - `MutationEngine::mutate_region` rewrites real instructions
 *     in-place via the substitution-rule registry.
 *   - The padding pipeline finds NOP/INT3 runs that the linker /
 *     compiler left between functions and overwrites them with
 *     junk + opaque predicates.
 *
 * The two never reuse each other's helpers and have independent
 * inputs (live instruction stream vs. dead byte runs). Splitting
 * keeps `mutation_pass.cpp` focused on the substitution path and
 * gives the padding logic a stable API for future tightening.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx {

namespace analysis {
class IDisassembler;
}

class JunkGenerator;
class OpaquePredicateGenerator;
class Randomizer;

namespace mutation {

/// Aggregate stats from `fill_section_padding`. Returned to the
/// caller so the pass can log / sum across all sections.
struct PaddingFillStats {
    std::uint32_t regions_filled       = 0;
    std::uint32_t predicates_inserted  = 0;
    std::uint32_t junk_bytes           = 0;
};

/**
 * @brief Find dead NOP/INT3 runs in @p code and replace them with
 *        junk and (where the run is large enough) opaque predicates.
 *
 * Dead-padding heuristic:
 *   - INT3 runs are always considered dead (linker padding between
 *     functions).
 *   - NOP runs are dead when they sit at the start of the section
 *     or directly after a `ret` / unconditional `jmp`.
 *
 * For runs of ≥14 bytes there is a 50% chance of inserting an
 * always-true opaque predicate whose dead branch hosts the junk;
 * smaller runs (or the other 50%) are filled with plain junk bytes.
 *
 * The function does NOT touch live instructions — it disassembles
 * the buffer, isolates dead padding runs, and only writes inside
 * those runs. Bytes outside any dead run are preserved verbatim.
 *
 * @param code         Mutable view over the section's bytes.
 * @param base_address Virtual address corresponding to `code[0]` —
 *                     needed by the disassembler to label addresses
 *                     correctly so dead-run detection lines up with
 *                     real RVAs.
 * @param disasm       Disassembler used to decode the buffer.
 * @param junk_gen     Junk byte generator (architecture-aware).
 * @param pred_gen     Opaque-predicate generator (architecture-aware).
 * @param rng          Build-shared randomiser; the function calls
 *                     `next_bool` to decide between predicate and
 *                     plain-junk fills.
 * @return             Stats covering all dead runs in @p code.
 */
[[nodiscard]] PaddingFillStats fill_section_padding(
    MutableByteView          code,
    Va                       base_address,
    analysis::IDisassembler& disasm,
    JunkGenerator&           junk_gen,
    OpaquePredicateGenerator& pred_gen,
    Randomizer&              rng);

} // namespace mutation
} // namespace mx
