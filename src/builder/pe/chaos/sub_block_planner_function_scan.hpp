/**
 * @file sub_block_planner_function_scan.hpp
 * @brief Private helper — input gathering for sub-block planning.
 *
 * Owns the two read-only operations the planner needs from the
 * input PE image: enumerate every `.pdata` entry, and decode each
 * function to harvest candidate split points + intra-function rel
 * displacement spans.
 *
 * Lives in `src/builder/pe/chaos/` — internal to the chaos module.
 * Public consumers see only `plan_sub_blocks` from
 * `sub_block_planner.hpp`; the types and free functions declared
 * here are an implementation seam used by `sub_block_planner.cpp`.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

/**
 * @brief One entry from the PE32+ `.pdata` directory.
 *
 * Layout matches the on-disk `RUNTIME_FUNCTION` struct (12 bytes:
 * begin / end / unwind RVAs). We read it byte-for-byte and never
 * round-trip back to disk, so endianness / alignment is not a
 * concern past `std::memcpy` in the implementation.
 */
struct RuntimeFunction {
    std::uint32_t begin_address;
    std::uint32_t end_address;
    std::uint32_t unwind_data;
};

/**
 * @brief One rel8 / rel32 reference observed inside a function.
 *
 * `lo` / `hi` are the closed RVA bounds of the slot byte and the
 * branch target byte. A sub-block split point S breaks this rel
 * reference iff `lo < S <= hi` — see `split_breaks_any_rel` in
 * sub_block_planner.cpp for the rationale.
 */
struct RelRefSpan {
    Rva           lo;    ///< min(slot+1, target). slot+1 = byte AFTER disp.
    Rva           hi;    ///< max(slot+1, target).
    std::uint8_t  width; ///< 1 or 4 — diagnostic only.
};

/**
 * @brief Result of decoding one function's body.
 *
 * `split_candidates` holds the byte AFTER every unconditional
 * terminator (RET / unconditional JMP). `rel_spans` holds one
 * entry per intra-function rel8/rel32 branch operand.
 */
struct FunctionScan {
    std::vector<Rva>        split_candidates;
    std::vector<RelRefSpan> rel_spans;
};

/**
 * @brief Read every valid entry from the image's `.pdata` directory,
 *        sorted by `begin_address`.
 *
 * Returns an empty vector on PE32 inputs (no `.pdata`), missing
 * directory, or out-of-range section data. Drops malformed entries
 * (`begin >= end`, oversize functions, end-past-image) silently —
 * the caller does not need to distinguish "no entries" from
 * "entries that all looked broken".
 */
[[nodiscard]] std::vector<RuntimeFunction>
    collect_pdata_entries(const PeImage& image);

/**
 * @brief Decode `[rf.begin_address, rf.end_address)` and harvest
 *        candidate split points + rel displacement spans.
 *
 * Returns an empty `FunctionScan` if the function bytes cannot be
 * read (out-of-range RVA) or if Zydis fails on the very first
 * instruction. Decoding terminates early on the first decode
 * failure mid-function — partial scans are surfaced as-is so the
 * planner's split logic can still operate on the prefix.
 */
[[nodiscard]] FunctionScan
    scan_function(const PeImage& image, const RuntimeFunction& rf);

} // namespace mx::pe::chaos
