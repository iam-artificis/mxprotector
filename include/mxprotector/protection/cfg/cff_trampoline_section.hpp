/**
 * @file cff_trampoline_section.hpp
 * @brief Commit collected trampoline entries into a new executable section.
 *
 * Functions whose flattened form didn't fit inside the original byte
 * range are deferred into a `CffTrampolineEntry` list during the main
 * flatten loop. Once every candidate has been processed, this module
 * turns the list into a single self-contained executable section:
 *
 *   1. Concatenate every entry's flattened bytes at a 16-byte aligned
 *      offset, recording the offset back onto the entry.
 *   2. Inject the section under the per-build name from
 *      `ctx.section_names().cff`.
 *   3. Fix every RIP-relative / rel32 operand inside the placed blocks
 *      with `apply_relocation_fixups`.
 *   4. Patch each function's original body into a 5-byte `jmp rel32`
 *      pointing at its relocated copy.
 *
 * The `.pdata` entries for the trampolined functions are intentionally
 * left intact — see the implementation comment for the full rationale
 * (Windows unwinder needs the original `RUNTIME_FUNCTION` ranges to
 * walk frames through the trampoline site).
 */

#pragma once

#include <vector>

#include "mxprotector/protection/cfg/cfg_flattening.hpp"

namespace mx {
class ProtectionContext;
}

namespace mx::cff {

/**
 * @brief Commit all accumulated trampolines into a new executable section.
 *
 * @param ctx     Pipeline context.
 * @param entries Mutated in place — each entry's `section_offset` is
 *                filled as its bytes are laid into the new section.
 *
 * A no-op when `entries` is empty. Section-injection failures are
 * logged but do not abort the pipeline — this matches the original
 * fail-soft behaviour: subsequent passes tolerate a missing CFF
 * section (they key off `ctx.section_names().cff` and skip when the
 * section isn't present).
 */
void commit_trampoline_section(ProtectionContext&               ctx,
                               std::vector<CffTrampolineEntry>& entries);

} // namespace mx::cff
