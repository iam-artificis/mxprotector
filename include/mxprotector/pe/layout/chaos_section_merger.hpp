/**
 * @file chaos_section_merger.hpp
 * @brief Collapse every section in a `PeImage` into one unified RWX
 *        section.
 *
 * @details RVA-preserving merge — every original byte keeps its
 *          original RVA after the merge so internal references
 *          continue to resolve. The whole virtual span between the
 *          first section's start and the last section's end is
 *          reified as a single section; inter-section gaps are
 *          filled with `INT3` (0xCC) so a stray dispatch fault-traps
 *          deterministically.
 *
 *          This is one of the orchestration helpers extracted from
 *          `chaos_layout.cpp`. The merge step is independent from the
 *          chaos shuffle: chaos uses it to enforce a single-section
 *          image at finalisation, but it could be applied on its own
 *          for a "merge-only" layout regime.
 */

#pragma once

#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

/**
 * @brief Collapse every section in @p image into one unified
 *        chaos-stamped section, preserving original RVAs.
 *
 * @details No-op when the image has fewer than two sections (a single
 *          section is already merged by definition). On entry the
 *          image carries N sections; on exit it carries exactly one,
 *          its `characteristics` set to the chaos canonical mask
 *          (mixed-content + RWX), its `virtual_size` covering
 *          `[min_va, max_va_end)`, and its `data` filled with each
 *          original section's bytes at the correct RVA-relative
 *          offset. `NumberOfSections` in the FileHeader is rewritten
 *          to 1.
 */
void merge_into_unified_section(PeImage& image);

/**
 * @brief OR the chaos characteristics bit-mask into every existing
 *        section's flags. Called as defence in depth after
 *        `merge_into_unified_section` (which already stamps the
 *        unified section), so any code path that bypasses the merge
 *        still gets the chaos bits set.
 */
void stamp_chaos_characteristics(PeImage& image) noexcept;

} // namespace mx::pe::chaos
