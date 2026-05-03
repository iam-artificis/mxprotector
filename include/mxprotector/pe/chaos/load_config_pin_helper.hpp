/**
 * @file load_config_pin_helper.hpp
 * @brief Computes the *extra* pin ranges chaos must apply because a
 *        LOAD_CONFIG VA field points at a table whose contents have
 *        to stay contiguous after byte-level shuffling.
 *
 * Patching individual pointer slots is not enough for table-shaped
 * targets: even if the LOAD_CONFIG VA gets remapped to the new
 * position of the *first* chunk, subsequent table entries will sit
 * elsewhere because the chunks were permuted independently. The CFG
 * dispatcher then walks past chunk #0 and reads whatever bytes
 * happen to live there post-shuffle. Crash on first protected call.
 *
 * The helper inspects LOAD_CONFIG and, for every VA-bearing field
 * that points at an array of records, pins the *entire* section
 * holding the target. This is the conservative answer: we trade a
 * bit of locked-down free space (the section containing
 * `.gfids` / `.giats` / `.gehcont` / SEH-handler tables / etc.) for
 * a guaranteed-valid table after the shuffle.
 *
 * Why a separate header rather than inline in `chunk_planner.cpp`:
 * SRP. `ChunkPlanner` is format-agnostic — it knows about pin ranges
 * and chunks, not about CFG. This helper concentrates the
 * LOAD_CONFIG knowledge in one place; ChunkPlanner consumes the
 * result via its `extra_pins` parameter.
 *
 * Threading: stateless free function; safe to call from any thread.
 */

#pragma once

#include <vector>

#include "mxprotector/pe/chaos/chunk_planner.hpp"

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief Walk `image`'s LOAD_CONFIG directory and return one
 *        `PinnedRange` per host section that contains a pointer
 *        target whose contents must stay contiguous.
 *
 * Targets considered:
 *   * `GuardCFFunctionTable`            (CFG fid table)
 *   * `GuardAddressTakenIatEntryTable`  (IAT-taken table)
 *   * `GuardLongJumpTargetTable`        (long-jump table)
 *   * `GuardEHContinuationTable`        (EH continuation table)
 *   * `SEHandlerTable`                  (32-bit SEH; rarely set on x64)
 *
 * Skip rules:
 *   * `image.is_64bit() == false` → empty result.
 *   * LOAD_CONFIG empty / out-of-section → empty result.
 *   * Field offset past LOAD_CONFIG `Size` → field skipped.
 *   * VA below `image_base` → field skipped.
 *   * Target RVA outside any section → field skipped.
 *
 * Returned ranges may overlap each other and existing pins; the
 * planner's `merge_overlapping` step coalesces them.
 */
[[nodiscard]] std::vector<PinnedRange>
compute_load_config_target_pins(const PeImage& image);

} // namespace mx::pe::chaos
