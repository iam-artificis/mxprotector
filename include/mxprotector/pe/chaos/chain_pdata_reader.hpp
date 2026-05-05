/**
 * @file chain_pdata_reader.hpp
 * @brief Read `.pdata` `RUNTIME_FUNCTION` triples and group sub-blocks
 *        by their parent function.
 *
 * @details Both helpers are pure — they read the `PeImage` (or a
 *          sub-block plan) and produce vectors. They share filtering
 *          conventions with `sub_block_planner.cpp::collect_pdata_entries`
 *          so `SubBlock::function_index` lines up 1:1 with the
 *          `read_pdata_entries` output. Any divergence between the
 *          two filters would mismatch chain entries with their parent
 *          function and emit ChainInfo pointing at wrong unwind data.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/pe/chaos/sub_block_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

/// One in-image `RUNTIME_FUNCTION` triple. Indexed in the SAME
/// filter+sort order as `sub_block_planner.cpp::collect_pdata_entries`.
struct PdataEntry {
    std::uint32_t begin_address = 0;
    std::uint32_t end_address   = 0;
    std::uint32_t unwind_data   = 0;
};

/// Group sub-blocks by `function_index` so callers can ask "what's
/// the FIRST sub-block of function N" without re-walking the list.
struct FunctionGroup {
    std::uint32_t parent_index   = 0;
    std::size_t   first_sub_idx  = 0;
    std::size_t   sub_count      = 0;
};

/**
 * @brief Read every `RUNTIME_FUNCTION` triple from the EXCEPTION
 *        directory of @p image.
 *
 * @details Filters applied (matching `collect_pdata_entries`):
 *            * Zero / sentinel terminator entries dropped.
 *            * `end_address <= begin_address` rows dropped.
 *            * `end - begin > 1 MiB` rows dropped (defensive cap).
 *            * Survivors sorted by `begin_address` ascending.
 *          Returns an empty vector on 32-bit images, missing or
 *          empty `.pdata`, or out-of-bounds directory size.
 */
[[nodiscard]] std::vector<PdataEntry> read_pdata_entries(
    const PeImage& image);

/**
 * @brief Walk @p sub_blocks and produce one `FunctionGroup` per
 *        contiguous run of identical `function_index`.
 *
 * @details Pre-condition: the sub-block list is sorted by
 *          `function_index` (`plan_sub_blocks` guarantees this).
 *          Each group records the parent function index, the first
 *          sub-block's offset in the sub-block vector, and how many
 *          sub-blocks the function carved into.
 */
[[nodiscard]] std::vector<FunctionGroup> group_by_function(
    const std::vector<SubBlock>& sub_blocks);

} // namespace mx::pe::chaos
