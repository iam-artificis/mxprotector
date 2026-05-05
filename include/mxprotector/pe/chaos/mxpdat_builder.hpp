/**
 * @file mxpdat_builder.hpp
 * @brief Build the combined `.mxpdat` `RUNTIME_FUNCTION` array — the
 *        replacement for the original `.pdata` directory.
 *
 * @details Two-stage build:
 *
 *            1. Original `.pdata` entries — `EndAddress` SHRUNK to
 *               first sub-block end so the entry covers exactly the
 *               first sub-block. Functions with no chained entries
 *               keep their original `EndAddress`.
 *            2. One chained entry per non-first sub-block, with
 *               `UnwindInfoAddress` pointing into `.mxchain`.
 *
 *          The combined list is sorted by `BeginAddress` so the SEH
 *          unwinder's binary search lands deterministically on the
 *          smallest enclosing entry.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/chaos/chain_blob_builder.hpp"
#include "mxprotector/pe/chaos/chain_pdata_reader.hpp"
#include "mxprotector/pe/chaos/sub_block_planner.hpp"

namespace mx::pe::chaos {

/// On-wire `RUNTIME_FUNCTION` triple plus enough context to debug.
struct MxPdataEntry {
    std::uint32_t begin_address  = 0;
    std::uint32_t end_address    = 0;
    std::uint32_t unwind_address = 0;
};

/**
 * @brief Build the combined entry list (originals + chained), sorted
 *        by `BeginAddress`.
 */
[[nodiscard]] std::vector<MxPdataEntry> build_mxpdat_entries(
    const std::vector<SubBlock>&        sub_blocks,
    const std::vector<FunctionGroup>&   groups,
    const std::vector<PdataEntry>&      pdata,
    const std::vector<ChainedSubBlock>& chained,
    Rva                                 chain_rva);

/**
 * @brief Serialize an entry list to its on-wire 12-byte-per-entry
 *        byte representation.
 */
[[nodiscard]] std::vector<std::uint8_t> serialize_mxpdat(
    const std::vector<MxPdataEntry>& entries);

} // namespace mx::pe::chaos
