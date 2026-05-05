/**
 * @file chain_blob_builder.hpp
 * @brief Build `.mxchain` byte content (chained `UNWIND_INFO` blobs)
 *        and register the corresponding `ExtraRvaRefSlot` overrides.
 *
 * @details Each non-first sub-block of a multi-sub-block function
 *          gets one 16-byte chained `UNWIND_INFO`:
 *
 *            * 4-byte header carrying the `UNW_FLAG_CHAININFO` bit
 *              (no local prologue codes — the chain returns to the
 *              parent's primary entry which carries them).
 *            * 12-byte ChainInfo trailer holding the parent's
 *              `BeginAddress`, `EndAddress` (encoded as
 *              `rva_end_exclusive`), and `UnwindInfoAddress`.
 *
 *          The chaos refmap remaps every ChainInfo RVA after shuffle
 *          via the registered `ExtraRvaRefSlot`s.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/chaos/chain_pdata_reader.hpp"
#include "mxprotector/pe/chaos/sub_block_planner.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

/**
 * @brief One non-first sub-block paired with its chained UNWIND_INFO
 *        offset within `.mxchain`.
 *
 * @details After `.mxchain` gets assigned an RVA, the offset resolves
 *          to the `UnwindInfoAddress` written into the matching
 *          `.mxpdat` entry.
 */
struct ChainedSubBlock {
    const SubBlock* sub                = nullptr;
    std::uint32_t   chained_uwi_offset = 0;
};

/**
 * @brief Append one chained UNWIND_INFO blob per non-first sub-block
 *        of every multi-sub-block function into @p chain_bytes.
 *
 * @return List of `(sub-block, offset)` for every blob written. Empty
 *         when no function carved into > 1 sub-blocks.
 */
[[nodiscard]] std::vector<ChainedSubBlock> build_chain_section(
    const std::vector<SubBlock>&     sub_blocks,
    const std::vector<FunctionGroup>& groups,
    const std::vector<PdataEntry>&   pdata,
    std::vector<std::uint8_t>&       chain_bytes);

/**
 * @brief Register one `ExtraRvaRefSlot` per ChainInfo RVA on
 *        @p chain_section so the chaos refmap remaps the stored
 *        values through the chunk planner after shuffle.
 *
 * @details Each chained blob contributes three slots: `BeginAddress`,
 *          `EndAddress` (as `rva_end_exclusive`), and
 *          `UnwindInfoAddress`. ChainInfo lives at offset
 *          `chained_uwi_offset + 4` inside `.mxchain`.
 */
void register_chain_info_refs(
    SectionInfo&                       chain_section,
    const std::vector<ChainedSubBlock>& chained,
    const std::vector<SubBlock>&        sub_blocks,
    const std::vector<FunctionGroup>&   groups,
    const std::vector<PdataEntry>&      pdata);

} // namespace mx::pe::chaos
