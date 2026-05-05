/**
 * @file pdata_chain_emitter.cpp
 * @brief Implementation of `PdataChainEmitter::emit` — orchestration
 *        only; helpers live in sibling files.
 *
 * @details Layout of `emit()`:
 *
 *            1. Plan sub-blocks via `plan_sub_blocks(image)`. Bail
 *               when every function yields a single sub-block.
 *            2. Read every original `.pdata` `RUNTIME_FUNCTION` —
 *               see `chain_pdata_reader.hpp`.
 *            3. Build the `.mxchain` byte buffer — see
 *               `chain_blob_builder.hpp`.
 *            4. Emit `.mxchain` via `SectionEmitter`.
 *            5. Build the `.mxpdat` byte buffer — see
 *               `mxpdat_builder.hpp` — and emit it.
 *            6. Update `IMAGE_DIRECTORY_ENTRY_EXCEPTION` to point at
 *               `.mxpdat`.
 *            7. Register `extra_rva_refs` on `.mxchain` for each
 *               ChainInfo RVA so the chaos refmap patches them after
 *               shuffle.
 */

#include "mxprotector/pe/chaos/pdata_chain_emitter.hpp"

#include <type_traits>
#include <variant>
#include <vector>

#include "mxprotector/pe/chaos/chain_blob_builder.hpp"
#include "mxprotector/pe/chaos/chain_pdata_reader.hpp"
#include "mxprotector/pe/chaos/mxpdat_builder.hpp"
#include "mxprotector/pe/chaos/sub_block_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pre_scanned_ref_slot.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace mx::pe::chaos {

namespace {

void rewrite_exception_directory(
    PeImage& image, Rva new_rva, std::uint32_t new_size) noexcept
{
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                dir.VirtualAddress = new_rva;
                dir.Size           = new_size;
            }
        }
    }, image.nt_headers());
}

} // namespace

std::size_t PdataChainEmitter::emit(
    PeImage& image, SectionEmitter& emitter) const
{
    const auto sub_blocks = plan_sub_blocks(image);
    if (sub_blocks.empty()) return 0;

    const auto groups = group_by_function(sub_blocks);
    bool any_chain = false;
    for (const auto& g : groups) {
        if (g.sub_count > 1) { any_chain = true; break; }
    }
    if (!any_chain) return 0;

    const auto pdata = read_pdata_entries(image);
    if (pdata.empty()) return 0;

    // 1. Build .mxchain content.
    std::vector<std::uint8_t> chain_bytes;
    const auto chained = build_chain_section(
        sub_blocks, groups, pdata, chain_bytes);
    if (chained.empty()) return 0;

    // 2. Emit .mxchain.
    auto chain_idx_result = emitter.append_section(
        ".mxchain",
        ByteView{chain_bytes.data(), chain_bytes.size()},
        SectionIntent{
            SectionContentType::data,
            SectionPermissions::r,
        });
    if (!chain_idx_result) return 0;
    const auto chain_idx = *chain_idx_result;
    auto& chain_section = image.sections()[chain_idx];
    const Rva chain_rva = chain_section.virtual_address;

    // The chaos layout policy stamps `IMAGE_SCN_CNT_CODE` on every
    // section's characteristics so the merged `.mxchaos` reads as
    // mixed code/data uniformly. As a side effect,
    // `CodeReferenceScanner` walks `.mxchain`'s structured bytes
    // through Zydis and emits BOGUS `rel`/`rip-rel` references from
    // coincidental opcode patterns inside the 16-byte chained
    // UNWIND_INFO blobs. Register the entire byte range as a
    // `DataRegion` so the scanner skips it.
    chain_section.data_regions.push_back(DataRegion{
        .begin_rva = chain_rva,
        .size      = static_cast<std::uint32_t>(chain_bytes.size()),
        .kind      = DataRegionKind::chained_unwind_info_array,
    });

    // 3. Build .mxpdat content.
    const auto mxpdat_entries = build_mxpdat_entries(
        sub_blocks, groups, pdata, chained, chain_rva);
    auto mxpdat_bytes = serialize_mxpdat(mxpdat_entries);

    // 4. Emit .mxpdat.
    auto mxpdat_idx_result = emitter.append_section(
        ".mxpdat",
        ByteView{mxpdat_bytes.data(), mxpdat_bytes.size()},
        SectionIntent{
            SectionContentType::data,
            SectionPermissions::r,
        });
    if (!mxpdat_idx_result) return 0;
    const auto mxpdat_idx = *mxpdat_idx_result;
    auto& mxpdat_section = image.sections()[mxpdat_idx];
    const Rva mxpdat_rva = mxpdat_section.virtual_address;

    // Same Zydis-treats-as-code hazard as `.mxchain`. Register the
    // full extent so the scanner skips it; the existing
    // `StructureReferenceScanner` (which walks `.mxpdat` structurally
    // now that the EXCEPTION directory points at it) remains the
    // sole producer of references for those bytes.
    mxpdat_section.data_regions.push_back(DataRegion{
        .begin_rva = mxpdat_rva,
        .size      = static_cast<std::uint32_t>(mxpdat_bytes.size()),
        .kind      = DataRegionKind::pdata_runtime_function_array,
    });

    // 5. Re-resolve chain_section pointer — `append_section` may
    // have invalidated the earlier reference if the section vector
    // grew.
    auto& chain_section_after = image.sections()[chain_idx];
    register_chain_info_refs(
        chain_section_after, chained, sub_blocks, groups, pdata);

    // 6. Update the EXCEPTION data directory to point at .mxpdat.
    rewrite_exception_directory(
        image, mxpdat_rva,
        static_cast<std::uint32_t>(mxpdat_bytes.size()));

    return chained.size();
}

} // namespace mx::pe::chaos
