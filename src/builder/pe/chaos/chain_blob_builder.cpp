/**
 * @file chain_blob_builder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/chain_blob_builder.hpp"

#include <array>

namespace mx::pe::chaos {

namespace {

/// `UNW_FLAG_CHAININFO` from `winnt.h` — the chaining bit the
/// unwinder checks to decide whether to follow the trailer
/// instead of consuming local prologue codes.
constexpr std::uint8_t kUnwFlagChainInfo = 0x4;

/// Pack the 4-byte chained `UNWIND_INFO` header.
[[nodiscard]] std::array<std::uint8_t, 4> chained_uwi_header() noexcept {
    std::array<std::uint8_t, 4> hdr{};
    // Version (3 bits) = 1, Flags (5 bits) = UNW_FLAG_CHAININFO.
    hdr[0] = static_cast<std::uint8_t>(0x01u | (kUnwFlagChainInfo << 3));
    hdr[1] = 0; // SizeOfProlog
    hdr[2] = 0; // CountOfCodes
    hdr[3] = 0; // FrameRegister | FrameOffset
    return hdr;
}

void write_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    buf.insert(buf.end(), p, p + 4);
}

/// Append one chained UNWIND_INFO blob — 4-byte header + 12-byte
/// ChainInfo trailer pointing at @p parent_first_sub.
void append_chained_unwind_info(
    std::vector<std::uint8_t>& buf,
    const SubBlock&            parent_first_sub,
    std::uint32_t              parent_unwind)
{
    const auto hdr = chained_uwi_header();
    buf.insert(buf.end(), hdr.begin(), hdr.end());
    write_u32_le(buf, static_cast<std::uint32_t>(parent_first_sub.start_rva));
    write_u32_le(buf, static_cast<std::uint32_t>(parent_first_sub.end_rva()));
    write_u32_le(buf, parent_unwind);
}

} // namespace

std::vector<ChainedSubBlock> build_chain_section(
    const std::vector<SubBlock>&     sub_blocks,
    const std::vector<FunctionGroup>& groups,
    const std::vector<PdataEntry>&   pdata,
    std::vector<std::uint8_t>&       chain_bytes)
{
    std::vector<ChainedSubBlock> chained;
    for (const auto& g : groups) {
        if (g.sub_count <= 1) continue;
        if (g.parent_index >= pdata.size()) continue;
        const auto& parent     = pdata[g.parent_index];
        const auto& first_sub  = sub_blocks[g.first_sub_idx];
        for (std::size_t k = 1; k < g.sub_count; ++k) {
            const auto offset = static_cast<std::uint32_t>(chain_bytes.size());
            append_chained_unwind_info(chain_bytes, first_sub, parent.unwind_data);
            chained.push_back(ChainedSubBlock{
                .sub                = &sub_blocks[g.first_sub_idx + k],
                .chained_uwi_offset = offset,
            });
        }
    }
    return chained;
}

void register_chain_info_refs(
    SectionInfo&                       chain_section,
    const std::vector<ChainedSubBlock>& chained,
    const std::vector<SubBlock>&        sub_blocks,
    const std::vector<FunctionGroup>&   groups,
    const std::vector<PdataEntry>&      pdata)
{
    chain_section.extra_rva_refs.reserve(chained.size() * 3);
    for (const auto& c : chained) {
        // ChainInfo lives at chained_uwi_offset + 4.
        const Rva chain_info_rva = static_cast<Rva>(
            chain_section.virtual_address + c.chained_uwi_offset + 4);

        const std::uint32_t parent_idx = c.sub->function_index;
        const FunctionGroup* g = nullptr;
        for (const auto& candidate : groups) {
            if (candidate.parent_index == parent_idx) { g = &candidate; break; }
        }
        if (g == nullptr) continue;
        if (parent_idx >= pdata.size()) continue;
        const auto& first_sub = sub_blocks[g->first_sub_idx];
        const auto& parent    = pdata[parent_idx];

        chain_section.extra_rva_refs.push_back(ExtraRvaRefSlot{
            .slot_rva      = chain_info_rva,
            .target_rva    = static_cast<Rva>(first_sub.start_rva),
            .end_exclusive = false,
        });
        chain_section.extra_rva_refs.push_back(ExtraRvaRefSlot{
            .slot_rva      = static_cast<Rva>(chain_info_rva + 4),
            .target_rva    = static_cast<Rva>(first_sub.end_rva()),
            .end_exclusive = true,
        });
        chain_section.extra_rva_refs.push_back(ExtraRvaRefSlot{
            .slot_rva      = static_cast<Rva>(chain_info_rva + 8),
            .target_rva    = static_cast<Rva>(parent.unwind_data),
            .end_exclusive = false,
        });
    }
}

} // namespace mx::pe::chaos
