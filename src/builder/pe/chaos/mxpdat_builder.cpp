/**
 * @file mxpdat_builder.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/mxpdat_builder.hpp"

#include <algorithm>

namespace mx::pe::chaos {

namespace {

/// One `RUNTIME_FUNCTION` slot is three 4-byte RVAs.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

void write_u32_le(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
    buf.insert(buf.end(), p, p + 4);
}

void append_runtime_function(
    std::vector<std::uint8_t>& buf,
    std::uint32_t              begin_address,
    std::uint32_t              end_address,
    std::uint32_t              unwind_address)
{
    write_u32_le(buf, begin_address);
    write_u32_le(buf, end_address);
    write_u32_le(buf, unwind_address);
}

} // namespace

std::vector<MxPdataEntry> build_mxpdat_entries(
    const std::vector<SubBlock>&        sub_blocks,
    const std::vector<FunctionGroup>&   groups,
    const std::vector<PdataEntry>&      pdata,
    const std::vector<ChainedSubBlock>& chained,
    Rva                                 chain_rva)
{
    std::vector<MxPdataEntry> out;
    out.reserve(pdata.size() + chained.size());

    std::size_t group_cursor = 0;
    for (std::uint32_t pi = 0; pi < pdata.size(); ++pi) {
        const auto& p = pdata[pi];
        if (p.begin_address == 0 && p.end_address == 0) continue;

        const FunctionGroup* g = nullptr;
        while (group_cursor < groups.size() &&
               groups[group_cursor].parent_index < pi)
        {
            ++group_cursor;
        }
        if (group_cursor < groups.size() &&
            groups[group_cursor].parent_index == pi)
        {
            g = &groups[group_cursor];
        }

        std::uint32_t end_addr = p.end_address;
        if (g != nullptr && g->sub_count > 1) {
            end_addr = static_cast<std::uint32_t>(
                sub_blocks[g->first_sub_idx].end_rva());
        }
        out.push_back(MxPdataEntry{
            .begin_address  = p.begin_address,
            .end_address    = end_addr,
            .unwind_address = p.unwind_data,
        });
    }

    for (const auto& c : chained) {
        out.push_back(MxPdataEntry{
            .begin_address  = static_cast<std::uint32_t>(c.sub->start_rva),
            .end_address    = static_cast<std::uint32_t>(c.sub->end_rva()),
            .unwind_address = static_cast<std::uint32_t>(
                chain_rva + c.chained_uwi_offset),
        });
    }

    std::sort(out.begin(), out.end(),
              [](const MxPdataEntry& a, const MxPdataEntry& b) noexcept {
                  return a.begin_address < b.begin_address;
              });
    return out;
}

std::vector<std::uint8_t> serialize_mxpdat(
    const std::vector<MxPdataEntry>& entries)
{
    std::vector<std::uint8_t> bytes;
    bytes.reserve(entries.size() * kRuntimeFunctionSize);
    for (const auto& e : entries) {
        append_runtime_function(bytes,
            e.begin_address, e.end_address, e.unwind_address);
    }
    return bytes;
}

} // namespace mx::pe::chaos
