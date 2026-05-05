/**
 * @file chain_pdata_reader.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/chain_pdata_reader.hpp"

#include <algorithm>
#include <cstring>
#include <type_traits>
#include <variant>

#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// One `RUNTIME_FUNCTION` slot is three 4-byte RVAs.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

struct PdataLocation {
    Rva           rva;
    std::uint32_t size;
};

[[nodiscard]] PdataLocation find_pdata_directory(
    const PeImage& image) noexcept
{
    PdataLocation result{0, 0};
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                const auto& dir = nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                result = {dir.VirtualAddress, dir.Size};
            }
        }
    }, image.nt_headers());
    return result;
}

} // namespace

std::vector<PdataEntry> read_pdata_entries(const PeImage& image) {
    std::vector<PdataEntry> out;
    if (!image.is_64bit()) return out;

    const auto loc = find_pdata_directory(image);
    if (loc.rva == 0 || loc.size < kRuntimeFunctionSize) return out;

    const auto* sec = image.section_by_rva(loc.rva);
    if (sec == nullptr) return out;

    const auto off = loc.rva - sec->virtual_address;
    if (off + loc.size > sec->data.size()) return out;

    constexpr std::uint32_t kMaxFunctionBytes = 1u << 20;
    std::uint32_t image_size_hint = 0;
    for (const auto& s : image.sections()) {
        image_size_hint = std::max(
            image_size_hint, s.virtual_address + s.virtual_size);
    }

    const std::uint8_t* dir = sec->data.data() + off;
    const std::uint32_t entry_count = loc.size / kRuntimeFunctionSize;
    out.reserve(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        PdataEntry e{};
        std::memcpy(&e.begin_address, dir + i * kRuntimeFunctionSize + 0, 4);
        std::memcpy(&e.end_address,   dir + i * kRuntimeFunctionSize + 4, 4);
        std::memcpy(&e.unwind_data,   dir + i * kRuntimeFunctionSize + 8, 4);
        if (e.begin_address == 0 && e.end_address == 0)         continue;
        if (e.end_address <= e.begin_address)                   continue;
        if (e.end_address - e.begin_address > kMaxFunctionBytes) continue;
        if (image_size_hint != 0 && e.end_address > image_size_hint) continue;
        out.push_back(e);
    }
    std::sort(out.begin(), out.end(),
              [](const PdataEntry& a, const PdataEntry& b) noexcept {
                  return a.begin_address < b.begin_address;
              });
    return out;
}

std::vector<FunctionGroup> group_by_function(
    const std::vector<SubBlock>& sub_blocks)
{
    std::vector<FunctionGroup> groups;
    groups.reserve(sub_blocks.size());
    std::size_t i = 0;
    while (i < sub_blocks.size()) {
        const auto idx = sub_blocks[i].function_index;
        std::size_t j = i;
        while (j < sub_blocks.size() &&
               sub_blocks[j].function_index == idx)
        {
            ++j;
        }
        groups.push_back(FunctionGroup{
            .parent_index  = idx,
            .first_sub_idx = i,
            .sub_count     = j - i,
        });
        i = j;
    }
    return groups;
}

} // namespace mx::pe::chaos
