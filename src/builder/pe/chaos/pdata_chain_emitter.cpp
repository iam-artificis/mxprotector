/**
 * @file pdata_chain_emitter.cpp
 * @brief Implementation — see header.
 *
 * Layout of `emit()`:
 *
 *   1. Plan sub-blocks via `plan_sub_blocks(image)`. Bail when
 *      every function yields a single sub-block (no chain entries
 *      to emit).
 *   2. Read every original `.pdata` `RUNTIME_FUNCTION`. Index by
 *      `function_index` so we can recover each parent's
 *      `UnwindInfoAddress` when building chained ChainInfo.
 *   3. Build the `.mxchain` byte buffer — one 16-byte chained
 *      `UNWIND_INFO` per non-first sub-block. Each blob's
 *      ChainInfo trailer holds:
 *        * `BeginAddress = first_sub_block.start` — points at the
 *          parent's first sub-block, the "primary" entry the
 *          chained info conceptually returns to.
 *        * `EndAddress   = first_sub_block.end` — encoded as
 *          `rva_end_exclusive`.
 *        * `UnwindInfoAddress = parent_unwind_rva` — pinned data,
 *          identity remap.
 *   4. Emit `.mxchain` via `SectionEmitter`. The new section's
 *      RVA is now known; populate each non-first sub-block's
 *      chained `UnwindInfoAddress` slot accordingly.
 *   5. Build the `.mxpdat` byte buffer — original entries with
 *      `EndAddress` SHRUNK to the first sub-block's end (so the
 *      original entry covers exactly the first sub-block) +
 *      chained entries. Sort by `BeginAddress` so the loader's
 *      binary search lands deterministically on the smallest
 *      enclosing entry.
 *   6. Emit `.mxpdat`. Update
 *      `IMAGE_DIRECTORY_ENTRY_EXCEPTION` to point at it.
 *   7. Register `extra_rva_refs` on `.mxchain` for each ChainInfo
 *      RVA so the chaos refmap patches them after shuffle. The
 *      `.mxpdat` entries are scanned by the existing
 *      `StructureReferenceScanner` once the directory points at
 *      `.mxpdat`.
 */

#include "mxprotector/pe/chaos/pdata_chain_emitter.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <variant>
#include <vector>

#include "mxprotector/pe/chaos/sub_block_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/pre_scanned_ref_slot.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace mx::pe::chaos {

namespace {

/// One `RUNTIME_FUNCTION` slot is three 4-byte RVAs.
constexpr std::uint32_t kRuntimeFunctionSize = 12;

/// One chained `UNWIND_INFO` is a 4-byte header (`Version | Flags`,
/// `SizeOfProlog`, `CountOfCodes`, `FrameRegister | FrameOffset`)
/// plus the 12-byte ChainInfo trailer. No unwind codes — the chain
/// directs the unwinder to the parent's primary entry which carries
/// the actual prologue codes.
constexpr std::uint32_t kChainedUnwindInfoSize = 16;

/// `UNW_FLAG_CHAININFO` from `winnt.h` — the chaining bit the
/// unwinder checks to decide whether to follow the trailer
/// instead of consuming local prologue codes.
constexpr std::uint8_t kUnwFlagChainInfo = 0x4;

// ---------------------------------------------------------------------------
// `.pdata` reading
// ---------------------------------------------------------------------------

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

/// One in-image `RUNTIME_FUNCTION` triple. Indexed in the SAME
/// filter+sort order as `sub_block_planner.cpp::collect_pdata_entries`
/// so `SubBlock::function_index` lines up 1:1 with this vector —
/// any filter divergence between the two would mismatch chain
/// entries with their parent functions and emit ChainInfo
/// pointing at wrong unwind data.
///
///   * Zero / sentinel terminator entries are dropped.
///   * `end_address <= begin_address` rows are dropped.
///   * `end - begin > 1 MiB` rows are dropped (defensive cap).
///   * Survivors are sorted by `begin_address` ascending.
struct PdataEntry {
    std::uint32_t begin_address = 0;
    std::uint32_t end_address   = 0;
    std::uint32_t unwind_data   = 0;
};

[[nodiscard]] std::vector<PdataEntry> read_pdata_entries(
    const PeImage& image)
{
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

// ---------------------------------------------------------------------------
// Sub-block grouping
// ---------------------------------------------------------------------------

/// Group sub-blocks by `function_index` so we can ask "what's the
/// FIRST sub-block of function N" without re-walking the list.
struct FunctionGroup {
    std::uint32_t parent_index   = 0;
    std::size_t   first_sub_idx  = 0;
    std::size_t   sub_count      = 0;
};

[[nodiscard]] std::vector<FunctionGroup> group_by_function(
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

// ---------------------------------------------------------------------------
// Chained `UNWIND_INFO` + `RUNTIME_FUNCTION` byte builders
// ---------------------------------------------------------------------------

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

/// Append one chained `UNWIND_INFO` blob to `buf`.
///
///   * `parent_first_sub` — the parent function's FIRST sub-block.
///                          Its start RVA + end RVA become the
///                          ChainInfo's `BeginAddress` and
///                          `EndAddress`.
///   * `parent_unwind`    — original `UnwindInfoAddress` of the
///                          parent. Goes into ChainInfo's
///                          `UnwindInfoAddress`.
void append_chained_unwind_info(
    std::vector<std::uint8_t>& buf,
    const SubBlock&            parent_first_sub,
    std::uint32_t              parent_unwind)
{
    const auto hdr = chained_uwi_header();
    buf.insert(buf.end(), hdr.begin(), hdr.end());
    // ChainInfo: 12 bytes — BeginAddress, EndAddress, UnwindInfoAddress.
    write_u32_le(buf, static_cast<std::uint32_t>(parent_first_sub.start_rva));
    write_u32_le(buf, static_cast<std::uint32_t>(parent_first_sub.end_rva()));
    write_u32_le(buf, parent_unwind);
}

/// Append one `RUNTIME_FUNCTION` entry to `buf`.
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

// ---------------------------------------------------------------------------
// `.mxchain` builder + per-non-first-sub-block plumbing
// ---------------------------------------------------------------------------

/// One non-first sub-block paired with its chained UNWIND_INFO offset
/// within `.mxchain`. After the section gets its RVA, the offset
/// resolves to the `UnwindInfoAddress` written into the matching
/// `.mxpdat` entry.
struct ChainedSubBlock {
    const SubBlock* sub                  = nullptr;
    std::uint32_t   chained_uwi_offset   = 0;
};

/// For every non-first sub-block of a function with > 1 sub-blocks,
/// emit one chained UNWIND_INFO blob into `chain_bytes` and return
/// the parallel `(sub-block, offset)` list. The `parent_first_sub`
/// passed to `append_chained_unwind_info` is the function's first
/// sub-block, which carries the parent's BeginAddress; the parent's
/// UnwindInfoAddress comes from the matching `.pdata` entry.
[[nodiscard]] std::vector<ChainedSubBlock> build_chain_section(
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

// ---------------------------------------------------------------------------
// `.mxpdat` builder
// ---------------------------------------------------------------------------

/// Combined entry the `.mxpdat` builder sorts. Mirrors the on-wire
/// `RUNTIME_FUNCTION` triple plus the `function_index` so we can
/// figure out which entry came from which parent / sub-block when
/// debugging.
struct MxPdataEntry {
    std::uint32_t begin_address  = 0;
    std::uint32_t end_address    = 0;
    std::uint32_t unwind_address = 0;
};

/// Build the combined entry list:
///
///   * Original `.pdata` entries — `EndAddress` SHRUNK to first
///     sub-block end so the entry covers exactly the first sub-
///     block. Functions with no chained entries get their original
///     `EndAddress` left unchanged (the trailing INT3 absorbed
///     into the function-as-one-sub-block atom IS still part of
///     the chunk).
///   * One chained entry per non-first sub-block.
[[nodiscard]] std::vector<MxPdataEntry> build_mxpdat_entries(
    const std::vector<SubBlock>&     sub_blocks,
    const std::vector<FunctionGroup>& groups,
    const std::vector<PdataEntry>&   pdata,
    const std::vector<ChainedSubBlock>& chained,
    Rva                              chain_rva)
{
    std::vector<MxPdataEntry> out;
    out.reserve(pdata.size() + chained.size());

    // Walk groups so we can pair every parent with its first sub-block.
    std::size_t group_cursor = 0;
    for (std::uint32_t pi = 0; pi < pdata.size(); ++pi) {
        const auto& p = pdata[pi];
        if (p.begin_address == 0 && p.end_address == 0) continue;

        // Find the matching group, if any.
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
            // Shrink to first sub-block end.
            end_addr = static_cast<std::uint32_t>(
                sub_blocks[g->first_sub_idx].end_rva());
        }
        out.push_back(MxPdataEntry{
            .begin_address  = p.begin_address,
            .end_address    = end_addr,
            .unwind_address = p.unwind_data,
        });
    }

    // Append chained entries — one per non-first sub-block.
    for (const auto& c : chained) {
        out.push_back(MxPdataEntry{
            .begin_address  = static_cast<std::uint32_t>(c.sub->start_rva),
            .end_address    = static_cast<std::uint32_t>(c.sub->end_rva()),
            .unwind_address = static_cast<std::uint32_t>(
                chain_rva + c.chained_uwi_offset),
        });
    }

    // Sort by BeginAddress — required by the SEH unwinder's binary
    // search.
    std::sort(out.begin(), out.end(),
              [](const MxPdataEntry& a, const MxPdataEntry& b) noexcept {
                  return a.begin_address < b.begin_address;
              });
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> serialize_mxpdat(
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

// ---------------------------------------------------------------------------
// Directory rewrite
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Chain-info reference registration
// ---------------------------------------------------------------------------

/// Register one `ExtraRvaRefSlot` per ChainInfo RVA so the chaos
/// refmap patches them through the chunk planner. ChainInfo is a
/// 12-byte `RUNTIME_FUNCTION`-shaped trailer at offset
/// `chained_uwi_offset + 4` inside `.mxchain`.
void register_chain_info_refs(
    SectionInfo&                            chain_section,
    const std::vector<ChainedSubBlock>&     chained,
    const std::vector<SubBlock>&            sub_blocks,
    const std::vector<FunctionGroup>&       groups,
    const std::vector<PdataEntry>&          pdata)
{
    chain_section.extra_rva_refs.reserve(chained.size() * 3);
    for (const auto& c : chained) {
        // ChainInfo lives at chained_uwi_offset + 4.
        const Rva chain_info_rva = static_cast<Rva>(
            chain_section.virtual_address + c.chained_uwi_offset + 4);
        // Find the parent function this chained entry belongs to.
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

} // anonymous namespace

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
