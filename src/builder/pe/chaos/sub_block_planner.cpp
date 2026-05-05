/**
 * @file sub_block_planner.cpp
 * @brief Sub-block planning — emission side.
 *
 * Two-pass walker per function (kept identical to the legacy logic
 * in `basic_block_atom_source.cpp` so both consumers see the same
 * splits):
 *
 *   1. `scan_function` (in `sub_block_planner_function_scan.cpp`)
 *      decodes every instruction in `[BeginAddress, EndAddress)`.
 *      Records the byte AFTER each unconditional terminator
 *      (`RET` / `JMP`) and every intra-function rel8/rel32 span.
 *   2. This file walks the candidate split points and keeps only
 *      the ones that are `kSubBlockSplitAlignment`-aligned RVAs and
 *      do not break any rel reference, then emits one `SubBlock`
 *      per surviving span.
 *
 * The trailing sub-block extends across the function's INT3 tail
 * padding up to the next 8-aligned RVA, capped by the next
 * function's start. The leading sub-block extends BACK over INT3
 * padding down to the previous 8-aligned RVA, capped by the
 * previous function's end. This matches `FunctionAtomSource`'s
 * head/tail absorption.
 */

#include "mxprotector/pe/chaos/sub_block_planner.hpp"

#include "sub_block_planner_function_scan.hpp"

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::uint8_t kInt3 = 0xCC;

// ---------------------------------------------------------------------------
// Tail / head INT3 absorption
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr std::uint32_t align_up_u32(
    std::uint32_t v, std::uint32_t a) noexcept
{
    return (v + a - 1u) & ~(a - 1u);
}

[[nodiscard]] constexpr std::uint32_t align_down_u32(
    std::uint32_t v, std::uint32_t a) noexcept
{
    return v & ~(a - 1u);
}

[[nodiscard]] bool all_int3(
    const PeImage& image, Rva rva, std::uint32_t count) noexcept
{
    if (count == 0) return true;
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return false;
    const auto off = rva - sec->virtual_address;
    if (static_cast<std::size_t>(off) + count > sec->data.size()) {
        return false;
    }
    const auto* p = sec->data.data() + off;
    for (std::uint32_t k = 0; k < count; ++k) {
        if (p[k] != kInt3) return false;
    }
    return true;
}

[[nodiscard]] std::uint32_t extend_tail(
    const PeImage& image, const RuntimeFunction& rf,
    std::uint32_t next_function_start)
{
    const std::uint32_t target_end = align_up_u32(
        rf.end_address, kSubBlockFunctionEndAlignment);
    const std::uint32_t cap = next_function_start == 0
        ? target_end
        : std::min(target_end, next_function_start);
    if (cap <= rf.end_address) return rf.end_address;
    if (!all_int3(image, static_cast<Rva>(rf.end_address),
                  cap - rf.end_address))
    {
        return rf.end_address;
    }
    return cap;
}

[[nodiscard]] std::uint32_t extend_head(
    const PeImage& image, const RuntimeFunction& rf,
    std::uint32_t prev_function_end)
{
    const std::uint32_t target_start = align_down_u32(
        rf.begin_address, kSubBlockFunctionEndAlignment);
    const std::uint32_t floor = std::max(target_start, prev_function_end);
    if (floor >= rf.begin_address) return rf.begin_address;
    if (!all_int3(image, static_cast<Rva>(floor),
                  rf.begin_address - floor))
    {
        return rf.begin_address;
    }
    return floor;
}

// ---------------------------------------------------------------------------
// Sub-block emission per function
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr bool is_split_aligned(Rva rva) noexcept {
    return (rva % kSubBlockSplitAlignment) == 0;
}

/// `true` when splitting the function at `split` would put a rel
/// slot in one sub-block and its target in another. Such a split
/// would force the chaos refmap to write a new disp into the slot,
/// and for `rel8` slots a cross-chunk distance overflows the int8
/// range — the patcher truncates and the jump lands on a wrong
/// byte (most often mid-instruction → illegal-instruction crash).
/// We refuse the split rather than break the jump.
[[nodiscard]] bool split_breaks_any_rel(
    Rva                          split,
    std::span<const RelRefSpan>  rel_spans) noexcept
{
    // Reject splits that would put the slot in one chunk and the
    // target in another. A split at `S` breaks the rel reference
    // when `lo < S <= hi` — the half-open boundary on the high
    // side is what lets us split RIGHT AT the rel's source byte
    // (slot strictly precedes the split) without breaking it.
    for (const auto& s : rel_spans) {
        if (s.lo < split && split <= s.hi) return true;
    }
    return false;
}

void emit_sub_blocks_for_function(
    const PeImage&              image,
    const RuntimeFunction&      rf,
    std::uint32_t               function_index,
    std::uint32_t               prev_function_end,
    std::uint32_t               next_function_start,
    std::span<const Rva>        raw_splits,
    std::span<const RelRefSpan> rel_spans,
    std::vector<SubBlock>&      out)
{
    const Rva fn_start_with_head = static_cast<Rva>(
        extend_head(image, rf, prev_function_end));
    const Rva fn_end_with_tail = static_cast<Rva>(
        extend_tail(image, rf, next_function_start));

    const std::size_t first_emit = out.size();
    Rva run_start = fn_start_with_head;
    for (const Rva split : raw_splits) {
        if (split <= run_start)         continue;
        if (split >= fn_end_with_tail)  break;
        if (!is_split_aligned(split))   continue;
        if (!is_split_aligned(run_start)) continue;
        if (split_breaks_any_rel(split, rel_spans)) continue;
        out.push_back(SubBlock{
            .function_index = function_index,
            .start_rva      = run_start,
            .size           = static_cast<std::uint32_t>(split - run_start),
            .is_first       = false,
            .is_last        = false,
        });
        run_start = split;
    }
    out.push_back(SubBlock{
        .function_index = function_index,
        .start_rva      = run_start,
        .size           = static_cast<std::uint32_t>(
            fn_end_with_tail - run_start),
        .is_first       = false,
        .is_last        = false,
    });

    // Mark the first/last sub-block of this function — convenient
    // for downstream consumers that need to know which sub-block
    // owns the parent function's `BeginAddress` / `EndAddress`.
    if (first_emit < out.size()) {
        out[first_emit].is_first = true;
        out.back().is_last       = true;
    }
}

} // anonymous namespace

std::vector<SubBlock> plan_sub_blocks(const PeImage& image) {
    std::vector<SubBlock> out;
    const auto entries = collect_pdata_entries(image);
    if (entries.empty()) return out;

    out.reserve(entries.size() * 2);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& rf = entries[i];
        const std::uint32_t prev_end =
            (i > 0) ? entries[i - 1].end_address : 0;
        const std::uint32_t next_start =
            (i + 1 < entries.size()) ? entries[i + 1].begin_address : 0;
        const auto scan = scan_function(image, rf);
        emit_sub_blocks_for_function(
            image, rf, static_cast<std::uint32_t>(i),
            prev_end, next_start,
            std::span<const Rva>{scan.split_candidates.data(),
                                 scan.split_candidates.size()},
            std::span<const RelRefSpan>{scan.rel_spans.data(),
                                        scan.rel_spans.size()},
            out);
    }
    return out;
}

} // namespace mx::pe::chaos
