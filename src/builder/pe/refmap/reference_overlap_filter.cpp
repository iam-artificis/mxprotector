/**
 * @file reference_overlap_filter.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/pe/refmap/reference_overlap_filter.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace mx::pe::refmap {

namespace {

/// Half-open `[begin, end)` byte range owned by a "hard" reference.
struct ByteRange {
    Rva begin;
    Rva end;
};

/// Returns `true` when this encoding marks bytes that the patcher
/// owns *as a structured slot* — meaning the bytes are not part of
/// an x86 instruction's operand and any overlap from a `rel`
/// reference is a decoder mis-alignment.
[[nodiscard]] constexpr bool is_hard_encoding(ReferenceEncoding e) noexcept {
    switch (e) {
        case ReferenceEncoding::rel:
            return false;
        case ReferenceEncoding::rva:
        case ReferenceEncoding::absolute_va:
        case ReferenceEncoding::rel32_call_pop_anchored:
        case ReferenceEncoding::rel32_with_imm_offset:
        case ReferenceEncoding::xor_encoded_signed_delta_imm32:
            return true;
    }
    return false;
}

/// Returns `true` when this origin marks the reference as a code
/// scanner emission (i.e. produced by `CodeReferenceScanner` while
/// walking instructions). These are the only references that can be
/// "bogus" — every other origin emits via a structured walker that
/// already knows the slot's byte boundary.
[[nodiscard]] constexpr bool is_code_scanner_origin(
    ReferenceOrigin o) noexcept
{
    return o == ReferenceOrigin::code_branch_or_call
        || o == ReferenceOrigin::code_rip_relative;
}

/// Bytes-of-slot for a reference, half-open.
[[nodiscard]] constexpr ByteRange byte_range_of(const Reference& r) noexcept {
    const auto width = static_cast<std::uint32_t>(r.width);
    return ByteRange{
        .begin = r.location_rva,
        .end   = static_cast<Rva>(r.location_rva + width),
    };
}

/// Collect every hard reference's byte range, sorted by `begin`. The
/// list is the working set the soft-reference loop binary-searches
/// against.
[[nodiscard]] std::vector<ByteRange> collect_hard_ranges(
    const ReferenceTable& input)
{
    std::vector<ByteRange> ranges;
    ranges.reserve(input.size());
    for (const auto& r : input.slots()) {
        if (!is_hard_encoding(r.encoding)) continue;
        ranges.push_back(byte_range_of(r));
    }
    std::sort(ranges.begin(), ranges.end(),
        [](const ByteRange& a, const ByteRange& b) {
            return a.begin < b.begin;
        });
    return ranges;
}

/// `true` when half-open `[a.begin, a.end)` overlaps `[b.begin, b.end)`.
[[nodiscard]] constexpr bool overlaps(
    const ByteRange& a, const ByteRange& b) noexcept
{
    return a.begin < b.end && b.begin < a.end;
}

/// Binary-search the sorted hard-range list for the first entry whose
/// `end` exceeds `query.begin` — that is the only candidate that
/// could overlap `query`.
[[nodiscard]] bool any_hard_range_overlaps(
    const std::vector<ByteRange>& hard,
    const ByteRange&              query) noexcept
{
    auto it = std::lower_bound(
        hard.begin(), hard.end(), query.begin,
        [](const ByteRange& r, Rva v) {
            return r.end <= v;
        });
    if (it == hard.end()) return false;
    return overlaps(*it, query);
}

} // anonymous namespace

namespace {

/// Project every `pe::DataRegion` to a `ByteRange`. Caller merges
/// these with the hard-range list before binary-search.
[[nodiscard]] std::vector<ByteRange> project_data_regions(
    std::span<const DataRegion> regions)
{
    std::vector<ByteRange> out;
    out.reserve(regions.size());
    for (const auto& dr : regions) {
        if (dr.size == 0) continue;
        out.push_back(ByteRange{
            .begin = dr.begin_rva,
            .end   = static_cast<Rva>(dr.begin_rva + dr.size),
        });
    }
    return out;
}

/// Sort + merge two adjacent range lists into a single sorted list.
/// Used to give one binary-search input combining hard slots and
/// data regions. The two lists never overlap by construction (hard
/// slots are emitted by scanners; data regions are emitted by passes
/// that own the bytes), so a simple sort suffices.
[[nodiscard]] std::vector<ByteRange> merge_ranges(
    std::vector<ByteRange> a,
    const std::vector<ByteRange>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    std::sort(a.begin(), a.end(),
        [](const ByteRange& x, const ByteRange& y) {
            return x.begin < y.begin;
        });
    return a;
}

} // anonymous namespace

ReferenceTable ReferenceOverlapFilter::filter(
    const ReferenceTable&       input,
    std::span<const DataRegion> data_regions,
    OverlapFilterStats*         stats_out) const
{
    auto hard = collect_hard_ranges(input);
    const auto data_ranges = project_data_regions(data_regions);
    const auto all_keep_out = merge_ranges(std::move(hard), data_ranges);

    OverlapFilterStats stats{};
    ReferenceTable     output;
    output.reserve(input.size());

    for (const auto& r : input.slots()) {
        ++stats.total;

        if (is_hard_encoding(r.encoding)) {
            output.add(r);
            ++stats.hard_kept;
            continue;
        }

        if (!is_code_scanner_origin(r.origin)) {
            output.add(r);
            ++stats.soft_kept;
            continue;
        }

        // Soft reference from a code scanner. Drop when it overlaps
        // any hard slot OR any externally-registered data region.
        const auto br = byte_range_of(r);
        if (any_hard_range_overlaps(all_keep_out, br)) {
            // Distinguish data-region drops from hard-slot drops in
            // stats so callers can verify the data-region path is
            // wired up; the filtering decision is identical.
            if (any_hard_range_overlaps(data_ranges, br)) {
                ++stats.soft_dropped_in_data_region;
            } else {
                ++stats.soft_dropped;
            }
            continue;
        }

        output.add(r);
        ++stats.soft_kept;
    }

    if (stats_out != nullptr) *stats_out = stats;
    return output;
}

} // namespace mx::pe::refmap
