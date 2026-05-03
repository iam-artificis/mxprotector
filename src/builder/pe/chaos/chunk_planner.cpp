/**
 * @file chunk_planner.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/chunk_planner.hpp"

#include <algorithm>
#include <variant>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

namespace {

/// Append a non-empty pinned range to `out`. Empty ranges are
/// dropped to keep the post-merge set small.
void append_pin(std::vector<PinnedRange>& out, Rva start, std::uint32_t size) {
    if (size == 0) return;
    out.push_back(PinnedRange{start, size});
}

/// Coalesce overlapping or adjacent ranges into a sorted, disjoint
/// set. Modifies `ranges` in place.
void merge_overlapping(std::vector<PinnedRange>& ranges) {
    if (ranges.empty()) return;
    std::sort(ranges.begin(), ranges.end(),
              [](const PinnedRange& a, const PinnedRange& b) noexcept {
                  return a.start < b.start;
              });

    std::size_t write = 0;
    for (std::size_t read = 1; read < ranges.size(); ++read) {
        auto& last = ranges[write];
        const auto& cur = ranges[read];
        if (cur.start <= last.end()) {
            const Rva merged_end = std::max(last.end(), cur.end());
            last.size = merged_end - last.start;
        } else {
            ++write;
            ranges[write] = cur;
        }
    }
    ranges.resize(write + 1);
}

/// Compute the SizeOfHeaders for the image's PE32+ optional header.
[[nodiscard]] std::uint32_t size_of_headers(const PeImage& image) noexcept {
    std::uint32_t result = 0;
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            result = nt.OptionalHeader.SizeOfHeaders;
        } else if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS32>) {
            result = nt.OptionalHeader.SizeOfHeaders;
        }
    }, image.nt_headers());
    return result;
}

/// Append the **whole section** that contains each non-empty
/// DataDirectory entry. Pinning only `[VirtualAddress, VirtualAddress
/// + Size)` is too narrow: most directories carry pointers *out* of
/// their immediate body to siblings in the same section (e.g.
/// `IMAGE_IMPORT_DESCRIPTOR.Name` → DLL-name string elsewhere in
/// `.rdata`; `OriginalFirstThunk` → IAT entries; `IMAGE_IMPORT_BY_
/// NAME` records — all in `.rdata`). Tracking those internal RVAs
/// requires per-directory deep scanners (B.4.8 follow-up). Until
/// those land, the safe pin granularity is the whole section.
void append_data_directory_pins(
    const PeImage&            image,
    std::vector<PinnedRange>& out)
{
    std::visit([&](const auto& nt) {
        using NT = std::decay_t<decltype(nt)>;
        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            const std::uint32_t limit = std::min(
                nt.OptionalHeader.NumberOfRvaAndSizes,
                pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
            for (std::uint32_t i = 0; i < limit; ++i) {
                const auto& dir = nt.OptionalHeader.DataDirectory[i];
                if (dir.VirtualAddress == 0) continue;
                const auto* sec = image.section_by_rva(dir.VirtualAddress);
                if (sec != nullptr) {
                    append_pin(out, sec->virtual_address, sec->virtual_size);
                } else {
                    // Directory points outside any section — pin its
                    // own body as a defensive minimum.
                    append_pin(out, dir.VirtualAddress, dir.Size);
                }
            }
        }
    }, image.nt_headers());
}

/// Append every code section's body range to `out`.
void append_code_section_pins(
    const PeImage&            image,
    std::vector<PinnedRange>& out)
{
    for (const auto& sec : image.sections()) {
        if (!sec.is_code()) continue;
        if (sec.virtual_size == 0) continue;
        append_pin(out, sec.virtual_address, sec.virtual_size);
    }
}

/// Compute the [first_section.va, last_section.va + virtual_size)
/// span the planner shuffles within. Returns `{0, 0}` for an image
/// with no sections.
struct ImageSpan {
    Rva           first_va;
    std::uint32_t size;
};

[[nodiscard]] ImageSpan compute_image_span(const PeImage& image) noexcept {
    if (image.sections().empty()) return {0, 0};
    Rva first = image.sections().front().virtual_address;
    Rva last_end = 0;
    for (const auto& sec : image.sections()) {
        first    = std::min(first, sec.virtual_address);
        last_end = std::max(last_end,
                            sec.virtual_address + sec.virtual_size);
    }
    return {first, static_cast<std::uint32_t>(last_end - first)};
}

/// Compute free ranges = `image_span` minus the union of `pinned`.
/// Pre-condition: `pinned` is sorted and disjoint.
[[nodiscard]] std::vector<PinnedRange> compute_free_ranges(
    const ImageSpan&                span,
    const std::vector<PinnedRange>& pinned)
{
    std::vector<PinnedRange> free_ranges;
    Rva cursor = span.first_va;
    const Rva span_end = static_cast<Rva>(span.first_va + span.size);
    for (const auto& p : pinned) {
        if (p.end() <= cursor) continue; // entirely before cursor
        if (p.start >= span_end) break;  // beyond span
        if (p.start > cursor) {
            free_ranges.push_back(PinnedRange{
                cursor,
                static_cast<std::uint32_t>(p.start - cursor),
            });
        }
        cursor = std::max(cursor, p.end());
        if (cursor >= span_end) break;
    }
    if (cursor < span_end) {
        free_ranges.push_back(PinnedRange{
            cursor,
            static_cast<std::uint32_t>(span_end - cursor),
        });
    }
    return free_ranges;
}

/// Carve `range` into fixed `chunk_size` pieces. Trailing remainder
/// smaller than `chunk_size` is dropped (stays effectively pinned —
/// it never enters the remapper).
void carve_chunks(
    const PinnedRange&        range,
    std::uint32_t             chunk_size,
    std::vector<PinnedRange>& chunks)
{
    if (chunk_size == 0) return;
    Rva pos = range.start;
    while (pos + chunk_size <= range.end()) {
        chunks.push_back(PinnedRange{pos, chunk_size});
        pos += chunk_size;
    }
}

} // anonymous namespace

ChunkPlanner::ChunkPlanner(std::uint32_t chunk_size) noexcept
    : chunk_size_(chunk_size == 0 ? kDefaultChunkSize : chunk_size)
{}

std::vector<PinnedRange> ChunkPlanner::compute_pinned_ranges(
    const PeImage& image) const
{
    std::vector<PinnedRange> ranges;

    // 1. Headers.
    append_pin(ranges, /*start=*/0, size_of_headers(image));

    // 2. Code sections.
    append_code_section_pins(image, ranges);

    // 3. DataDirectory bodies.
    append_data_directory_pins(image, ranges);

    merge_overlapping(ranges);
    return ranges;
}

refmap::RvaRemapper ChunkPlanner::plan(
    const PeImage&               image,
    Randomizer&                  rng,
    std::span<const PinnedRange> extra_pins) const
{
    refmap::RvaRemapper remapper;

    const auto img_span = compute_image_span(image);
    if (img_span.size == 0) {
        (void)remapper.finalize();
        return remapper;
    }

    auto pinned = compute_pinned_ranges(image);
    if (!extra_pins.empty()) {
        pinned.insert(pinned.end(),
                      extra_pins.begin(), extra_pins.end());
        merge_overlapping(pinned);
    }
    const auto frees = compute_free_ranges(img_span, pinned);

    // Carve chunks across all free ranges.
    std::vector<PinnedRange> chunks;
    for (const auto& fr : frees) {
        carve_chunks(fr, chunk_size_, chunks);
    }

    if (chunks.empty()) {
        (void)remapper.finalize();
        return remapper;
    }

    // Permute the slot positions among themselves.
    std::vector<Rva> slots;
    slots.reserve(chunks.size());
    for (const auto& c : chunks) slots.push_back(c.start);

    // Fisher–Yates over the slot vector via the project's
    // `Randomizer::next_range` so the permutation is reproducible
    // for a given seed.
    for (std::size_t i = slots.size() - 1; i > 0; --i) {
        const std::uint32_t j = rng.next_range(0, static_cast<std::uint32_t>(i));
        std::swap(slots[i], slots[j]);
    }

    // Emit one remapper chunk per (old, new) pair.
    for (std::size_t i = 0; i < chunks.size(); ++i) {
        remapper.add_chunk(chunks[i].start, slots[i], chunk_size_);
    }
    (void)remapper.finalize();
    return remapper;
}

} // namespace mx::pe::chaos
