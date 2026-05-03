/**
 * @file atomic_chunk_planner.cpp
 * @brief Implementation — see header.
 *
 * Layout of plan():
 *   1. Compute image span [first_va, end_va) — the free range.
 *   2. Aggregate atoms from every registered source, normalize.
 *      `normalize()` applies the origin-policy alignment floor so
 *      every atom carries its correct pinned/movable classification.
 *   3. Partition atoms into pinned (alignment > 1) and movable
 *      (alignment == 1). Pinned atoms keep their original RVA — they
 *      are not added to the remapper at all.
 *   4. Compute free ranges = image span minus pinned ranges. Each
 *      free range is handled independently: walk movable atoms and
 *      gap-carved loose chunks within it, Fisher-Yates the resulting
 *      chunk list, lay it out back-to-back from the free range's
 *      start, emit one (old_rva → new_rva, size) per chunk into the
 *      remapper.
 *
 * Result: pinned PE structures (LOAD_CONFIG, IAT, TLS, …) stay at
 * their loader-readable RVAs; instructions, strings, and miscellaneous
 * data interleave freely in the bytes between them.
 */

#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <span>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

/// One entry in the chunk list — a movable atom or a loose-byte chunk.
/// Pinned atoms never enter this list.
struct PlanChunk {
    Rva           old_rva;
    std::uint32_t size;
};

/// Half-open RVA range used both for the image span and for free
/// (movable-only) sub-ranges between pinned atoms.
struct Range {
    Rva           start;
    std::uint32_t size;

    [[nodiscard]] constexpr Rva end() const noexcept {
        return static_cast<Rva>(start + size);
    }
};

/// Boundary alignment for every chunk emitted into the remapper.
/// 8-byte alignment guarantees that no naturally-aligned 64-bit
/// value is split across a chunk boundary — the most common
/// failure mode of the byte-granular shuffle.
constexpr std::uint32_t kChunkAlignment = 8;

[[nodiscard]] constexpr Rva align_down_rva(
    Rva value, std::uint32_t alignment) noexcept
{
    return static_cast<Rva>(value & ~(alignment - 1u));
}

[[nodiscard]] constexpr Rva align_up_rva(
    Rva value, std::uint32_t alignment) noexcept
{
    return static_cast<Rva>((value + alignment - 1u) & ~(alignment - 1u));
}

/// `true` when both `start` and `size` give a chunk whose
/// boundaries land on `kChunkAlignment`-multiple RVAs.
[[nodiscard]] constexpr bool atom_boundaries_aligned(
    const Atom& a) noexcept
{
    return (a.start_rva % kChunkAlignment) == 0 &&
           (a.end_rva() % kChunkAlignment) == 0;
}

[[nodiscard]] Range compute_image_span(const PeImage& image) noexcept {
    if (image.sections().empty()) return {0, 0};
    Rva first    = image.sections().front().virtual_address;
    Rva last_end = 0;
    for (const auto& sec : image.sections()) {
        first    = std::min(first, sec.virtual_address);
        last_end = std::max(last_end,
                            sec.virtual_address + sec.virtual_size);
    }
    return {first, static_cast<std::uint32_t>(last_end - first)};
}


[[nodiscard]] AtomTable collect_atoms(
    const PeImage&                                    image,
    const std::vector<std::unique_ptr<IAtomSource>>&  sources)
{
    AtomTable table;
    table.reserve(8192);
    for (const auto& src : sources) {
        if (src) src->emit_atoms(image, table);
    }
    table.normalize();
    return table;
}

/// Build the sorted list of pinned ranges from a normalised atom
/// table. Two kinds of atoms generate pin ranges:
///
///   * Atoms with `alignment > 1` (explicitly pinned by origin
///     policy): they stay at their original RVA.
///
///   * Movable atoms whose start OR end is not 8-aligned: those
///     can't be shuffled without splitting an adjacent
///     8-byte-aligned value across chunk boundaries, so we leave
///     them in place too. Importantly we add them to the pin set
///     here so the planner reserves their RVA range and no other
///     chunk ends up writing over those bytes in the unified
///     buffer.
///
/// The atom table is already disjoint-sorted by `normalize()`, so
/// pin ranges come out sorted and non-overlapping by construction.
/// Coalescing of touching pins is not needed: even if two
/// adjacent ranges touch, `compute_free_ranges` produces the same
/// free-range list either way.
[[nodiscard]] std::vector<Range> collect_pinned_ranges(
    const AtomTable& atoms,
    const Range&     span)
{
    std::vector<Range> pins;
    pins.reserve(atoms.size());
    for (const auto& a : atoms.atoms()) {
        if (a.size == 0) continue;
        if (a.start_rva < span.start || a.end_rva() > span.end()) {
            continue;
        }
        const bool pinned_by_origin = a.is_pinned();
        const bool pinned_by_alignment_mismatch =
            !a.is_pinned() && !atom_boundaries_aligned(a);
        if (!pinned_by_origin && !pinned_by_alignment_mismatch) continue;
        pins.push_back(Range{a.start_rva, a.size});
    }
    return pins;
}

/// Compute free ranges = `span` minus the union of `pins`. Pre-
/// condition: `pins` is sorted and disjoint (guaranteed by
/// `collect_pinned_ranges` post-`normalize()`).
[[nodiscard]] std::vector<Range> compute_free_ranges(
    const Range&              span,
    const std::vector<Range>& pins)
{
    std::vector<Range> frees;
    frees.reserve(pins.size() + 1);
    Rva       cursor = span.start;
    const Rva limit  = span.end();
    for (const auto& p : pins) {
        if (p.end() <= cursor) continue;
        if (p.start >= limit)  break;
        if (p.start > cursor) {
            frees.push_back(Range{
                cursor,
                static_cast<std::uint32_t>(p.start - cursor),
            });
        }
        cursor = std::max(cursor, p.end());
        if (cursor >= limit) break;
    }
    if (cursor < limit) {
        frees.push_back(Range{
            cursor,
            static_cast<std::uint32_t>(limit - cursor),
        });
    }
    return frees;
}

/// Pick the next loose-chunk size from `[min, max]`, then round
/// the result DOWN to the nearest multiple of `kChunkAlignment`
/// so the chunk boundary lands on an 8-aligned RVA.
///
/// When the rounded value would underflow (size < alignment), we
/// clamp to `kChunkAlignment` so the carver still makes progress.
[[nodiscard]] std::uint32_t pick_aligned_loose_size(
    std::uint32_t min_size,
    std::uint32_t max_size,
    Randomizer&   rng) noexcept
{
    if (min_size == 0) min_size = kChunkAlignment;
    if (max_size < min_size) max_size = min_size;
    const std::uint32_t raw = max_size <= min_size
        ? min_size
        : rng.next_range(min_size, max_size);
    std::uint32_t aligned = raw & ~(kChunkAlignment - 1u);
    if (aligned < kChunkAlignment) aligned = kChunkAlignment;
    return aligned;
}

/// Append loose chunks covering [start, end). Pre-condition: both
/// `start` and `end` are multiples of `kChunkAlignment`. Each
/// emitted chunk's size is also a multiple of `kChunkAlignment`,
/// so chunk boundaries always land on 8-aligned RVAs.
void carve_aligned_loose_chunks(
    Rva                     start,
    Rva                     end,
    std::uint32_t           min_size,
    std::uint32_t           max_size,
    Randomizer&             rng,
    std::vector<PlanChunk>& out)
{
    if (start >= end) return;
    Rva pos = start;
    while (pos < end) {
        const auto remaining = static_cast<std::uint32_t>(end - pos);
        std::uint32_t sz = pick_aligned_loose_size(min_size, max_size, rng);
        if (sz > remaining) sz = remaining;
        out.push_back(PlanChunk{pos, sz});
        pos = static_cast<Rva>(pos + sz);
    }
}

/// Build the chunk list for a single free range.
///
/// Semantics — bytes in the free range fall into one of three
/// categories:
///
///   * Movable atoms whose start AND end are `kChunkAlignment`-
///     aligned become chunks. The shuffle reorders them.
///
///   * Movable atoms whose boundaries are NOT aligned would split
///     adjacent naturally-aligned values across chunk boundaries
///     if shuffled, so they are passed through (no chunk emitted —
///     the bytes stay at their original RVA in the unified buffer).
///
///   * Bytes outside any movable atom are also passed through.
///     This is what the prior loose-chunk carving did, but the
///     carving caused a subtle bug: inter-function code (compiler
///     thunks, jump pads) is not covered by `.pdata` and lands in
///     the gap, so a 7-byte `LEA` instruction emitted there could
///     start in one function atom and end in the loose region.
///     After shuffle, the two halves no longer sat next to each
///     other and the patcher's 4-byte disp32 write spilled into
///     the wrong bytes (illegal-instruction crash). Treating gaps
///     as passthrough keeps every cross-atom instruction intact.
///
/// The invariant `sum(chunks.size) ≤ range.size` holds; the
/// difference is the union of all passthrough byte ranges.
///
/// The `min_loose` / `max_loose` parameters are accepted for
/// signature compatibility but no longer drive any carving — the
/// implementation never emits loose chunks. They will be removed
/// when the public `AtomicChunkPlanner` contract changes.
[[nodiscard]] std::vector<PlanChunk> chunks_in_free_range(
    const Range&     range,
    const AtomTable& atoms,
    std::uint32_t /*min_loose*/,
    std::uint32_t /*max_loose*/,
    Randomizer& /*rng*/)
{
    std::vector<PlanChunk> chunks;
    chunks.reserve(64);

    for (const auto& a : atoms.atoms()) {
        if (a.is_pinned()) continue;
        if (a.size == 0)   continue;
        if (a.end_rva() <= range.start) continue;
        if (a.start_rva  >= range.end()) break;
        if (a.start_rva  < range.start)  continue;
        if (a.end_rva()  > range.end())  continue;
        if (!atom_boundaries_aligned(a)) continue;
        chunks.push_back(PlanChunk{a.start_rva, a.size});
    }
    return chunks;
}

/// Fisher-Yates over `idx` in place using the project's `Randomizer`
/// so the permutation is reproducible for a given seed.
void shuffle_indices(
    std::vector<std::size_t>& idx,
    Randomizer&               rng)
{
    if (idx.size() < 2) return;
    for (std::size_t i = idx.size() - 1; i > 0; --i) {
        const std::uint32_t j = rng.next_range(
            0, static_cast<std::uint32_t>(i));
        std::swap(idx[i], idx[static_cast<std::size_t>(j)]);
    }
}

/// Lay chunks out back-to-back inside [first_va, first_va + total)
/// in the order dictated by `idx`, emitting one mapping per chunk
/// into `remapper`.
void emit_layout_for_range(
    Rva                              first_va,
    const std::vector<PlanChunk>&    chunks,
    const std::vector<std::size_t>&  idx,
    refmap::RvaRemapper&             remapper)
{
    Rva cursor = first_va;
    for (const auto i : idx) {
        const auto& c = chunks[i];
        if (c.size == 0) continue;
        remapper.add_chunk(c.old_rva, cursor, c.size);
        cursor = static_cast<Rva>(cursor + c.size);
    }
}

/// Plan one free range: build chunks → shuffle → emit. Empty ranges
/// or ranges that produce a single chunk are still walked (cheaply)
/// so the remapper sees identity mappings for the lone chunk — keeps
/// downstream code uniform.
void plan_one_free_range(
    const Range&         range,
    const AtomTable&     atoms,
    std::uint32_t        min_loose,
    std::uint32_t        max_loose,
    Randomizer&          rng,
    refmap::RvaRemapper& remapper)
{
    if (range.size == 0) return;
    auto chunks = chunks_in_free_range(
        range, atoms, min_loose, max_loose, rng);
    if (chunks.empty()) return;

    std::vector<std::size_t> idx(chunks.size());
    std::iota(idx.begin(), idx.end(), 0);
    shuffle_indices(idx, rng);
    emit_layout_for_range(range.start, chunks, idx, remapper);
}

} // anonymous namespace

AtomicChunkPlanner::AtomicChunkPlanner(
    std::uint32_t loose_chunk_size) noexcept
    : min_loose_chunk_size_(loose_chunk_size == 0
                            ? kDefaultLooseChunkSize
                            : loose_chunk_size)
    , max_loose_chunk_size_(loose_chunk_size == 0
                            ? kDefaultLooseChunkSize
                            : loose_chunk_size)
{}

AtomicChunkPlanner::AtomicChunkPlanner(
    std::uint32_t min_loose_chunk_size,
    std::uint32_t max_loose_chunk_size) noexcept
    : min_loose_chunk_size_(min_loose_chunk_size == 0
                            ? kDefaultLooseChunkSize
                            : min_loose_chunk_size)
    , max_loose_chunk_size_(max_loose_chunk_size < min_loose_chunk_size_
                            ? min_loose_chunk_size_
                            : max_loose_chunk_size)
{}

void AtomicChunkPlanner::add_source(
    std::unique_ptr<IAtomSource> source)
{
    if (source) sources_.push_back(std::move(source));
}

refmap::RvaRemapper AtomicChunkPlanner::plan(
    const PeImage& image,
    Randomizer&    rng) const
{
    refmap::RvaRemapper remapper;

    const auto span = compute_image_span(image);
    if (span.size == 0) {
        (void)remapper.finalize();
        return remapper;
    }

    const auto atoms = collect_atoms(image, sources_);
    const auto pins  = collect_pinned_ranges(atoms, span);
    const auto frees = compute_free_ranges(span, pins);

    for (const auto& fr : frees) {
        plan_one_free_range(fr, atoms,
                            min_loose_chunk_size_,
                            max_loose_chunk_size_,
                            rng, remapper);
    }
    (void)remapper.finalize();
    return remapper;
}

} // namespace mx::pe::chaos
