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
/// table. Atoms with `alignment > 1` are pinned; the planner never
/// moves them. `normalize()` already disjoint-sorted the table, so
/// pinned ranges come out sorted and non-overlapping by construction.
[[nodiscard]] std::vector<Range> collect_pinned_ranges(
    const AtomTable& atoms,
    const Range&     span)
{
    std::vector<Range> pins;
    pins.reserve(atoms.size());
    for (const auto& a : atoms.atoms()) {
        if (!a.is_pinned()) continue;
        if (a.size == 0)    continue;
        // Drop atoms whose range falls (even partially) outside the
        // image span — they cannot anchor anything inside the layout.
        if (a.start_rva < span.start || a.end_rva() > span.end()) {
            continue;
        }
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

/// `true` when both `start` and `size` give a chunk whose
/// boundaries land on `kChunkAlignment`-multiple RVAs.
[[nodiscard]] constexpr bool atom_boundaries_aligned(
    const Atom& a) noexcept
{
    return (a.start_rva % kChunkAlignment) == 0 &&
           (a.end_rva() % kChunkAlignment) == 0;
}

/// Build the chunk list for a single free range under alignment-
/// aware semantics:
///
///   * Bytes in `[range.start, aligned_inner_start)` and
///     `[aligned_inner_end, range.end)` are passthrough — they
///     stay at their original RVA in the unified buffer because
///     no `add_chunk` call lands them in the remapper.
///
///   * Inside `[aligned_inner_start, aligned_inner_end)`, every
///     movable atom whose start AND end are 8-aligned becomes one
///     chunk. Movable atoms with non-aligned boundaries are
///     skipped (their bytes stay at original RVA — passthrough).
///
///   * Gaps between aligned movable atoms (and the inner range
///     ends) are carved into 8-aligned loose chunks via
///     `carve_aligned_loose_chunks`.
///
/// The invariant `sum(chunks.size) ≤ aligned_inner_end -
/// aligned_inner_start` holds; the difference is exactly the
/// passthrough bytes of skipped non-aligned atoms.
[[nodiscard]] std::vector<PlanChunk> chunks_in_free_range(
    const Range&     range,
    const AtomTable& atoms,
    std::uint32_t    min_loose,
    std::uint32_t    max_loose,
    Randomizer&      rng)
{
    std::vector<PlanChunk> chunks;
    chunks.reserve(64);

    const Rva inner_start = align_up_rva(range.start, kChunkAlignment);
    const Rva inner_end   = align_down_rva(range.end(), kChunkAlignment);
    if (inner_start >= inner_end) return chunks;

    Rva cursor = inner_start;
    for (const auto& a : atoms.atoms()) {
        if (a.is_pinned()) continue;
        if (a.size == 0)   continue;
        if (a.end_rva() <= inner_start) continue;
        if (a.start_rva  >= inner_end)  break;
        if (a.start_rva  < inner_start) continue;
        if (a.end_rva()  > inner_end)   continue;

        if (!atom_boundaries_aligned(a)) {
            // Atom can't become a chunk without splitting an
            // adjacent 8-aligned value. Carve loose up to the
            // 8-aligned RVA below the atom, then jump cursor past
            // the atom + any trailing unaligned bytes so the next
            // chunk boundary lands on 8-aligned again. Atom bytes
            // remain at their original RVA via passthrough.
            const Rva carve_end = align_down_rva(a.start_rva,
                                                 kChunkAlignment);
            if (cursor < carve_end) {
                carve_aligned_loose_chunks(
                    cursor, carve_end, min_loose, max_loose, rng,
                    chunks);
            }
            cursor = align_up_rva(a.end_rva(), kChunkAlignment);
            if (cursor > inner_end) cursor = inner_end;
            continue;
        }

        if (cursor < a.start_rva) {
            carve_aligned_loose_chunks(
                cursor, a.start_rva, min_loose, max_loose, rng,
                chunks);
        }
        chunks.push_back(PlanChunk{a.start_rva, a.size});
        cursor = a.end_rva();
    }

    if (cursor < inner_end) {
        carve_aligned_loose_chunks(
            cursor, inner_end, min_loose, max_loose, rng, chunks);
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
