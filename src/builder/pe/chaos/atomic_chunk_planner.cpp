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

/// Append loose chunks of up to `chunk_size` bytes covering [start, end).
void carve_loose_chunks(
    Rva                     start,
    Rva                     end,
    std::uint32_t           chunk_size,
    std::vector<PlanChunk>& out)
{
    if (chunk_size == 0) return;
    Rva pos = start;
    while (pos < end) {
        const auto remaining = static_cast<std::uint32_t>(end - pos);
        const std::uint32_t sz = std::min(chunk_size, remaining);
        out.push_back(PlanChunk{pos, sz});
        pos = static_cast<Rva>(pos + sz);
    }
}

/// Build the chunk list for a single free range: every movable atom
/// that falls inside the range becomes one chunk; gaps between
/// atoms are carved into `chunk_size`-byte loose chunks. The
/// invariant `sum(chunks.size) == range.size` holds by construction.
[[nodiscard]] std::vector<PlanChunk> chunks_in_free_range(
    const Range&     range,
    const AtomTable& atoms,
    std::uint32_t    loose_chunk_size)
{
    std::vector<PlanChunk> chunks;
    chunks.reserve(64);

    Rva cursor = range.start;
    for (const auto& a : atoms.atoms()) {
        if (a.is_pinned()) continue;
        if (a.size == 0)   continue;
        if (a.end_rva() <= range.start) continue;
        if (a.start_rva  >= range.end()) break;

        // Skip atoms that straddle the range boundary — defence in
        // depth; `normalize()` keeps pinned ranges disjoint, so a
        // movable atom should never partially overlap a pinned one,
        // but the planner remains correct if it ever does.
        if (a.start_rva  < range.start) continue;
        if (a.end_rva()  > range.end()) continue;

        if (cursor < a.start_rva) {
            carve_loose_chunks(cursor, a.start_rva,
                               loose_chunk_size, chunks);
        }
        chunks.push_back(PlanChunk{a.start_rva, a.size});
        cursor = a.end_rva();
    }

    if (cursor < range.end()) {
        carve_loose_chunks(cursor, range.end(),
                           loose_chunk_size, chunks);
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
    std::uint32_t        loose_chunk_size,
    Randomizer&          rng,
    refmap::RvaRemapper& remapper)
{
    if (range.size == 0) return;
    auto chunks = chunks_in_free_range(range, atoms, loose_chunk_size);
    if (chunks.empty()) return;

    std::vector<std::size_t> idx(chunks.size());
    std::iota(idx.begin(), idx.end(), 0);
    shuffle_indices(idx, rng);
    emit_layout_for_range(range.start, chunks, idx, remapper);
}

} // anonymous namespace

AtomicChunkPlanner::AtomicChunkPlanner(
    std::uint32_t loose_chunk_size) noexcept
    : loose_chunk_size_(loose_chunk_size == 0
                        ? kDefaultLooseChunkSize
                        : loose_chunk_size)
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
        plan_one_free_range(fr, atoms, loose_chunk_size_,
                            rng, remapper);
    }
    (void)remapper.finalize();
    return remapper;
}

} // namespace mx::pe::chaos
