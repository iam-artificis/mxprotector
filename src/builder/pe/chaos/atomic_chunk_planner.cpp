/**
 * @file atomic_chunk_planner.cpp
 * @brief Implementation — see header.
 *
 * Layout of plan():
 *   1. Compute image span [first_va, end_va) — the free range.
 *   2. Aggregate atoms from every registered source, normalize.
 *   3. Walk atoms in RVA order; for every gap between cursor and
 *      next atom, carve into loose chunks of `loose_chunk_size_`.
 *   4. Combine atoms + loose chunks into one chunk list.
 *   5. Fisher-Yates the indices; lay out back-to-back starting at
 *      first_va; emit one (old_rva → new_rva, size) per chunk.
 */

#include "mxprotector/pe/chaos/atomic_chunk_planner.hpp"

#include <algorithm>
#include <cstdint>
#include <numeric>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

/// One entry in the chunk list — an atom or a loose-byte chunk.
struct PlanChunk {
    Rva           old_rva;
    std::uint32_t size;
};

/// Compute the unified-section's free RVA range:
/// `[min(va), max(va + virtual_size))` across all sections.
struct ImageSpan {
    Rva           first_va;
    std::uint32_t size;
};

[[nodiscard]] ImageSpan compute_image_span(const PeImage& image) noexcept {
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

/// Aggregate atoms from every registered source and normalise.
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

/// Append a loose-byte chunk of up to `chunk_size` bytes covering
/// the range `[start, end)`. Splits into multiple chunks when
/// `(end - start) > chunk_size`.
void carve_loose_chunks(
    Rva                    start,
    Rva                    end,
    std::uint32_t          chunk_size,
    std::vector<PlanChunk>& out)
{
    Rva pos = start;
    while (pos < end) {
        const auto remaining = static_cast<std::uint32_t>(end - pos);
        const std::uint32_t sz = std::min(chunk_size, remaining);
        out.push_back(PlanChunk{pos, sz});
        pos = static_cast<Rva>(pos + sz);
    }
}

/// Walk the normalised atom table in RVA order and produce the
/// final chunk list (atoms + loose). Atoms outside the free range
/// are skipped; loose bytes around in-range atoms are carved.
[[nodiscard]] std::vector<PlanChunk> build_chunk_list(
    const ImageSpan& span,
    const AtomTable& atoms,
    std::uint32_t    loose_chunk_size)
{
    std::vector<PlanChunk> chunks;
    chunks.reserve(atoms.size() * 2 + 1024);

    const Rva range_end = static_cast<Rva>(span.first_va + span.size);
    Rva cursor = span.first_va;

    for (const auto& atom : atoms.atoms()) {
        if (atom.size == 0) continue;
        if (atom.start_rva < cursor)             continue;  // out of range or overlapping
        if (atom.end_rva() > range_end)          continue;  // extends past free range

        // Loose bytes between cursor and the atom.
        if (cursor < atom.start_rva) {
            carve_loose_chunks(cursor, atom.start_rva,
                               loose_chunk_size, chunks);
        }
        // The atom itself.
        chunks.push_back(PlanChunk{atom.start_rva, atom.size});
        cursor = atom.end_rva();
    }

    // Trailing loose bytes after the last atom.
    if (cursor < range_end) {
        carve_loose_chunks(cursor, range_end,
                           loose_chunk_size, chunks);
    }
    return chunks;
}

/// Fisher-Yates over a vector of indices `0..n-1` in place.
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

/// Lay chunks out back-to-back starting at `first_va` in the order
/// dictated by `idx`, emitting one mapping per chunk into
/// `remapper`. Returns the total bytes laid out — should equal
/// `span.size`.
[[nodiscard]] std::uint64_t emit_layout(
    const std::vector<PlanChunk>&   chunks,
    const std::vector<std::size_t>& idx,
    Rva                             first_va,
    refmap::RvaRemapper&            remapper)
{
    Rva           cursor = first_va;
    std::uint64_t total  = 0;
    for (const auto i : idx) {
        const auto& c = chunks[i];
        if (c.size == 0) continue;
        remapper.add_chunk(c.old_rva, cursor, c.size);
        cursor = static_cast<Rva>(cursor + c.size);
        total += c.size;
    }
    return total;
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
    auto chunks = build_chunk_list(span, atoms, loose_chunk_size_);

    if (chunks.empty()) {
        (void)remapper.finalize();
        return remapper;
    }

    std::vector<std::size_t> idx(chunks.size());
    std::iota(idx.begin(), idx.end(), 0);
    shuffle_indices(idx, rng);

    [[maybe_unused]] const auto bytes_laid =
        emit_layout(chunks, idx, span.first_va, remapper);
    (void)remapper.finalize();
    return remapper;
}

} // namespace mx::pe::chaos
