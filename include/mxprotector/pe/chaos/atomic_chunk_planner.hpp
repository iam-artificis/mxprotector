/**
 * @file atomic_chunk_planner.hpp
 * @brief Planner that consumes a list of `IAtomSource`s and emits an
 *        `RvaRemapper` describing a maximally-fine-grained shuffle.
 *
 * Replaces the fixed-256B chunk planner of B.4.7. Where the old
 * planner pinned entire sections (.text, .rdata, …) and only
 * shuffled what was left, the atomic planner pins ONLY the PE
 * headers and treats every other byte as either:
 *
 *   * **An atom** — a byte range that one of the configured atom
 *     sources marked as indivisible (instruction, string, PE
 *     structure). Atoms move as units.
 *
 *   * **Loose** — a byte not claimed by any source. Loose bytes
 *     are carved into `loose_chunk_size` byte chunks (default 1
 *     for maximum granularity).
 *
 * After all sources have run, atoms are sorted, overlaps are
 * merged, and loose ranges are filled around them. The combined
 * atom + loose chunk list is shuffled (Fisher-Yates) and packed
 * back-to-back starting at the first free RVA. Total bytes
 * exactly equal the free-range size, so no padding or holes
 * appear in the unified section.
 *
 * Result: instructions interleave with data interleave with
 * strings interleave with PE-structure bytes. The shuffle is
 * deterministic given the same `Randomizer` seed.
 *
 * SOLID:
 *   * SRP — atom discovery is delegated to sources; the planner
 *     only orders + permutes.
 *   * OCP — adding a new format coverage = construct an
 *     `IAtomSource` and `add_source()` it. No planner edits.
 *
 * Threading: not safe for concurrent mutation. The chaos pipeline
 * is single-threaded by construction.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "mxprotector/pe/chaos/atom_source.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx {
class PeImage;
class Randomizer;
}

namespace mx::pe::chaos {

/**
 * @brief Atomic-level chaos chunk planner — see file header.
 */
class AtomicChunkPlanner final {
public:
    /**
     * @brief Default loose-byte chunk size (1 byte = maximum
     *        granularity). Higher values keep small runs of loose
     *        bytes together — useful when the user wants 10-50
     *        byte alternations between code and data.
     */
    static constexpr std::uint32_t kDefaultLooseChunkSize = 1;

    /**
     * @brief Construct the planner with the loose-chunk size.
     *
     * Pre-condition: `loose_chunk_size > 0`. Zero is silently
     * clamped to `kDefaultLooseChunkSize`.
     */
    explicit AtomicChunkPlanner(
        std::uint32_t loose_chunk_size = kDefaultLooseChunkSize) noexcept;

    /**
     * @brief Register an atom source. Multiple sources are aggregated
     *        in registration order; overlap resolution happens at
     *        plan time via `AtomTable::normalize`.
     */
    void add_source(std::unique_ptr<IAtomSource> source);

    /**
     * @brief Compute the shuffle plan.
     *
     * @param image  Source image — read-only. The merged section's
     *               post-shuffle RVAs are computed against
     *               `image.sections()` (which still holds the
     *               pre-merge layout when called from the chaos
     *               layout's `apply_fragment_shuffle`).
     * @param rng    Randomizer for the Fisher-Yates permutation.
     *
     * @return  An already-`finalize()`d `RvaRemapper`. An empty
     *          remapper indicates an image with no sections / no
     *          atoms / no loose bytes — all valid no-op outcomes.
     */
    [[nodiscard]] refmap::RvaRemapper plan(
        const PeImage& image,
        Randomizer&    rng) const;

private:
    std::uint32_t                              loose_chunk_size_;
    std::vector<std::unique_ptr<IAtomSource>>  sources_;
};

} // namespace mx::pe::chaos
