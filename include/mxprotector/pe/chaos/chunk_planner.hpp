/**
 * @file chunk_planner.hpp
 * @brief Chaos-specific planner that decides which RVA ranges can be
 *        safely shuffled and computes the new positions for each.
 *
 * The chaos shuffler moves byte chunks inside the unified merged
 * section. A subset of bytes cannot move:
 *
 *   * **PE headers** `[0, SizeOfHeaders)` — the loader reads them at
 *     fixed RVAs. Moving them breaks parsing.
 *
 *   * **Every code section** — instructions can span byte boundaries,
 *     so a coarse chunk move would cleave an instruction in half.
 *     This MVP pins all code; future iterations can add
 *     instruction-aligned chunking via the disassembler.
 *
 *   * **Every non-empty DataDirectory entry's body** — the loader
 *     parses `IMAGE_IMPORT_DESCRIPTOR` arrays, export tables,
 *     resource trees, etc. *as data structures*. Internal RVAs
 *     within those bodies (FirstThunk → IAT, AddressOfFunctions →
 *     export-RVA-array, …) are not in our scanners' coverage, so
 *     pinning the whole body keeps internal RVAs valid by
 *     construction.
 *
 * Free ranges are everything else — typically the parts of `.rdata`
 * / `.data` that hold compiler-generated constants, scratch data,
 * vtables. Each free range is split into `chunk_size`-byte chunks;
 * any trailing remainder smaller than `chunk_size` stays pinned.
 * The chunks are then assigned to a Fisher–Yates-shuffled
 * permutation of the same set of RVA positions, and an
 * `RvaRemapper` is built describing the moves.
 *
 * The planner does NOT touch image bytes. It only describes the
 * intended shuffle. The patcher (B.4.6) and the orchestrator
 * (B.4.7) consume the remapper and rewrite the actual bytes +
 * references.
 */

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx {
class PeImage;
class Randomizer;
}

namespace mx::pe::chaos {

/**
 * @brief Half-open RVA range `[start, start + size)`.
 */
struct PinnedRange {
    Rva           start;
    std::uint32_t size;

    [[nodiscard]] constexpr Rva end() const noexcept {
        return static_cast<Rva>(start + size);
    }

    [[nodiscard]] constexpr bool operator==(const PinnedRange&) const noexcept = default;
};

/**
 * @brief Chaos chunk planner — see file header.
 *
 * Stateless aside from the configured `chunk_size`. Construct on
 * the stack, call `plan`, throw away.
 */
class ChunkPlanner final {
public:
    /// Default chunk size — large enough to keep the remapper count
    /// manageable, small enough for visible interleaving.
    static constexpr std::uint32_t kDefaultChunkSize = 256;

    /**
     * @brief Configure the chunk size for the next `plan` call.
     *
     * Pre-condition: `chunk_size > 0`. Sizes that are zero are
     * silently clamped to `kDefaultChunkSize`.
     */
    explicit ChunkPlanner(std::uint32_t chunk_size = kDefaultChunkSize) noexcept;

    /**
     * @brief Compute the pinned ranges for `image`.
     *
     * Test seam — `plan` consumes the same data internally. Exposed
     * publicly so callers can inspect the pin set without running
     * the shuffle.
     *
     * Returns disjoint, sorted `PinnedRange`s covering:
     *   * `[0, SizeOfHeaders)` — PE headers.
     *   * Every code section's `[va, va + virtual_size)`.
     *   * Every non-empty `DataDirectory[i]` body.
     */
    [[nodiscard]] std::vector<PinnedRange> compute_pinned_ranges(
        const PeImage& image) const;

    /**
     * @brief Plan the shuffle: identify free ranges, split into
     *        chunks, generate a random permutation, populate an
     *        `RvaRemapper`.
     *
     * The returned remapper is already `finalize()`d. An empty
     * remapper indicates either zero free space or a pinned set
     * that already fills the image — both are valid no-op outcomes.
     *
     * @param image       Source image. Read-only.
     * @param rng         Source of randomness for the permutation.
     * @param extra_pins  Additional pin ranges from external sources
     *                    (e.g. LOAD_CONFIG target sections). Coalesced
     *                    with the planner's standard pins via
     *                    `merge_overlapping`. Empty by default.
     */
    [[nodiscard]] refmap::RvaRemapper plan(
        const PeImage&                image,
        Randomizer&                   rng,
        std::span<const PinnedRange>  extra_pins = {}) const;

private:
    std::uint32_t chunk_size_;
};

} // namespace mx::pe::chaos
