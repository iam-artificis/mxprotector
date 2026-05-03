/**
 * @file rva_remapper.hpp
 * @brief Chunk-aware RVA translator — general-purpose.
 *
 * Any transform that moves byte ranges (chunks) from one RVA to
 * another inside the image needs to update every `Reference` whose
 * target falls inside a moved chunk. `RvaRemapper` is the data
 * structure that answers `old_rva → new_rva` for the patcher.
 * First consumers: the chaos fragment interleaver (Feature B.4),
 * with future mutation-overflow and instruction-insertion transforms
 * lined up to share the same machinery.
 *
 * Contract:
 *
 *   * Chunks are non-overlapping ranges `[old_rva, old_rva + size)`
 *     mapping to `[new_rva, new_rva + size)`. Chunk size is
 *     preserved by the move; offsets within a chunk shift uniformly.
 *   * Insertion order does not matter; `finalize()` sorts by
 *     `old_rva` and enables binary-search lookup.
 *   * `remap(rva)` returns the translated RVA when `rva` is inside
 *     a registered chunk, else returns `rva` unchanged. PINNED
 *     bytes (PE headers, directory contents, …) are simply not
 *     registered as chunks — the remapper passes them through.
 *
 * Threading: not safe for concurrent mutation. Reads after
 * `finalize()` are safe across threads.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::pe::refmap {

/**
 * @brief Single chunk record — see `RvaRemapper`.
 */
struct RvaChunk {
    Rva           old_rva;
    Rva           new_rva;
    std::uint32_t size;

    [[nodiscard]] constexpr bool operator==(const RvaChunk&) const noexcept = default;
};

/**
 * @brief Chunk-aware RVA translator — see file header.
 */
class RvaRemapper {
public:
    /**
     * @brief Register a chunk's old → new RVA mapping.
     *
     * Pre-condition: the registered chunks must not overlap each
     * other's old RVA range. Violations are detected lazily by
     * `finalize()` and reported via the return code.
     *
     * Insertion order is irrelevant — `finalize()` sorts before
     * lookups begin. `add()` is `O(1)` amortised.
     */
    void add_chunk(Rva old_rva, Rva new_rva, std::uint32_t size);

    /**
     * @brief Sort the chunks by `old_rva` so `remap()` can binary-
     *        search. Must be called once before the first
     *        `remap()` / `is_remapped()` query.
     *
     * @return `false` if any two registered chunks overlap each
     *         other's old RVA range — caller should treat as a
     *         programmer error and abort.
     */
    [[nodiscard]] bool finalize() noexcept;

    /**
     * @brief Translate `rva` through the registered chunks.
     *
     * Pre-condition: `finalize()` was called and returned `true`.
     * Calling without finalising returns `rva` unchanged (a
     * defensive default — production code must finalise first).
     *
     * Behaviour:
     *
     *   * `rva` inside a registered chunk → returns
     *     `chunk.new_rva + (rva - chunk.old_rva)`.
     *   * `rva` outside every chunk → returns `rva` unchanged
     *     (PINNED region — caller passes through).
     */
    [[nodiscard]] Rva remap(Rva rva) const noexcept;

    /// `true` when the supplied RVA falls inside one of the
    /// registered chunks.
    [[nodiscard]] bool is_remapped(Rva rva) const noexcept;

    /// Number of registered chunks. Useful for tests / logs.
    [[nodiscard]] std::size_t chunk_count() const noexcept {
        return chunks_.size();
    }

    /// Total bytes across every registered chunk.
    [[nodiscard]] std::uint64_t total_bytes() const noexcept;

private:
    std::vector<RvaChunk> chunks_;
    bool                  finalized_ = false;

    /// Find the chunk that holds `rva` (if any). Returns nullptr if
    /// `rva` is outside every chunk or `finalize()` has not been
    /// called.
    [[nodiscard]] const RvaChunk* find_chunk_for(Rva rva) const noexcept;
};

} // namespace mx::pe::refmap
