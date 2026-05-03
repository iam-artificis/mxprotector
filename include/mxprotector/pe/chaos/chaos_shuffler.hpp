/**
 * @file chaos_shuffler.hpp
 * @brief Applies an `RvaRemapper` to a byte buffer — moves chunks
 *        from their old positions to their new positions, leaving
 *        bytes outside any chunk untouched.
 *
 * Mechanically: the shuffler takes a copy of the input buffer and
 * writes every chunk's *original* bytes to its *new* offset. Bytes
 * at positions not covered by any registered chunk are read from
 * the copy and never re-written, so PINNED ranges (PE headers,
 * DataDirectory bodies, code sections — anything the chunk planner
 * deliberately did not move) appear at their original offsets in
 * the output buffer.
 *
 * Why a separate file: keeps `chaos_layout.cpp` focused on the
 * top-level finalize orchestration. The shuffler is the bulk-byte
 * mover; the patcher (B.4.6) is the bulk-reference rewriter; and
 * the planner (B.4.5) decides what moves where. Each fits cleanly
 * under its own SRP.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx::pe::chaos {

/**
 * @brief Apply a chunk shuffle to `buffer` whose first byte sits at
 *        `base_rva`.
 *
 * Pre-conditions:
 *
 *   * `remapper.finalize()` has succeeded — chunks are non-overlapping.
 *   * Every chunk's `old_rva` and `new_rva` (and full `size`) lie
 *     inside `[base_rva, base_rva + buffer.size())`. Out-of-range
 *     chunks are silently skipped (a malformed remapper does not
 *     corrupt the buffer).
 *
 * Side effects: `buffer` is mutated in place.
 *
 * Cost: `O(buffer.size() + sum(chunk.size))` — one buffer copy plus
 * one memcpy per chunk.
 */
void apply_chunk_shuffle(
    ByteBuffer&             buffer,
    Rva                     base_rva,
    const refmap::RvaRemapper& remapper);

} // namespace mx::pe::chaos
