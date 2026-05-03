/**
 * @file chaos_shuffler.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/chaos_shuffler.hpp"

#include <algorithm>
#include <cstring>

namespace mx::pe::chaos {

namespace {

/// Test whether `[chunk_old, chunk_old + size)` and the equally-
/// sized `[chunk_new, chunk_new + size)` both fit inside the
/// buffer's `[base_rva, base_rva + buffer_size)` span.
[[nodiscard]] bool chunk_in_buffer(
    Rva           chunk_rva,
    std::uint32_t size,
    Rva           base_rva,
    std::size_t   buffer_size) noexcept
{
    if (chunk_rva < base_rva) return false;
    const auto offset = static_cast<std::uint64_t>(chunk_rva - base_rva);
    return offset + size <= buffer_size;
}

} // anonymous namespace

void apply_chunk_shuffle(
    ByteBuffer&             buffer,
    Rva                     base_rva,
    const refmap::RvaRemapper& remapper)
{
    if (remapper.chunk_count() == 0) return;

    // Snapshot the input — the loop reads `original` and writes
    // `buffer`. Two chunks may have crossing source/dest spans
    // (Y is some chunk's old, also another chunk's new); writing
    // through a snapshot avoids the order-dependent overwrite
    // hazard a fully in-place shuffle would have.
    const ByteBuffer original = buffer;

    // Walk the remapper's chunks via repeated `remap` queries on
    // each old position the user registered. The remapper does not
    // expose its internal vector, so we re-derive `(old, new, size)`
    // by scanning the buffer in `chunk_size` strides — but we don't
    // know `chunk_size` either. Instead, use the fact that
    // `remap(old) != old` for every registered chunk's first byte
    // and `remap(old + offset)` is contiguous for `offset < size`.
    //
    // Rather than reverse-engineer chunks, take advantage of the
    // remapper's `is_remapped(rva)` predicate: walk the buffer
    // byte-by-byte; for each byte that is registered, look up its
    // `remap()` and write the original byte to the new offset.
    //
    // This is `O(buffer.size())` — same cost as the snapshot copy
    // above, no extra allocation.
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        const Rva old_rva = static_cast<Rva>(base_rva + i);
        if (!remapper.is_remapped(old_rva)) continue;

        const Rva new_rva = remapper.remap(old_rva);
        // Defensive: skip chunks that escape the buffer.
        if (!chunk_in_buffer(new_rva, /*size=*/1,
                             base_rva, buffer.size())) {
            continue;
        }
        const auto new_off = static_cast<std::size_t>(new_rva - base_rva);
        buffer[new_off] = original[i];
    }
}

} // namespace mx::pe::chaos
