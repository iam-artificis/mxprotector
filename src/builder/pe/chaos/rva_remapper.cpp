/**
 * @file rva_remapper.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/rva_remapper.hpp"

#include <algorithm>

namespace mx::pe::chaos {

namespace {

/// Two chunks `a` and `b` overlap if neither ends strictly before
/// the other starts. Ranges are half-open `[old_rva, old_rva + size)`.
[[nodiscard]] bool ranges_overlap(const RvaChunk& a, const RvaChunk& b) noexcept {
    const auto a_end = static_cast<std::uint64_t>(a.old_rva) + a.size;
    const auto b_end = static_cast<std::uint64_t>(b.old_rva) + b.size;
    return !(a_end <= b.old_rva || b_end <= a.old_rva);
}

} // anonymous namespace

void RvaRemapper::add_chunk(Rva old_rva, Rva new_rva, std::uint32_t size) {
    chunks_.push_back(RvaChunk{
        .old_rva = old_rva,
        .new_rva = new_rva,
        .size    = size,
    });
    finalized_ = false;
}

bool RvaRemapper::finalize() noexcept {
    std::sort(chunks_.begin(), chunks_.end(),
              [](const RvaChunk& a, const RvaChunk& b) noexcept {
                  return a.old_rva < b.old_rva;
              });

    for (std::size_t i = 1; i < chunks_.size(); ++i) {
        if (ranges_overlap(chunks_[i - 1], chunks_[i])) {
            finalized_ = false;
            return false;
        }
    }

    finalized_ = true;
    return true;
}

const RvaChunk* RvaRemapper::find_chunk_for(Rva rva) const noexcept {
    if (!finalized_) return nullptr;
    if (chunks_.empty()) return nullptr;

    // Binary search for the largest old_rva ≤ rva.
    auto it = std::upper_bound(
        chunks_.begin(), chunks_.end(), rva,
        [](Rva needle, const RvaChunk& c) noexcept {
            return needle < c.old_rva;
        });
    if (it == chunks_.begin()) return nullptr;
    --it;

    if (rva < it->old_rva || rva >= it->old_rva + it->size) {
        return nullptr;
    }
    return &*it;
}

Rva RvaRemapper::remap(Rva rva) const noexcept {
    const auto* chunk = find_chunk_for(rva);
    if (chunk == nullptr) return rva;
    const auto offset = rva - chunk->old_rva;
    return static_cast<Rva>(chunk->new_rva + offset);
}

bool RvaRemapper::is_remapped(Rva rva) const noexcept {
    return find_chunk_for(rva) != nullptr;
}

std::uint64_t RvaRemapper::total_bytes() const noexcept {
    std::uint64_t total = 0;
    for (const auto& c : chunks_) {
        total += c.size;
    }
    return total;
}

} // namespace mx::pe::chaos
