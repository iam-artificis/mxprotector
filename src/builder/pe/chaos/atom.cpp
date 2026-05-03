/**
 * @file atom.cpp
 * @brief Implementation of `AtomTable::normalize` — see header.
 */

#include "mxprotector/pe/chaos/atom.hpp"

#include <algorithm>

namespace mx::pe::chaos {

void AtomTable::normalize() {
    // Drop zero-sized atoms — they cover no bytes and only add
    // noise to the merge loop.
    std::erase_if(atoms_, [](const Atom& a) noexcept {
        return a.size == 0;
    });

    if (atoms_.size() < 2) return;

    // Stable sort so that two atoms with identical start_rva keep
    // their relative input order — the first-seen origin wins.
    std::stable_sort(atoms_.begin(), atoms_.end());

    std::size_t write = 0;
    for (std::size_t read = 1; read < atoms_.size(); ++read) {
        Atom&       last = atoms_[write];
        const Atom& cur  = atoms_[read];
        if (cur.start_rva < last.end_rva()) {
            // Overlap — extend `last` to cover the union. Origin
            // tag stays as the earlier-input atom's tag.
            const Rva merged_end = std::max(last.end_rva(), cur.end_rva());
            last.size = static_cast<std::uint32_t>(
                merged_end - last.start_rva);
        } else {
            ++write;
            atoms_[write] = cur;
        }
    }
    atoms_.resize(write + 1);
}

} // namespace mx::pe::chaos
