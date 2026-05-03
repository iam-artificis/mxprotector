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

    // Apply origin-policy alignment as a floor BEFORE merge — every
    // atom gets at least its origin's default. Doing this first lets
    // the overlap merge below see each atom's intended alignment,
    // so a pinned `tls_directory` atom that overlaps a movable
    // `instruction` correctly carries its alignment into the
    // merged result.
    for (auto& a : atoms_) {
        a.alignment = std::max(a.alignment, default_alignment_for(a.origin));
    }

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
            // tag stays as the earlier-input atom's tag. Alignment
            // is the strictest of the two inputs so a pinned atom
            // merged with a movable one stays pinned.
            const Rva merged_end = std::max(last.end_rva(), cur.end_rva());
            last.size = static_cast<std::uint32_t>(
                merged_end - last.start_rva);
            last.alignment = std::max(last.alignment, cur.alignment);
        } else {
            ++write;
            atoms_[write] = cur;
        }
    }
    atoms_.resize(write + 1);
}

} // namespace mx::pe::chaos
