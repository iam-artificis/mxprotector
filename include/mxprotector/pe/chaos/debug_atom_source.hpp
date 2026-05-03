/**
 * @file debug_atom_source.hpp
 * @brief Atom source for the DEBUG directory.
 *
 * The DEBUG directory is an array of fixed-size 28-byte
 * `IMAGE_DEBUG_DIRECTORY` entries. Each entry stays as a single
 * atom; the directory itself is just a contiguous run of entries
 * (we emit one big atom covering the whole array, since the
 * loader reads them as a unit).
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class DebugAtomSource final : public IAtomSource {
public:
    DebugAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
