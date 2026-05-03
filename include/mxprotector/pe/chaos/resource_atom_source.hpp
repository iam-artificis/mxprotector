/**
 * @file resource_atom_source.hpp
 * @brief Atom source for the RESOURCE directory tree.
 *
 * Two atom kinds:
 *
 *   * `resource_directory_node` — each `IMAGE_RESOURCE_DIRECTORY`
 *     header (16 B) + its `NumberOfNamedEntries +
 *     NumberOfIdEntries` entries (8 B each) emitted as one atom.
 *     The runtime walks the entries inline immediately after the
 *     header, so they must travel together.
 *
 *   * `resource_data_entry` — each leaf `IMAGE_RESOURCE_DATA_ENTRY`
 *     (16 B) emitted as one atom.
 *
 * Recursion is bounded at depth 8 to defend against malformed
 * cycles (PE practice rarely goes past 3 levels).
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class ResourceAtomSource final : public IAtomSource {
public:
    ResourceAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
