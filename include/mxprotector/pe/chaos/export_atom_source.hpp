/**
 * @file export_atom_source.hpp
 * @brief Atom source for the EXPORT directory and its three lookup
 *        tables (functions / names / ordinals).
 *
 * Atoms emitted:
 *   * `export_directory`       — `IMAGE_EXPORT_DIRECTORY` (40 B).
 *   * `export_address_table`   — `NumberOfFunctions` × 4-byte RVAs.
 *   * `export_name_table`      — `NumberOfNames` × 4-byte RVAs.
 *   * `export_ordinal_table`   — `NumberOfNames` × 2-byte ordinals.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class ExportAtomSource final : public IAtomSource {
public:
    ExportAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
