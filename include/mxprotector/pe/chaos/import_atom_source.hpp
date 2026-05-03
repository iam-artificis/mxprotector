/**
 * @file import_atom_source.hpp
 * @brief Atom source that walks `IMAGE_DIRECTORY_ENTRY_IMPORT` and
 *        emits one atom per IMAGE_IMPORT_DESCRIPTOR, per thunk, and
 *        per IMAGE_IMPORT_BY_NAME record.
 *
 * Three atom kinds:
 *
 *   * `import_descriptor` — 20-byte `IMAGE_IMPORT_DESCRIPTOR`
 *     records (including the all-zero terminator at the end of
 *     the array, which the loader looks for as the sentinel).
 *
 *   * `import_thunk` — each 8-byte `IMAGE_THUNK_DATA64` slot in
 *     INT (`OriginalFirstThunk`) and IAT (`FirstThunk`) thunk
 *     arrays, plus the trailing zero terminator.
 *
 *   * `import_by_name` — each `IMAGE_IMPORT_BY_NAME` record
 *     (`Hint`<2B> + `Name`<ASCIIZ>). Variable size = 2 + strlen +
 *     1. Pinning the whole record together is required because
 *     the `AsciiStringAtomSource` would only catch the Name part,
 *     leaving the Hint orphaned.
 *
 * Atoms cover the same bytes the IMPORT scanner (refmap) emits
 * references for, but with a different concern: the scanner
 * tells the patcher *what to rewrite*, this source tells the
 * planner *what must move together*.
 *
 * Threading: stateless. Construct on the stack, call `emit_atoms`,
 * throw away.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief IMPORT-directory atom source — see file header.
 *
 * No-op on PE32 (chaos pipeline is x64-only).
 */
class ImportAtomSource final : public IAtomSource {
public:
    ImportAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
