/**
 * @file delay_import_atom_source.hpp
 * @brief Atom source for the DELAY_IMPORT directory.
 *
 * Each `IMAGE_DELAYLOAD_DESCRIPTOR` is a fixed 32-byte record;
 * the array is null-terminated. We emit one atom per record,
 * including the terminator. Records with `RvaBased == 0` (legacy
 * VA-based delay-load) are still emitted as atoms — keeping the
 * bytes intact is sound regardless of whether the patcher
 * rewrites them.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class DelayImportAtomSource final : public IAtomSource {
public:
    DelayImportAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
