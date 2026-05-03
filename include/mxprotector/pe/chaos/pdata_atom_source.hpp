/**
 * @file pdata_atom_source.hpp
 * @brief Atom source that emits one 12-byte atom per
 *        `RUNTIME_FUNCTION` entry in the EXCEPTION directory's
 *        `.pdata`.
 *
 * Each `RUNTIME_FUNCTION` is exactly 12 bytes (3× 4-byte RVAs:
 * `BeginAddress`, `EndAddress`, `UnwindInfoAddress`). The runtime
 * unwinder walks `.pdata` as a contiguous array, sorted by
 * `BeginAddress`. After the chaos shuffle, every entry stays
 * intact (atom) and the patcher rewrites the three RVAs through
 * the `pdata_runtime_function` references the refmap scanner
 * already emits.
 *
 * Threading: stateless. Construct on the stack, call `emit_atoms`,
 * throw away.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief `.pdata` `RUNTIME_FUNCTION` atom source — see file header.
 */
class PdataAtomSource final : public IAtomSource {
public:
    PdataAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
