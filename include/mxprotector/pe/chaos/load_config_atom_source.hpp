/**
 * @file load_config_atom_source.hpp
 * @brief Atom source covering the LOAD_CONFIG directory and the
 *        function tables it points at.
 *
 * Two atom kinds:
 *
 *   * `load_config_directory` — one atom covering the entire
 *     `IMAGE_LOAD_CONFIG_DIRECTORY` block. Size = `min(outer_size,
 *     inner_size)` so we never exceed the linker's intent.
 *
 *   * `load_config_table` — one atom per non-empty CFG / SEH /
 *     IAT-taken / longjmp / EH-cont table, sized
 *     `count * stride`. Stride = `4 + ((GuardFlags >> 28) & 0xF)`
 *     for CFG-class tables, plain 4 for EH-cont and SEH.
 *
 * Why both: the LOAD_CONFIG block contains absolute-VA pointers
 * to those tables. The reference scanner already emits patches
 * for the pointer slots; this source keeps the *pointed-at*
 * tables intact post-shuffle so the runtime walks them as
 * expected.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class LoadConfigAtomSource final : public IAtomSource {
public:
    LoadConfigAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
