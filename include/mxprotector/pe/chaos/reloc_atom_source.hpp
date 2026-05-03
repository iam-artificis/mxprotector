/**
 * @file reloc_atom_source.hpp
 * @brief Two atom sources for the `.reloc` directory:
 *
 *   * `RelocBlockAtomSource` — each `IMAGE_BASE_RELOCATION` block
 *     (8-byte header + N 16-bit entries) becomes one variable-size
 *     atom. The loader walks `.reloc` as a contiguous chain of
 *     blocks; cutting one block in half breaks the chain.
 *
 *   * `RelocPointerAtomSource` — each 8-byte slot pointed at by an
 *     `IMAGE_REL_BASED_DIR64` entry becomes its own 8-byte atom.
 *     Without this, an 8-byte absolute-VA slot in `.data` would
 *     get scattered across the shuffle, and the patcher's 8-byte
 *     write would land on whatever bytes ended up at the
 *     post-shuffle location.
 *
 * Threading: both sources are stateless. Construct on the stack,
 * call `emit_atoms`, throw away.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief `.reloc` block atom source — see file header.
 */
class RelocBlockAtomSource final : public IAtomSource {
public:
    RelocBlockAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

/**
 * @brief Per-DIR64-target 8-byte slot atom source — see file header.
 */
class RelocPointerAtomSource final : public IAtomSource {
public:
    RelocPointerAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
