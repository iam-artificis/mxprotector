/**
 * @file code_gap_pin_atom_source.hpp
 * @brief Pin every byte in a code section that does NOT belong to a
 *        `.pdata`-listed function (B.4.12.3).
 *
 * MSVC routinely emits real x64 instructions inside the inter-
 * function gap of `.text` — most commonly five-byte `JMP rel32`
 * thunks for `/INCREMENTAL` linker mode, hot-patch landing pads,
 * and CFG-related stubs. None of these have `RUNTIME_FUNCTION`
 * entries in `.pdata`, so `FunctionAtomSource` does not see them,
 * yet `CodeReferenceScanner` decodes them sequentially and emits
 * a `Reference` for every embedded `disp32`.
 *
 * If those bytes were left as plain "passthrough" while their
 * neighbouring function atom moves to a NEW position lower than
 * its OLD start (which can happen because the planner packs
 * movable chunks back-to-back from the free range's
 * 8-aligned cursor), the moved atom's bytes overwrite the gap's
 * thunk bytes in the unified buffer. The patcher then writes the
 * new `disp32` at `remap(thunk_disp_loc) = thunk_disp_loc`
 * (identity, because the gap is not in any chunk), but the bytes
 * around it are no longer the thunk's bytes — they are the
 * neighbour atom's first three bytes. The result is corruption
 * that surfaces as a random access violation or illegal
 * instruction during CRT init.
 *
 * Pinning the gap fixes this at the planner level: the gap's RVA
 * range is added to the pin set, the planner reserves it from
 * the free range, and no chunk's NEW range can overlap it. The
 * thunk's bytes survive verbatim and the patcher's writes at the
 * gap's RVA land on the right `disp32` slot.
 *
 * SOLID:
 *   * SRP — exactly one concern: pin code-section bytes outside
 *     `.pdata`-listed function ranges.
 *   * OCP — adding/removing the source is a one-line change in
 *     `chaos_layout.cpp::register_atom_sources`.
 *
 * Threading: stateless apart from a `.pdata` parse — re-create
 * the source per call.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Inter-function `.text` gap pin atom source.
 */
class CodeGapPinAtomSource final : public IAtomSource {
public:
    CodeGapPinAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
