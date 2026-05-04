/**
 * @file section_movable_block_atom_source.hpp
 * @brief Atom source for `SectionInfo::movable_blocks` — turns
 *        emitter-declared self-contained byte runs (indirect-call
 *        stubs, CFF state blocks) into movable atoms.
 *
 * **Why this source exists.**
 *
 * The canonical `FunctionAtomSource` produces movable atoms only
 * for `.pdata`-listed functions in `.text`. Everything else the
 * protector emits — the 40 KB `.callstub` section, CFG-flattening
 * trampolines, etc. — is pinned by `CodeGapPinAtomSource` because
 * those sections never appear in `.pdata`. As a result the chaos
 * shuffle's byte-coverage stops at whatever fraction of the image
 * is in `.pdata`, even though the stubs and trampolines are easily
 * shuffleable in their own right.
 *
 * Every emitter that creates self-contained sub-blocks (each block
 * is referenced only by patchable rel32 / RIP-relative slots that
 * the existing reference scanner already knows about) appends a
 * `pe::MovableBlock` to its emitted section's `movable_blocks`.
 * This atom source then turns each block into a movable atom that
 * the `AtomicChunkPlanner` can permute alongside the function
 * atoms.
 *
 * **Why a separate source.**
 *
 *   * SOLID/SRP: `FunctionAtomSource` owns `.pdata` semantics; this
 *     source owns "emitter-declared movable byte runs". Mixing them
 *     would couple two unrelated parsing concerns.
 *   * Adding a new movable origin (e.g. a future MBA-block emitter)
 *     just appends to the section's `movable_blocks`. No edit to
 *     this file required.
 *   * Tests instantiate the source standalone with a minimal
 *     `SectionInfo` carrying a few hand-crafted blocks.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Atom source for emitter-declared movable byte runs — see
 *        file header.
 */
class SectionMovableBlockAtomSource final : public IAtomSource {
public:
    SectionMovableBlockAtomSource() = default;

    /**
     * @brief Walk every section's `movable_blocks` list and append
     *        one `instruction`-origin atom (alignment 1) per block.
     *
     * Uses `AtomOrigin::instruction` for movable code blocks so the
     * planner treats them with the same default alignment as the
     * existing function atoms.
     */
    void emit_atoms(const PeImage& image, AtomTable& out) const override;
};

} // namespace mx::pe::chaos
