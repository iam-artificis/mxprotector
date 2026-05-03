/**
 * @file fall_through_jmp_filler.hpp
 * @brief Post-shuffle pass that materialises implicit fall-through
 *        edges as explicit `JMP rel32` (B.4.18-foundation).
 *
 * ### Role in the chaos pipeline
 *
 * `AtomicChunkPlanner` takes a stream of atoms and produces an
 * `RvaRemapper` — every byte the planner moves carries an
 * `(old_rva → new_rva)` mapping. After the byte shuffle and the
 * reference patcher run, the binary is *almost* live: every
 * RVA-carrying slot already points at the right place.
 *
 * The single class of edges the patcher cannot rewrite is the
 * **implicit fall-through** between adjacent basic blocks. A block
 * that originally ended without an explicit branch relied on the
 * next byte simply being its successor; once the chaos shuffle
 * separates the two atoms in RVA space, the fall-through goes to
 * the wrong place.
 *
 * This filler closes that gap. For every atom whose
 * `fall_through_to != 0`, it:
 *
 *   1. Asks the remapper for the atom's new content end and the
 *      successor's new start.
 *   2. If the two RVAs already abut (the planner happened to keep
 *      them adjacent), it writes 5 `0x90` (NOP) bytes into the
 *      atom's reserved `slack_after` region.
 *   3. Otherwise it writes `0xE9 disp32` into the slack so the
 *      relocated block jumps to its successor's new RVA.
 *
 * The pass is **idempotent** — re-running it on a stable image
 * produces the same bytes. It is **stateless** — instantiate per
 * call. It runs *after* the reference patcher and the relocation
 * rebuilder, *before* the deferred-hash refinalisers (the slack we
 * fill is part of the bytes those refinalisers later hash, so the
 * sequence is: shuffle → patch refs → rebuild reloc → fill slack →
 * recompute hashes).
 *
 * SOLID:
 *   * SRP — exactly one task: turn fall-through annotations into
 *     real branch instructions (or NOPs when adjacency holds).
 *   * OCP — atoms that do not need fall-through fixups simply leave
 *     `fall_through_to = 0`. The filler walks atoms and is a no-op
 *     for the current `FunctionAtomSource` / `CodeGapPinAtomSource`
 *     output; the upcoming basic-block atom source is what actually
 *     populates the field.
 *
 * Threading: not safe for concurrent invocation against the same
 * `PeImage`. One instance per build.
 */

#pragma once

#include <cstddef>
#include <span>

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {
class RvaRemapper;
}

namespace mx::pe::chaos {

struct Atom;

/**
 * @brief Post-shuffle fall-through fixup — see file header.
 */
class FallThroughJmpFiller {
public:
    FallThroughJmpFiller() = default;

    /**
     * @brief Walk every atom in `atoms`; for each atom whose
     *        `fall_through_to != 0`, write `JMP <new_target>` (or
     *        five `0x90` NOPs when the planner kept it adjacent)
     *        into the atom's `slack_after` region.
     *
     * @param image     PE image whose unified section's bytes will
     *                  be patched in place.
     * @param atoms     Snapshot of the post-`normalize` atom table
     *                  the planner consumed. Atoms with
     *                  `fall_through_to == 0` are skipped.
     * @param remapper  Finalised remapper produced by the planner.
     *
     * @return Number of slack regions filled (atoms touched). Zero
     *         when no atom carries a fall-through annotation —
     *         which is the case under the current atom-source
     *         registration.
     */
    std::size_t fill(
        PeImage&                       image,
        std::span<const Atom>          atoms,
        const ::mx::pe::refmap::RvaRemapper& remapper) const;
};

} // namespace mx::pe::chaos
