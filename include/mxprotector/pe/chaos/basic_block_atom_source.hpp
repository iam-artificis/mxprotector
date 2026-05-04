/**
 * @file basic_block_atom_source.hpp
 * @brief Sub-function atom source — splits `.pdata` functions into
 *        smaller movable runs at unconditional-terminator boundaries
 *        (B.4.23).
 *
 * `FunctionAtomSource` (B.4.11.2) emits one atom per `.pdata`
 * `RUNTIME_FUNCTION`. That gives function-granularity shuffle but
 * leaves the bytes inside each function pinned at their original
 * relative position. For a typical MSVC `/O2` binary this caps byte
 * coverage around ~35-40 % — most of the image is "inside a
 * function" and never moves.
 *
 * `BasicBlockAtomSource` (this file) splits each function at
 * **clean terminator boundaries**:
 *
 *   * The instruction terminating each sub-block is one of
 *     `RET` / `JMP <rel/r/m>` / `UD2` / `INT 1` / `INT 3` / `HLT` /
 *     `IRET*`. These all transfer control unconditionally, so the
 *     sub-block's last instruction does not rely on implicit
 *     fall-through. After chaos shuffle, the explicit branch
 *     destination is patched by the refmap exactly like any other
 *     `JMP rel32`; `RET` works regardless of position.
 *
 *   * The byte AFTER the terminator must be **`kSplitAlignment`-
 *     aligned** (4 bytes — same as the planner's chunk granularity).
 *     Otherwise the planner pins the resulting atom for boundary
 *     mismatch and the split is wasted. Internal split points that
 *     are not naturally 4-aligned are simply skipped — the algorithm
 *     keeps walking until it finds the next aligned terminator.
 *
 * Conditional branches (`JCC`), `CALL`, and "fall-through to the
 * next instruction" terminators are **never** treated as splits —
 * they require slack-after fall-through fixup, which lives in
 * `FallThroughJmpFiller`. The basic-block source emits zero-slack
 * atoms exclusively; the slack story is reserved for a follow-up
 * pass that wants JCC-granularity splits.
 *
 * The end-of-function adjustment from `FunctionAtomSource` (round
 * the trailing `INT3` padding into the atom so the chunk planner
 * can shuffle it) is preserved on the **last** sub-block of every
 * function.
 *
 * SOLID:
 *   * SRP — exactly one task: produce sub-function instruction-run
 *     atoms. PE-format atoms remain in their per-directory sources;
 *     the inter-function gap-pin pass remains in
 *     `CodeGapPinAtomSource`.
 *
 *   * OCP — adding a new terminator class (e.g. `SYSCALL` /
 *     `SYSRET`) is one entry in `is_unconditional_terminator()`.
 *     The planner, the refmap, and downstream sources are
 *     untouched.
 *
 *   * LSP — the source is a drop-in replacement for
 *     `FunctionAtomSource`: every function still produces one or
 *     more atoms covering exactly its `[BeginAddress, EndAddress)`
 *     range (plus optional INT3 padding on the last sub-block).
 *     Functions that yield no usable splits emit a single atom
 *     identical to the function-source output.
 *
 * Threading: stateless — re-create per call. The Zydis decoder is
 * a per-call local.
 */

#pragma once

#include <cstdint>

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief `.pdata`-driven sub-function atom source — see file header.
 */
class BasicBlockAtomSource final : public IAtomSource {
public:
    /// Boundary alignment for emitted sub-block atoms. Must equal
    /// the planner's `kChunkAlignment` so sub-blocks survive the
    /// planner's "movable atom whose boundaries are unaligned"
    /// pin policy. 4 matches `AtomicChunkPlanner`'s post-B.4.13
    /// chunk granularity.
    static constexpr std::uint32_t kSplitAlignment = 4;

    /// Trailing-INT3 absorption alignment for the **last** sub-block
    /// in each function. Mirrors `FunctionAtomSource::kBoundaryAlignment`
    /// — 8 bytes — so a function whose `EndAddress` has trailing
    /// `0xCC` filler still ends on an 8-aligned RVA, keeping every
    /// naturally-aligned 8-byte value in one chunk.
    static constexpr std::uint32_t kFunctionEndAlignment = 8;

    BasicBlockAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
