/**
 * @file instruction_atom_source.hpp
 * @brief Atom source that disassembles every code section and emits
 *        one atom per x86 instruction.
 *
 * Why one atom per instruction (not per basic block, not per
 * function): the chaos shuffler permutes atoms among themselves to
 * maximally interleave code with data. Per-instruction granularity
 * gives the planner the fine-grained mobility the user wants
 * (10-50 byte alternations between code and data) while every
 * instruction's bytes stay contiguous — splitting a 6-byte CALL
 * across two new positions would corrupt the encoding.
 *
 * Bytes the disassembler cannot decode (Zydis returns an error)
 * are emitted as single-byte atoms tagged
 * `instruction_undecoded`. Treating them as 1-byte atoms keeps
 * them in play for shuffling — typical undecoded bytes are `0xCC`
 * alignment padding or compiler-generated debug breakpoints, both
 * harmless to permute. If a real data table is embedded in a code
 * section (rare; jump tables historically), those bytes will also
 * shuffle byte-for-byte. The chaos contract documents that case
 * as best-effort; pinning embedded tables is a future refinement.
 *
 * What this source does NOT touch:
 *
 *   * Sections without `IMAGE_SCN_CNT_CODE` set — they are not code
 *     sections and the disassembler would generate noise on them.
 *
 *   * Instruction *operands* — those are encoded as `Reference`
 *     entries by `CodeReferenceScanner` (refmap) so the patcher can
 *     rewrite displacement bytes after the shuffle. The atom source
 *     only declares the byte range, not its semantics.
 *
 * Threading: stateless. Construct on the stack, call `emit_atoms`,
 * throw away.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Disassembles every code section via Zydis and emits one
 *        atom per decoded instruction. Undecoded bytes become
 *        1-byte atoms tagged `instruction_undecoded`.
 *
 * No-op on PE32 (chaos pipeline is x64-only).
 */
class InstructionAtomSource final : public IAtomSource {
public:
    InstructionAtomSource() noexcept = default;

    /**
     * @brief Walk `image`'s code sections and append every emitted
     *        atom to `out`.
     *
     * Skip rules:
     *   * `image.is_64bit() == false` → no-op.
     *   * Section without `is_code()` → skipped.
     *   * Section's `data` empty → skipped.
     *   * Decode error at offset N → emit 1-byte atom at N, advance.
     */
    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
