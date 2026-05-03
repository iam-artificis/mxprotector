/**
 * @file data_section_pin_atom_source.hpp
 * @brief Pin every non-code section as one big atom (B.4.11.1).
 *
 * The chaos shuffle's loose-chunk carving is byte-granular by
 * default and routinely splits natural-aligned data values
 * (`__security_cookie`, `__guard_check_icall_fptr`, vtable slots,
 * inline atomics, …) across two chunks. The two halves end up at
 * non-contiguous positions in the unified section, so a 64-bit
 * read from the value's translated RVA returns six bytes of the
 * value and two unrelated shuffle bytes. The CRT typically dies
 * during `__security_init_cookie`; user code dies the first time
 * it touches a corrupted struct.
 *
 * The simplest correct fix is to refuse to shuffle data at all:
 * pin every non-code section as a single atom with 8-byte
 * alignment, so the planner leaves the section's bytes verbatim
 * at their original RVAs.
 *
 * Trade-off: data interleaving is sacrificed in exchange for DLL/
 * EXE correctness. Code shuffle still runs at function granularity
 * (see `FunctionAtomSource`). Future work can restore data
 * shuffle by atomising structs at pointer boundaries — that
 * requires struct-layout knowledge the protector does not have
 * today.
 *
 * SOLID:
 *   * SRP — exactly one concern: pin non-code sections.
 *   * OCP — adding/removing the source is a one-line change in
 *     `chaos_layout.cpp::register_atom_sources`.
 *
 * Threading: stateless. Safe to construct on the stack and
 * discard.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

/**
 * @brief Whole-section pinned-atom source for non-code sections.
 *
 * Iterates `image.sections()` and emits one atom per section
 * whose `is_code()` is `false`. Each atom uses
 * `AtomOrigin::load_config_directory` so the policy floor in
 * `AtomTable::normalize` raises alignment to 8 and the planner
 * pins the range. Code sections are deliberately skipped — they
 * are covered by `FunctionAtomSource`.
 */
class DataSectionPinAtomSource final : public IAtomSource {
public:
    DataSectionPinAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
