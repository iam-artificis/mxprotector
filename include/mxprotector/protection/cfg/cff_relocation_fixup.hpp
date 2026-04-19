/**
 * @file cff_relocation_fixup.hpp
 * @brief Rewrite RIP-relative and rel32 operands after a block move.
 *
 * Every basic block the flattener relocates into the trampoline section
 * keeps its original bytes verbatim. Any instruction inside the block
 * that encodes a RIP-relative memory displacement (`mov rax, [rip+X]`)
 * or a rel32 immediate (`call X`, `jmp X`) still points at the
 * original RVA. After the move, those targets are off by the distance
 * between the original and new block positions.
 *
 * `apply_relocation_fixups` walks the block placements, decodes every
 * instruction with Zydis, and subtracts the placement delta from the
 * encoded offset so each reference still resolves to the same absolute
 * RVA it pointed to before the move.
 */

#pragma once

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"

namespace mx::cff {

/**
 * @brief Fix every RIP-relative / rel32 operand inside a relocated
 *        trampoline entry.
 *
 * @param section_data Bytes of the trampoline section; modified in place.
 * @param trampoline   Entry whose blocks were appended into
 *                     `section_data` at `trampoline.section_offset`.
 * @param section_rva  RVA the section was injected at.
 * @param image_base   PE `ImageBase` — used to convert original VAs
 *                     recorded inside `trampoline.block_placements`
 *                     back to RVAs for the delta calculation.
 */
void apply_relocation_fixups(ByteBuffer&              section_data,
                             const CffTrampolineEntry& trampoline,
                             Rva                      section_rva,
                             Va                       image_base);

} // namespace mx::cff
