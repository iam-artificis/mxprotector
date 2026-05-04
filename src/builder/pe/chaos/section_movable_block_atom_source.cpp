/**
 * @file section_movable_block_atom_source.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/pe/chaos/section_movable_block_atom_source.hpp"

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx::pe::chaos {

void SectionMovableBlockAtomSource::emit_atoms(
    const PeImage& image, AtomTable& out) const
{
    for (const auto& sec : image.sections()) {
        for (const auto& block : sec.movable_blocks) {
            if (block.size == 0) continue;
            // Sanity check: drop blocks that fall outside the
            // section's virtual extent. The pass that registered the
            // block should have caught this; we fail-closed here so
            // a future bug doesn't translate into out-of-section
            // shuffle moves.
            if (block.begin_rva < sec.virtual_address) continue;
            if (block.end_rva() >
                sec.virtual_address + sec.virtual_size) continue;

            out.add(Atom{
                .start_rva = block.begin_rva,
                .size      = block.size,
                .origin    = AtomOrigin::instruction,
                .alignment = block.alignment,
            });
        }
    }
}

} // namespace mx::pe::chaos
