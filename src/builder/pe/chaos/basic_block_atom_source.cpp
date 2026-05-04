/**
 * @file basic_block_atom_source.cpp
 * @brief Implementation — see header.
 *
 * The split logic (decode + terminator detection + alignment +
 * INT3 head/tail absorption) lives in `sub_block_planner.{hpp,cpp}`
 * — both this source and `PdataChainEmitter` consume the same
 * `SubBlock` list so the atom set and the chained `.pdata` stay
 * in lockstep.
 */

#include "mxprotector/pe/chaos/basic_block_atom_source.hpp"

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/chaos/sub_block_planner.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

void BasicBlockAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    const auto sub_blocks = plan_sub_blocks(image);
    for (const auto& sb : sub_blocks) {
        if (sb.size == 0) continue;
        out.add(Atom{
            .start_rva = sb.start_rva,
            .size      = sb.size,
            .origin    = AtomOrigin::instruction,
        });
    }
}

} // namespace mx::pe::chaos
