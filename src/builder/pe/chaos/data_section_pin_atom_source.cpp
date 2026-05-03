/**
 * @file data_section_pin_atom_source.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/chaos/data_section_pin_atom_source.hpp"

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

void DataSectionPinAtomSource::emit_atoms(
    const PeImage& image,
    AtomTable&     out) const
{
    for (const auto& sec : image.sections()) {
        if (sec.is_code())          continue;
        if (sec.virtual_size == 0)  continue;
        out.add(Atom{
            .start_rva = sec.virtual_address,
            .size      = sec.virtual_size,
            .origin    = AtomOrigin::load_config_directory,
        });
    }
}

} // namespace mx::pe::chaos
