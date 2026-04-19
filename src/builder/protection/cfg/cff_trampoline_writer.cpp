/**
 * @file cff_trampoline_writer.cpp
 * @brief JMP rel32 + INT3 padding emitter for relocated functions.
 */

#include "mxprotector/protection/cfg/cff_trampoline_writer.hpp"

#include <cstring>

#include "mxprotector/pe/pe_image.hpp"

namespace mx::cff {

void write_jmp_trampoline(pe::SectionInfo& section,
                          uint32_t         offset_in_section,
                          uint32_t         original_size,
                          Rva              source_rva,
                          Rva              target_rva) noexcept
{
    if (offset_in_section + 5 > section.data.size()) return;

    // `rel32` on x64 is the signed byte distance from the END of the 5-byte
    // JMP to the target RVA: target = source + 5 + rel32.
    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) - static_cast<int64_t>(source_rva) - 5);

    section.data[offset_in_section] = 0xE9;
    std::memcpy(section.data.data() + offset_in_section + 1, &rel32, 4);

    for (uint32_t i = 5; i < original_size; ++i) {
        if (offset_in_section + i < section.data.size()) {
            section.data[offset_in_section + i] = 0xCC;
        }
    }
}

} // namespace mx::cff
