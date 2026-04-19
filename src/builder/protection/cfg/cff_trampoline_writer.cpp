/**
 * @file cff_trampoline_writer.cpp
 * @brief JMP rel32 + INT3 padding emitter for relocated functions.
 *
 * Uses the `mx::asm64` in-place writers so the byte-level encoding
 * lives in one place and this TU stays about CFF's policy ("overwrite
 * the original function body with a redirect") rather than opcode
 * arithmetic.
 */

#include "mxprotector/protection/cfg/cff_trampoline_writer.hpp"

#include <algorithm>

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::cff {

void write_jmp_trampoline(pe::SectionInfo& section,
                          uint32_t         offset_in_section,
                          uint32_t         original_size,
                          Rva              source_rva,
                          Rva              target_rva) noexcept
{
    if (offset_in_section + 5 > section.data.size()) return;

    // `rel32` on x64 is the signed byte distance from the END of the
    // 5-byte JMP to the target RVA: `target = source + 5 + rel32`.
    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) - static_cast<int64_t>(source_rva) - 5);

    const size_t span_size = std::min<size_t>(
        original_size, section.data.size() - offset_in_section);
    MutableByteView span{section.data.data() + offset_in_section, span_size};

    asm64::write_jmp_rel32(span.subspan(0, 5), rel32);
    if (span.size() > 5) {
        asm64::fill_int3(span.subspan(5));
    }
}

} // namespace mx::cff
