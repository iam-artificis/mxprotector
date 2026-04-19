/**
 * @file string_section_committer.hpp
 * @brief Phase 8..12 of the StringProtectionPass pipeline — inject
 *        the assembled `.mxstr` buffer, back-patch every rip-relative
 *        slot, rewrite source-side LEAs as `call trampoline`, wipe
 *        plaintext in the source data sections.
 *
 * Runs strictly in order:
 *
 *   (8)  `SectionManager::add_section`    — assigns the final RVA
 *   (9)  patch the two (or three) disp32 slots inside `mx_str_get`
 *   (10) patch each trampoline's `call rel32 → mx_str_get`
 *   (10a) if the VM lift succeeded, overwrite the decrypt-loop window
 *        inside `mx_str_get` with `call vm_entry + NOP pad`
 *   (11) rewrite every source LEA site with `call rel32 <trampoline>`
 *        + NOP pad
 *   (12) zero every plaintext string in its owning source section.
 */

#pragma once

#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/string/string_artifact_builder.hpp"
#include "mxprotector/protection/string/string_candidate_gather.hpp"
#include "mxprotector/protection/string/string_section_assembler.hpp"

namespace mx {
class ProtectionContext;
} // namespace mx

namespace mx::string_protect {

/// Inject the assembled section, back-patch every rel32/disp32,
/// rewrite source LEAs, wipe plaintexts. Returns the caller an
/// error only if the section add itself fails; everything else is
/// bounds-checked best-effort.
[[nodiscard]] MxStatus commit_string_section(
    ProtectionContext&         ctx,
    const GatheredStrings&     gathered,
    const StringArtifacts&     artifacts,
    const StringSectionLayout& layout);

} // namespace mx::string_protect
