/**
 * @file string_section_assembler.hpp
 * @brief Phase 7 (+ optional Phase 7a VM lift) of the
 *        StringProtectionPass pipeline — compose the `.mxstr`
 *        section buffer.
 *
 * Section layout produced:
 *
 * ```
 *     [mx_str_get decryptor]             (stub or ephemeral variant)
 *     [trampoline_0 .. N-1]              (parallel to usable_xrefs)
 *     [descriptor table]                 (8 bytes × kept_strings)
 *     [data pool: ciphertext + key NULs] (one slot per kept string)
 *     [S3 scratch ring, 4-byte aligned]  (ephemeral mode only)
 *     [VM blob, 16-byte aligned]         (--strings=vm only)
 * ```
 *
 * Each offset is recorded so the post-commit patcher can back-fill
 * rip-relative disp32 slots inside the decryptor and the trampoline
 * `call rel32`s once the section has an assigned RVA.
 *
 * The optional VM lift lifts the middle of the stub decryptor's
 * decrypt loop into a VM runtime blob. Falls back silently to the
 * plain stub on any lift / generate failure — the protected binary
 * still works correctly.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/string/string_artifact_builder.hpp"

namespace mx {
class ProtectionContext;
} // namespace mx

namespace mx::string_protect {

/// Offsets (section-relative) captured during assembly. The pipeline
/// adds `section_rva` after the section commit to get runtime RVAs.
struct StringSectionLayout {
    std::vector<uint8_t> section_buf;
    size_t               decryptor_offset     = 0;
    std::vector<size_t>  trampoline_offsets;
    size_t               desc_table_offset    = 0;
    size_t               data_pool_offset     = 0;
    size_t               scratch_ring_offset  = 0;  // S3 only
    // VM lift (optional, only set when vm_lift_succeeded == true):
    size_t               vm_blob_offset       = 0;
    uint32_t             vm_blob_entry_offset = 0;
    bool                 vm_lift_succeeded    = false;
};

/// Compose the `.mxstr` section buffer from a gather output + the
/// freshly-built byte artefacts. Optionally lifts the decryptor's
/// XOR loop into a VM blob appended to the section. `rng` is used
/// by the VM generator when lifting.
[[nodiscard]] StringSectionLayout assemble_string_section(
    ProtectionContext&     ctx,
    const GatheredStrings& gathered,
    const StringArtifacts& artifacts,
    Randomizer&            rng);

} // namespace mx::string_protect
