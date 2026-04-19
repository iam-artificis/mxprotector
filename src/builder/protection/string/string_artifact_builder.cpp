/**
 * @file string_artifact_builder.cpp
 * @brief Implementation of `build_string_artifacts` — see header.
 */

#include "mxprotector/protection/string/string_artifact_builder.hpp"

#include <Zydis/Zydis.h>

namespace mx::string_protect {

namespace {

/// Zydis register enum → AMD64 GPR index. Duplicated from
/// `string_candidate_gather.cpp` because the two files don't share
/// a common internal helper — the translation is a 3-liner and
/// inlining it here keeps each TU self-contained.
[[nodiscard]] constexpr GprIndex zydis_reg_to_gpr(uint32_t zydis_reg) noexcept {
    const auto lo = static_cast<uint32_t>(ZYDIS_REGISTER_RAX);
    const auto hi = static_cast<uint32_t>(ZYDIS_REGISTER_R15);
    if (zydis_reg < lo || zydis_reg > hi) return 16;
    return static_cast<GprIndex>(zydis_reg - lo);
}

} // anonymous namespace

StringArtifacts build_string_artifacts(
    const GatheredStrings& gathered,
    Randomizer&            rng)
{
    StringArtifacts out;

    // (5) Per-string XOR encryption.
    out.encrypted = encrypt_all(gathered.kept_strings, rng);

    // (6a) Emit mx_str_get. Two variants:
    //   - S2b/S2c stub: `emit_mx_str_get()` — sticky flag caching,
    //     XOR decrypt in place in the data pool. Returned pointer
    //     stays valid forever.
    //   - S3 ephemeral: `emit_mx_str_get_ephemeral()` — scratch-ring
    //     allocator, copy+decrypt per call, no caching. Returned
    //     pointer is valid until the ring wraps around.
    //
    // Common fields (`code`, two disp32 offsets) are copied into
    // local variables so downstream patch logic only branches on
    // the extra scratch-ring disp32 once.
    if (gathered.is_ephemeral_mode) {
        auto emitted = emit_mx_str_get_ephemeral();
        out.decryptor_code            = std::move(emitted.code);
        out.decryptor_desc_disp32_off = emitted.desc_table_disp32_offset;
        out.decryptor_data_disp32_off = emitted.data_base_disp32_offset;
        out.decryptor_ring_disp32_off = emitted.scratch_ring_disp32_offset;
    } else {
        auto emitted = emit_mx_str_get();
        out.decryptor_code            = std::move(emitted.code);
        out.decryptor_desc_disp32_off = emitted.desc_table_disp32_offset;
        out.decryptor_data_disp32_off = emitted.data_base_disp32_offset;
    }

    // (6b) One trampoline per xref. The dense string id is already
    // stored parallel to `usable_xrefs` in `xref_string_id`.
    out.trampolines.reserve(gathered.usable_xrefs.size());
    for (size_t i = 0; i < gathered.usable_xrefs.size(); ++i) {
        const auto& x   = gathered.usable_xrefs[i];
        const GprIndex gpr = zydis_reg_to_gpr(x.dest_reg);
        TrampolineRequest req{
            .string_id  = gathered.xref_string_id[i],
            .target_reg = gpr,
        };
        out.trampolines.push_back(emit_trampoline(req));
    }

    return out;
}

} // namespace mx::string_protect
