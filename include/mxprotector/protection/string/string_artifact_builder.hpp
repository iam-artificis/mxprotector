/**
 * @file string_artifact_builder.hpp
 * @brief Phase 5..6 of the StringProtectionPass pipeline — encrypt
 *        kept strings, emit the `mx_str_get` decryptor, emit one
 *        trampoline per usable xref.
 *
 * The decryptor variant (sticky S2b vs. ephemeral S3) is selected
 * from the gather output's `is_ephemeral_mode` flag so the rest of
 * the pipeline can treat both uniformly — via the optional
 * `decryptor_ring_disp32_off` slot that only the S3 layout fills.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/string/string_candidate_gather.hpp"
#include "mxprotector/protection/string/string_decryptor_codegen.hpp"
#include "mxprotector/protection/string/string_encryptor.hpp"

namespace mx::string_protect {

/// Byte artefacts produced by the builder:
///   * `encrypted` — ciphertext + key + length per kept string;
///   * `decryptor_code` — raw bytes of `mx_str_get` (stub or ephemeral);
///   * `decryptor_*_disp32_off` — offsets of the two (or three)
///     rip-relative disp32 slots inside the decryptor, for post-
///     inject patching;
///   * `trampolines` — one `EmittedTrampoline` per usable xref,
///     parallel to `GatheredStrings::usable_xrefs`.
struct StringArtifacts {
    std::vector<EncryptedString>   encrypted;
    std::vector<uint8_t>           decryptor_code;
    size_t                         decryptor_desc_disp32_off = 0;
    size_t                         decryptor_data_disp32_off = 0;
    size_t                         decryptor_ring_disp32_off = 0;  // S3 only
    std::vector<EmittedTrampoline> trampolines;
};

/// XOR-encrypt every kept string, emit the right `mx_str_get`
/// variant, emit one trampoline per xref.
[[nodiscard]] StringArtifacts build_string_artifacts(
    const GatheredStrings& gathered,
    Randomizer&            rng);

} // namespace mx::string_protect
