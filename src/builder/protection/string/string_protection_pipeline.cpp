/**
 * @file string_protection_pipeline.cpp
 * @brief Implementation of `StringProtectionPipeline::execute` — see header.
 */

#include "mxprotector/protection/string/string_protection_pipeline.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/string/string_artifact_builder.hpp"
#include "mxprotector/protection/string/string_candidate_gather.hpp"
#include "mxprotector/protection/string/string_section_assembler.hpp"
#include "mxprotector/protection/string/string_section_committer.hpp"

namespace mx::string_protect {

MxStatus StringProtectionPipeline::execute()
{
    ctx_.log("StringProtectionPass: старт S2 "
             "(scan → xref → encrypt → emit → patch)");

    // --- Phase 1..4 — gather candidates, xrefs, filter, assign IDs --
    auto gathered = gather_string_candidates(ctx_);
    if (!gathered) {
        // Leaf already logged the reason for the empty result.
        return {};
    }

    // --- Phase 5..6 — encrypt + decryptor + trampolines -------------
    //
    // The rng is created here and threaded through the encryption
    // and optional VM-lift steps. The draw order is fixed so that
    // --strings=stub, --strings=ephemeral, and --strings=vm builds
    // of the same binary remain reproducible per-seed.
    Randomizer rng;
    auto artifacts = build_string_artifacts(*gathered, rng);

    // --- Phase 7..7a — compose section buffer (+ optional VM lift) --
    auto layout = assemble_string_section(ctx_, *gathered, artifacts, rng);

    // --- Phase 8..12 — inject section, patch, rewrite LEAs, wipe ---
    return commit_string_section(ctx_, *gathered, artifacts, layout);
}

} // namespace mx::string_protect
