/**
 * @file string_protection_pipeline.hpp
 * @brief Orchestrator class for the StringProtectionPass pipeline.
 *
 * The `IProtectionPass` facade (`string_protection_pass.cpp`)
 * delegates straight to this class. `execute()` walks the phases in
 * order:
 *
 *   1. gather_string_candidates    (string_candidate_gather.hpp)
 *   2. build_string_artifacts      (string_artifact_builder.hpp)
 *   3. assemble_string_section     (string_section_assembler.hpp)
 *   4. commit_string_section       (string_section_committer.hpp)
 *
 * No cross-phase mutable state lives here — each leaf returns its
 * output explicitly and the pipeline threads it to the next phase.
 */

#pragma once

#include "mxprotector/core/result.hpp"

namespace mx {
class ProtectionContext;
} // namespace mx

namespace mx::string_protect {

class StringProtectionPipeline {
public:
    explicit StringProtectionPipeline(ProtectionContext& ctx) noexcept
        : ctx_(ctx) {}

    [[nodiscard]] MxStatus execute();

private:
    ProtectionContext& ctx_;
};

} // namespace mx::string_protect
