/**
 * @file cfg_flattening_pipeline.hpp
 * @brief Orchestration class for a single `CfgFlatteningPass::execute`.
 *
 * The pipeline threads the CFF steps together — candidate discovery,
 * per-function flattening, trampoline accumulation, and the final
 * trampoline-section commit — while owning the cross-step state
 * (counters, the trampolines list, the shared RNG). Keeping this out
 * of the pass class means the pass itself stays a thin
 * `IProtectionPass` facade.
 *
 * Mirrors the pattern used by `PackerPipeline<Emitter>` — the packer
 * refactor (R2.x) set the convention that each big pass has a
 * dedicated pipeline class driving its steps.
 */

#pragma once

#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/cfg/cfg_flattening.hpp"
#include "mxprotector/protection/cfg/cff_function_source.hpp"

namespace mx {
class ProtectionContext;
namespace pe { struct SectionInfo; }
}

namespace mx::cff {

/**
 * @brief Owns the per-execution state of one CFF pass run.
 *
 * Not thread-safe; one pipeline object per pass execution.
 */
class CfgFlatteningPipeline final {
public:
    explicit CfgFlatteningPipeline(ProtectionContext& ctx) noexcept;

    /**
     * @brief Walk every candidate the gather phase produced, commit
     *        the trampoline section if any deferred entries
     *        accumulated, and log a summary.
     */
    [[nodiscard]] MxStatus execute();

private:
    /// How a single candidate was resolved by `try_flatten`.
    enum class Outcome {
        in_place,    ///< Flattened bytes fit, written over the original.
        trampolined, ///< Flattened bytes too large, deferred to `.mxprot1`.
        skipped      ///< Candidate rejected by a filter or flatten failure.
    };

    /// Try to flatten one candidate. Updates counters / trampoline
    /// list as a side effect.
    [[nodiscard]] Outcome try_flatten(pe::SectionInfo&         section,
                                      const FunctionCandidate& candidate);

    ProtectionContext&              ctx_;
    FlatteningConfig                flat_config_;
    Randomizer                      rng_;
    std::vector<CffTrampolineEntry> trampolines_;

    uint32_t flattened_inplace_ = 0;
    uint32_t trampolined_       = 0;
    uint32_t skipped_           = 0;
    uint32_t total_blocks_      = 0;
};

} // namespace mx::cff
