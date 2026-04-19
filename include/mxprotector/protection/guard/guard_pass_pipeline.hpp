/**
 * @file guard_pass_pipeline.hpp
 * @brief Orchestrator class for the GuardPass pipeline.
 *
 * The `IProtectionPass` facade (`guard_pass.cpp`) delegates straight
 * to this class. `execute()` walks the pipeline phases in order:
 *
 *   1. collect_pending_guards     (guard_collector.hpp)
 *   2. assemble_guard_section     (guard_section_assembler.hpp)
 *   3. SectionManager::add_section
 *   4. finalize_guard_regions     (guard_region_finalizer.hpp)
 *   5. back_patch_guard_handlers  (guard_handler_back_patcher.hpp)
 *   6. register the TLS installer VA with the packer via
 *      `ctx.set_extra_tls_callback_va`.
 *
 * No cross-phase mutable state lives here — each leaf returns its
 * output explicitly and the pipeline threads it to the next phase.
 */

#pragma once

#include "mxprotector/core/result.hpp"

namespace mx {
class ProtectionContext;
} // namespace mx

namespace mx::guard {

class GuardPassPipeline {
public:
    explicit GuardPassPipeline(ProtectionContext& ctx) noexcept
        : ctx_(ctx) {}

    [[nodiscard]] MxStatus execute();

private:
    ProtectionContext& ctx_;
};

} // namespace mx::guard
