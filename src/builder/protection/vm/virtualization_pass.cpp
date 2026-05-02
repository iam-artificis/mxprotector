/**
 * @file virtualization_pass.cpp
 * @brief [BUILDER] VirtualizationPass facade.
 *
 * The actual pipeline (region lift, junk insertion, cross-VM split,
 * runtime generation, section emission, trace-hints, CALL patching)
 * lives in `vm::VirtualizationPipeline` (R3.2 split-out). This file
 * stays thin: applicability gate + a one-line dispatch into the
 * pipeline.
 *
 * The pass is gated on `is_windows_pe_x64()` because every emitter
 * underneath is x64-only. EXE / DLL / SYS / EFI on x64 PE are all
 * accepted; the pipeline suppresses anti-tamper / anti-emulation
 * entry-stub checks for non-user-mode targets via
 * `skip_user_mode_checks` inside `build_default_options()`.
 */

#include "mxprotector/protection/vm/virtualization_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/protection/vm/virtualization_pipeline.hpp"

namespace mx {

bool VirtualizationPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    if (!ctx.config().enable_vm)           return false;
    // The VM dispatcher, handlers, bytecode encoder and entry stub
    // are all x64-only. Driver and EFI targets are accepted via the
    // pipeline's `skip_user_mode_checks` path.
    if (!ctx.target().is_windows_pe_x64()) return false;
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::vm_begin) return true;
    }
    return false;
}

MxStatus VirtualizationPass::execute(ProtectionContext& ctx) {
    return vm::VirtualizationPipeline{ctx}.execute();
}

} // namespace mx
