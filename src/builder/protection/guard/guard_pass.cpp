/**
 * @file guard_pass.cpp
 * @brief [BUILDER] `IProtectionPass` facade for GuardPass.
 *
 * Section layout produced by the pass:
 *
 * ```
 *     [guard_page_0 .. N-1]   N × kGuardPageSize       (one per MX_GUARD pair)
 *     [descriptor_table]      N × kGuardDescriptorStride bytes  (VEH input)
 *     [veh_handler]           ~234 bytes + tail         (installed by TLS thunk)
 *     [decrypt_vm_blob]       ~16 KB                    (VM-lifted decrypt unit)
 *     [tls_installer]         ~240 bytes                (registered via ctx)
 * ```
 *
 * The orchestration logic lives in `GuardPassPipeline`; this file is
 * only the `IProtectionPass` contract. Composition is intentional —
 * it lets the pipeline's phase leaves (collector, section assembler,
 * region finalizer, handler back-patcher, decrypt VM lifter) be
 * tested in isolation without pulling in the `IProtectionPass`
 * surface.
 */

#include "mxprotector/protection/guard/guard_pass.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/protection/guard/guard_pass_pipeline.hpp"

namespace mx {

bool GuardPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::guard_begin) return true;
    }
    return false;
}

MxStatus GuardPass::execute(ProtectionContext& ctx) {
    return guard::GuardPassPipeline{ctx}.execute();
}

} // namespace mx
