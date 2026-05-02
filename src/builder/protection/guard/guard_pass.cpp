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
    // Runtime-guards emit a Vectored Exception Handler and a TLS installer
    // thunk — both are Win32 *user-mode* facilities. Kernel drivers run in
    // ring0 (no `RtlAddVectoredExceptionHandler`, dispatch is IDT /
    // KiDispatchException) and UEFI binaries run before the OS user-mode
    // loader is even alive (no PEB, no VEH, no TLS callbacks); both must
    // be rejected. `is_user_mode()` is the single semantic predicate
    // that captures "this binary lives in Win32 user-mode" and is the
    // gate of record — see project memory note "VEH only for user-mode".
    // The `is_windows_pe_x64()` filter still applies because the stub is
    // emitted as x64 PE bytes and the rest of the pipeline assumes that.
    if (!ctx.target().is_windows_pe_x64()) return false;
    if (!ctx.target().is_user_mode())      return false;

    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::guard_begin) return true;
    }
    return false;
}

MxStatus GuardPass::execute(ProtectionContext& ctx) {
    return guard::GuardPassPipeline{ctx}.execute();
}

} // namespace mx
