/**
 * @file x64_vm_backend.cpp
 * @brief Public facade for the x64 VM runtime backend.
 *
 * `X64VmBackend::generate` validates the request and forwards to the
 * x64-specific `GenerationSession` (declared in `x64_vm_session.hpp`,
 * implemented across `x64_vm_session.cpp` +
 * `x64_vm_session_step1.cpp`). The session in turn delegates byte
 * emission to the dedicated sibling files
 * (`x64_bytecode_encoder.cpp`, `x64_entry_stub.cpp`,
 * `x64_handler_emitter.cpp`, `x64_inner_vm.cpp`,
 * `x64_blob_patcher.cpp`).
 *
 * `X64VmBackendFactory::create` is the registration seam for the
 * arch-aware pipeline: pick this factory when
 * `ctx.target().arch == arch::ArchFamily::x64`. A future arm64 or
 * Cortex-M VM backend lands as a sibling factory + sibling
 * `IVmBackend` impl, with no changes here.
 *
 * R8.1 wired `arch::IVmBackend`; R13 confirmed that the IVmBackend
 * abstraction itself IS the engine seam — there is no separate
 * `vm::VmRuntimeEngine` class because the orchestration state is
 * inherently target-specific (per-build randomisation seeds the
 * x64 stack layout, picks x64 register slots, draws x64 vEFLAGS
 * scramble parameters). When arm64 lands, an Arm64VmBackend will
 * own its own GenerationSession with its own randomisation policy.
 */

#include "mxprotector/protection/vm/x64/x64_vm_backend.hpp"

#include "x64_vm_session.hpp"

namespace mx::vm::x64 {

// ============================================================================
//                     Public facade: X64VmBackend::generate
// ============================================================================

MxResult<VmRuntime> X64VmBackend::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng,
    VmGenOptions opts)
{
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "X64VmBackend: empty VM instruction list"));
    }
    GenerationSession session(instructions, rng, opts);
    return session.run();
}

// ============================================================================
//                          X64VmBackendFactory
// ============================================================================
//
// Single-impl factory today. The pipeline picks `X64VmBackendFactory`
// when `ctx.target().arch == arch::ArchFamily::x64`. Future arm64 /
// Cortex-M factories register alongside without changing this one.
// ============================================================================

MxResult<std::unique_ptr<arch::IVmBackend>>
X64VmBackendFactory::create(arch::ArchInfo info) {
    if (info.family != arch::ArchFamily::x64) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "X64VmBackendFactory: requested arch family is not x64"));
    }
    return std::make_unique<X64VmBackend>();
}

} // namespace mx::vm::x64
