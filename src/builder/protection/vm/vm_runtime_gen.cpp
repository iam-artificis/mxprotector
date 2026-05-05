/**
 * @file vm_runtime_gen.cpp
 * @brief [BUILDER] Public facade for the VM runtime generator.
 *
 * `VmRuntimeGenerator::generate` constructs a backend through the
 * `arch::IVmBackendFactory` registered for the target architecture and
 * forwards the call. Today only `vm::x64::X64VmBackendFactory` is wired
 * in (and selected when no factory override is provided), so the runtime
 * behaviour is identical to the previous direct call into `X64VmBackend`.
 *
 * When an arm64 backend ships, the factory selector here grows one
 * branch on `arch::ArchFamily` — every other call site in the pipeline
 * already speaks `arch::IVmBackend`.
 */

#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/arch/vm_backend.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_backend.hpp"

namespace mx::vm {

namespace {

/// Pick the right backend factory for `arch_family`.
/// Today only x64 is implemented; future arches register here as siblings.
[[nodiscard]] MxResult<std::unique_ptr<arch::IVmBackend>>
make_backend_for(arch::ArchFamily family) {
    if (family == arch::ArchFamily::x64) {
        x64::X64VmBackendFactory factory;
        return factory.create(arch::ArchInfo::x64_baseline());
    }
    return std::unexpected(MxError(
        ProtectionErrorCode::pass_failed,
        "VmRuntimeGenerator: no VM backend registered for this arch"));
}

} // namespace

MxResult<VmRuntime> VmRuntimeGenerator::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng,
    VmGenOptions opts)
{
    auto backend = make_backend_for(arch::ArchFamily::x64);
    if (!backend) {
        return std::unexpected(backend.error());
    }
    return (*backend)->generate(instructions, rng, opts);
}

} // namespace mx::vm
