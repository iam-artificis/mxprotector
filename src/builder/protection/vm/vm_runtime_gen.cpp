/**
 * @file vm_runtime_gen.cpp
 * @brief [BUILDER] Public facade for the VM runtime generator.
 *
 * After the Phase 2 arch refactor this file is a thin facade. The
 * actual byte emission machinery (entry stub, handlers, vEFLAGS
 * scrambling, native-escape handlers, table assembly, patching) lives
 * under `src/builder/protection/vm/x64/` and is owned by
 * `mx::vm::x64::X64VmBackend`. `VmRuntimeGenerator` exists only to
 * give external callers (currently `VirtualizationPass`) a stable
 * `mx::vm::*` entry point that does not pull in arch-specific
 * headers.
 *
 * When a second backend lands (Arm64VmBackend), this facade will pick
 * the right one based on `ctx.target().arch` rather than hard-coding
 * x64. The interface that lets backends compose into the engine is
 * sketched in `include/mxprotector/arch/vm_backend.hpp`.
 */

#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

#include "mxprotector/protection/vm/x64/x64_vm_backend.hpp"

namespace mx::vm {

MxResult<VmRuntime> VmRuntimeGenerator::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng,
    VmGenOptions opts)
{
    x64::X64VmBackend backend;
    return backend.generate(instructions, rng, opts);
}

} // namespace mx::vm
