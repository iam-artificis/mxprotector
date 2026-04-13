/**
 * @file x64_vm_backend.hpp
 * @brief [BUILDER, x64] X64-specific VM runtime backend.
 *
 * `X64VmBackend` owns the orchestration that used to live directly
 * inside `VmRuntimeGenerator::generate`: pick a per-build random
 * register / stack layout, derive the rolling-key seed and the
 * vEFLAGS scramble parameters, lay out the bytecode stream, emit the
 * entry stub, every handler, the native-escape handler instances,
 * the encrypted handler table, and finally patch all rel32s.
 *
 * The class is intentionally a regular value type with one entry
 * point — `generate` — that takes the lifted instruction list and
 * returns a fully-assembled `vm::VmRuntime` blob. The public
 * `VmRuntimeGenerator` (in `vm_runtime_gen.hpp`) is now a thin
 * facade that just instantiates this backend and forwards.
 *
 * Why a class and not a free function? Two reasons:
 *
 *   1. Future arm64 work. `Arm64VmBackend` will sit alongside this
 *      class with the same shape, and the pipeline can pick the
 *      right one based on `ctx.target().arch`. The
 *      `mx::arch::IVmBackend` sketch interface
 *      (`include/mxprotector/arch/vm_backend.hpp`) describes the
 *      eventual seam — `X64VmBackend` will implement it once the
 *      `vm::VmRuntime` ↔ `arch::VmBackendRuntime` typedef bridge
 *      lands. For now we keep the seam at the concrete class so the
 *      x64 refactor lands without touching the arch package.
 *
 *   2. Internal helpers grow. The orchestration uses many
 *      x64-specific lambdas / tables / patch records. Hiding them
 *      inside a class with private members is cleaner than a nest
 *      of free helpers in an anonymous namespace inside a single
 *      .cpp file.
 *
 * All of the byte-emission machinery this class drives lives in
 * `x64_emitters.hpp`, `x64_vflags.hpp`, and `x64_handlers.hpp`.
 */

#pragma once

#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::vm::x64 {

class X64VmBackend final {
public:
    /// Generate a complete VM runtime blob for the given lifted
    /// instructions. The signature mirrors `VmRuntimeGenerator::generate`
    /// so the facade can forward without touching the result.
    [[nodiscard]] MxResult<VmRuntime> generate(
        const std::vector<VmInstruction>& instructions,
        Randomizer& rng,
        VmGenOptions opts);
};

} // namespace mx::vm::x64
