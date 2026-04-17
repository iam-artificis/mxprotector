/**
 * @file x64_vm_backend.hpp
 * @brief [BUILDER, x64] X64-specific VM runtime backend — public entry.
 *
 * `X64VmBackend` is the facade the caller uses to produce a finished
 * VM runtime blob for one virtualised region. The class is an empty
 * value type: all per-call state lives in a session helper inside the
 * implementation file (`GenerationSession`), and the step pipeline is
 * split across five sibling compilation units:
 *
 *   * `x64_bytecode_encoder.{hpp,cpp}` — instructions → encrypted
 *     bytecode + native-handler index map.
 *   * `x64_entry_stub.{hpp,cpp}` — entry pushfq + 16 pushes + rolling-
 *     key seed + vflags scramble + ImageBase key block (G6 loop +
 *     MBA + integrity check) + anti-emulation / anti-tamper picks +
 *     inline first dispatch.
 *   * `x64_handler_emitter.{hpp,cpp}` — every handler body (generic
 *     + per-instruction native + G1 specialised) with G5 trampoline
 *     bookkeeping and the deterministic drain.
 *   * `x64_inner_vm.{hpp,cpp}` — the shared 88-byte nested interpreter
 *     (called directly from the orchestrator's step-3f).
 *   * `x64_blob_patcher.{hpp,cpp}` — rel32 fixups, trampoline chain
 *     fixups, handler-table entry encryption, integrity expected-sum,
 *     self-CRC finalisation.
 *
 * Shared types: `x64_vm_patch_records.hpp` defines the small patch-
 * record structs (`TablePatch`, `TrampolineTarget`, `PendingTrampoline`,
 * `TrampolineFixup`) that cross component boundaries. Compile-time
 * variant metadata lives in `x64_vm_variants.hpp`.
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
 *   2. The class is the obvious extension point when a new per-call
 *      option shows up — subclassing the facade or swapping the
 *      session helper is cheaper than juggling many free functions.
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
