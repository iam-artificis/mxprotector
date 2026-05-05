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

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/arch/vm_backend.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::vm::x64 {

/**
 * @brief x64 implementation of `arch::IVmBackend`.
 *
 * This is the only backend that ships today. The class is an empty value
 * type — all per-call state lives in `GenerationSession` inside the
 * implementation file — so it is cheap to instantiate one per region.
 *
 * Implementing `arch::IVmBackend` lets the rest of the pipeline (today
 * `vm::VmRuntimeGenerator`, tomorrow virtualization-pass / packer-VM-lifter
 * factories) talk to backends through the abstract interface. Adding an
 * arm64 backend will be a sibling class implementing the same interface;
 * no caller has to special-case x64.
 */
class X64VmBackend final : public arch::IVmBackend {
public:
    [[nodiscard]] arch::ArchInfo arch() const noexcept override {
        return arch::ArchInfo::x64_baseline();
    }

    /// Generate a complete VM runtime blob for the given lifted
    /// instructions. The signature mirrors `VmRuntimeGenerator::generate`
    /// so the facade can forward without touching the result.
    [[nodiscard]] MxResult<VmRuntime> generate(
        const std::vector<VmInstruction>& instructions,
        Randomizer& rng,
        VmGenOptions opts) override;
};

/**
 * @brief Factory that produces `X64VmBackend` for the x64 family.
 *
 * Selected by `vm::VmRuntimeGenerator` based on `ctx.target().arch`. Future
 * arm64 / Cortex-M factories will sit alongside this one and the pipeline's
 * factory selector picks the right one.
 */
class X64VmBackendFactory final : public arch::IVmBackendFactory {
public:
    [[nodiscard]] arch::ArchFamily supported_family() const noexcept override {
        return arch::ArchFamily::x64;
    }

    [[nodiscard]] MxResult<std::unique_ptr<arch::IVmBackend>>
        create(arch::ArchInfo info) override;
};

} // namespace mx::vm::x64
