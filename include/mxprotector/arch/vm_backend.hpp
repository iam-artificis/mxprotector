/**
 * @file vm_backend.hpp
 * @brief Abstract VM runtime generator — one impl per target architecture.
 *
 * Today's `vm::VmRuntimeGenerator` (in
 * `src/builder/protection/vm/vm_runtime_gen.cpp`) is a thin facade over
 * `vm::x64::X64VmBackend`. The x64 backend bakes every mechanical decision —
 * register layout, flag scrambling, handler dispatch, stream cipher trick —
 * directly into x86-64 byte emission. That's fine while x64 is the only
 * target, but painful to replicate for arm64 because arm64 differs in every
 * mechanical detail:
 *
 *   - 31 GPRs instead of 16
 *   - fixed 32-bit instruction width
 *   - condition flags in NZCV, not RFLAGS
 *   - no push/pop (must use STP/LDP with explicit SP updates)
 *   - no inline stream-cipher trick with pushfq/popfq
 *   - branches use cond-codes + label form, not rel8/rel32 jcc
 *
 * `IVmBackend` is the seam. Each architecture implements the contract once
 * and the rest of the pipeline talks to backends through this interface.
 *
 * Why `vm::VmRuntime` directly (and not a separate `arch::VmBackendRuntime`)
 * --------------------------------------------------------------------------
 * The runtime blob's shape — entry offset, bytecode offset/size, handler
 * count, dispatch table offset, opcode permutation — is *conceptually*
 * arch-agnostic. Every backend that uses a dispatch-driven VM will have
 * the same metadata. Keeping `vm::VmRuntime` as the canonical type avoids
 * a parallel struct and a conversion layer; the arch package legitimately
 * depends on the vm package because vm is the contract every backend
 * produces.
 *
 * Status
 * ------
 *   * `IVmBackend` — declared and implemented by `vm::x64::X64VmBackend`.
 *   * `IVmBackendFactory` — declared and implemented by
 *     `vm::x64::X64VmBackendFactory`. Today's pipeline uses it through
 *     `vm::VmRuntimeGenerator`, which forwards to the registered factory
 *     for the target's arch family.
 *   * Future arm64 backend lands as a sibling factory + impl; no churn
 *     in passes that already speak `IVmBackend`.
 */

#pragma once

#include <memory>
#include <vector>

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx::arch {

/**
 * @brief Architecture-specific VM runtime backend.
 *
 * The shared VM pipeline holds one instance per build (or per region group).
 * Calling `generate` produces a fully-assembled runtime blob. Everything
 * x64-specific inside `vm::x64::X64VmBackend` — register layout, pushfq
 * tricks, NZCV vs RFLAGS, handler dispatch via `lea rcx, [rip+rel32]` +
 * `jmp rcx`, stream cipher via in-line `xor [rsp+disp]` — is internal to
 * that backend. Future arm64 backend implements the same `generate`
 * contract via:
 *
 *   - register layout: 31 GPRs, use SP-relative LDP/STP for push/pop
 *   - flag handling: explicit MRS/MSR NZCV, or computed predicates in GPRs
 *   - handler dispatch: ADR + LDR + BR via a relative table
 *   - stream cipher: 4-byte XOR via LDR/LDR/EOR/STR
 *
 * Thread-safety: one instance per pipeline, single-threaded.
 */
class IVmBackend {
public:
    virtual ~IVmBackend() = default;

    /// @brief Architecture this backend targets.
    [[nodiscard]] virtual ArchInfo arch() const noexcept = 0;

    /// @brief Assemble a VM runtime blob for the given lifted instructions.
    [[nodiscard]] virtual MxResult<vm::VmRuntime> generate(
        const std::vector<vm::VmInstruction>& instructions,
        Randomizer& rng,
        vm::VmGenOptions opts) = 0;
};

/**
 * @brief Factory selector — picks the backend for a target architecture.
 *
 * The pipeline calls `create()` once per build (or per region group) to
 * obtain the `IVmBackend` matching `ctx.target().arch`. If the target is
 * unsupported (e.g. Cortex-M before its backend ships), `create()` returns
 * an error and the caller's `is_applicable()` guard downgrades the pass
 * gracefully.
 */
class IVmBackendFactory {
public:
    virtual ~IVmBackendFactory() = default;

    /// Architecture family this factory can produce backends for.
    [[nodiscard]] virtual ArchFamily supported_family() const noexcept = 0;

    /// Construct a backend for `info`. `info.family` must match
    /// `supported_family()`.
    [[nodiscard]] virtual MxResult<std::unique_ptr<IVmBackend>>
        create(ArchInfo info) = 0;
};

} // namespace mx::arch
