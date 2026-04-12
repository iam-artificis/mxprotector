/**
 * @file vm_backend.hpp
 * @brief Abstract VM runtime generator — one impl per target architecture.
 *
 * Today's `VmRuntimeGenerator` (in `src/builder/protection/vm/vm_runtime_gen.cpp`)
 * is an x64-only ~2K LOC monster that bakes every decision — from register
 * layout to flag scrambling to handler dispatch — directly into x86-64 byte
 * emission. That's fine while x64 is the only target, but painful to
 * replicate for arm64 because arm64 differs in every mechanical detail:
 *
 *   - 31 GPRs instead of 16
 *   - fixed 32-bit instruction width
 *   - condition flags in NZCV, not RFLAGS
 *   - no push/pop (must use STP/LDP with explicit SP updates)
 *   - no inline stream-cipher trick with pushfq/popfq
 *   - branches use cond-codes + label form, not rel8/rel32 jcc
 *
 * `IVmBackend` is the seam. The *shared* VM runtime engine (instruction
 * lifting, handler permutation, rolling-key encryption, polymorphism
 * variant selection — all the *policy*) stays container- and arch-
 * agnostic. The *mechanical* emission — how a push becomes actual bytes,
 * how vEFLAGS is represented, where handlers live — is delegated to a
 * backend implementing this interface.
 *
 * Phase 5 plan
 * ------------
 * 1. Extract everything target-agnostic from `vm_runtime_gen.cpp` into a
 *    new `VmRuntimeEngine` that operates on `IVmBackend` instead of raw
 *    bytes.
 * 2. Ship `X64VmBackend` as the single existing implementation. The x64
 *    pipeline keeps working unchanged (engine → backend → same bytes).
 * 3. Ship `Arm64VmBackend` alongside it — new file, same interface.
 *    Arm64 builds start working the moment the backend is feature-complete.
 * 4. Ship `CortexMVmBackend` later for bare-metal / RTOS targets (probably
 *    with a reduced polymorphism palette since Thumb-2 encoding is more
 *    restrictive).
 *
 * This header is the contract for that refactor. It is declared but not
 * implemented today; nothing references it from the existing x64 pipeline.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"

namespace mx::arch {

/**
 * @brief Output of a VM backend: the runtime blob and its metadata.
 *
 * Same shape as `mx::vm::VmRuntime` today. Included here so the interface
 * doesn't leak the existing x64-specific struct — when the engine refactor
 * lands, `vm::VmRuntime` can be replaced by (or become a typedef for) this.
 */
struct VmBackendRuntime {
    ByteBuffer blob;                 ///< Full runtime: entry + handlers + table + bytecode
    uint32_t   entry_offset    = 0;  ///< Offset of entry point inside `blob`
    uint32_t   bytecode_offset = 0;  ///< Offset of the bytecode stream
    uint32_t   bytecode_size   = 0;
    uint32_t   handler_count   = 0;
    vm::VmOpcodeMap opcode_map;

    /// For Cross-VM: if non-zero, the exit stub ends with `jmp rel32`
    /// (or equivalent branch) at this offset, and the caller patches it
    /// to the next sub-VM's entry.
    uint32_t exit_jmp_patch = 0;
};

/**
 * @brief Parameters for a single VM runtime emission.
 *
 * Carried by the shared engine and passed to the backend so the backend
 * never has to touch the engine's state directly. The engine decides
 * policy (which polymorphism variants, which key, which register layout),
 * the backend executes the mechanics.
 */
struct VmRuntimeRequest {
    const std::vector<vm::VmInstruction>* instructions = nullptr;
    Randomizer*                           rng          = nullptr;

    /// If true, the exit stub emits a branch to a sibling blob (Cross-VM).
    /// The backend writes a placeholder; the caller patches `exit_jmp_patch`.
    bool emit_exit_as_jmp = false;
};

/**
 * @brief Architecture-specific VM runtime backend.
 *
 * The shared VM engine holds one instance per build. It calls `generate`
 * and receives a fully-assembled runtime blob. Everything x64-specific
 * inside today's `vm_runtime_gen.cpp` — register layout, pushfq tricks,
 * NZCV vs RFLAGS, handler dispatch via `lea rcx, [rip+rel32]` + `jmp rcx`,
 * stream cipher via in-line `xor [rsp+disp]` — moves into the x64 backend.
 * The arm64 backend will implement the same operations via arm64-native
 * mechanisms:
 *
 *   - register layout: 31 GPRs, use SP-relative LDP/STP pairs for push/pop
 *   - flag handling: explicit MRS/MSR NZCV, or keep computed predicates
 *     in ordinary GPRs
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

    /// @brief Assemble a VM runtime blob for the given request.
    [[nodiscard]] virtual MxResult<VmBackendRuntime>
        generate(const VmRuntimeRequest& req) = 0;
};

/**
 * @brief Factory selector — picks the backend for a target architecture.
 *
 * The pipeline calls this once per build (or per region group) to get the
 * `IVmBackend` matching `ctx.target().arch`. If the target is unsupported
 * (e.g. Cortex-M before its backend ships), the factory returns an error
 * and the `VirtualizationPass::is_applicable()` guard downgrades the pass
 * gracefully.
 */
class IVmBackendFactory {
public:
    virtual ~IVmBackendFactory() = default;

    [[nodiscard]] virtual ArchFamily supported_family() const noexcept = 0;

    [[nodiscard]] virtual MxResult<std::unique_ptr<IVmBackend>>
        create(ArchInfo info) = 0;
};

} // namespace mx::arch
