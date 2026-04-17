/**
 * @file x64_handler_emitter.hpp
 * @brief [BUILDER, x64] VM handler emission (generic / native / specialised)
 *        + G5 trampoline-chain bookkeeping.
 *
 * Performs the central pass of the runtime-blob construction:
 *
 *   * Generic handlers — one body per variant of every canonical VmOp.
 *     Variants are emitted in order; each handler body ends with the
 *     G4 per-handler rolling-key fold-in + the tail dispatch.
 *   * Per-instruction native handlers — one body per `VmOp::native`
 *     encountered during lifting. Saves the native ctx onto the stack,
 *     restores rflags, runs the original x86 bytes, stores rflags back,
 *     restores ctx, dispatches.
 *   * G1 specialised handlers — zero or more bodies with dst/src slot
 *     displacements baked in. Emitted after natives so their handler
 *     ids land at the tail of the shuffled slot space.
 *   * G5 trampoline drain — flushes any trampoline entries queued by
 *     the emission loops but not drained by the interleaved random
 *     draws. The deterministic drain guarantees every chain head /
 *     intermediate / terminal eventually gets its offset recorded.
 *
 * Inputs are the phase-1 + phase-2 outputs (layout / keys / cipher
 * mode / handler-id tables / specialisations / inner-VM ISA /
 * instruction list / native-handler-of-insn map).
 *
 * Sinks are the caller-owned bookkeeping lists: per-handler offsets
 * and trampoline chain state for step 4's handler-table patcher, plus
 * the shared rel32 / table-key / inner-VM-call patch lists every
 * emitter contributes to.
 *
 * `exit_jmp_offset` is written by the exit handler body when the
 * region is emitted as a cross-VM `jmp rel32` instead of a `ret`.
 * Zero in normal builds.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"
#include "mxprotector/protection/vm/x64/x64_bytecode_encoder.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_patch_records.hpp"

namespace mx::vm::x64 {

struct HandlerEmitterInputs {
    RawEmitter&                              rt;
    Randomizer&                              rng;

    int32_t                                  rolling_key_disp;
    int32_t                                  imagebase_key_disp;
    bool                                     rolling;
    bool                                     has_branches;

    uint32_t                                 vflags_key;
    uint32_t                                 vflags_rol;
    int32_t                                  rflags_disp;
    int32_t                                  native_shift;
    const VmStackLayout&                     layout;
    bool                                     emit_exit_as_jmp;

    const std::vector<uint8_t>&              per_handler_key;
    const std::vector<std::vector<uint8_t>>& variant_handler_ids;
    const std::vector<uint8_t>&              native_handler_ids;
    const std::vector<Specialization>&       specializations;

    const std::vector<VmInstruction>&        instructions;
    const std::vector<uint32_t>&             native_handler_of_insn;

    const InnerVmIsa&                        inner_vm_isa;
};

struct HandlerEmitterSinks {
    std::vector<size_t>&            handler_offset_by_id;
    std::vector<size_t>&            trampoline_offset_by_slot;
    std::vector<uint32_t>&          head_slot_of_handler;
    std::vector<PendingTrampoline>& pending_trampolines;
    std::vector<TrampolineFixup>&   trampoline_fixups;
    std::vector<TablePatch>&        table_patches;
    std::vector<size_t>&            table_key_patches;
    std::vector<size_t>&            inner_vm_call_patches;
    uint32_t&                       exit_jmp_offset;
};

/// Emit every handler body for the runtime blob in the canonical order:
/// generic → native → specialised → trampoline drain. Appends into the
/// caller-owned sinks as it goes.
void emit_all_handlers(const HandlerEmitterInputs& in,
                       HandlerEmitterSinks         sinks);

} // namespace mx::vm::x64
