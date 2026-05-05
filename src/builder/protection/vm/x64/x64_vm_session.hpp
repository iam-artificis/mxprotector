/**
 * @file x64_vm_session.hpp
 * @brief Private — `GenerationSession` for the x64 VM backend.
 *
 * The session owns all per-call state for one
 * `X64VmBackend::generate` invocation and drives the seven-step
 * pipeline (randomize → encode → entry → handlers → inner VM →
 * table+bytecode → patch). Implementations live in two sibling
 * `.cpp` files:
 *
 *   * `x64_vm_session.cpp`        — class data, `run()`, and the
 *     light delegating step methods (step2..step4 + step3a/3/3f/3g).
 *   * `x64_vm_session_step1.cpp`  — `step1_randomize`, the heavy
 *     per-build policy step (opcode permutation, vEFLAGS scramble,
 *     stack layout, specialization picks, handler-id shuffle,
 *     per-handler keys).
 *
 * Lives in `src/builder/protection/vm/x64/` — internal to the
 * x64 VM backend. Public consumers see only `X64VmBackend` from
 * `mxprotector/protection/vm/x64/x64_vm_backend.hpp`.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"
#include "mxprotector/protection/vm/x64/x64_bytecode_encoder.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_patch_records.hpp"

namespace mx::vm::x64 {

/**
 * @brief One run of the x64 VM backend.
 *
 * Holds every piece of per-call state as a member so the step
 * methods can share them without lambda captures. Field names mirror
 * the original locals (no trailing underscore) so the implementation
 * reads as a procedural pipeline. Construct → call `run()` → throw
 * away.
 */
class GenerationSession {
public:
    GenerationSession(const std::vector<VmInstruction>& in_instructions,
                      Randomizer& in_rng,
                      VmGenOptions in_opts) noexcept
        : instructions(in_instructions), rng(in_rng), opts(in_opts) {}

    /// Run the full pipeline. Returns the assembled `VmRuntime` blob
    /// or an `MxError` if a step fails (handler budget exhausted,
    /// orphaned trampoline chain, etc).
    MxResult<VmRuntime> run();

private:
    // ==== Inputs ============================================================
    const std::vector<VmInstruction>& instructions;
    Randomizer& rng;
    VmGenOptions opts;
    bool emit_exit_as_jmp{};

    // ==== Step 1 — per-build randomization outputs ==========================
    VmOpcodeMap map{};
    uint8_t initial_key{};
    uint32_t vflags_key{};
    uint32_t vflags_rol{};
    VmStackLayout layout{};
    int32_t rolling_key_disp{};
    int32_t rflags_disp{};
    int32_t native_shift{};
    uint32_t total_handlers{};
    std::vector<Specialization> specializations;
    std::vector<std::vector<uint8_t>> variant_handler_ids;
    std::vector<uint8_t> native_handler_ids;
    std::vector<uint8_t> per_handler_key;

    // ==== Step 2 — bytecode encoding (only the fields that outlive the
    //               encoder pass; everything else — spec_match, dead/opq
    //               insertion counts, bc_offset, fold events — lives and
    //               dies inside `encode_bytecode`).
    ByteBuffer            bytecode_plain;
    std::vector<uint32_t> native_handler_of_insn;
    bool                  has_branches{};
    bool                  rolling{};

    // ==== Step 3 — runtime blob state =======================================
    RawEmitter rt;

    // Patch record types (`TablePatch`, `TrampolineTarget`,
    // `PendingTrampoline`, `TrampolineFixup`) are shared with the entry
    // stub emitter and other step-3 components via
    // `x64_vm_patch_records.hpp`.
    std::vector<TablePatch> table_patches;
    std::vector<anti_tamper::SelfCrcPatchRecord> self_crc_patches;

    size_t entry_offset{};
    int32_t imagebase_key_disp{-1};
    uint32_t table_xor_key{};
    size_t integrity_expected_patch{};

    size_t entry_bc_patch{};
    size_t entry_bc_patch_end{};

    std::vector<size_t> table_key_patches;
    std::vector<size_t> handler_offset_by_id;

    std::vector<size_t>            trampoline_offset_by_slot;
    std::vector<uint32_t>          head_slot_of_handler;
    std::vector<PendingTrampoline> pending_trampolines;
    std::vector<TrampolineFixup>   trampoline_fixups;
    uint32_t exit_jmp_offset{};
    std::vector<size_t> inner_vm_call_patches;
    InnerVmIsa inner_vm_isa{};
    size_t inner_vm_entry_offset{};
    size_t handler_table_offset{};
    size_t bytecode_offset{};

    // ==== Step methods ======================================================
    [[nodiscard]] MxResult<void> step1_randomize();
    void                         step2_emit_bytecode();
    void                         step3a_emit_entry_stub();
    void                         step3_emit_handlers();
    void                         step3f_emit_inner_vm_runtime();
    void                         step3g_emit_table_and_bytecode();
    [[nodiscard]] MxResult<void> step4_apply_patches();
};

} // namespace mx::vm::x64
