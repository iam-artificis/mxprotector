/**
 * @file x64_vm_session.cpp
 * @brief Implementation — `GenerationSession::run` + light steps.
 *
 * Holds the orchestrator (`run`) and the small step methods that
 * delegate emission to the dedicated sibling files
 * (`x64_bytecode_encoder.cpp`, `x64_entry_stub.cpp`,
 * `x64_handler_emitter.cpp`, `x64_inner_vm.cpp`,
 * `x64_blob_patcher.cpp`).
 *
 * `step1_randomize` lives in `x64_vm_session_step1.cpp` because the
 * per-build randomisation logic (~150 LOC of policy) is the largest
 * and most independently testable step.
 */

#include "x64_vm_session.hpp"

#include <cstring>

#include "mxprotector/protection/vm/x64/x64_blob_patcher.hpp"
#include "mxprotector/protection/vm/x64/x64_entry_stub.hpp"
#include "mxprotector/protection/vm/x64/x64_handler_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

namespace mx::vm::x64 {

// ============================================================================
//                          run — pipeline dispatch
// ============================================================================

MxResult<VmRuntime> GenerationSession::run() {
    emit_exit_as_jmp = opts.emit_exit_as_jmp;

    if (auto r = step1_randomize(); !r) {
        return std::unexpected(r.error());
    }
    step2_emit_bytecode();
    step3a_emit_entry_stub();
    step3_emit_handlers();
    step3f_emit_inner_vm_runtime();
    step3g_emit_table_and_bytecode();
    if (auto r = step4_apply_patches(); !r) {
        return std::unexpected(r.error());
    }

    VmRuntime result;
    result.blob            = std::move(rt.buf);
    result.entry_offset    = static_cast<uint32_t>(entry_offset);
    result.bytecode_offset = static_cast<uint32_t>(bytecode_offset);
    result.bytecode_size   = static_cast<uint32_t>(bytecode_plain.size());
    result.handler_count   = total_handlers;
    result.handler_table_offset = static_cast<uint32_t>(handler_table_offset);
    result.inner_vm_handler_table_offset = static_cast<uint32_t>(
        inner_vm_entry_offset + x64::kInnerVmHandlerTableOffset);
    result.inner_vm_handler_table_size = static_cast<uint32_t>(
        x64::kInnerVmHandlerTableSize);
    result.opcode_map      = map;
    result.exit_jmp_patch  = exit_jmp_offset;
    return result;
}

// ============================================================================
//                          Step 2 — bytecode encoding
// ============================================================================
//
// Delegated to `x64_bytecode_encoder.cpp`. The encoder is a pure
// data-in / data-out pass: given the phase-1 outputs and the shared
// `Randomizer`, it returns the encrypted bytecode, the per-instruction
// native-handler map, and the `has_branches` / `rolling` flags that
// downstream handler emission needs to pick the right cipher mode.
// ============================================================================

void GenerationSession::step2_emit_bytecode() {
    const BytecodeEncoderInputs encoder_in{
        instructions,
        specializations,
        variant_handler_ids,
        native_handler_ids,
        per_handler_key,
        initial_key,
        layout,
        rng,
    };
    BytecodeEncoderOutputs encoder_out = encode_bytecode(encoder_in);
    bytecode_plain         = std::move(encoder_out.bytecode);
    native_handler_of_insn = std::move(encoder_out.native_handler_of_insn);
    has_branches           = encoder_out.has_branches;
    rolling                = encoder_out.rolling;
}

// ============================================================================
//                         Step 3a — entry stub emission
// ============================================================================
//
// Delegated to `x64_entry_stub.cpp`. The emitter owns the full byte
// layout of the entry stub (pushfq, G7 pad, 16 register pushes,
// rolling-key seed, vflags scramble, ImageBase-derived handler-table
// key block, G6 loop + MBA + integrity check, anti-emulation /
// anti-tamper picks, lea r11 + inline first dispatch) and appends to
// the caller's patch sinks (`table_patches`, `table_key_patches`,
// `self_crc_patches`) as it goes.
//
// The inner-VM ISA permutation and the trampoline bookkeeping are
// not strictly part of the entry stub — they're session-level state
// consumed by step 3b / step 3f — so they're initialised here after
// the stub emission.
// ============================================================================

void GenerationSession::step3a_emit_entry_stub() {
    const EntryStubInputs stub_in{
        opts, layout,
        rolling_key_disp, rflags_disp,
        initial_key, vflags_key, vflags_rol,
        rolling, total_handlers, rng,
    };
    const EntryStubSinks sinks{
        table_patches, table_key_patches, self_crc_patches,
    };
    const EntryStubOutputs stub_out = emit_entry_stub(rt, stub_in, sinks);

    entry_offset             = stub_out.entry_offset;
    entry_bc_patch           = stub_out.entry_bc_patch;
    entry_bc_patch_end       = stub_out.entry_bc_patch_end;
    imagebase_key_disp       = stub_out.imagebase_key_disp;
    table_xor_key            = stub_out.table_xor_key;
    integrity_expected_patch = stub_out.integrity_expected_patch;
    // `integrity_table_lea_patch` is already recorded inside
    // `sinks.table_patches` by the entry-stub emitter; the patcher
    // walks that list without a dedicated entry on the Session.

    // Per-build inner-VM ISA permutation. Computed ONCE here and
    // threaded through every nested-wrapper emission + the final
    // `emit_inner_vm_runtime` call — so the byte values in the inline
    // inner bytecodes and the handler table ordering agree.
    inner_vm_isa = make_random_inner_vm_isa(rng);

    // Reset per-handler emission bookkeeping.
    handler_offset_by_id.assign(total_handlers, SIZE_MAX);

    // G5 trampoline bookkeeping — see `queue_trampoline_chain` /
    // `emit_one_pending_trampoline` for the invariants.
    trampoline_offset_by_slot.reserve(total_handlers * 2);
    head_slot_of_handler.assign(total_handlers, UINT32_MAX);
    pending_trampolines.reserve(total_handlers * 2);
    trampoline_fixups.reserve(total_handlers * 2);
}

// ============================================================================
//   Step 3 (handlers) — generic + native + specialised + trampoline drain
// ============================================================================
//
// Delegated to `x64_handler_emitter.cpp`. The emitter owns the huge
// `emit_op_variant` switch, the trampoline-chain bookkeeping (G5),
// the G4 per-handler fold-in helper, the begin/end-handler hooks, and
// the three emission loops (generic, native, specialised) + the
// deterministic drain.
// ============================================================================

void GenerationSession::step3_emit_handlers() {
    const HandlerEmitterInputs handler_in{
        rt, rng,
        rolling_key_disp, imagebase_key_disp,
        rolling, has_branches,
        vflags_key, vflags_rol, rflags_disp, native_shift,
        layout, emit_exit_as_jmp,
        per_handler_key, variant_handler_ids,
        native_handler_ids, specializations,
        instructions, native_handler_of_insn,
        inner_vm_isa,
    };
    HandlerEmitterSinks handler_sinks{
        handler_offset_by_id, trampoline_offset_by_slot,
        head_slot_of_handler, pending_trampolines,
        trampoline_fixups, table_patches,
        table_key_patches, inner_vm_call_patches,
        exit_jmp_offset,
    };
    emit_all_handlers(handler_in, handler_sinks);
}

// ============================================================================
//                      Step 3f — inner VM runtime (G2)
// ============================================================================
//
// Emit the 88-byte inner VM runtime (dispatcher + 6 inner handlers +
// relative handler table) exactly once per outer VM blob, and patch
// every outer handler's `call rel32 inner_vm_entry` that was left
// zero-filled during emission.
//
// The inner VM is placed AFTER the last outer handler and BEFORE the
// outer handler table. Putting it here means:
//   - Outer handlers that use V2 reference it via a forward rel32
//     `call`, which is the normal dispatch direction.
//   - The outer handler table still comes last, right before the
//     bytecode stream, so the existing rel32 patches to
//     `handler_table_offset` aren't affected.
//   - If no outer handler ended up choosing V2 for any instance, the
//     inner VM block still exists but is dead code. 88 bytes of
//     overhead is acceptable.
//
// The inner VM is self-contained: all of its intra-block branches
// (rel8 jumps back to the dispatch loop) and the rip-relative
// `lea r13, handler_table` are computed at emit time from static
// offsets. No runtime patches are needed.
// ============================================================================

void GenerationSession::step3f_emit_inner_vm_runtime() {
    // Align to 16 so the dispatcher entry is instruction-cache
    // friendly and so a future self-mutation pass can trivially find
    // the block by scanning for a 16-byte-aligned signature.
    while (rt.size() % 16 != 0) rt.u8(0xCC);
    inner_vm_entry_offset = rt.size();
    (void) emit_inner_vm_runtime(rt, inner_vm_isa);

    // Patch every G2 V2 outer-handler's `call rel32 inner_vm_entry`
    // now that the inner VM entry has a definite offset.
    for (const size_t rel32_patch : inner_vm_call_patches) {
        const size_t call_end = rel32_patch + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(inner_vm_entry_offset) -
            static_cast<int64_t>(call_end));
        std::memcpy(rt.buf.data() + rel32_patch, &rel, 4);
    }
}

// ============================================================================
//                Step 3g — handler table + bytecode layout
// ============================================================================

void GenerationSession::step3g_emit_table_and_bytecode() {
    // Align to 4 bytes so the 32-bit entries are naturally aligned.
    while (rt.size() % 4 != 0) rt.u8(0xCC);
    handler_table_offset = rt.size();
    for (uint32_t h = 0; h < total_handlers; ++h) {
        rt.u32(0);  // placeholder, patched below
    }

    while (rt.size() % 8 != 0) rt.u8(0xCC);
    bytecode_offset = rt.size();
    rt.bytes(ByteView{bytecode_plain.data(), bytecode_plain.size()});
}

// ============================================================================
//                        Step 4 — apply all patches
// ============================================================================
//
// Delegated to `x64_blob_patcher.cpp`. Session passes references to
// every patch record / offset list it accumulated during steps
// 3a–3g; the patcher walks them in the right order to finalise the
// blob.
// ============================================================================

MxResult<void> GenerationSession::step4_apply_patches() {
    const BlobPatchInputs patch_in{
        entry_bc_patch, entry_bc_patch_end, bytecode_offset,
        table_patches, handler_table_offset,
        table_key_patches, table_xor_key,
        trampoline_fixups, handler_offset_by_id, trampoline_offset_by_slot,
        total_handlers, head_slot_of_handler,
        integrity_expected_patch,
        self_crc_patches,
    };
    return apply_blob_patches(rt, patch_in);
}

} // namespace mx::vm::x64
