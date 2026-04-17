/**
 * @file x64_vm_backend.cpp
 * @brief [BUILDER, x64] X64-specific VM runtime backend.
 *
 * Owns `X64VmBackend::generate`, the orchestration that used to live
 * inside `VmRuntimeGenerator::generate` in the legacy
 * `vm_runtime_gen.cpp` monolith. The byte emission has moved into
 * `x64_emitters.cpp`, `x64_vflags.cpp`, and `x64_handlers.cpp`. This
 * file is the conductor: it picks per-build randomization, lays out
 * the bytecode stream, drives the entry stub, every handler body,
 * the per-instruction native-escape handlers, the encrypted handler
 * table, and the final patch-up.
 *
 * Internal structure: the orchestration lives in `GenerationSession`,
 * a session-scoped class in the anonymous namespace that holds every
 * per-call piece of state (RawEmitter, bytecode buffer, patch lists,
 * trampoline bookkeeping, per-build random parameters) as members and
 * implements the step pipeline as private methods. `X64VmBackend::generate`
 * is a thin facade: validate inputs, construct a session, run it.
 * The split prepares for follow-on refactors (R1.3+) that extract
 * individual steps into dedicated files; the field names mirror the
 * original locals so future extractions move bodies verbatim.
 */

#include "mxprotector/protection/vm/x64/x64_vm_backend.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <numeric>

#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/anti_emulation/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/check_registry.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"
#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"
#include "mxprotector/protection/cfg/mba_transition_gen.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"
#include "mxprotector/protection/vm/x64/x64_bytecode_encoder.hpp"
#include "mxprotector/protection/vm/x64/x64_emitters.hpp"
#include "mxprotector/protection/vm/x64/x64_entry_stub.hpp"
#include "mxprotector/protection/vm/x64/x64_handler_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm_wrappers.hpp"
#include "mxprotector/protection/vm/x64/x64_vflags.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_patch_records.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

namespace mx::vm::x64 {

namespace {

// `Specialization` (the runtime (op, dst_vreg, src_vreg, handler_id)
// tuple) is defined in `x64_bytecode_encoder.hpp`, which the encoder
// and this file share. The compile-time metadata
// (`kMaxSpecializations`, `kSpecializableOps`, `is_specializable_op`,
// `alu_op_mr_for`, `variant_count_for`) lives in `x64_vm_variants.hpp`.

// ----------------------------------------------------------------------------
// GenerationSession — one run of the backend.
//
// Holds every piece of per-call state as a member so the step methods and
// the former emit-lambdas can share them without capture. Field names
// mirror the original locals (no trailing underscore) so lambda bodies
// translate to method bodies verbatim — the only transformation is the
// `auto X = [&](...) { ... };` → `void GenerationSession::X(...) { ... }`
// wrapping change.
// ----------------------------------------------------------------------------
class GenerationSession {
public:
    GenerationSession(const std::vector<VmInstruction>& in_instructions,
                      Randomizer& in_rng,
                      VmGenOptions in_opts)
        : instructions(in_instructions), rng(in_rng), opts(in_opts) {}

    /// Runs the full pipeline. Returns the assembled `VmRuntime` blob or
    /// an `MxError` if a step fails (handler budget exhausted, orphaned
    /// trampoline chain, etc).
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
    uint32_t native_count{};
    uint32_t generic_variant_total{};
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
    size_t integrity_table_lea_patch{};
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

// ============================================================================
//                            Session::run — dispatch
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
    result.opcode_map      = map;
    result.exit_jmp_patch  = exit_jmp_offset;
    return result;
}

// ============================================================================
//                        Step 1 — per-build randomization
// ============================================================================
//
// Opcode handler_id permutation, handler variant assignment, initial
// rolling key, vEFLAGS scramble (key + rol), G1 specialisation pool,
// G4 per-handler rolling-key fold-in bytes.
// ============================================================================

MxResult<void> GenerationSession::step1_randomize() {
    do { map.opcode_xor_key = rng.next_u8(); } while (map.opcode_xor_key == 0);
    initial_key = map.opcode_xor_key;

    // vEFLAGS transform: stored_slot = rol(real_rflags, vflags_rol) ^ vflags_key
    //   - key is a full 32-bit random — can land bits anywhere because the exit
    //     stub fully descrambles before popfq (no writable-bits constraint)
    //   - rol is 1..31 (non-zero) so the shape of the `xor imm32; popfq` pattern
    //     breaks completely: the imm32 differs between slots, and there's
    //     always a rol/ror instruction adjacent to it
    vflags_key = rng.next_u32() | 1;      // any non-zero u32
    vflags_rol = rng.next_range(1, 31);   // rotate amount 1..31

    // Per-build random VM stack layout: which virtual slot hosts each native
    // GPR, which slot is the junk slot, AND how many extra padding qwords
    // sit between the GPR area and the RFLAGS slot (G7 randomization).
    // Cross-VM sub-VMs use independent layouts — register state flows
    // between them via CPU, not via slots.
    layout           = VmStackLayout::make_random(rng);
    rolling_key_disp = layout.rolling_key_disp;
    rflags_disp      = layout.rflags_offset();
    native_shift     = layout.native_frame_shift();

    native_count = static_cast<uint32_t>(std::count_if(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) { return v.op == VmOp::native; }));

    // Total generic variant slots (sum of variants across all canonical VmOps).
    generic_variant_total = 0;
    for (uint32_t i = 0; i < kVmOpCount; ++i) {
        generic_variant_total += variant_count_for(static_cast<VmOp>(i));
    }

    // ------------------------------------------------------------------------
    // G1 — Generate per-build handler specialisations.
    //
    // We pick at most `kMaxSpecializations` random (op, dst_vreg, src_vreg)
    // tuples from {mov_rr, add_rr, sub_rr, xor_rr, and_rr, or_rr} × non-junk
    // slots. Duplicates are skipped. Cap by the available handler-id budget
    // so total_handlers never exceeds 255 (the encoder uses uint8 IDs).
    // ------------------------------------------------------------------------
    {
        // Build the candidate vreg pool: every slot index except the junk
        // slot (which holds the rolling key — writing to it would corrupt
        // the cipher).
        std::vector<uint8_t> non_junk_slots;
        non_junk_slots.reserve(VmStackLayout::kSlotCount - 1);
        for (uint8_t v = 0; v < VmStackLayout::kSlotCount; ++v) {
            if (v != layout.junk_slot) non_junk_slots.push_back(v);
        }

        // Compute remaining handler-id budget after generic + native.
        const size_t base_count = generic_variant_total + native_count;
        const size_t spec_budget = (base_count >= 255)
            ? 0u
            : std::min<size_t>(kMaxSpecializations, 255 - base_count);

        // Try up to 4× the budget to find unique tuples (collisions on
        // small `non_junk_slots` are common with 6 ops × 15 slots × 15
        // slots = 1350 possible values, so 4× headroom is generous).
        for (size_t attempts = 0;
             specializations.size() < spec_budget && attempts < spec_budget * 4u;
             ++attempts)
        {
            Specialization s{};
            s.op = kSpecializableOps[
                rng.next_range(0, static_cast<uint32_t>(std::size(kSpecializableOps)) - 1)];
            s.dst_vreg = non_junk_slots[
                rng.next_range(0, static_cast<uint32_t>(non_junk_slots.size()) - 1)];
            s.src_vreg = non_junk_slots[
                rng.next_range(0, static_cast<uint32_t>(non_junk_slots.size()) - 1)];

            const bool dup = std::any_of(
                specializations.begin(), specializations.end(),
                [&](const Specialization& existing) {
                    return existing.op == s.op
                        && existing.dst_vreg == s.dst_vreg
                        && existing.src_vreg == s.src_vreg;
                });
            if (!dup) specializations.push_back(s);
        }
    }

    total_handlers =
        generic_variant_total + native_count +
        static_cast<uint32_t>(specializations.size());
    if (total_handlers > 255) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            std::format("X64VmBackend: too many handlers ({} > 255)",
                total_handlers)));
    }
    map.total_handlers = total_handlers;

    // Shuffle handler_id assignment across the entire slot space.
    std::vector<uint8_t> slots(total_handlers);
    std::iota(slots.begin(), slots.end(), static_cast<uint8_t>(0));
    std::shuffle(slots.begin(), slots.end(), rng.engine());

    // variant_handler_ids[op] = list of handler_ids (one per variant).
    variant_handler_ids.assign(kVmOpCount, {});
    {
        uint32_t idx = 0;
        for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
            const uint32_t vcount = variant_count_for(static_cast<VmOp>(opi));
            variant_handler_ids[opi].reserve(vcount);
            for (uint32_t v = 0; v < vcount; ++v) {
                variant_handler_ids[opi].push_back(slots[idx++]);
            }
            // Keep VmOpcodeMap's "canonical" id for compatibility: it stores
            // the FIRST variant's id. Encoders normally bypass this and pick
            // a random variant directly from variant_handler_ids.
            map.generic_handler_id[opi] = variant_handler_ids[opi].front();
        }
    }

    native_handler_ids.reserve(native_count);
    for (uint32_t i = generic_variant_total;
         i < generic_variant_total + native_count; ++i) {
        native_handler_ids.push_back(slots[i]);
    }

    // G1 — assign the remaining shuffled slots to specialisations.
    for (size_t s = 0; s < specializations.size(); ++s) {
        specializations[s].handler_id =
            slots[generic_variant_total + native_count + s];
    }

    // G4 per-handler rolling-key fold-in. Each handler_id gets a
    // random non-zero byte. When a handler finishes its body (and
    // is about to enter the tail dispatch), it does
    // `xor byte [rsp+key_disp], per_handler_key[id]`, folding its
    // handler_id into the live rolling-key state before the fetch
    // of the next opcode byte. The encoder applies the matching
    // XOR to the running encryption key after each instruction's
    // bytes are emitted. Static decryption without actually
    // executing handlers therefore needs to know the per-handler
    // key table — which is itself per-build randomised and only
    // reachable by tracing handler dispatch.
    //
    // Only active in rolling-cipher regions (has_branches == false).
    // Branch-containing regions use a static XOR where the key
    // byte is a constant, so folding would break decryption.
    per_handler_key.assign(total_handlers, 0);
    for (auto& k : per_handler_key) {
        k = static_cast<uint8_t>(rng.next_range(1, 255));
    }

    return {};
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
// layout of the entry stub (pushfq, G7 pad, 16 register pushes, rolling-
// key seed, vflags scramble, ImageBase-derived handler-table key block,
// G6 loop + MBA + integrity check, anti-emulation / anti-tamper picks,
// lea r11 + inline first dispatch) and appends to the caller's patch
// sinks (`table_patches`, `table_key_patches`, `self_crc_patches`) as
// it goes.
//
// The inner-VM ISA permutation and the trampoline bookkeeping are not
// strictly part of the entry stub — they're session-level state consumed
// by step 3b / step 3f — so they're initialised here after the stub
// emission.
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

    entry_offset              = stub_out.entry_offset;
    entry_bc_patch            = stub_out.entry_bc_patch;
    entry_bc_patch_end        = stub_out.entry_bc_patch_end;
    imagebase_key_disp        = stub_out.imagebase_key_disp;
    table_xor_key             = stub_out.table_xor_key;
    integrity_table_lea_patch = stub_out.integrity_table_lea_patch;
    integrity_expected_patch  = stub_out.integrity_expected_patch;

    // Per-build inner-VM ISA permutation. Computed ONCE here and threaded
    // through every nested-wrapper emission + the final
    // `emit_inner_vm_runtime` call — so the byte values in the inline inner
    // bytecodes and the handler table ordering agree.
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
// `emit_op_variant` switch, the trampoline-chain bookkeeping (G5), the
// G4 per-handler fold-in helper, the begin/end-handler hooks, and the
// three emission loops (generic, native, specialised) + the
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
// relative handler table) exactly once per outer VM blob, and patch every
// outer handler's `call rel32 inner_vm_entry` that was left zero-filled
// during emission.
//
// The inner VM is placed AFTER the last outer handler and BEFORE the
// outer handler table. Putting it here means:
//   - Outer handlers that use V2 reference it via a forward rel32 `call`,
//     which is the normal dispatch direction.
//   - The outer handler table still comes last, right before the bytecode
//     stream, so the existing rel32 patches to `handler_table_offset`
//     aren't affected.
//   - If no outer handler ended up choosing V2 for any instance, the
//     inner VM block still exists but is dead code. 88 bytes of overhead
//     is acceptable.
//
// The inner VM is self-contained: all of its intra-block branches (rel8
// jumps back to the dispatch loop) and the rip-relative
// `lea r13, handler_table` are computed at emit time from static offsets.
// No runtime patches are needed.
// ============================================================================

void GenerationSession::step3f_emit_inner_vm_runtime() {
    // Align to 16 so the dispatcher entry is instruction-cache friendly
    // and so a future self-mutation pass can trivially find the block by
    // scanning for a 16-byte-aligned signature.
    while (rt.size() % 16 != 0) rt.u8(0xCC);
    inner_vm_entry_offset = rt.size();
    (void) emit_inner_vm_runtime(rt, inner_vm_isa);

    // Patch every G2 V2 outer-handler's `call rel32 inner_vm_entry` now
    // that the inner VM entry has a definite offset.
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
// Rel32 fixups for entry → bytecode, every tail-dispatch lea → handler
// table, legacy table-key imm32 placeholders, trampoline chain fixups,
// handler-table entry encryption, integrity expected-sum, self-CRC.
// ============================================================================

MxResult<void> GenerationSession::step4_apply_patches() {
    // Entry → bytecode (via lea r11, [rip + rel32])
    patch_rel32(rt.buf, entry_bc_patch, entry_bc_patch_end, bytecode_offset);

    // All tail-dispatch lea reg, [rip + rel32] → handler_table
    for (const auto& p : table_patches) {
        patch_rel32(rt.buf, p.rel32_offset, p.instruction_end, handler_table_offset);
    }

    // Patch the legacy `xor eax, imm32` placeholders in tail dispatches.
    // (The ImageBase path leaves `table_key_patches` empty.)
    for (const auto patch_off : table_key_patches) {
        std::memcpy(rt.buf.data() + patch_off, &table_xor_key, 4);
    }

    // G5: patch each trampoline's placeholder int32 slot with
    // `target_offset - anchor_offset`, sending runtime rip to the
    // next link in the chain. The target can be either a real
    // handler (for the terminal trampoline) or another trampoline
    // (for head / intermediate links). The anchor semantics are
    // shape-specific (see `emit_trampoline`): for Direct and
    // PushRet it is the byte right after the rel32 slot; for
    // CallPop it is the byte right after the `call rel32 = 0`
    // that leaked the anchor onto the stack. The formula is
    // uniform — the shape-specific math is baked into
    // `anchor_offset` at emit time.
    //
    // Every emitted handler has a corresponding chain with every
    // chain slot allocated up front. A missing handler offset or
    // trampoline slot offset means the emission loop lost track
    // of something, which is a bug — we surface it explicitly
    // instead of silently leaving a trampoline whose final jump
    // lands on offset 0.
    for (const auto& tf : trampoline_fixups) {
        size_t target_offset = 0;
        switch (tf.target.kind) {
            case TrampolineTarget::Kind::Handler: {
                if (handler_offset_by_id[tf.target.id] == SIZE_MAX) {
                    return std::unexpected(MxError(
                        ProtectionErrorCode::vm_translation_error,
                        std::format("X64VmBackend: trampoline chain targets un-emitted handler {}",
                                     tf.target.id)));
                }
                target_offset = handler_offset_by_id[tf.target.id];
                break;
            }
            case TrampolineTarget::Kind::Trampoline: {
                if (tf.target.id >= trampoline_offset_by_slot.size() ||
                    trampoline_offset_by_slot[tf.target.id] == SIZE_MAX) {
                    return std::unexpected(MxError(
                        ProtectionErrorCode::vm_translation_error,
                        std::format("X64VmBackend: trampoline chain targets un-emitted slot {}",
                                     tf.target.id)));
                }
                target_offset = trampoline_offset_by_slot[tf.target.id];
                break;
            }
        }
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(target_offset) -
            static_cast<int64_t>(tf.patch.anchor_offset));
        std::memcpy(rt.buf.data() + tf.patch.fixup_offset, &rel, 4);
    }

    // handler_table entries: each = (head_trampoline_offset - table_offset) ^ table_xor_key.
    //
    // G5 phase 3: the entry points at the head of each handler's
    // trampoline chain. Intermediate and terminal trampolines in
    // the chain are reachable only by following the head, which
    // itself reads as one of three polymorphic shapes. The
    // integrity-check XOR sum still works byte-for-byte — it
    // hashes whatever the entries hold, agnostic of what the
    // targets represent — so the check's expected-sum imm32
    // patched below remains correct.
    uint32_t table_xor_sum = 0;
    for (uint32_t h = 0; h < total_handlers; ++h) {
        const uint32_t head_slot = head_slot_of_handler[h];
        if (head_slot == UINT32_MAX ||
            head_slot >= trampoline_offset_by_slot.size() ||
            trampoline_offset_by_slot[head_slot] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("X64VmBackend: handler id {} missing trampoline chain", h)));
        }
        auto rel = static_cast<int32_t>(
            static_cast<int64_t>(trampoline_offset_by_slot[head_slot]) -
            static_cast<int64_t>(handler_table_offset));
        rel ^= static_cast<int32_t>(table_xor_key);
        std::memcpy(rt.buf.data() + handler_table_offset + h * 4, &rel, 4);
        table_xor_sum ^= static_cast<uint32_t>(rel);
    }

    // Patch the integrity-check expected-XOR-sum into the entry stub.
    if (integrity_expected_patch != 0) {
        std::memcpy(rt.buf.data() + integrity_expected_patch,
                    &table_xor_sum, 4);
    }

    // Self-CRC finalisation. Must run AFTER every other patch has
    // modified the entry-stub bytes, because the Self-CRC check's
    // CRC range includes bytes that only become stable here (the
    // integrity-check rel32, the integrity expected-sum imm32, and
    // the tail-dispatch rel32s). Computing the expected CRC over
    // the finalised buffer guarantees the runtime loop — which
    // reads the same finalised bytes — gets an identical value.
    anti_tamper::finalize_self_crc_patches(rt, self_crc_patches);
    return {};
}

// === GenerationSession helpers (begin_handler / end_handler_tail /
//     emit_op_variant / trampoline bookkeeping) moved to
//     x64_handler_emitter.cpp in R1.5.


} // anonymous namespace

// ============================================================================
//                     Public facade: X64VmBackend::generate
// ============================================================================

MxResult<VmRuntime> X64VmBackend::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng,
    VmGenOptions opts)
{
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "X64VmBackend: empty VM instruction list"));
    }
    GenerationSession session(instructions, rng, opts);
    return session.run();
}

} // namespace mx::vm::x64
