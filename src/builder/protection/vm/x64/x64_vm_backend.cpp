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
    uint8_t current_handler_id{};
    uint32_t exit_jmp_offset{};
    std::vector<size_t> inner_vm_call_patches;
    InnerVmIsa inner_vm_isa{};
    size_t inner_vm_entry_offset{};
    size_t handler_table_offset{};
    size_t bytecode_offset{};

    // Constants that were local `constexpr` in the original function.
    static constexpr uint32_t kMaxChainLen = 3;

    // ==== Step methods ======================================================
    [[nodiscard]] MxResult<void> step1_randomize();
    void                         step2_emit_bytecode();
    void                         step3a_emit_entry_stub();
    void                         step3b_emit_handlers();
    void                         step3c_emit_native_handlers();
    void                         step3d_emit_specialised_handlers();
    void                         step3e_drain_trampolines();
    void                         step3f_emit_inner_vm_runtime();
    void                         step3g_emit_table_and_bytecode();
    [[nodiscard]] MxResult<void> step4_apply_patches();

    // ==== Shared helpers (were lambdas inside `generate`) ====================
    uint32_t allocate_trampoline_slot();
    void     queue_trampoline_chain(uint8_t handler_id);
    void     emit_one_pending_trampoline();
    void     maybe_drain_trampolines();
    void     begin_handler(uint8_t handler_id);
    void     emit_handler_key_fold_in(uint8_t handler_id);
    void     finish_handler_chain();
    void     end_handler_tail();
    bool     emit_op_variant(VmOp op, uint32_t variant);
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
    step3b_emit_handlers();
    step3c_emit_native_handlers();
    step3d_emit_specialised_handlers();
    step3e_drain_trampolines();
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
//               Step 3b — generic handler bodies (all variants)
// ============================================================================

void GenerationSession::step3b_emit_handlers() {
    // Generic handlers: emit every variant of every canonical VmOp.
    for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
        const auto op = static_cast<VmOp>(opi);
        const auto& variants = variant_handler_ids[opi];
        for (uint32_t v = 0; v < variants.size(); ++v) {
            begin_handler(variants[v]);
            const bool needs_tail = emit_op_variant(op, v);
            if (needs_tail) {
                end_handler_tail();
            }
        }
    }
}

// ============================================================================
//            Step 3c — per-instruction native handlers (VmOp::native)
// ============================================================================

void GenerationSession::step3c_emit_native_handlers() {
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].op != VmOp::native) continue;
        const uint8_t hid = native_handler_ids[native_handler_of_insn[i]];
        begin_handler(hid);

        // sub rsp, 24   — reserve scratch for vpc save (the comment in
        // vm_runtime_gen.cpp said "16" but the encoded imm is 0x18 = 24)
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xEC); rt.u8(0x18);
        // mov [rsp], r11   — save vpc
        rt.u8(0x4C); rt.u8(0x89); rt.u8(0x1C); rt.u8(0x24);

        // Reload native regs from ctx. After `sub rsp, 24` the ctx lives at
        // [rsp + 24 + slot * 8]. Each native reg N (N != 4) lives at its
        // per-build permuted slot.
        struct RegLoad { uint8_t native_reg; int32_t offset; };
        RegLoad loads[15];
        {
            size_t k = 0;
            for (uint8_t n = 0; n < 16; ++n) {
                if (n == 4) continue;   // skip RSP
                const uint8_t slot = layout.native_to_slot[n];
                loads[k++] = {n, 24 + static_cast<int32_t>(slot) * 8};
            }
        }

        auto emit_mem_mov = [&](uint8_t opcode, uint8_t reg, int32_t disp) {
            // opcode=0x8B (load) or 0x89 (store)
            uint8_t rex = 0x48 | ((reg >= 8) ? 0x04 : 0x00);
            rt.u8(rex);
            rt.u8(opcode);
            const uint8_t reg3 = reg & 0x07;
            if (disp >= -128 && disp <= 127) {
                rt.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
            } else {
                rt.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u32(static_cast<uint32_t>(disp));
            }
        };

        for (const auto& l : loads) emit_mem_mov(0x8B, l.native_reg, l.offset);

        // Restore CPU flags from ctx so flag-dependent native instructions
        // (CMOV, ADC, SBB, etc.) see the correct state.
        {
            const int32_t rf_disp = 24 + rflags_disp;
            const auto popfq_v = pick_popfq_variant(rng);
            const bool uses_rax = (popfq_v != VflagsPopfqV::InPlace);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_popfq(rt, popfq_v, vflags_key, vflags_rol, rf_disp);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x8B); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
        }

        // Shift rsp to caller frame via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(native_shift));

        // Execute native bytes (sees correct GPRs, flags, and caller frame).
        rt.bytes(ByteView{
            instructions[i].native_bytes.data(),
            instructions[i].native_bytes.size()});

        // Shift rsp back via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(-native_shift));

        // Save CPU flags after native execution into ctx so the NEXT
        // handler (or VJCC) sees the correct flags.
        {
            const int32_t rf_disp = 24 + rflags_disp;
            const auto store_v = pick_store_variant(rng);
            const bool uses_rax = (store_v != VflagsStoreV::InPlace);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_store(rt, store_v, vflags_key, vflags_rol, rf_disp);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x8B); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
        }

        // Save all native regs back to ctx.
        for (const auto& l : loads) emit_mem_mov(0x89, l.native_reg, l.offset);

        // Restore vpc: mov r11, [rsp]    4C 8B 1C 24
        rt.u8(0x4C); rt.u8(0x8B); rt.u8(0x1C); rt.u8(0x24);
        // lea rsp, [rsp + 24]    48 8D 64 24 18  (flags-preserving)
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0x64); rt.u8(0x24); rt.u8(0x18);

        // save_rflags=false: native handler already saved flags above.
        // G4 rolling-key fold-in: current_handler_id was set by
        // begin_handler(hid) at the top of the native-handler loop
        // body, so the fold-in folds this native handler's key
        // into the live rolling-key state before the tail fetch.
        emit_handler_key_fold_in(current_handler_id);
        {
            const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                              false, table_key_patches,
                                              vflags_key, vflags_rol,
                                              rflags_disp, &rng,
                                              imagebase_key_disp);
            table_patches.push_back({p.rel32_offset, p.instruction_end});
        }
        // G5: native handlers join the same trampoline chain
        // mechanism as generic/specialised handlers. The chain
        // length roll is independent per handler so native
        // handlers get the same 1..3 distribution.
        queue_trampoline_chain(current_handler_id);
        maybe_drain_trampolines();
    }
}

// ============================================================================
//                     Step 3d — specialised handlers (G1)
// ============================================================================
//
// Each specialisation emits a body with hard-coded slot disps. No operand
// fetch, no remap, no reusable shape — every specialised handler differs
// from the others and from every generic handler.
// ============================================================================

void GenerationSession::step3d_emit_specialised_handlers() {
    for (const auto& spec : specializations) {
        begin_handler(spec.handler_id);
        const uint8_t dst_disp = static_cast<uint8_t>(spec.dst_vreg * 8);
        const uint8_t src_disp = static_cast<uint8_t>(spec.src_vreg * 8);
        if (spec.op == VmOp::mov_rr) {
            emit_handler_mov_rr_specialized(rt, dst_disp, src_disp);
        } else {
            emit_handler_alu_rr_specialized(rt, alu_op_mr_for(spec.op),
                                             dst_disp, src_disp);
        }
        end_handler_tail();
    }
}

// ============================================================================
//                   Step 3e — drain remaining trampolines (G5)
// ============================================================================
//
// The random-draw drain inside `end_handler_tail` and the native loop only
// flushes when the dice roll picks the drain path, so the tail of the run
// usually has a handful of stragglers. This step empties the queue fully.
// ============================================================================

void GenerationSession::step3e_drain_trampolines() {
    while (!pending_trampolines.empty()) {
        emit_one_pending_trampoline();
    }
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

// ============================================================================
//                 Shared helpers (were lambdas inside `generate`)
// ============================================================================

uint32_t GenerationSession::allocate_trampoline_slot() {
    const uint32_t slot = static_cast<uint32_t>(trampoline_offset_by_slot.size());
    trampoline_offset_by_slot.push_back(SIZE_MAX);
    return slot;
}

// Register a chain of random length for the just-emitted handler:
// allocate `len` slots, wire each slot's target at the next slot (or at
// the handler for the terminal), remember the head slot in
// `head_slot_of_handler`, and drop every slot into the pending queue so
// subsequent drains can flush them in random order. Chain length
// distribution is biased toward shorter chains (len==1 ~50%, len==2 ~33%,
// len==3 ~17%) to keep amortised trampoline overhead moderate while still
// producing a meaningful fraction of multi-hop chains.
void GenerationSession::queue_trampoline_chain(uint8_t handler_id) {
    const uint32_t roll = rng.next_range(0, 5);
    uint32_t chain_len;
    if (roll < 3)      chain_len = 1;   // 3/6
    else if (roll < 5) chain_len = 2;   // 2/6
    else               chain_len = 3;   // 1/6
    if (chain_len > kMaxChainLen) chain_len = kMaxChainLen;

    // Allocate all slots for this chain up front so we can set every
    // slot's target to point at its successor before any of them are
    // drained.
    std::array<uint32_t, kMaxChainLen> slots{};
    for (uint32_t i = 0; i < chain_len; ++i) {
        slots[i] = allocate_trampoline_slot();
    }
    head_slot_of_handler[handler_id] = slots[0];

    for (uint32_t i = 0; i < chain_len; ++i) {
        TrampolineTarget tgt{};
        if (i + 1 < chain_len) {
            tgt.kind = TrampolineTarget::Kind::Trampoline;
            tgt.id   = slots[i + 1];
        } else {
            tgt.kind = TrampolineTarget::Kind::Handler;
            tgt.id   = handler_id;
        }
        pending_trampolines.push_back({slots[i], tgt});
    }
}

void GenerationSession::emit_one_pending_trampoline() {
    if (pending_trampolines.empty()) return;
    // Pop a random slot, not FIFO. FIFO would correlate the physical
    // blob position of trampolines with their handler completion order;
    // random draws decorrelate them so chains end up scrambled across
    // the handler block.
    const uint32_t idx = rng.next_range(
        0, static_cast<uint32_t>(pending_trampolines.size() - 1));
    const PendingTrampoline pt = pending_trampolines[idx];
    pending_trampolines[idx] = pending_trampolines.back();
    pending_trampolines.pop_back();

    trampoline_offset_by_slot[pt.slot] = rt.size();
    const auto tp = vm::x64::emit_trampoline(rt, rng, /*max_junk_bytes=*/8);
    trampoline_fixups.push_back({pt.target, tp});
}

// After each handler's end_tail we queue a fresh chain for the handler
// and, with some probability, flush one or more queued entries right
// now. Flushing follows a geometric distribution (0 ~2/3, 1 ~2/9, 2 ~2/27,
// ...), so over the full emission trampolines from different chains end
// up interleaved with handler bodies. Any stragglers are flushed by the
// deterministic drain after the last handler.
void GenerationSession::maybe_drain_trampolines() {
    while (!pending_trampolines.empty() && rng.next_range(0, 2) == 0) {
        emit_one_pending_trampoline();
    }
}

void GenerationSession::begin_handler(uint8_t handler_id) {
    current_handler_id = handler_id;
    handler_offset_by_id[handler_id] = rt.size();
    emit_junk_prologue(rt, rng, /*max_bytes=*/8);
}

// G4: `xor byte [rsp + rolling_key_disp], imm8=per_handler_key[id]`.
// Emitted right before the tail dispatch, so the fetch of the next opcode
// byte sees the post-fold key. Skipped entirely in static-cipher regions
// (rolling == false) where there is no mutable key state to fold into.
void GenerationSession::emit_handler_key_fold_in(uint8_t handler_id) {
    if (!rolling) return;
    // 80 /6 ib — xor r/m8, imm8
    //   ModRM: 01 110 100 = 0x74  (mod=01 disp8, reg=/6=xor, rm=100 SIB)
    //   SIB:   00 100 100 = 0x24  (scale=00, index=100 none, base=rsp)
    rt.u8(0x80); rt.u8(0x74); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(rolling_key_disp));
    rt.u8(per_handler_key[handler_id]);
}

// G5 invariant: every handler_id the backend begins via `begin_handler`
// MUST later get a trampoline chain queued via `queue_trampoline_chain`,
// otherwise the post-emit handler_table patch fires the "handler id N
// missing trampoline chain" error. The standard path goes through
// `end_handler_tail`, which emits the tail dispatch AND queues the chain
// in one shot. A handful of `VmOp` cases (dead / opq_branch / native)
// emit their own inline tail and `return false` from `emit_op_variant` to
// tell the surrounding loop "don't call end_handler_tail" — they must
// still call `finish_handler_chain` themselves so the invariant holds.
void GenerationSession::finish_handler_chain() {
    queue_trampoline_chain(current_handler_id);
    maybe_drain_trampolines();
}

void GenerationSession::end_handler_tail() {
    emit_handler_key_fold_in(current_handler_id);
    const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                      has_branches, table_key_patches,
                                      vflags_key, vflags_rol,
                                      rflags_disp, &rng,
                                      imagebase_key_disp);
    table_patches.push_back({p.rel32_offset, p.instruction_end});
    finish_handler_chain();
}

// ----------------------------------------------------------------------------
// emit_op_variant — the big switch. Produces one variant body for a given
// canonical VmOp. Returns true if the surrounding loop still needs to call
// `end_handler_tail` after the variant (the standard path); false for
// inline-tail variants (native / dead / opq_branch / exit) that take care
// of their own tail and trampoline-chain registration.
// ----------------------------------------------------------------------------
bool GenerationSession::emit_op_variant(VmOp op, uint32_t variant) {
    switch (op) {
        case VmOp::mov_rr:
            if (variant == 0) {
                emit_handler_mov_rr(rt, rolling_key_disp, rolling);
            } else if (variant == 1) {
                emit_handler_mov_rr_pushpop(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_mov_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::add_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x01);
            } else if (variant == 1) {
                emit_handler_add_rr_mba(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, InnerVmOp::iadd_rr,
                                            patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::sub_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x29);
            } else if (variant == 1) {
                emit_handler_sub_rr_neg(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, InnerVmOp::isub_rr,
                                            patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::xor_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x31);
            } else if (variant == 1) {
                emit_handler_xor_rr_mba(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, InnerVmOp::ixor_rr,
                                            patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::and_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x21);
            } else if (variant == 1) {
                emit_handler_and_rr_demorgan(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, InnerVmOp::iand_rr,
                                            patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::or_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, rolling_key_disp, rolling, 0x09);
            } else if (variant == 1) {
                emit_handler_or_rr_demorgan(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, rolling_key_disp, rolling,
                                            inner_vm_isa, InnerVmOp::ior_rr,
                                            patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::imul_rr:  emit_handler_imul_rr(rt, rolling_key_disp, rolling);            return true;

        case VmOp::mov_ri32:
            if (variant == 0) {
                emit_handler_mov_ri32(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_mov_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::add_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x01);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, InnerVmOp::iadd_rr,
                                              patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::sub_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x29);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, InnerVmOp::isub_rr,
                                              patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::xor_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x31);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, InnerVmOp::ixor_rr,
                                              patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::and_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x21);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, InnerVmOp::iand_rr,
                                              patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::or_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, rolling_key_disp, rolling, 0x09);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, rolling_key_disp, rolling,
                                              inner_vm_isa, InnerVmOp::ior_rr,
                                              patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::mov_ri64: emit_handler_mov_ri64(rt, rolling_key_disp, rolling);           return true;

        case VmOp::not_r:
            if (variant == 0) {
                emit_handler_unary(rt, rolling_key_disp, rolling, 2);
            } else if (variant == 1) {
                emit_handler_not_r_xor(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_not_r_nested(rt, rolling_key_disp, rolling,
                                           inner_vm_isa, patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::neg_r:
            if (variant == 0) {
                emit_handler_unary(rt, rolling_key_disp, rolling, 3);
            } else if (variant == 1) {
                emit_handler_neg_r_notinc(rt, rolling_key_disp, rolling);
            } else {
                size_t patch = 0;
                emit_handler_neg_r_nested(rt, rolling_key_disp, rolling,
                                           inner_vm_isa, patch);
                inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::shl_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 4);           return true;
        case VmOp::shr_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 5);           return true;
        case VmOp::sar_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 7);           return true;
        case VmOp::rol_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 0);           return true;
        case VmOp::ror_ri:   emit_handler_shift(rt, rolling_key_disp, rolling, 1);           return true;

        case VmOp::vjmp:
            emit_handler_vjmp(rt, rolling_key_disp, rolling);
            return true;

        case VmOp::vjcc: {
            // Coin flip per handler body: 50% chance the taken path is
            // the V0 direct `add r11, rax`, 50% it's the V2 nested
            // `mov r15, rax; call inner_vm_entry`. Because vjcc's
            // variant axis is already fully consumed by the condition
            // code (16 values), this build-time randomization is the
            // only diversity knob available for its handler bodies.
            const bool nested = rng.next_bool();
            size_t patch = 0;
            emit_handler_vjcc(rt, rolling_key_disp, rolling,
                              static_cast<uint8_t>(variant),
                              vflags_key, vflags_rol,
                              rflags_disp, rng,
                              nested ? &inner_vm_isa : nullptr,
                              nested ? &patch : nullptr);
            if (nested) {
                inner_vm_call_patches.push_back(patch);
            }
            return true;
        }

        case VmOp::native:
            // Generic native slot is never invoked — each native insn gets
            // its own handler. Trap with ud2 (no tail). Still needs a
            // trampoline chain queued so the handler_table entry for this
            // id has a valid target and the integrity-check XOR sum
            // matches; the trampoline points at `ud2` and only fires if
            // something dispatches through the generic native slot by
            // mistake, in which case the process crashes immediately —
            // which is exactly what we want.
            emit_ud2(rt);
            finish_handler_chain();
            return false;

        case VmOp::dead: {
            // G4 dead opcode — empty handler body. The encoder inserts
            // `dead` bytes into the bytecode stream at random positions
            // between real instructions; this handler consumes its byte,
            // runs NO body, and dispatches to the next handler without
            // touching vflags.
            //
            // IMPORTANT: the tail dispatch here is emitted with
            // save_rflags=FALSE even in branch-containing regions where
            // all other handlers use save=TRUE.
            //
            // Why: on entry to this handler, host rflags do NOT reflect
            // the previous real handler's guest ALU — they reflect the
            // previous handler's TAIL-DISPATCH fetch/xor sequence, which
            // clobbered rflags after the real save happened. If we let
            // the dead handler's tail call emit_vflags_store, it would
            // write those fetch-clobbered garbage flags to `vflags`,
            // overwriting the real guest flags that were already safely
            // stored there by the previous handler's tail. A downstream
            // `vjcc` would then see garbage ZF/SF/CF and mispredict the
            // branch.
            //
            // Skipping the save leaves vflags untouched — the real guest
            // flags remain visible to the next `vjcc`. Net effect of the
            // dead handler on the VM state: r11 advanced by 1 (via the
            // fetch inside the tail), nothing else. That's exactly what
            // a "no-op insert" should do.
            emit_handler_key_fold_in(current_handler_id);
            const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                               /*save_rflags=*/false,
                                               table_key_patches,
                                               vflags_key, vflags_rol,
                                               rflags_disp, &rng,
                                               imagebase_key_disp);
            table_patches.push_back({p.rel32_offset, p.instruction_end});
            finish_handler_chain();  // G5: inline-tail path still owes a chain
            return false;
        }

        case VmOp::opq_branch: {
            // G4 opaque branch. Shape-compatible with `vjmp`: a 4-byte
            // rel32-shaped operand is fetched by the handler body, but
            // NEVER added to r11. Falls through to the next instruction
            // regardless of what the operand bytes say.
            //
            // The fetch IS necessary — without it, r11 would still point
            // at the rel32 bytes when the tail dispatch fetches, and
            // those bytes would get dispatched as a handler_id
            // (misdecode).
            //
            // As with `dead`, the tail is emitted inline with
            // save_rflags=false to avoid clobbering the real guest flags
            // in vflags. `emit_fetch_dword` clobbers host rflags via its
            // xor sequences, and we don't want those garbage flags
            // landing in vflags where a downstream `vjcc` would read
            // them.
            emit_fetch_dword(rt, rolling_key_disp, rolling);
            emit_handler_key_fold_in(current_handler_id);
            const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                               /*save_rflags=*/false,
                                               table_key_patches,
                                               vflags_key, vflags_rol,
                                               rflags_disp, &rng,
                                               imagebase_key_disp);
            table_patches.push_back({p.rel32_offset, p.instruction_end});
            finish_handler_chain();  // G5: inline-tail path still owes a chain
            return false;
        }

        case VmOp::exit: {
            if (vflags_key != 0 || vflags_rol != 0) {
                emit_vflags_inslot_descramble(rt, pick_inslot_variant(rng),
                                               vflags_key, vflags_rol,
                                               rflags_disp);
            }

            // Pop all 16 slots in slot order.
            for (uint8_t v = 0; v < 16; ++v) {
                if (v == layout.junk_slot) {
                    // add rsp, 8       48 83 C4 08
                    rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4); rt.u8(0x08);
                } else {
                    emit_pop_reg(rt, layout.slot_to_native[v]);
                }
            }

            // G7: discard the extra padding slots that entry pushed.
            if (layout.extra_pad_slots > 0) {
                rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4);
                rt.u8(static_cast<uint8_t>(layout.extra_pad_slots * 8));
            }

            emit_popfq(rt);
            if (emit_exit_as_jmp) {
                // Cross-VM: jmp rel32 to next sub-VM entry (patched later)
                rt.u8(0xE9);
                exit_jmp_offset = static_cast<uint32_t>(rt.size());
                rt.u32(0);
            } else {
                emit_ret(rt);
            }
            // G5: exit handler has no tail dispatch (it unwinds the VM
            // state and returns), but it still needs a trampoline chain
            // queued — the handler_table entry for exit must point at a
            // valid trampoline so the integrity-check XOR sum stays
            // consistent. The trampoline jmps into the exit body; on
            // dispatch, the body pops registers and returns to the
            // caller, exactly as a direct call would.
            finish_handler_chain();
            return false;
        }
        case VmOp::count_:
            return false;
    }
    return false;
}

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
