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
#include "mxprotector/protection/vm/x64/x64_emitters.hpp"
#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm_wrappers.hpp"
#include "mxprotector/protection/vm/x64/x64_vflags.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

namespace mx::vm::x64 {

namespace {

// ----------------------------------------------------------------------------
// G1 — Per-build handler specialisation (runtime side)
// ----------------------------------------------------------------------------
//
// The compile-time metadata for specialisation — `kMaxSpecializations`,
// `kSpecializableOps`, `is_specializable_op`, `alu_op_mr_for` and the
// generic `variant_count_for` table — lives in `x64_vm_variants.hpp`.
// What stays here is the runtime tuple that binds those tables to the
// per-build handler-id allocator.
//
// A `Specialization` is a (op, dst_vreg, src_vreg) tuple for which the
// backend will emit a dedicated handler with the destination and source
// slot displacements baked in. Instructions that match a specialisation
// emit only the specialised handler_id (1 byte of bytecode) instead of
// the generic 3-byte form (handler_id + dst byte + src byte).
//
// Per-build random selection. Two builds of the same input get different
// specialisations, with different handler_ids, in different positions in
// the handler table.
struct Specialization {
    VmOp    op{};         // mov_rr / add_rr / sub_rr / xor_rr / and_rr / or_rr
    uint8_t dst_vreg{};   // 0..15, ≠ junk_slot
    uint8_t src_vreg{};   // 0..15, ≠ junk_slot
    uint8_t handler_id{}; // assigned during slot allocation
};

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

    // ==== Step 2 — bytecode encoding state ==================================
    ByteBuffer bytecode_plain;
    uint32_t next_native_idx{};
    std::vector<uint32_t> native_handler_of_insn;
    std::vector<int> spec_match;
    std::vector<uint8_t> dead_before;
    std::vector<uint8_t> opq_before;
    std::vector<uint32_t> bc_offset;
    uint8_t dead_handler_id{};
    uint8_t opq_branch_handler_id{};

    // G4 per-handler-key fold-in events. Each entry marks the end of one
    // handler's byte range in `bytecode_plain` and the handler_id that
    // processed those bytes.
    struct FoldInEvent { size_t end_offset; uint8_t handler_id; };
    std::vector<FoldInEvent> fold_events;

    bool has_branches{};
    bool rolling{};

    // ==== Step 3 — runtime blob state =======================================
    RawEmitter rt;

    struct TablePatch { size_t rel32_offset; size_t instruction_end; };
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

    struct TrampolineTarget {
        enum class Kind : uint8_t { Handler, Trampoline };
        Kind     kind;
        uint32_t id;
    };
    struct PendingTrampoline {
        uint32_t          slot;
        TrampolineTarget  target;
    };
    struct TrampolineFixup {
        TrampolineTarget         target;
        vm::x64::TrampolinePatch patch;
    };

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
    static constexpr uint32_t kMaxDeadPerSlot       = 3;
    static constexpr uint32_t kOpqBranchProbability = 30;   // /100
    static constexpr uint32_t kMaxChainLen          = 3;

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
    uint8_t  remap_reg(uint8_t native_reg) const;
    void     push32(int32_t v);
    void     record_fold(uint8_t hid);
    uint32_t insert_bytes_at(size_t i) const;
    void     emit_g4_inserts(size_t i);
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
// Build plain bytecode stream, then stream-encrypt with rolling key. The
// encryption walks bytes in fetch order (opcode, operands, next opcode,
// ...) so the runtime decryption order matches.
//
// Plumbing order:
//   1. Define the operand remap helper (uses the per-region layout).
//   2. Precompute spec_match[i]: whether each instruction matches one
//      of the per-build specialisations. Drives BOTH the bytecode size
//      table and the encoding loop.
//   3. Compute bc_offset[] using the spec-aware sizes.
//   4. Emit bytecode using the same spec_match decisions.
// ============================================================================

void GenerationSession::step2_emit_bytecode() {
    bytecode_plain.reserve(instructions.size() * 4);

    next_native_idx = 0;
    native_handler_of_insn.assign(instructions.size(), UINT32_MAX);

    // G1 — Precompute specialisation matches.
    //
    // spec_match[i] = index into `specializations[]`, or -1 for "no match,
    // emit via the generic path". We do this BEFORE bc_offset[] because a
    // matched instruction's bytecode size shrinks from 3 bytes (handler_id
    // + 2 operand bytes) to 1 byte (handler_id only), and vjmp/vjcc rel32
    // values depend on bc_offset[].
    spec_match.assign(instructions.size(), -1);
    if (!specializations.empty()) {
        for (size_t i = 0; i < instructions.size(); ++i) {
            const auto& vi = instructions[i];
            if (!is_specializable_op(vi.op)) continue;
            const uint8_t dst_v = remap_reg(vi.dst);
            const uint8_t src_v = remap_reg(vi.src);
            for (size_t s = 0; s < specializations.size(); ++s) {
                const auto& spec = specializations[s];
                if (spec.op == vi.op
                 && spec.dst_vreg == dst_v
                 && spec.src_vreg == src_v)
                {
                    spec_match[i] = static_cast<int>(s);
                    break;  // first match wins
                }
            }
        }
    }

    // G4 dead-opcode insertion. Pre-decide how many dead bytes to
    // emit BEFORE each real instruction (position 0..N-1) and after
    // the last one (position N, before the terminal `exit`). Both
    // bc_offset computation and the phase-2 emit loop read from
    // this array, so they stay in sync.
    //
    // Insertion density: 0..kMaxDeadPerSlot dead bytes per slot,
    // uniform draw. With ~3-instruction average spacing the real
    // bytecode grows by ~1.5x and every vjcc's vflags window gets
    // mixed with dead-op fetches, making static opcode-table
    // recovery have to disambiguate "live" vs "dead" bytes without
    // actually running the VM.
    //
    // Regions with virtual branches fall back to static XOR
    // encryption later on. Dead opcodes work under BOTH encryption
    // modes — the encryption operates on bytes in fetch order and
    // doesn't care whether a byte is live or dead.
    // G4 obfuscation insertion. Two kinds of dummy bytes sprinkled
    // between real instructions:
    //
    //   * `dead_before[i]` — number of zero-operand `VmOp::dead`
    //     handler_id bytes to insert before real instruction `i`.
    //     Each insert is 1 byte. Uniform draw [0..kMaxDeadPerSlot].
    //
    //   * `opq_before[i]` — whether to insert a single
    //     `VmOp::opq_branch` at this slot. Each insert is 5 bytes
    //     (handler_id + 4 random rel32-shaped bytes). Binary draw
    //     with probability kOpqBranchProbability.
    //
    // Both arrays contribute to `bc_offset[]` so vjmp/vjcc rel32
    // values land on the right target even with inserts in between.
    //
    // Branch constraint: neither insertion happens right after a
    // vjmp/vjcc (index `i` such that `instructions[i-1]` is a
    // branch). The branch's rel32 at runtime lands r11 at
    // `bc_offset[i-1] + size(branch) = bc_offset[i] - inserts`, so
    // any nonzero insert count at that slot would leave r11
    // `inserts` bytes BEFORE the target. Zeroing the slot is the
    // simplest correct fix: bytes after a branch are unreachable
    // on the taken path anyway (and the fall-through path still
    // walks through them via the normal dispatch chain).
    dead_before.assign(instructions.size() + 1, 0);
    opq_before.assign(instructions.size() + 1, 0);
    for (size_t i = 0; i <= instructions.size(); ++i) {
        const bool after_branch =
            (i > 0) &&
            (instructions[i - 1].op == VmOp::vjmp ||
             instructions[i - 1].op == VmOp::vjcc);
        if (after_branch) continue;
        dead_before[i] =
            static_cast<uint8_t>(rng.next_range(0, kMaxDeadPerSlot));
        if (rng.next_range(0, 99) < kOpqBranchProbability) {
            opq_before[i] = 1;
        }
    }

    // Phase 1: compute bytecode offsets using spec-aware sizes +
    // G4 obfuscation insertions. vjmp/vjcc rel32 depends on the
    // target instruction's bytecode offset, so the counts of dead
    // bytes and opaque branches inserted BEFORE the target are
    // correctly reflected in the computed rel32.
    //
    // Insertion bytes per slot i:
    //   dead_before[i]            (1 byte each)
    // + opq_before[i] * 5         (handler_id + 4 operand bytes)
    bc_offset.assign(instructions.size() + 1, 0);
    bc_offset[0] = insert_bytes_at(0);
    for (size_t i = 0; i < instructions.size(); ++i) {
        const uint32_t size = (spec_match[i] >= 0)
            ? 1u   // specialised: just handler_id, no operand bytes
            : (1u + vm_op_operand_size(instructions[i].op));
        bc_offset[i + 1] = bc_offset[i] + size + insert_bytes_at(i + 1);
    }

    // Phase 2: encode bytecode.

    // G4: cached handler ids for the phase-2 inserter below.
    dead_handler_id =
        variant_handler_ids[static_cast<uint32_t>(VmOp::dead)][0];
    opq_branch_handler_id =
        variant_handler_ids[static_cast<uint32_t>(VmOp::opq_branch)][0];

    // G4 per-handler-key fold-in events. The rolling-cipher encryption
    // pass below walks this list and applies `key ^= per_handler_key[id]`
    // after each range, matching the `xor [rsp+key_disp], imm8` fold-in
    // the handler body emits right before its tail dispatch.
    //
    // A trailing sentinel event for the terminal `exit` handler isn't
    // needed: exit doesn't dispatch, so there's no "next fetch" to fold
    // into.
    fold_events.clear();
    fold_events.reserve(instructions.size() * 2);

    for (size_t i = 0; i < instructions.size(); ++i) {
        // G4: insert this slot's dummy bytes BEFORE the real
        // instruction. bc_offset[i] already accounts for them.
        emit_g4_inserts(i);

        const auto& vi = instructions[i];

        // G1 — Specialised path: emit only the handler_id, no operand bytes.
        // The matched specialised handler has dst/src disps baked in, so the
        // runtime decoder needs no operand fetch.
        if (spec_match[i] >= 0) {
            const uint8_t spec_hid =
                specializations[static_cast<size_t>(spec_match[i])].handler_id;
            bytecode_plain.push_back(spec_hid);
            record_fold(spec_hid);
            continue;
        }

        uint8_t handler_id;
        if (vi.op == VmOp::native) {
            handler_id = native_handler_ids[next_native_idx];
            native_handler_of_insn[i] = next_native_idx;
            ++next_native_idx;
        } else if (vi.op == VmOp::vjcc) {
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(VmOp::vjcc)];
            handler_id = variants[vi.branch_cc];
        } else {
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(vi.op)];
            const uint32_t v = (variants.size() > 1)
                ? rng.next_range(0, static_cast<uint32_t>(variants.size() - 1))
                : 0u;
            handler_id = variants[v];
        }

        bytecode_plain.push_back(handler_id);

        switch (vi.op) {
            case VmOp::mov_rr:
            case VmOp::add_rr:
            case VmOp::sub_rr:
            case VmOp::xor_rr:
            case VmOp::and_rr:
            case VmOp::or_rr:
            case VmOp::imul_rr:
                bytecode_plain.push_back(remap_reg(vi.dst));
                bytecode_plain.push_back(remap_reg(vi.src));
                break;

            case VmOp::mov_ri32:
            case VmOp::add_ri32:
            case VmOp::sub_ri32:
            case VmOp::xor_ri32:
            case VmOp::and_ri32:
            case VmOp::or_ri32:
                bytecode_plain.push_back(remap_reg(vi.dst));
                push32(vi.imm32);
                break;

            case VmOp::mov_ri64:
                bytecode_plain.push_back(remap_reg(vi.dst));
                for (int b = 0; b < 8; ++b)
                    bytecode_plain.push_back(
                        static_cast<uint8_t>((vi.imm64 >> (b * 8)) & 0xFF));
                break;

            case VmOp::not_r:
            case VmOp::neg_r:
                bytecode_plain.push_back(remap_reg(vi.dst));
                break;

            case VmOp::shl_ri:
            case VmOp::shr_ri:
            case VmOp::sar_ri:
            case VmOp::rol_ri:
            case VmOp::ror_ri:
                bytecode_plain.push_back(remap_reg(vi.dst));
                bytecode_plain.push_back(vi.shift_count);
                break;

            case VmOp::vjmp:
            case VmOp::vjcc: {
                const auto target_off = bc_offset[vi.branch_target_insn];
                const auto next_off   = bc_offset[i + 1];
                push32(static_cast<int32_t>(target_off) -
                       static_cast<int32_t>(next_off));
                break;
            }

            case VmOp::native:
            case VmOp::exit:
            case VmOp::dead:          // never in instructions[], -Wswitch
            case VmOp::opq_branch:    // never in instructions[], -Wswitch
            case VmOp::count_:
                break;
        }

        // G4: record fold-in boundary after this instruction's
        // handler_id + operand bytes. `exit` doesn't dispatch
        // anywhere afterwards, so its fold would be unused — the
        // runtime handler emits no fold-in either. Skip it.
        if (vi.op != VmOp::exit) {
            record_fold(handler_id);
        }
    }

    // G4: last batch of dummy bytes between the final real
    // instruction and the terminal `exit` opcode.
    emit_g4_inserts(instructions.size());

    // Terminal exit opcode.
    bytecode_plain.push_back(
        variant_handler_ids[static_cast<uint32_t>(VmOp::exit)][0]);

    // Detect whether the instruction list contains any virtual branches.
    // If it does, fall back to static XOR encryption (all bytes XOR'd with
    // the same key) because branch targets would need key-state checkpoints
    // that complicate the first-pass design. Straight-line regions keep the
    // stronger rolling-key cipher.
    has_branches = std::any_of(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) {
            return v.op == VmOp::vjmp || v.op == VmOp::vjcc;
        });
    rolling = !has_branches;

    // Bytecode encryption: rolling-key (+ G4 per-handler fold-in)
    // or static XOR.
    if (rolling) {
        uint8_t key = initial_key;
        size_t byte_pos = 0;
        size_t event_idx = 0;
        while (byte_pos < bytecode_plain.size()) {
            const size_t next_boundary =
                (event_idx < fold_events.size())
                ? fold_events[event_idx].end_offset
                : bytecode_plain.size();

            // Roll through bytes up to the next handler boundary.
            while (byte_pos < next_boundary) {
                const uint8_t plain = bytecode_plain[byte_pos];
                bytecode_plain[byte_pos] =
                    static_cast<uint8_t>(plain ^ key);
                key ^= plain;
                ++byte_pos;
            }

            // Apply this handler's fold-in (mirrors the
            // `xor [rsp+key_disp], imm8` that the handler body
            // emits right before its tail dispatch).
            if (event_idx < fold_events.size()) {
                key ^= per_handler_key[fold_events[event_idx].handler_id];
                ++event_idx;
            }
        }
    } else {
        for (auto& b : bytecode_plain) {
            b ^= initial_key;
        }
    }
}

// ============================================================================
//                         Step 3a — entry stub emission
// ============================================================================
//
// Emits the entry stub into `rt`:
//   [pushfq] [G7 pad] [16 pushes] [rolling-key seed] [vflags scramble]
//   [ImageBase-key derivation + G6 loop + MBA + integrity check]
//   [anti-emulation] [anti-tamper]
//   [lea r11, [rip + bytecode]] [inline first dispatch]
// ============================================================================

void GenerationSession::step3a_emit_entry_stub() {
    entry_offset = rt.size();

    emit_pushfq(rt);

    // G7: extra padding slots between RFLAGS and the GPR area. After pushfq,
    // before the 16 reg pushes, emit `extra_pad_slots` × `push imm32` so the
    // GPR area still lands at [rsp + 0..120] but RFLAGS sits 8*N bytes higher.
    for (uint8_t p = 0; p < layout.extra_pad_slots; ++p) {
        rt.u8(0x68);
        rt.u32(rng.next_u32());
    }

    // 16 register pushes, permuted per-build. Push at position K lands at
    // offset (15-K)*8, so to put slot V at [rsp + V*8] we push it at K=15-V.
    // The junk slot (native RSP's would-be home) is filled with a dummy
    // `push rax` — its byte becomes the rolling-key scratch.
    for (int k = 0; k < 16; ++k) {
        const uint8_t v = static_cast<uint8_t>(15 - k);
        if (v == layout.junk_slot) {
            emit_push_reg(rt, 0);  // dummy push rax (value irrelevant)
        } else {
            emit_push_reg(rt, layout.slot_to_native[v]);
        }
    }

    // Seed the rolling key inside the junk slot. Displacement varies per-build.
    //   C6 44 24 disp8 ib     (disp ≤ 120 always)
    rt.u8(0xC6); rt.u8(0x44); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(rolling_key_disp));
    rt.u8(initial_key);

    // Transform the raw RFLAGS the entry's pushfq just wrote into the
    // scrambled form: slot = rol(real, vflags_rol) ^ vflags_key.
    if (vflags_key != 0 || vflags_rol != 0) {
        emit_vflags_inslot_scramble(rt, pick_inslot_variant(rng),
                                     vflags_key, vflags_rol, rflags_disp);
    }

    // Handler-table key derivation: if `opts.use_imagebase_key` is set,
    // compute the key at runtime from PEB.ImageBaseAddress and store it in
    // the upper 4 bytes of the junk slot ([rsp + rolling_key_disp + 4]).
    // Every tail dispatch then reads `xor eax, [rsp + disp8]` instead of
    // carrying an imm32 — the table key never appears as a literal.
    imagebase_key_disp =
        opts.use_imagebase_key ? (rolling_key_disp + 4) : -1;

    // Handler-table encryption key.
    table_xor_key = opts.use_imagebase_key
        ? rng.next_u32()
        : (rng.next_u32() | 1);  // legacy path wants non-zero

    // Patch offsets for the integrity check that is emitted inside the
    // ImageBase block. Zero when integrity is not enabled.
    integrity_table_lea_patch = 0;
    integrity_expected_patch  = 0;

    if (opts.use_imagebase_key) {
        //   65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]    ; PEB
        //   48 8B 40 10                  mov rax, [rax + 0x10] ; ImageBase
        //   <G6 loop>                    iterated bit-mix: eax = f^N(IB_low32)
        //   <MBA chain>                  transforms loop_output -> table_xor_key
        //   <integrity check>            xor'd into eax (zero on intact table)
        //   89 44 24 <disp8>             mov [rsp + key_disp], eax
        rt.u8(0x65); rt.u8(0x48); rt.u8(0x8B); rt.u8(0x04); rt.u8(0x25);
        rt.u8(0x60); rt.u8(0x00); rt.u8(0x00); rt.u8(0x00);
        rt.u8(0x48); rt.u8(0x8B); rt.u8(0x40); rt.u8(0x10);

        const uint32_t ib_low32 =
            static_cast<uint32_t>(opts.preferred_image_base & 0xFFFFFFFFULL);

        // ----------------------------------------------------------
        // G6 — loop-based key schedule.
        //
        // Before feeding the ImageBase into the MBA chain, run a
        // short iterated bit-mix `f(x) = g(x) op K` applied N times.
        // A symbolic execution engine (angr, KLEE, Triton) that
        // tries to express the full key derivation as a single
        // constraint has to either unroll the loop N times (path
        // explosion for N≥32) or infer a closed-form invariant for
        // the iterated rotate-xor transform (no general technique
        // does this at bit level). The loop adds ~17 emitted bytes
        // and ~N ALU ops at runtime — microseconds for any
        // sensible N, invisible next to the syscalls the tail
        // anti-tamper checks already make.
        //
        // Three polymorphic shapes are chosen uniformly per build.
        // Each is an 8-byte body encoded by hand; they all use
        // eax as accumulator and no other register, so the loop
        // counter sits in ecx without interference. ecx is freely
        // clobberable here — the very next thing the entry stub
        // emits after the MBA chain is a `mov ecx, total_handlers`
        // for the integrity-check loop, so ecx is already dead at
        // this point. Likewise for rflags: every instruction down
        // to the anti-tamper checks clobbers them.
        //
        // Invariant: apply the runtime loop body N times to
        // `ib_low32` at build time and feed the result into the
        // MBA chain as its new input. The MBA chain still maps
        // that input to `table_xor_key`, so the handler-table
        // encryption, integrity-check expected sum, and every
        // downstream consumer of the key see the same value they
        // did pre-G6.
        // ----------------------------------------------------------
        constexpr uint32_t kLoopVariantCount = 3;
        enum : uint32_t {
            kVariantRolXor = 0,  // rol eax, rot; xor eax, K
            kVariantRorAdd = 1,  // ror eax, rot; add eax, K
            kVariantXorRol = 2,  // xor eax, K;   rol eax, rot
        };

        const uint32_t loop_variant = rng.next_range(0, kLoopVariantCount - 1);
        const uint32_t loop_count   = rng.next_range(32, 128);
        const uint8_t  loop_rot     = static_cast<uint8_t>(rng.next_range(1, 31));
        const uint32_t loop_key     = rng.next_u32();

        auto apply_loop_step = [&](uint32_t x) -> uint32_t {
            switch (loop_variant) {
                case kVariantRolXor: {
                    const uint32_t r = (x << loop_rot) |
                                       (x >> (32u - loop_rot));
                    return r ^ loop_key;
                }
                case kVariantRorAdd: {
                    const uint32_t r = (x >> loop_rot) |
                                       (x << (32u - loop_rot));
                    return r + loop_key;
                }
                case kVariantXorRol: {
                    const uint32_t y = x ^ loop_key;
                    return (y << loop_rot) | (y >> (32u - loop_rot));
                }
                default:
                    return x;  // unreachable — next_range clamps.
            }
        };

        uint32_t loop_output = ib_low32;
        for (uint32_t i = 0; i < loop_count; ++i) {
            loop_output = apply_loop_step(loop_output);
        }

        //   mov ecx, loop_count           B9 imm32
        rt.u8(0xB9);
        rt.u32(loop_count);
        // .loop:
        const size_t g6_loop_body_start = rt.size();
        switch (loop_variant) {
            case kVariantRolXor:
                //   rol eax, rot          C1 C0 rot
                rt.u8(0xC1); rt.u8(0xC0); rt.u8(loop_rot);
                //   xor eax, K            35 imm32
                rt.u8(0x35); rt.u32(loop_key);
                break;
            case kVariantRorAdd:
                //   ror eax, rot          C1 C8 rot
                rt.u8(0xC1); rt.u8(0xC8); rt.u8(loop_rot);
                //   add eax, K            05 imm32
                rt.u8(0x05); rt.u32(loop_key);
                break;
            case kVariantXorRol:
                //   xor eax, K            35 imm32
                rt.u8(0x35); rt.u32(loop_key);
                //   rol eax, rot          C1 C0 rot
                rt.u8(0xC1); rt.u8(0xC0); rt.u8(loop_rot);
                break;
            default:
                break;
        }
        //   dec ecx                       FF C9
        rt.u8(0xFF); rt.u8(0xC9);
        //   jnz .loop                     75 rel8
        {
            const size_t jnz_end = rt.size() + 2;
            const int32_t rel8 = static_cast<int32_t>(g6_loop_body_start) -
                                 static_cast<int32_t>(jnz_end);
            rt.u8(0x75);
            rt.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
        }

        MbaTransitionGenerator mba_gen(Architecture::x64);
        auto chain = mba_gen.generate(
            loop_output, table_xor_key, mx::x86::Reg::rax, rng,
            /*state_preserved=*/true);
        rt.bytes(ByteView{chain.data(), chain.size()});

        // Handler-table integrity check.
        // lea rbx, [rip + rel32]    48 8D 1D rel32
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0x1D);
        integrity_table_lea_patch = rt.size();
        rt.u32(0);
        table_patches.push_back(
            {integrity_table_lea_patch, rt.size()});

        // mov ecx, total_handlers    B9 imm32
        rt.u8(0xB9);
        rt.u32(total_handlers);

        // xor edx, edx               31 D2
        rt.u8(0x31); rt.u8(0xD2);

        // .loop:
        const size_t loop_start = rt.size();
        rt.u8(0x33); rt.u8(0x13);              // xor edx, [rbx]
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xC3); rt.u8(0x04);  // add rbx, 4
        rt.u8(0xFF); rt.u8(0xC9);              // dec ecx
        const size_t jnz_end = rt.size() + 2;
        const int32_t  rel8    = static_cast<int32_t>(loop_start) -
                                 static_cast<int32_t>(jnz_end);
        rt.u8(0x75); rt.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8))); // jnz

        // xor edx, <expected>        81 F2 imm32
        rt.u8(0x81); rt.u8(0xF2);
        integrity_expected_patch = rt.size();
        rt.u32(0);

        // xor eax, edx               31 D0
        rt.u8(0x31); rt.u8(0xD0);

        // mov [rsp + disp8], eax    89 44 24 disp8
        rt.u8(0x89); rt.u8(0x44); rt.u8(0x24);
        rt.u8(static_cast<uint8_t>(static_cast<int8_t>(imagebase_key_disp)));

        // Anti-emulation checks. Suppressed when the caller opted
        // out via `skip_anti_tamper_checks` — see VmGenOptions docs
        // for why S2c's inner VM needs this.
        if (!opts.skip_anti_tamper_checks) {
            static const anti_emulation::CheckRegistry registry;
            if (registry.size() > 0) {
                const size_t upper = std::min<size_t>(registry.size(), 2);
                const size_t count = rng.next_range(1, static_cast<uint32_t>(upper));
                const auto picks = registry.pick_random(count, rng);
                for (const auto* check : picks) {
                    check->emit(rt, imagebase_key_disp, rng);
                }
            }
        }

        // G3 — Anti-tamper checks.
        //
        // These probe the running process for live debuggers, hardware
        // breakpoints, EDR hooks, and suspicious memory permissions.
        // The registry contains a mix of syscall-based checks
        // (hw_breakpoint_sweep, page_protection_sweep) and user-mode
        // checks (import_hook_detect, self_crc). We cap at one
        // pick per build: anti-tamper check bodies range from ~50 to
        // ~150 bytes each, and stacking several would bloat the entry
        // stub without proportional gain.
        //
        // The check's `required_syscall_name()` tells us whether we
        // need to emit a Hell's Gate resolver before the check runs,
        // and which function it should resolve. For non-syscall
        // checks the name is null and we skip the ~155-byte resolver
        // block entirely — this is what makes it cheap to add new
        // user-mode checks without touching the orchestration here.
        // The backend folds a per-call random salt into both the
        // target-hash constant and the runtime DJB2 seed, so the
        // emitted resolver's `cmp eax, imm32` and `mov eax, imm32`
        // slots change from build to build.
        //
        // Suppressed when the caller opted out via
        // `skip_anti_tamper_checks`. Specifically, `page_protection_check`
        // reads its containing section's protection mask via
        // NtQueryVirtualMemory and expects the packer to have revoked
        // WRITE; S2c's inner VM lives in `.mxstr` which is
        // intentionally R+W+X (for the in-place XOR decrypt + sticky
        // flag), so the check would corrupt the handler-table key
        // on roughly one build in four.
        if (!opts.skip_anti_tamper_checks) {
            static const anti_tamper::CheckRegistry tamper_registry;
            if (tamper_registry.size() > 0) {
                const auto picks = tamper_registry.pick_random(1, rng);
                if (!picks.empty()) {
                    const anti_tamper::ICheck* picked = picks[0];

                    // Emit the Hell's Gate SSN resolver ONLY when
                    // the picked check actually needs a syscall.
                    const char* syscall_name =
                        picked->required_syscall_name();
                    if (syscall_name != nullptr && *syscall_name != '\0') {
                        const uint32_t salt = rng.next_u32();
                        const uint32_t target_hash =
                            anti_tamper::djb2_ascii_hash_salted(
                                syscall_name, salt);
                        anti_tamper::emit_hells_gate_resolver(
                            rt, target_hash, salt);
                    }

                    // Build the per-region context. Self-CRC reads
                    // `entry_offset` from here to compute the rip-
                    // relative rel32 back to the entry stub start,
                    // and pushes into `self_crc_patches` so the
                    // backend can finalise its expected-CRC imm32
                    // after every other post-hoc patch has landed.
                    anti_tamper::CheckContext ctx{};
                    ctx.entry_offset     = entry_offset;
                    ctx.self_crc_patches = &self_crc_patches;
                    picked->emit(rt, imagebase_key_disp, rng, ctx);
                }
            }
        }
    }

    // lea r11, [rip + bytecode_rel32]
    entry_bc_patch = emit_lea_r11_rip_rel32(rt);
    entry_bc_patch_end = rt.size();

    // Inline first dispatch. Polymorphism on: entry is a prime signature
    // target, so it gets a random table-base reg and dispatch shape just
    // like handler tails.
    const auto entry_tail = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                                false, table_key_patches,
                                                vflags_key, vflags_rol,
                                                rflags_disp, &rng,
                                                imagebase_key_disp);
    table_patches.push_back({entry_tail.rel32_offset, entry_tail.instruction_end});

    // Per-build inner-VM ISA permutation. Computed ONCE here and threaded
    // through every nested-wrapper emission + the final
    // `emit_inner_vm_runtime` call — so the byte values in the inline inner
    // bytecodes and the handler table ordering agree. Two builds of the
    // same input produce two different permutations, so the byte-level
    // shape of every inner-VM call site differs per build even though the
    // semantics are identical.
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

// Translate a native-reg operand (as emitted by the lifter) to its
// per-build virtual slot. The lifter refuses to emit RSP operands for
// generic ops, so native_to_slot[n] must be valid here.
uint8_t GenerationSession::remap_reg(uint8_t native_reg) const {
    const uint8_t slot = layout.native_to_slot[native_reg];
    return (slot == VmStackLayout::kJunkMarker) ? layout.junk_slot : slot;
}

void GenerationSession::push32(int32_t v) {
    const auto u = static_cast<uint32_t>(v);
    bytecode_plain.push_back(static_cast<uint8_t>(u & 0xFF));
    bytecode_plain.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
    bytecode_plain.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
    bytecode_plain.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
}

void GenerationSession::record_fold(uint8_t hid) {
    fold_events.push_back({bytecode_plain.size(), hid});
}

uint32_t GenerationSession::insert_bytes_at(size_t i) const {
    return static_cast<uint32_t>(dead_before[i]) +
           static_cast<uint32_t>(opq_before[i]) * 5u;
}

void GenerationSession::emit_g4_inserts(size_t i) {
    for (uint8_t k = 0; k < dead_before[i]; ++k) {
        bytecode_plain.push_back(dead_handler_id);
        record_fold(dead_handler_id);
    }
    if (opq_before[i]) {
        bytecode_plain.push_back(opq_branch_handler_id);
        // 4 rel32-shaped bytes — random-looking to make the
        // fake target point "somewhere" in the bytecode. The
        // handler never adds them to r11, so the value is
        // purely for appearance.
        for (int b = 0; b < 4; ++b) {
            bytecode_plain.push_back(
                static_cast<uint8_t>(rng.next_range(0, 255)));
        }
        record_fold(opq_branch_handler_id);
    }
}

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
