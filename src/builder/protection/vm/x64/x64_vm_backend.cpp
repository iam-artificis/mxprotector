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

namespace mx::vm::x64 {

namespace {

/// How many handler variants each canonical VmOp emits. Ops with multiple
/// variants have two (or more) mathematically equivalent emission forms;
/// the encoder picks one at random per instruction to defeat simple
/// opcode-table recovery (G4 — handler-id polymorphism) and, for
/// add/sub/xor_rr, optionally dispatch through a nested inner VM
/// (G2 — nested VM).
constexpr uint8_t variant_count_for(VmOp op) {
    switch (op) {
        // add_rr / sub_rr / xor_rr each have THREE variants:
        //   V0 canonical direct ALU
        //   V1 MBA / neg / mba alternative
        //   V2 G2 nested — outer handler body calls into the inner VM
        //                  runtime and returns via `ret`
        case VmOp::add_rr:
        case VmOp::sub_rr:
        case VmOp::xor_rr:
        case VmOp::and_rr:   // V0 direct, V1 De Morgan, V2 nested
        case VmOp::or_rr:    // V0 direct, V1 De Morgan, V2 nested
        case VmOp::mov_rr:   // V0 mov/mov,  V1 push/pop, V2 nested
        case VmOp::not_r:    // V0 not r/m64, V1 xor -1,  V2 nested
        case VmOp::neg_r:    // V0 neg r/m64, V1 not+inc, V2 nested
            return 3;
        // Immediate-form ALU / mov: no MBA alternative today, so
        // V0 direct and V1 nested — 50/50 choice per bytecode
        // instruction. Adding an MBA-style V2 later is welcome but
        // out of scope for G2.
        case VmOp::mov_ri32:
        case VmOp::add_ri32:
        case VmOp::sub_ri32:
        case VmOp::xor_ri32:
        case VmOp::and_ri32:
        case VmOp::or_ri32:
            return 2;
        case VmOp::vjcc:
            return 16;   // one handler per x86 condition code (0..F)
        case VmOp::dead:
            return 1;    // G4: one dead-op handler, called from random bc positions
        case VmOp::opq_branch:
            return 1;    // G4: single opaque-branch handler (fakes vjmp at the byte level)
        default:
            return 1;
    }
}

// ----------------------------------------------------------------------------
// G1 — Per-build handler specialisation
// ----------------------------------------------------------------------------
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

/// Maximum specialisations per build. Each one consumes one handler_id
/// and adds ~10 bytes of body (plus the standard tail dispatch). Eight
/// fits comfortably under the 255-handler budget even for regions with
/// dozens of native escapes.
constexpr size_t kMaxSpecializations = 8;

/// Ops whose r-r form has a tractable specialised body. imul_rr is
/// excluded because its opcode is `48 0F AF` (4 prefix bytes) and would
/// need a different specialised emitter; can be added later.
constexpr VmOp kSpecializableOps[] = {
    VmOp::mov_rr,
    VmOp::add_rr,
    VmOp::sub_rr,
    VmOp::xor_rr,
    VmOp::and_rr,
    VmOp::or_rr,
};

/// True if a VmOp is a candidate for specialisation. Used in the bytecode
/// encoder to skip the spec_match search for non-r-r ops.
constexpr bool is_specializable_op(VmOp op) {
    switch (op) {
        case VmOp::mov_rr:
        case VmOp::add_rr:
        case VmOp::sub_rr:
        case VmOp::xor_rr:
        case VmOp::and_rr:
        case VmOp::or_rr:
            return true;
        default:
            return false;
    }
}

/// Maps a specialisable VmOp to the `op_mr` byte expected by
/// `emit_handler_alu_rr_specialized`. mov_rr is special-cased by the
/// caller (it uses the dedicated `emit_handler_mov_rr_specialized`).
constexpr uint8_t alu_op_mr_for(VmOp op) {
    switch (op) {
        case VmOp::add_rr: return 0x01;
        case VmOp::sub_rr: return 0x29;
        case VmOp::xor_rr: return 0x31;
        case VmOp::and_rr: return 0x21;
        case VmOp::or_rr:  return 0x09;
        default:           return 0x00;  // unreachable for specialisations
    }
}

} // anonymous namespace

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

    const bool emit_exit_as_jmp = opts.emit_exit_as_jmp;

    // ------------------------------------------------------------------------
    // Step 1 — per-build randomization: opcode handler_id permutation, handler
    // variant assignment, initial rolling key, vEFLAGS scramble (key + rol).
    // ------------------------------------------------------------------------
    VmOpcodeMap map{};
    do { map.opcode_xor_key = rng.next_u8(); } while (map.opcode_xor_key == 0);
    const uint8_t initial_key = map.opcode_xor_key;

    // vEFLAGS transform: stored_slot = rol(real_rflags, vflags_rol) ^ vflags_key
    //   - key is a full 32-bit random — can land bits anywhere because the exit
    //     stub fully descrambles before popfq (no writable-bits constraint)
    //   - rol is 1..31 (non-zero) so the shape of the `xor imm32; popfq` pattern
    //     breaks completely: the imm32 differs between slots, and there's
    //     always a rol/ror instruction adjacent to it
    const uint32_t vflags_key = rng.next_u32() | 1;      // any non-zero u32
    const uint32_t vflags_rol = rng.next_range(1, 31);   // rotate amount 1..31

    // Per-build random VM stack layout: which virtual slot hosts each native
    // GPR, which slot is the junk slot, AND how many extra padding qwords
    // sit between the GPR area and the RFLAGS slot (G7 randomization).
    // Cross-VM sub-VMs use independent layouts — register state flows
    // between them via CPU, not via slots.
    const VmStackLayout layout      = VmStackLayout::make_random(rng);
    const int32_t rolling_key_disp  = layout.rolling_key_disp;
    const int32_t rflags_disp       = layout.rflags_offset();
    const int32_t native_shift      = layout.native_frame_shift();

    const uint32_t native_count = static_cast<uint32_t>(std::count_if(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) { return v.op == VmOp::native; }));

    // Total generic variant slots (sum of variants across all canonical VmOps).
    uint32_t generic_variant_total = 0;
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
    std::vector<Specialization> specializations;
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

    const uint32_t total_handlers =
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
    std::vector<std::vector<uint8_t>> variant_handler_ids(kVmOpCount);
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

    std::vector<uint8_t> native_handler_ids;
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

    // ------------------------------------------------------------------------
    // Step 2 — build plain bytecode stream, then stream-encrypt with rolling
    // key. The encryption walks bytes in fetch order (opcode, operands, next
    // opcode, ...) so the runtime decryption order matches.
    //
    // Plumbing order:
    //   1. Define the operand remap helper (uses the per-region layout).
    //   2. Precompute spec_match[i]: whether each instruction matches one
    //      of the per-build specialisations. Drives BOTH the bytecode size
    //      table and the encoding loop.
    //   3. Compute bc_offset[] using the spec-aware sizes.
    //   4. Emit bytecode using the same spec_match decisions.
    // ------------------------------------------------------------------------
    ByteBuffer bytecode_plain;
    bytecode_plain.reserve(instructions.size() * 4);

    uint32_t next_native_idx = 0;
    std::vector<uint32_t> native_handler_of_insn(instructions.size(), UINT32_MAX);

    // Translate a native-reg operand (as emitted by the lifter) to its
    // per-build virtual slot. The lifter refuses to emit RSP operands for
    // generic ops, so native_to_slot[n] must be valid here.
    auto remap_reg = [&](uint8_t native_reg) -> uint8_t {
        const uint8_t slot = layout.native_to_slot[native_reg];
        return (slot == VmStackLayout::kJunkMarker) ? layout.junk_slot : slot;
    };

    // G1 — Precompute specialisation matches.
    //
    // spec_match[i] = index into `specializations[]`, or -1 for "no match,
    // emit via the generic path". We do this BEFORE bc_offset[] because a
    // matched instruction's bytecode size shrinks from 3 bytes (handler_id
    // + 2 operand bytes) to 1 byte (handler_id only), and vjmp/vjcc rel32
    // values depend on bc_offset[].
    std::vector<int> spec_match(instructions.size(), -1);
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
    constexpr uint32_t kMaxDeadPerSlot        = 3;
    constexpr uint32_t kOpqBranchProbability  = 30;  // /100
    std::vector<uint8_t> dead_before(instructions.size() + 1, 0);
    std::vector<uint8_t> opq_before(instructions.size() + 1, 0);
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
    auto insert_bytes_at = [&](size_t i) -> uint32_t {
        return static_cast<uint32_t>(dead_before[i]) +
               static_cast<uint32_t>(opq_before[i]) * 5u;
    };
    std::vector<uint32_t> bc_offset(instructions.size() + 1);
    bc_offset[0] = insert_bytes_at(0);
    for (size_t i = 0; i < instructions.size(); ++i) {
        const uint32_t size = (spec_match[i] >= 0)
            ? 1u   // specialised: just handler_id, no operand bytes
            : (1u + vm_op_operand_size(instructions[i].op));
        bc_offset[i + 1] = bc_offset[i] + size + insert_bytes_at(i + 1);
    }

    // Phase 2: encode bytecode.
    auto push32 = [&](int32_t v) {
        const auto u = static_cast<uint32_t>(v);
        bytecode_plain.push_back(static_cast<uint8_t>(u & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
    };

    // G4: cached handler ids for the phase-2 inserter below.
    const uint8_t dead_handler_id =
        variant_handler_ids[static_cast<uint32_t>(VmOp::dead)][0];
    const uint8_t opq_branch_handler_id =
        variant_handler_ids[static_cast<uint32_t>(VmOp::opq_branch)][0];
    auto emit_g4_inserts = [&](size_t i) {
        for (uint8_t k = 0; k < dead_before[i]; ++k) {
            bytecode_plain.push_back(dead_handler_id);
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
        }
    };

    for (size_t i = 0; i < instructions.size(); ++i) {
        // G4: insert this slot's dummy bytes BEFORE the real
        // instruction. bc_offset[i] already accounts for them.
        emit_g4_inserts(i);

        const auto& vi = instructions[i];

        // G1 — Specialised path: emit only the handler_id, no operand bytes.
        // The matched specialised handler has dst/src disps baked in, so the
        // runtime decoder needs no operand fetch.
        if (spec_match[i] >= 0) {
            bytecode_plain.push_back(
                specializations[static_cast<size_t>(spec_match[i])].handler_id);
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
    const bool has_branches = std::any_of(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) {
            return v.op == VmOp::vjmp || v.op == VmOp::vjcc;
        });
    const bool rolling = !has_branches;

    // Bytecode encryption: rolling-key or static XOR.
    if (rolling) {
        uint8_t key = initial_key;
        for (auto& b : bytecode_plain) {
            const uint8_t plain = b;
            b = static_cast<uint8_t>(plain ^ key);
            key ^= plain;
        }
    } else {
        for (auto& b : bytecode_plain) {
            b ^= initial_key;
        }
    }

    // ------------------------------------------------------------------------
    // Step 3 — emit the runtime blob:
    //   [entry_stub][handlers ...][handler_table][bytecode]
    // ------------------------------------------------------------------------
    RawEmitter rt;

    struct TablePatch {
        size_t rel32_offset;
        size_t instruction_end;
    };
    std::vector<TablePatch> table_patches;

    // Self-CRC patch records. Populated by the Self-CRC anti-tamper
    // check (if picked) at emit time; finalised in Step 4 AFTER every
    // other post-hoc patch has been applied to the entry stub, so
    // that the computed CRC matches what the runtime loop reads.
    std::vector<anti_tamper::SelfCrcPatchRecord> self_crc_patches;

    // ---- Entry stub --------------------------------------------------------
    const size_t entry_offset = rt.size();

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
    const int32_t imagebase_key_disp =
        opts.use_imagebase_key ? (rolling_key_disp + 4) : -1;

    // Handler-table encryption key.
    const uint32_t table_xor_key = opts.use_imagebase_key
        ? rng.next_u32()
        : (rng.next_u32() | 1);  // legacy path wants non-zero

    // Patch offsets for the integrity check that is emitted inside the
    // ImageBase block. Zero when integrity is not enabled.
    size_t integrity_table_lea_patch = 0;
    size_t integrity_expected_patch  = 0;

    if (opts.use_imagebase_key) {
        //   65 48 8B 04 25 60 00 00 00   mov rax, gs:[0x60]    ; PEB
        //   48 8B 40 10                  mov rax, [rax + 0x10] ; ImageBase
        //   <MBA chain>                  transforms eax IB_low32 -> table_xor_key
        //   <integrity check>            xor'd into eax (zero on intact table)
        //   89 44 24 <disp8>             mov [rsp + key_disp], eax
        rt.u8(0x65); rt.u8(0x48); rt.u8(0x8B); rt.u8(0x04); rt.u8(0x25);
        rt.u8(0x60); rt.u8(0x00); rt.u8(0x00); rt.u8(0x00);
        rt.u8(0x48); rt.u8(0x8B); rt.u8(0x40); rt.u8(0x10);

        const uint32_t ib_low32 =
            static_cast<uint32_t>(opts.preferred_image_base & 0xFFFFFFFFULL);
        MbaTransitionGenerator mba_gen(Architecture::x64);
        auto chain = mba_gen.generate(
            ib_low32, table_xor_key, mx::x86::Reg::rax, rng,
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
        // The check's `required_syscall_hash()` tells us whether we
        // need to emit a Hell's Gate resolver before the check runs,
        // and which function it should resolve. For non-syscall
        // checks the hash is 0 and we skip the ~155-byte resolver
        // block entirely — this is what makes it cheap to add new
        // user-mode checks without touching the orchestration here.
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
                    const uint32_t target_hash =
                        picked->required_syscall_hash();
                    if (target_hash != 0u) {
                        anti_tamper::emit_hells_gate_resolver(
                            rt, target_hash);
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
    const size_t entry_bc_patch = emit_lea_r11_rip_rel32(rt);
    const size_t entry_bc_patch_end = rt.size();

    // Collection of positions where TABLE_XOR_KEY must be patched into the
    // `xor eax, KEY` instructions. Empty when `use_imagebase_key` is set.
    std::vector<size_t> table_key_patches;

    // Inline first dispatch. Polymorphism on: entry is a prime signature
    // target, so it gets a random table-base reg and dispatch shape just
    // like handler tails.
    const auto entry_tail = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                                false, table_key_patches,
                                                vflags_key, vflags_rol,
                                                rflags_disp, &rng,
                                                imagebase_key_disp);
    table_patches.push_back({entry_tail.rel32_offset, entry_tail.instruction_end});

    // ---- Handler emission --------------------------------------------------
    std::vector<size_t> handler_offset_by_id(total_handlers, SIZE_MAX);

    auto begin_handler = [&](uint8_t handler_id) {
        handler_offset_by_id[handler_id] = rt.size();
        emit_junk_prologue(rt, rng, /*max_bytes=*/8);
    };

    auto end_handler_tail = [&]() {
        const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                          has_branches, table_key_patches,
                                          vflags_key, vflags_rol,
                                          rflags_disp, &rng,
                                          imagebase_key_disp);
        table_patches.push_back({p.rel32_offset, p.instruction_end});
    };

    uint32_t exit_jmp_offset = 0;  // patched if emit_exit_as_jmp

    // G2 nested VM: every time an outer handler V2 is emitted, it
    // leaves a zero-filled `call rel32` operand where the rel32 to
    // `inner_vm_entry` needs to go. We collect those offsets here
    // and patch them all at once after the inner VM runtime has
    // been appended to the blob and its entry offset is known.
    std::vector<size_t> inner_vm_call_patches;

    // Per-build inner-VM ISA permutation. Computed ONCE here and
    // threaded through every nested-wrapper emission + the final
    // `emit_inner_vm_runtime` call — so the byte values in the
    // inline inner bytecodes and the handler table ordering agree.
    // Two builds of the same input produce two different
    // permutations, so the byte-level shape of every inner-VM call
    // site differs per build even though the semantics are
    // identical.
    const InnerVmIsa inner_vm_isa = make_random_inner_vm_isa(rng);

    auto emit_op_variant = [&](VmOp op, uint32_t variant) -> bool {
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
                // Coin flip per handler body: 50% chance the taken
                // path is the V0 direct `add r11, rax`, 50% it's
                // the V2 nested `mov r15, rax; call inner_vm_entry`.
                // Because vjcc's variant axis is already fully
                // consumed by the condition code (16 values), this
                // build-time randomization is the only diversity
                // knob available for its handler bodies.
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
                // its own handler. Trap with ud2 (no tail).
                emit_ud2(rt);
                return false;

            case VmOp::dead: {
                // G4 dead opcode — empty handler body. The encoder
                // inserts `dead` bytes into the bytecode stream at
                // random positions between real instructions; this
                // handler consumes its byte, runs NO body, and
                // dispatches to the next handler without touching
                // vflags.
                //
                // IMPORTANT: the tail dispatch here is emitted with
                // save_rflags=FALSE even in branch-containing
                // regions where all other handlers use save=TRUE.
                //
                // Why: on entry to this handler, host rflags do NOT
                // reflect the previous real handler's guest ALU —
                // they reflect the previous handler's TAIL-DISPATCH
                // fetch/xor sequence, which clobbered rflags after
                // the real save happened. If we let the dead
                // handler's tail call emit_vflags_store, it would
                // write those fetch-clobbered garbage flags to
                // `vflags`, overwriting the real guest flags that
                // were already safely stored there by the previous
                // handler's tail. A downstream `vjcc` would then
                // see garbage ZF/SF/CF and mispredict the branch.
                //
                // Skipping the save leaves vflags untouched — the
                // real guest flags remain visible to the next
                // `vjcc`. Net effect of the dead handler on the VM
                // state: r11 advanced by 1 (via the fetch inside
                // the tail), nothing else. That's exactly what a
                // "no-op insert" should do.
                const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                                   /*save_rflags=*/false,
                                                   table_key_patches,
                                                   vflags_key, vflags_rol,
                                                   rflags_disp, &rng,
                                                   imagebase_key_disp);
                table_patches.push_back({p.rel32_offset, p.instruction_end});
                return false;  // tail already emitted inline
            }

            case VmOp::opq_branch: {
                // G4 opaque branch. Shape-compatible with `vjmp`: a
                // 4-byte rel32-shaped operand is fetched by the
                // handler body, but NEVER added to r11. Falls
                // through to the next instruction regardless of
                // what the operand bytes say.
                //
                // The fetch IS necessary — without it, r11 would
                // still point at the rel32 bytes when the tail
                // dispatch fetches, and those bytes would get
                // dispatched as a handler_id (misdecode).
                //
                // As with `dead`, the tail is emitted inline with
                // save_rflags=false to avoid clobbering the real
                // guest flags in vflags. `emit_fetch_dword`
                // clobbers host rflags via its xor sequences, and
                // we don't want those garbage flags landing in
                // vflags where a downstream `vjcc` would read them.
                emit_fetch_dword(rt, rolling_key_disp, rolling);
                const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                                   /*save_rflags=*/false,
                                                   table_key_patches,
                                                   vflags_key, vflags_rol,
                                                   rflags_disp, &rng,
                                                   imagebase_key_disp);
                table_patches.push_back({p.rel32_offset, p.instruction_end});
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
                return false;
            }
            case VmOp::count_:
                return false;
        }
        return false;
    };

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

    // Per-instruction native handlers — one per VmOp::native insn.
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
        {
            const auto p = emit_tail_dispatch(rt, rolling_key_disp, rolling,
                                              false, table_key_patches,
                                              vflags_key, vflags_rol,
                                              rflags_disp, &rng,
                                              imagebase_key_disp);
            table_patches.push_back({p.rel32_offset, p.instruction_end});
        }
    }

    // ---- Specialised handlers (G1) -----------------------------------------
    // Each specialisation emits a body with hard-coded slot disps. No
    // operand fetch, no remap, no reusable shape — every specialised
    // handler differs from the others and from every generic handler.
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

    // ---- Inner VM runtime (G2 — nested VM) ---------------------------------
    //
    // Emit the 88-byte inner VM runtime (dispatcher + 6 inner
    // handlers + relative handler table) exactly once per outer VM
    // blob, and patch every outer handler's `call rel32
    // inner_vm_entry` that was left zero-filled during emission.
    //
    // The inner VM is placed AFTER the last outer handler and
    // BEFORE the outer handler table. Putting it here means:
    //   - Outer handlers that use V2 reference it via a forward
    //     rel32 `call`, which is the normal dispatch direction.
    //   - The outer handler table still comes last, right before
    //     the bytecode stream, so the existing rel32 patches to
    //     `handler_table_offset` aren't affected.
    //   - If no outer handler ended up choosing V2 for any
    //     instance, the inner VM block still exists but is dead
    //     code. 88 bytes of overhead is acceptable.
    //
    // The inner VM is self-contained: all of its intra-block
    // branches (rel8 jumps back to the dispatch loop) and the
    // rip-relative `lea r13, handler_table` are computed at emit
    // time from static offsets. No runtime patches are needed.
    size_t inner_vm_entry_offset = 0;
    {
        // Align to 16 so the dispatcher entry is instruction-cache
        // friendly and so a future self-mutation pass can trivially
        // find the block by scanning for a 16-byte-aligned
        // signature.
        while (rt.size() % 16 != 0) rt.u8(0xCC);
        inner_vm_entry_offset = rt.size();
        (void) emit_inner_vm_runtime(rt, inner_vm_isa);
    }

    // Patch every G2 V2 outer-handler's `call rel32 inner_vm_entry`
    // now that the inner VM entry has a definite offset.
    for (const size_t rel32_patch : inner_vm_call_patches) {
        const size_t call_end = rel32_patch + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(inner_vm_entry_offset) -
            static_cast<int64_t>(call_end));
        std::memcpy(rt.buf.data() + rel32_patch, &rel, 4);
    }

    // ---- Handler table -----------------------------------------------------
    // Align to 4 bytes so the 32-bit entries are naturally aligned.
    while (rt.size() % 4 != 0) rt.u8(0xCC);
    const size_t handler_table_offset = rt.size();
    for (uint32_t h = 0; h < total_handlers; ++h) {
        rt.u32(0);  // placeholder, patched below
    }

    // ---- Bytecode ----------------------------------------------------------
    while (rt.size() % 8 != 0) rt.u8(0xCC);
    const size_t bytecode_offset = rt.size();
    rt.bytes(ByteView{bytecode_plain.data(), bytecode_plain.size()});

    // ------------------------------------------------------------------------
    // Step 4 — patch all rel32s and the handler_table entries.
    // ------------------------------------------------------------------------

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

    // handler_table entries: each = (handler_offset - table_offset) ^ table_xor_key
    uint32_t table_xor_sum = 0;
    for (uint32_t h = 0; h < total_handlers; ++h) {
        if (handler_offset_by_id[h] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("X64VmBackend: handler id {} not emitted", h)));
        }
        auto rel = static_cast<int32_t>(
            static_cast<int64_t>(handler_offset_by_id[h]) -
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

    VmRuntime result;
    result.blob = std::move(rt.buf);
    result.entry_offset    = static_cast<uint32_t>(entry_offset);
    result.bytecode_offset = static_cast<uint32_t>(bytecode_offset);
    result.bytecode_size   = static_cast<uint32_t>(bytecode_plain.size());
    result.handler_count   = total_handlers;
    result.opcode_map      = map;
    result.exit_jmp_patch  = exit_jmp_offset;
    return result;
}

} // namespace mx::vm::x64
