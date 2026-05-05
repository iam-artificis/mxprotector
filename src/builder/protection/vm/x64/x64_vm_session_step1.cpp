/**
 * @file x64_vm_session_step1.cpp
 * @brief Implementation — `GenerationSession::step1_randomize`.
 *
 * Owns the per-build randomisation policy: opcode permutation, vEFLAGS
 * scramble parameters, stack layout choice, specialisation candidate
 * picks, handler-id shuffle, per-handler rolling-key fold-in keys.
 *
 * Lives in its own translation unit so the policy logic (~150 LOC) is
 * easy to read in isolation and to grow / test independently of the
 * orchestration in `x64_vm_session.cpp`.
 */

#include "x64_vm_session.hpp"

#include <algorithm>
#include <format>
#include <numeric>

#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

namespace mx::vm::x64 {

// ============================================================================
//                        Step 1 — per-build randomization
// ============================================================================
//
// Opcode handler_id permutation, handler variant assignment, initial
// rolling-key seed, stack layout, vEFLAGS scrambler keys, anti-debug
// specialisation picks, and the per-handler key table that feeds the
// rolling cipher.
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

} // namespace mx::vm::x64
