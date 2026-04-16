/**
 * @file x64_bytecode_encoder.hpp
 * @brief [BUILDER, x64] Plain-bytecode emission + stream encryption.
 *
 * The x64 VM runtime backend splits into four cooperating phases:
 *   1. Per-build randomization — opcode-map + handler-id allocation.
 *   2. **Bytecode encoding (this file)** — build the instruction stream,
 *      insert G4 dead-ops / opaque branches, compute vjmp rel32s, apply
 *      the rolling-key / static XOR cipher.
 *   3. Runtime blob emission — entry stub, handler bodies, inner VM,
 *      trampolines, handler table.
 *   4. Patch-up — rel32s, handler-table encryption, integrity sum,
 *      self-CRC finalisation.
 *
 * The encoder is a pure data-in / data-out pass: it never touches the
 * emitted runtime blob, the handler bodies, or the patch lists. Given
 * the phase-1 outputs (`variant_handler_ids`, `specializations`,
 * `per_handler_key`, `initial_key`, `layout`) and a mutable
 * `Randomizer`, it produces the encrypted bytecode plus the two facts
 * downstream phases need to know about the region:
 *
 *   * `has_branches` — whether any vjmp/vjcc survived lifting. Drives
 *     `rolling` below and forces the static-XOR cipher so key-state
 *     checkpoints don't have to be reconstructed at branch targets.
 *   * `rolling` — negation of `has_branches`. Enables the rolling-key
 *     cipher + G4 per-handler fold-ins in all downstream handler tails.
 *
 * `native_handler_of_insn[i]` maps the encoded index of each `VmOp::native`
 * instruction to the handler id reserved for it. Step 3c iterates the
 * original instruction list and uses this table to bind per-instruction
 * native-handler bodies to the right id.
 *
 * Internals (dead-op / opaque-branch insertion arrays, fold-in event
 * list, `bc_offset`) are intentionally NOT exposed — nothing outside
 * the encoder consumes them.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"
#include "mxprotector/protection/vm/vm_stack_layout.hpp"

namespace mx::vm::x64 {

/// G1 specialisation — runtime tuple bound to a specific handler_id.
///
/// Produced by the backend's step-1 handler-id allocator and consumed
/// by the bytecode encoder to short-circuit a matching r-r instruction
/// from the 3-byte generic form (handler_id + dst byte + src byte) to
/// the 1-byte specialised form (handler_id only).
///
/// The `handler_id` field is zero until the allocator assigns a slot in
/// the shuffled handler-id space; the encoder sees the post-allocation
/// state.
struct Specialization {
    VmOp    op{};         // mov_rr / add_rr / sub_rr / xor_rr / and_rr / or_rr
    uint8_t dst_vreg{};   // 0..15, ≠ junk_slot
    uint8_t src_vreg{};   // 0..15, ≠ junk_slot
    uint8_t handler_id{}; // assigned during slot allocation
};

/// Everything the encoder needs from phase 1. All references are
/// non-owning; the caller must keep them alive for the duration of the
/// `encode_bytecode` call.
///
/// `variant_handler_ids[op]` holds the handler ids allocated for each
/// variant of the canonical VmOp `op`. `native_handler_ids` is a
/// separate flat list — one id per `VmOp::native` encountered in
/// `instructions`, in encounter order — because native handlers are
/// per-instruction, not per-variant.
struct BytecodeEncoderInputs {
    const std::vector<VmInstruction>&        instructions;
    const std::vector<Specialization>&       specializations;
    const std::vector<std::vector<uint8_t>>& variant_handler_ids;
    const std::vector<uint8_t>&              native_handler_ids;
    const std::vector<uint8_t>&              per_handler_key;
    uint8_t                                  initial_key;
    const VmStackLayout&                     layout;
    Randomizer&                              rng;
};

/// What phase 3 / phase 4 need from the encoder. Only the fields that
/// outlive the encoding pass are kept — internal scratch (spec_match,
/// bc_offset, fold events, dead/opq insertion arrays) lives and dies
/// inside `encode_bytecode`.
struct BytecodeEncoderOutputs {
    ByteBuffer            bytecode;                 ///< Encrypted bytecode stream, ready to copy into the blob.
    std::vector<uint32_t> native_handler_of_insn;   ///< `instruction_index → native-handler slot` (UINT32_MAX for non-native).
    bool                  has_branches{};           ///< At least one vjmp/vjcc survived lifting.
    bool                  rolling{};                ///< Rolling-key cipher is active (== !has_branches).
};

/// Encode the instruction stream into the final bytecode.
///
/// Steps performed, in order:
///   1. Precompute G1 specialisation matches per instruction.
///   2. Draw G4 dead-op / opaque-branch insertion counts for every slot.
///   3. Phase 1 — compute `bc_offset[]` using spec-aware + insertion sizes.
///   4. Phase 2 — emit opcodes, operands, and insertion bytes in fetch order.
///   5. Apply the rolling-key cipher (with per-handler fold-in events) for
///      branch-free regions, or static XOR for branch-containing regions.
///
/// The encoder allocates all of its scratch internally; nothing escapes
/// except what sits in `BytecodeEncoderOutputs`.
[[nodiscard]] BytecodeEncoderOutputs encode_bytecode(const BytecodeEncoderInputs& in);

} // namespace mx::vm::x64
