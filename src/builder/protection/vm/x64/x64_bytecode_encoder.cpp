/**
 * @file x64_bytecode_encoder.cpp
 * @brief [BUILDER, x64] Bytecode encoder — implementation.
 *
 * Split out of `x64_vm_backend.cpp` (R1.3). Owns the pure
 * instructions-to-bytecode transformation and the stream cipher that
 * runs on top of it. Kept deliberately free of any handler-body or
 * runtime-blob knowledge so the emitter side can evolve independently.
 *
 * The implementation lives in an anonymous-namespace `Encoder` helper
 * that holds the phase-1 inputs and the partial outputs as members,
 * mirroring the pre-R1.3 in-function scratch. Each former inner lambda
 * (`remap_reg`, `push32`, `record_fold`, `insert_bytes_at`,
 * `emit_g4_inserts`) is now a method on this helper; the public
 * `encode_bytecode` entry point builds one and returns its outputs.
 */

#include "mxprotector/protection/vm/x64/x64_bytecode_encoder.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

#include <algorithm>

namespace mx::vm::x64 {

namespace {

/// G4 per-handler-key fold-in event. Each entry marks the end of one
/// handler's byte range in the bytecode buffer and the handler_id that
/// processed those bytes. The rolling-cipher pass walks this list and
/// applies `key ^= per_handler_key[id]` after each range.
struct FoldInEvent {
    size_t  end_offset;
    uint8_t handler_id;
};

class Encoder {
public:
    explicit Encoder(const BytecodeEncoderInputs& in) : in_(in) {}

    /// Runs the full encoding pipeline and returns the encoder outputs.
    [[nodiscard]] BytecodeEncoderOutputs run();

private:
    // G4 obfuscation insertion density:
    //   * `dead_before[i]` — number of zero-operand `VmOp::dead`
    //     handler_id bytes to insert before real instruction `i`.
    //     Uniform draw [0..kMaxDeadPerSlot].
    //   * `opq_before[i]` — whether to insert a single
    //     `VmOp::opq_branch` at this slot. Binary draw with
    //     probability kOpqBranchProbability.
    static constexpr uint32_t kMaxDeadPerSlot       = 3;
    static constexpr uint32_t kOpqBranchProbability = 30;   // /100

    const BytecodeEncoderInputs& in_;

    // Phase outputs under construction.
    ByteBuffer               bytecode_;
    std::vector<uint32_t>    native_handler_of_insn_;

    // Internal scratch.
    std::vector<int>         spec_match_;
    std::vector<uint8_t>     dead_before_;
    std::vector<uint8_t>     opq_before_;
    std::vector<uint32_t>    bc_offset_;
    std::vector<FoldInEvent> fold_events_;
    uint8_t                  dead_handler_id_{};
    uint8_t                  opq_branch_handler_id_{};
    uint32_t                 next_native_idx_{};

    // ---- Helpers (were lambdas inside the monolithic step) --------------
    [[nodiscard]] uint8_t  remap_reg(uint8_t native_reg) const;
    void                   push32(int32_t v);
    void                   record_fold(uint8_t hid);
    [[nodiscard]] uint32_t insert_bytes_at(size_t i) const;
    void                   emit_g4_inserts(size_t i);

    // ---- Phases ----------------------------------------------------------
    void phase_precompute_spec_match();
    void phase_roll_g4_insertions();
    void phase_compute_bc_offsets();
    void phase_emit_bytecode(bool& out_has_branches);
    void phase_encrypt(bool has_branches);
};

// =========================================================================
// Helpers
// =========================================================================

// Translate a native-reg operand (as emitted by the lifter) to its
// per-build virtual slot. The lifter refuses to emit RSP operands for
// generic ops, so native_to_slot[n] must be valid here.
uint8_t Encoder::remap_reg(uint8_t native_reg) const {
    const uint8_t slot = in_.layout.native_to_slot[native_reg];
    return (slot == VmStackLayout::kJunkMarker) ? in_.layout.junk_slot : slot;
}

void Encoder::push32(int32_t v) {
    const auto u = static_cast<uint32_t>(v);
    bytecode_.push_back(static_cast<uint8_t>(u & 0xFF));
    bytecode_.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
    bytecode_.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
    bytecode_.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
}

void Encoder::record_fold(uint8_t hid) {
    fold_events_.push_back({bytecode_.size(), hid});
}

uint32_t Encoder::insert_bytes_at(size_t i) const {
    return static_cast<uint32_t>(dead_before_[i]) +
           static_cast<uint32_t>(opq_before_[i]) * 5u;
}

void Encoder::emit_g4_inserts(size_t i) {
    for (uint8_t k = 0; k < dead_before_[i]; ++k) {
        bytecode_.push_back(dead_handler_id_);
        record_fold(dead_handler_id_);
    }
    if (opq_before_[i]) {
        bytecode_.push_back(opq_branch_handler_id_);
        // 4 rel32-shaped bytes — random-looking to make the fake
        // target point "somewhere" in the bytecode. The handler
        // never adds them to r11, so the value is purely for
        // appearance.
        for (int b = 0; b < 4; ++b) {
            bytecode_.push_back(
                static_cast<uint8_t>(in_.rng.next_range(0, 255)));
        }
        record_fold(opq_branch_handler_id_);
    }
}

// =========================================================================
// Phases
// =========================================================================

// G1 — Precompute specialisation matches.
//
// spec_match[i] = index into `specializations[]`, or -1 for "no match,
// emit via the generic path". We do this BEFORE bc_offset[] because a
// matched instruction's bytecode size shrinks from 3 bytes (handler_id
// + 2 operand bytes) to 1 byte (handler_id only), and vjmp/vjcc rel32
// values depend on bc_offset[].
void Encoder::phase_precompute_spec_match() {
    spec_match_.assign(in_.instructions.size(), -1);
    if (in_.specializations.empty()) return;

    for (size_t i = 0; i < in_.instructions.size(); ++i) {
        const auto& vi = in_.instructions[i];
        if (!is_specializable_op(vi.op)) continue;
        const uint8_t dst_v = remap_reg(vi.dst);
        const uint8_t src_v = remap_reg(vi.src);
        for (size_t s = 0; s < in_.specializations.size(); ++s) {
            const auto& spec = in_.specializations[s];
            if (spec.op == vi.op
             && spec.dst_vreg == dst_v
             && spec.src_vreg == src_v)
            {
                spec_match_[i] = static_cast<int>(s);
                break;  // first match wins
            }
        }
    }
}

// G4 dead-opcode / opaque-branch insertion draws. Pre-decide how many
// dummy bytes sit before each real instruction (position 0..N-1) and
// after the last one (position N, before the terminal `exit`).
//
// Branch constraint: neither insertion happens right after a vjmp/vjcc
// (index `i` such that `instructions[i-1]` is a branch). The branch's
// rel32 at runtime lands r11 at `bc_offset[i-1] + size(branch) =
// bc_offset[i] - inserts`, so any nonzero insert count at that slot
// would leave r11 `inserts` bytes BEFORE the target. Zeroing the slot
// is the simplest correct fix: bytes after a branch are unreachable on
// the taken path anyway.
void Encoder::phase_roll_g4_insertions() {
    dead_before_.assign(in_.instructions.size() + 1, 0);
    opq_before_.assign(in_.instructions.size() + 1, 0);
    for (size_t i = 0; i <= in_.instructions.size(); ++i) {
        const bool after_branch =
            (i > 0) &&
            (in_.instructions[i - 1].op == VmOp::vjmp ||
             in_.instructions[i - 1].op == VmOp::vjcc);
        if (after_branch) continue;
        dead_before_[i] =
            static_cast<uint8_t>(in_.rng.next_range(0, kMaxDeadPerSlot));
        if (in_.rng.next_range(0, 99) < kOpqBranchProbability) {
            opq_before_[i] = 1;
        }
    }
}

// Phase 1 — compute bytecode offsets using spec-aware sizes + G4
// obfuscation insertions. vjmp/vjcc rel32 depends on the target
// instruction's bytecode offset, so the counts of dead bytes and
// opaque branches inserted BEFORE the target are correctly reflected
// in the computed rel32.
//
// Insertion bytes per slot i:
//   dead_before[i]            (1 byte each)
// + opq_before[i] * 5         (handler_id + 4 operand bytes)
void Encoder::phase_compute_bc_offsets() {
    bc_offset_.assign(in_.instructions.size() + 1, 0);
    bc_offset_[0] = insert_bytes_at(0);
    for (size_t i = 0; i < in_.instructions.size(); ++i) {
        const uint32_t size = (spec_match_[i] >= 0)
            ? 1u   // specialised: just handler_id, no operand bytes
            : (1u + vm_op_operand_size(in_.instructions[i].op));
        bc_offset_[i + 1] = bc_offset_[i] + size + insert_bytes_at(i + 1);
    }
}

// Phase 2 — encode bytecode.
void Encoder::phase_emit_bytecode(bool& out_has_branches) {
    native_handler_of_insn_.assign(in_.instructions.size(), UINT32_MAX);

    // G4: cache the handler_ids for the dead / opq-branch handlers so
    // every dummy insertion refers to them without re-indexing.
    dead_handler_id_ =
        in_.variant_handler_ids[static_cast<uint32_t>(VmOp::dead)][0];
    opq_branch_handler_id_ =
        in_.variant_handler_ids[static_cast<uint32_t>(VmOp::opq_branch)][0];

    fold_events_.clear();
    fold_events_.reserve(in_.instructions.size() * 2);
    next_native_idx_ = 0;

    bytecode_.reserve(in_.instructions.size() * 4);

    for (size_t i = 0; i < in_.instructions.size(); ++i) {
        // G4: insert this slot's dummy bytes BEFORE the real
        // instruction. bc_offset[i] already accounts for them.
        emit_g4_inserts(i);

        const auto& vi = in_.instructions[i];

        // G1 — Specialised path: emit only the handler_id, no operand bytes.
        // The matched specialised handler has dst/src disps baked in, so the
        // runtime decoder needs no operand fetch.
        if (spec_match_[i] >= 0) {
            const uint8_t spec_hid =
                in_.specializations[static_cast<size_t>(spec_match_[i])].handler_id;
            bytecode_.push_back(spec_hid);
            record_fold(spec_hid);
            continue;
        }

        uint8_t handler_id;
        if (vi.op == VmOp::native) {
            handler_id = in_.native_handler_ids[next_native_idx_];
            native_handler_of_insn_[i] = next_native_idx_;
            ++next_native_idx_;
        } else if (vi.op == VmOp::vjcc) {
            const auto& variants = in_.variant_handler_ids[static_cast<uint32_t>(VmOp::vjcc)];
            handler_id = variants[vi.branch_cc];
        } else {
            const auto& variants = in_.variant_handler_ids[static_cast<uint32_t>(vi.op)];
            const uint32_t v = (variants.size() > 1)
                ? in_.rng.next_range(0, static_cast<uint32_t>(variants.size() - 1))
                : 0u;
            handler_id = variants[v];
        }

        bytecode_.push_back(handler_id);

        switch (vi.op) {
            case VmOp::mov_rr:
            case VmOp::add_rr:
            case VmOp::sub_rr:
            case VmOp::xor_rr:
            case VmOp::and_rr:
            case VmOp::or_rr:
            case VmOp::imul_rr:
                bytecode_.push_back(remap_reg(vi.dst));
                bytecode_.push_back(remap_reg(vi.src));
                break;

            case VmOp::mov_ri32:
            case VmOp::add_ri32:
            case VmOp::sub_ri32:
            case VmOp::xor_ri32:
            case VmOp::and_ri32:
            case VmOp::or_ri32:
                bytecode_.push_back(remap_reg(vi.dst));
                push32(vi.imm32);
                break;

            case VmOp::mov_ri64:
                bytecode_.push_back(remap_reg(vi.dst));
                for (int b = 0; b < 8; ++b)
                    bytecode_.push_back(
                        static_cast<uint8_t>((vi.imm64 >> (b * 8)) & 0xFF));
                break;

            case VmOp::not_r:
            case VmOp::neg_r:
                bytecode_.push_back(remap_reg(vi.dst));
                break;

            case VmOp::shl_ri:
            case VmOp::shr_ri:
            case VmOp::sar_ri:
            case VmOp::rol_ri:
            case VmOp::ror_ri:
                bytecode_.push_back(remap_reg(vi.dst));
                bytecode_.push_back(vi.shift_count);
                break;

            case VmOp::vjmp:
            case VmOp::vjcc: {
                const auto target_off = bc_offset_[vi.branch_target_insn];
                const auto next_off   = bc_offset_[i + 1];
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

    // G4: last batch of dummy bytes between the final real instruction
    // and the terminal `exit` opcode.
    emit_g4_inserts(in_.instructions.size());

    // Terminal exit opcode.
    bytecode_.push_back(
        in_.variant_handler_ids[static_cast<uint32_t>(VmOp::exit)][0]);

    // Detect whether the instruction list contains any virtual branches.
    out_has_branches = std::any_of(
        in_.instructions.begin(), in_.instructions.end(),
        [](const VmInstruction& v) {
            return v.op == VmOp::vjmp || v.op == VmOp::vjcc;
        });
}

// Bytecode encryption: rolling-key (+ G4 per-handler fold-in) for
// branch-free regions, or static XOR for branch-containing regions.
//
// Branch-containing regions would need key-state checkpoints at branch
// targets to survive the cipher; first-pass design defers that. Straight-
// line regions keep the stronger rolling-key cipher.
void Encoder::phase_encrypt(bool has_branches) {
    if (!has_branches) {
        uint8_t key = in_.initial_key;
        size_t byte_pos = 0;
        size_t event_idx = 0;
        while (byte_pos < bytecode_.size()) {
            const size_t next_boundary =
                (event_idx < fold_events_.size())
                ? fold_events_[event_idx].end_offset
                : bytecode_.size();

            // Roll through bytes up to the next handler boundary.
            while (byte_pos < next_boundary) {
                const uint8_t plain = bytecode_[byte_pos];
                bytecode_[byte_pos] =
                    static_cast<uint8_t>(plain ^ key);
                key ^= plain;
                ++byte_pos;
            }

            // Apply this handler's fold-in (mirrors the
            // `xor [rsp+key_disp], imm8` that the handler body
            // emits right before its tail dispatch).
            if (event_idx < fold_events_.size()) {
                key ^= in_.per_handler_key[fold_events_[event_idx].handler_id];
                ++event_idx;
            }
        }
    } else {
        for (auto& b : bytecode_) {
            b ^= in_.initial_key;
        }
    }
}

// =========================================================================
// Driver
// =========================================================================

BytecodeEncoderOutputs Encoder::run() {
    phase_precompute_spec_match();
    phase_roll_g4_insertions();
    phase_compute_bc_offsets();

    bool has_branches = false;
    phase_emit_bytecode(has_branches);
    phase_encrypt(has_branches);

    BytecodeEncoderOutputs out{};
    out.bytecode               = std::move(bytecode_);
    out.native_handler_of_insn = std::move(native_handler_of_insn_);
    out.has_branches           = has_branches;
    out.rolling                = !has_branches;
    return out;
}

} // anonymous namespace

// =========================================================================
// Public entry point
// =========================================================================

BytecodeEncoderOutputs encode_bytecode(const BytecodeEncoderInputs& in) {
    Encoder enc(in);
    return enc.run();
}

} // namespace mx::vm::x64
