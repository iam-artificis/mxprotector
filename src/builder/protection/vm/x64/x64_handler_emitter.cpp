/**
 * @file x64_handler_emitter.cpp
 * @brief [BUILDER, x64] Handler emission — implementation.
 *
 * Split out of `x64_vm_backend.cpp` (R1.5). Holds the internal
 * `HandlerEmitter` class that owns the emission loop, the trampoline
 * bookkeeping, the G4 fold-in helpers, and the big `emit_op_variant`
 * switch. The public `emit_all_handlers` function is a thin wrapper
 * that constructs a `HandlerEmitter` and drives its three emission
 * phases + the final deterministic trampoline drain.
 */

#include "mxprotector/protection/vm/x64/x64_handler_emitter.hpp"

#include <array>
#include <cstring>

#include "mxprotector/protection/vm/x64/x64_emitters.hpp"
#include "mxprotector/protection/vm/x64/x64_handlers.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm_wrappers.hpp"
#include "mxprotector/protection/vm/x64/x64_vflags.hpp"
#include "mxprotector/protection/vm/x64/x64_vm_variants.hpp"

namespace mx::vm::x64 {

namespace {

class HandlerEmitter {
public:
    HandlerEmitter(const HandlerEmitterInputs& in, HandlerEmitterSinks sinks)
        : in_(in), sinks_(sinks) {}

    void run();

private:
    const HandlerEmitterInputs& in_;
    HandlerEmitterSinks         sinks_;
    uint8_t                     current_handler_id_{};

    // Chain length distribution — biased toward shorter chains
    // (len==1 ~50%, len==2 ~33%, len==3 ~17%) to keep amortised
    // trampoline overhead moderate while still producing a meaningful
    // fraction of multi-hop chains.
    static constexpr uint32_t kMaxChainLen = 3;

    // Emission phases.
    void emit_generic_handlers();
    void emit_native_handlers();
    void emit_specialised_handlers();
    void drain_remaining_trampolines();

    // Handler-body helpers (were lambdas inside `generate`).
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

// =========================================================================
// Run — top-level phase sequence
// =========================================================================

void HandlerEmitter::run() {
    emit_generic_handlers();
    emit_native_handlers();
    emit_specialised_handlers();
    drain_remaining_trampolines();
}

// =========================================================================
// Emission phases
// =========================================================================

void HandlerEmitter::emit_generic_handlers() {
    // Generic handlers: emit every variant of every canonical VmOp.
    for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
        const auto op = static_cast<VmOp>(opi);
        const auto& variants = in_.variant_handler_ids[opi];
        for (uint32_t v = 0; v < variants.size(); ++v) {
            begin_handler(variants[v]);
            const bool needs_tail = emit_op_variant(op, v);
            if (needs_tail) {
                end_handler_tail();
            }
        }
    }
}

void HandlerEmitter::emit_native_handlers() {
    for (size_t i = 0; i < in_.instructions.size(); ++i) {
        if (in_.instructions[i].op != VmOp::native) continue;
        const uint8_t hid = in_.native_handler_ids[in_.native_handler_of_insn[i]];
        begin_handler(hid);

        RawEmitter& rt = in_.rt;

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
                const uint8_t slot = in_.layout.native_to_slot[n];
                loads[k++] = {n, 24 + static_cast<int32_t>(slot) * 8};
            }
        }

        auto emit_mem_mov = [&rt](uint8_t opcode, uint8_t reg, int32_t disp) {
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
            const int32_t rf_disp = 24 + in_.rflags_disp;
            const auto popfq_v = pick_popfq_variant(in_.rng);
            const bool uses_rax = (popfq_v != VflagsPopfqV::InPlace);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_popfq(rt, popfq_v, in_.vflags_key, in_.vflags_rol, rf_disp);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x8B); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
        }

        // Shift rsp to caller frame via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(in_.native_shift));

        // Execute native bytes (sees correct GPRs, flags, and caller frame).
        rt.bytes(ByteView{
            in_.instructions[i].native_bytes.data(),
            in_.instructions[i].native_bytes.size()});

        // Shift rsp back via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(-in_.native_shift));

        // Save CPU flags after native execution into ctx so the NEXT
        // handler (or VJCC) sees the correct flags.
        {
            const int32_t rf_disp = 24 + in_.rflags_disp;
            const auto store_v = pick_store_variant(in_.rng);
            const bool uses_rax = (store_v != VflagsStoreV::InPlace);
            if (uses_rax) {
                rt.u8(0x48); rt.u8(0x89); rt.u8(0x44); rt.u8(0x24); rt.u8(0x08);
            }
            emit_vflags_store(rt, store_v, in_.vflags_key, in_.vflags_rol, rf_disp);
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
        emit_handler_key_fold_in(current_handler_id_);
        {
            const auto p = emit_tail_dispatch(rt, in_.rolling_key_disp, in_.rolling,
                                              false, sinks_.table_key_patches,
                                              in_.vflags_key, in_.vflags_rol,
                                              in_.rflags_disp, &in_.rng,
                                              in_.imagebase_key_disp);
            sinks_.table_patches.push_back({p.rel32_offset, p.instruction_end});
        }
        // G5: native handlers join the same trampoline chain mechanism
        // as generic/specialised handlers. The chain length roll is
        // independent per handler so native handlers get the same 1..3
        // distribution.
        queue_trampoline_chain(current_handler_id_);
        maybe_drain_trampolines();
    }
}

void HandlerEmitter::emit_specialised_handlers() {
    for (const auto& spec : in_.specializations) {
        begin_handler(spec.handler_id);
        const uint8_t dst_disp = static_cast<uint8_t>(spec.dst_vreg * 8);
        const uint8_t src_disp = static_cast<uint8_t>(spec.src_vreg * 8);
        if (spec.op == VmOp::mov_rr) {
            emit_handler_mov_rr_specialized(in_.rt, dst_disp, src_disp);
        } else {
            emit_handler_alu_rr_specialized(in_.rt, alu_op_mr_for(spec.op),
                                             dst_disp, src_disp);
        }
        end_handler_tail();
    }
}

// The random-draw drain inside `end_handler_tail` and the native loop
// only flushes when the dice roll picks the drain path, so the tail of
// the run usually has a handful of stragglers. This loop is
// deterministic and empties the queue fully.
void HandlerEmitter::drain_remaining_trampolines() {
    while (!sinks_.pending_trampolines.empty()) {
        emit_one_pending_trampoline();
    }
}

// =========================================================================
// Trampoline / chain helpers
// =========================================================================

uint32_t HandlerEmitter::allocate_trampoline_slot() {
    const uint32_t slot = static_cast<uint32_t>(sinks_.trampoline_offset_by_slot.size());
    sinks_.trampoline_offset_by_slot.push_back(SIZE_MAX);
    return slot;
}

// Register a chain of random length for the just-emitted handler:
// allocate `len` slots, wire each slot's target at the next slot (or at
// the handler for the terminal), remember the head slot in
// `head_slot_of_handler`, and drop every slot into the pending queue so
// subsequent drains can flush them in random order.
void HandlerEmitter::queue_trampoline_chain(uint8_t handler_id) {
    const uint32_t roll = in_.rng.next_range(0, 5);
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
    sinks_.head_slot_of_handler[handler_id] = slots[0];

    for (uint32_t i = 0; i < chain_len; ++i) {
        TrampolineTarget tgt{};
        if (i + 1 < chain_len) {
            tgt.kind = TrampolineTarget::Kind::Trampoline;
            tgt.id   = slots[i + 1];
        } else {
            tgt.kind = TrampolineTarget::Kind::Handler;
            tgt.id   = handler_id;
        }
        sinks_.pending_trampolines.push_back({slots[i], tgt});
    }
}

void HandlerEmitter::emit_one_pending_trampoline() {
    if (sinks_.pending_trampolines.empty()) return;
    // Pop a random slot, not FIFO. FIFO would correlate the physical
    // blob position of trampolines with their handler completion
    // order; random draws decorrelate them so chains end up scrambled
    // across the handler block.
    const uint32_t idx = in_.rng.next_range(
        0, static_cast<uint32_t>(sinks_.pending_trampolines.size() - 1));
    const PendingTrampoline pt = sinks_.pending_trampolines[idx];
    sinks_.pending_trampolines[idx] = sinks_.pending_trampolines.back();
    sinks_.pending_trampolines.pop_back();

    sinks_.trampoline_offset_by_slot[pt.slot] = in_.rt.size();
    const auto tp = vm::x64::emit_trampoline(in_.rt, in_.rng, /*max_junk_bytes=*/8);
    sinks_.trampoline_fixups.push_back({pt.target, tp});
}

// After each handler's end_tail we queue a fresh chain for the handler
// and, with some probability, flush one or more queued entries right
// now. Flushing follows a geometric distribution (0 ~2/3, 1 ~2/9,
// 2 ~2/27, ...), so over the full emission trampolines from different
// chains end up interleaved with handler bodies.
void HandlerEmitter::maybe_drain_trampolines() {
    while (!sinks_.pending_trampolines.empty() && in_.rng.next_range(0, 2) == 0) {
        emit_one_pending_trampoline();
    }
}

void HandlerEmitter::begin_handler(uint8_t handler_id) {
    current_handler_id_ = handler_id;
    sinks_.handler_offset_by_id[handler_id] = in_.rt.size();
    emit_junk_prologue(in_.rt, in_.rng, /*max_bytes=*/8);
}

// G4: `xor byte [rsp + rolling_key_disp], imm8 = per_handler_key[id]`.
// Emitted right before the tail dispatch, so the fetch of the next
// opcode byte sees the post-fold key. Skipped entirely in static-cipher
// regions (rolling == false) where there is no mutable key state to
// fold into.
void HandlerEmitter::emit_handler_key_fold_in(uint8_t handler_id) {
    if (!in_.rolling) return;
    RawEmitter& rt = in_.rt;
    // 80 /6 ib — xor r/m8, imm8
    //   ModRM: 01 110 100 = 0x74  (mod=01 disp8, reg=/6=xor, rm=100 SIB)
    //   SIB:   00 100 100 = 0x24  (scale=00, index=100 none, base=rsp)
    rt.u8(0x80); rt.u8(0x74); rt.u8(0x24);
    rt.u8(static_cast<uint8_t>(in_.rolling_key_disp));
    rt.u8(in_.per_handler_key[handler_id]);
}

// G5 invariant: every handler_id the backend begins via `begin_handler`
// MUST later get a trampoline chain queued via `queue_trampoline_chain`,
// otherwise the post-emit handler_table patch fires the "handler id N
// missing trampoline chain" error.
void HandlerEmitter::finish_handler_chain() {
    queue_trampoline_chain(current_handler_id_);
    maybe_drain_trampolines();
}

void HandlerEmitter::end_handler_tail() {
    emit_handler_key_fold_in(current_handler_id_);
    const auto p = emit_tail_dispatch(in_.rt, in_.rolling_key_disp, in_.rolling,
                                      in_.has_branches, sinks_.table_key_patches,
                                      in_.vflags_key, in_.vflags_rol,
                                      in_.rflags_disp, &in_.rng,
                                      in_.imagebase_key_disp);
    sinks_.table_patches.push_back({p.rel32_offset, p.instruction_end});
    finish_handler_chain();
}

// -------------------------------------------------------------------------
// emit_op_variant — the big switch. Produces one variant body for a
// given canonical VmOp. Returns true if the surrounding loop still
// needs to call `end_handler_tail` after the variant (the standard
// path); false for inline-tail variants (native / dead / opq_branch /
// exit) that take care of their own tail and trampoline-chain
// registration.
// -------------------------------------------------------------------------
bool HandlerEmitter::emit_op_variant(VmOp op, uint32_t variant) {
    RawEmitter& rt = in_.rt;
    const int32_t kd   = in_.rolling_key_disp;
    const bool    roll = in_.rolling;

    switch (op) {
        case VmOp::mov_rr:
            if (variant == 0) {
                emit_handler_mov_rr(rt, kd, roll);
            } else if (variant == 1) {
                emit_handler_mov_rr_pushpop(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_mov_rr_nested(rt, kd, roll, in_.inner_vm_isa, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::add_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, kd, roll, 0x01);
            } else if (variant == 1) {
                emit_handler_add_rr_mba(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, kd, roll,
                                            in_.inner_vm_isa, InnerVmOp::iadd_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::sub_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, kd, roll, 0x29);
            } else if (variant == 1) {
                emit_handler_sub_rr_neg(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, kd, roll,
                                            in_.inner_vm_isa, InnerVmOp::isub_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::xor_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, kd, roll, 0x31);
            } else if (variant == 1) {
                emit_handler_xor_rr_mba(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, kd, roll,
                                            in_.inner_vm_isa, InnerVmOp::ixor_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::and_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, kd, roll, 0x21);
            } else if (variant == 1) {
                emit_handler_and_rr_demorgan(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, kd, roll,
                                            in_.inner_vm_isa, InnerVmOp::iand_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::or_rr:
            if (variant == 0) {
                emit_handler_alu_rr(rt, kd, roll, 0x09);
            } else if (variant == 1) {
                emit_handler_or_rr_demorgan(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_alu_rr_nested(rt, kd, roll,
                                            in_.inner_vm_isa, InnerVmOp::ior_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::imul_rr: emit_handler_imul_rr(rt, kd, roll); return true;

        case VmOp::mov_ri32:
            if (variant == 0) {
                emit_handler_mov_ri32(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_mov_ri32_nested(rt, kd, roll, in_.inner_vm_isa, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::add_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, kd, roll, 0x01);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, kd, roll,
                                              in_.inner_vm_isa, InnerVmOp::iadd_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::sub_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, kd, roll, 0x29);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, kd, roll,
                                              in_.inner_vm_isa, InnerVmOp::isub_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::xor_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, kd, roll, 0x31);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, kd, roll,
                                              in_.inner_vm_isa, InnerVmOp::ixor_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::and_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, kd, roll, 0x21);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, kd, roll,
                                              in_.inner_vm_isa, InnerVmOp::iand_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::or_ri32:
            if (variant == 0) {
                emit_handler_alu_ri32(rt, kd, roll, 0x09);
            } else {
                size_t patch = 0;
                emit_handler_alu_ri32_nested(rt, kd, roll,
                                              in_.inner_vm_isa, InnerVmOp::ior_rr, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::mov_ri64: emit_handler_mov_ri64(rt, kd, roll); return true;

        case VmOp::not_r:
            if (variant == 0) {
                emit_handler_unary(rt, kd, roll, 2);
            } else if (variant == 1) {
                emit_handler_not_r_xor(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_not_r_nested(rt, kd, roll, in_.inner_vm_isa, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::neg_r:
            if (variant == 0) {
                emit_handler_unary(rt, kd, roll, 3);
            } else if (variant == 1) {
                emit_handler_neg_r_notinc(rt, kd, roll);
            } else {
                size_t patch = 0;
                emit_handler_neg_r_nested(rt, kd, roll, in_.inner_vm_isa, patch);
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;

        case VmOp::shl_ri: emit_handler_shift(rt, kd, roll, 4); return true;
        case VmOp::shr_ri: emit_handler_shift(rt, kd, roll, 5); return true;
        case VmOp::sar_ri: emit_handler_shift(rt, kd, roll, 7); return true;
        case VmOp::rol_ri: emit_handler_shift(rt, kd, roll, 0); return true;
        case VmOp::ror_ri: emit_handler_shift(rt, kd, roll, 1); return true;

        case VmOp::vjmp:
            emit_handler_vjmp(rt, kd, roll);
            return true;

        case VmOp::vjcc: {
            // Coin flip per handler body: 50% chance the taken path is
            // the V0 direct `add r11, rax`, 50% it's the V2 nested
            // `mov r15, rax; call inner_vm_entry`. Because vjcc's
            // variant axis is already fully consumed by the condition
            // code (16 values), this build-time randomization is the
            // only diversity knob available for its handler bodies.
            const bool nested = in_.rng.next_bool();
            size_t patch = 0;
            emit_handler_vjcc(rt, kd, roll,
                              static_cast<uint8_t>(variant),
                              in_.vflags_key, in_.vflags_rol,
                              in_.rflags_disp, in_.rng,
                              nested ? &in_.inner_vm_isa : nullptr,
                              nested ? &patch : nullptr);
            if (nested) {
                sinks_.inner_vm_call_patches.push_back(patch);
            }
            return true;
        }

        case VmOp::native:
            // Generic native slot is never invoked — each native insn
            // gets its own handler. Trap with ud2 (no tail). Still
            // needs a trampoline chain queued so the handler_table
            // entry for this id has a valid target and the integrity-
            // check XOR sum matches; the trampoline points at `ud2`
            // and only fires if something dispatches through the
            // generic native slot by mistake, in which case the
            // process crashes immediately — which is exactly what we
            // want.
            emit_ud2(rt);
            finish_handler_chain();
            return false;

        case VmOp::dead: {
            // G4 dead opcode — empty handler body. The encoder inserts
            // `dead` bytes into the bytecode stream at random positions
            // between real instructions; this handler consumes its
            // byte, runs NO body, and dispatches to the next handler
            // without touching vflags.
            //
            // IMPORTANT: the tail dispatch here is emitted with
            // save_rflags=FALSE even in branch-containing regions
            // where all other handlers use save=TRUE.
            //
            // Why: on entry to this handler, host rflags do NOT
            // reflect the previous real handler's guest ALU — they
            // reflect the previous handler's TAIL-DISPATCH fetch/xor
            // sequence, which clobbered rflags after the real save
            // happened. If we let the dead handler's tail call
            // emit_vflags_store, it would write those fetch-clobbered
            // garbage flags to `vflags`, overwriting the real guest
            // flags that were already safely stored there by the
            // previous handler's tail. A downstream `vjcc` would then
            // see garbage ZF/SF/CF and mispredict the branch.
            //
            // Skipping the save leaves vflags untouched — the real
            // guest flags remain visible to the next `vjcc`. Net
            // effect of the dead handler on the VM state: r11
            // advanced by 1 (via the fetch inside the tail), nothing
            // else. That's exactly what a "no-op insert" should do.
            emit_handler_key_fold_in(current_handler_id_);
            const auto p = emit_tail_dispatch(rt, kd, roll,
                                               /*save_rflags=*/false,
                                               sinks_.table_key_patches,
                                               in_.vflags_key, in_.vflags_rol,
                                               in_.rflags_disp, &in_.rng,
                                               in_.imagebase_key_disp);
            sinks_.table_patches.push_back({p.rel32_offset, p.instruction_end});
            finish_handler_chain();
            return false;
        }

        case VmOp::opq_branch: {
            // G4 opaque branch. Shape-compatible with `vjmp`: a 4-byte
            // rel32-shaped operand is fetched by the handler body, but
            // NEVER added to r11. Falls through to the next
            // instruction regardless of what the operand bytes say.
            //
            // The fetch IS necessary — without it, r11 would still
            // point at the rel32 bytes when the tail dispatch fetches,
            // and those bytes would get dispatched as a handler_id
            // (misdecode).
            //
            // As with `dead`, the tail is emitted inline with
            // save_rflags=false to avoid clobbering the real guest
            // flags in vflags.
            emit_fetch_dword(rt, kd, roll);
            emit_handler_key_fold_in(current_handler_id_);
            const auto p = emit_tail_dispatch(rt, kd, roll,
                                               /*save_rflags=*/false,
                                               sinks_.table_key_patches,
                                               in_.vflags_key, in_.vflags_rol,
                                               in_.rflags_disp, &in_.rng,
                                               in_.imagebase_key_disp);
            sinks_.table_patches.push_back({p.rel32_offset, p.instruction_end});
            finish_handler_chain();
            return false;
        }

        case VmOp::exit: {
            if (in_.vflags_key != 0 || in_.vflags_rol != 0) {
                emit_vflags_inslot_descramble(rt, pick_inslot_variant(in_.rng),
                                               in_.vflags_key, in_.vflags_rol,
                                               in_.rflags_disp);
            }

            // Pop all 16 slots in slot order.
            for (uint8_t v = 0; v < 16; ++v) {
                if (v == in_.layout.junk_slot) {
                    // add rsp, 8       48 83 C4 08
                    rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4); rt.u8(0x08);
                } else {
                    emit_pop_reg(rt, in_.layout.slot_to_native[v]);
                }
            }

            // G7: discard the extra padding slots that entry pushed.
            if (in_.layout.extra_pad_slots > 0) {
                rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4);
                rt.u8(static_cast<uint8_t>(in_.layout.extra_pad_slots * 8));
            }

            emit_popfq(rt);
            if (in_.emit_exit_as_jmp) {
                // Cross-VM: jmp rel32 to next sub-VM entry (patched
                // later)
                rt.u8(0xE9);
                sinks_.exit_jmp_offset = static_cast<uint32_t>(rt.size());
                rt.u32(0);
            } else {
                emit_ret(rt);
            }
            // G5: exit handler has no tail dispatch (it unwinds the VM
            // state and returns), but it still needs a trampoline
            // chain queued — the handler_table entry for exit must
            // point at a valid trampoline so the integrity-check XOR
            // sum stays consistent. The trampoline jmps into the exit
            // body; on dispatch, the body pops registers and returns
            // to the caller, exactly as a direct call would.
            finish_handler_chain();
            return false;
        }
        case VmOp::count_:
            return false;
    }
    return false;
}

} // anonymous namespace

// =========================================================================
// Public entry point
// =========================================================================

void emit_all_handlers(const HandlerEmitterInputs& in,
                       HandlerEmitterSinks         sinks)
{
    HandlerEmitter emitter(in, sinks);
    emitter.run();
}

} // namespace mx::vm::x64
