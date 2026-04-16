/**
 * @file x64_vm_variants.hpp
 * @brief [BUILDER, x64] Pure handler-variant metadata for the x64 VM backend.
 *
 * Declares the compile-time tables that answer two questions the x64 VM
 * runtime generator asks repeatedly during emission:
 *
 *   1. "How many handler variants does this canonical VmOp emit?"
 *      — `variant_count_for(op)`. Drives the handler-id shuffle and the
 *      generic-variant handler emission loop.
 *
 *   2. "Is this VmOp a candidate for G1 per-build specialisation?"
 *      — `is_specializable_op(op)` and the companion lists `kSpecializableOps`
 *      / `alu_op_mr_for(op)` used by the specialisation generator.
 *
 * Everything here is `constexpr` / `inline constexpr` — no runtime state,
 * no Randomizer, no PE image. This is the pure metadata layer that the
 * rest of the backend (variant selection, handler emission, bytecode
 * encoding) consults when composing a per-build runtime.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/protection/vm/vm_bytecode.hpp"

namespace mx::vm::x64 {

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
// G1 — Per-build handler specialisation metadata.
//
// `Specialization` itself (the runtime-assigned tuple of (op, dst_vreg,
// src_vreg, handler_id)) lives inside the backend generator — it's tied
// to handler-id allocation and can't be pure metadata. What we expose
// here is the *compile-time* side of the feature:
//
//   - the maximum number of specialisations per build,
//   - the op whitelist,
//   - the predicate `is_specializable_op` used during bytecode encoding,
//   - the ModR/M `op_mr` byte needed by the specialised ALU emitter.
// ----------------------------------------------------------------------------

/// Maximum specialisations per build. Each one consumes one handler_id
/// and adds ~10 bytes of body (plus the standard tail dispatch). Eight
/// fits comfortably under the 255-handler budget even for regions with
/// dozens of native escapes.
inline constexpr size_t kMaxSpecializations = 8;

/// Ops whose r-r form has a tractable specialised body. imul_rr is
/// excluded because its opcode is `48 0F AF` (4 prefix bytes) and would
/// need a different specialised emitter; can be added later.
inline constexpr VmOp kSpecializableOps[] = {
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

} // namespace mx::vm::x64
