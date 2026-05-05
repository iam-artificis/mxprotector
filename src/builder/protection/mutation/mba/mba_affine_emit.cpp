/**
 * @file mba_affine_emit.cpp
 * @brief Implementation — see header.
 *
 * The body shape is one push/pop sandwich around three independent
 * "compute one basis term in a scratch" sequences plus a final
 * combine step. Each `emit_imul_const` call below either skips the
 * multiply (`c == 1`), folds the multiplier into a `neg` (`c == -1`),
 * clears the scratch (`c == 0`), or emits the full `imul reg, reg, c`
 * (everything else). That keeps the body free of redundant
 * `imul reg, reg, 1` instructions and lets the SMT-level analysis
 * see exactly the operations the affine identity calls for.
 */

#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"

#include "mxprotector/protection/mutation/mba/mba_alu_rr_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"

namespace mx::mutation::mba {

namespace {

/// Multiply `reg` by the constant `c` in place. Picks the smallest
/// equivalent encoding for the common scalar values (`xor` for 0,
/// `neg` for -1) and falls back to `imul reg, reg, c` for the
/// general case. The encoder picks between the imm8 (`6B`) and
/// imm32 (`69`) IMUL forms based on the magnitude of `c`.
void emit_imul_const(
    analysis::X86CodeEmitter& em,
    x86::Reg                  reg,
    std::int32_t              c)
{
    if (c == 0) {
        em.xor_(reg, reg);
    } else if (c == 1) {
        // Identity multiplier — emit nothing.
    } else if (c == -1) {
        em.neg(reg);
    } else {
        em.imul(reg, reg, c);
    }
}

} // namespace

std::int32_t pick_affine_t(Randomizer& rng) {
    return static_cast<std::int32_t>(
        rng.next_range(
            static_cast<std::uint32_t>(kAffineMinT),
            static_cast<std::uint32_t>(kAffineMaxT)));
}

AffineCoefficients affine_coefficients(AluImm32Op op, std::int32_t t) {
    switch (op) {
        case AluImm32Op::add:
        case AluImm32Op::sub:
            // f(x, K) = (1 + t)*OR + (1 - t)*AND + (-t)*XOR.
            // SUB applies an additional -2K post-correction in the
            // body emitter; the basis triple is identical.
            return {1 + t, 1 - t, -t};
        case AluImm32Op::xor_:
            // x ^ K = (1 - t)*OR + (t - 1)*AND + t*XOR.
            return {1 - t, t - 1, t};
        case AluImm32Op::or_:
            // x | K = -t*OR + (1 + t)*AND + (1 + t)*XOR.
            return {-t, 1 + t, 1 + t};
        case AluImm32Op::and_:
            // x & K = (1 + t)*OR + (-t)*AND + (-(1 + t))*XOR.
            return {1 + t, -t, -(1 + t)};
    }
    // Unreachable — every AluImm32Op value is covered above. The
    // explicit return keeps `-Wreturn-type` quiet and makes the
    // failure mode an obvious all-zero coefficient triple if a new
    // op is ever added without updating this switch.
    return {0, 0, 0};
}

MxResult<void> emit_affine_alu_body(
    analysis::X86CodeEmitter& em,
    const AluImm32View&       view,
    AffineCoefficients        coefficients)
{
    const auto scratches = pick_three_scratches_for(view.dst);
    const x86::Reg s_or  = scratches[0];
    const x86::Reg s_and = scratches[1];
    const x86::Reg s_xor = scratches[2];
    const auto k = static_cast<std::int32_t>(view.imm);

    wrap_with_push_pop_3(em, scratches,
        [&](analysis::X86CodeEmitter& e) {
            // Compute each basis term into its own scratch.
            e.mov(s_or,  view.dst);
            e.or_(s_or,  k);
            e.mov(s_and, view.dst);
            e.and_(s_and, k);
            e.mov(s_xor, view.dst);
            e.xor_(s_xor, k);

            // Apply per-term coefficients.
            emit_imul_const(e, s_or,  coefficients.c_or);
            emit_imul_const(e, s_and, coefficients.c_and);
            emit_imul_const(e, s_xor, coefficients.c_xor);

            // Combine: dst = c_or*OR + c_and*AND + c_xor*XOR.
            e.mov(view.dst, s_or);
            e.add(view.dst, s_and);
            e.add(view.dst, s_xor);

            // SUB post-correction: -2K, encoded as two `sub dst, K`
            // so the imm32 sign-extension cannot overflow when bit
            // 31 of K is set. For ADD/OR/AND/XOR there's nothing
            // to do — the basis sum already equals f(x, K).
            if (view.op == AluImm32Op::sub) {
                e.sub(view.dst, k);
                e.sub(view.dst, k);
            }
        });

    return {};
}

MxResult<void> emit_affine_alu_rr_body(
    analysis::X86CodeEmitter& em,
    const AluRrView&          view,
    AffineCoefficients        coefficients)
{
    // Both operand registers must stay live across the body — the
    // basis prep reads `view.src` three times. Pick three scratches
    // that don't alias either operand.
    const auto scratches = pick_three_scratches_for(view.dst, view.src);
    const x86::Reg s_or  = scratches[0];
    const x86::Reg s_and = scratches[1];
    const x86::Reg s_xor = scratches[2];

    wrap_with_push_pop_3(em, scratches,
        [&](analysis::X86CodeEmitter& e) {
            // Compute each basis term into its own scratch — `view.src`
            // takes the place of `K` from the imm32 path.
            e.mov(s_or,  view.dst);
            e.or_(s_or,  view.src);
            e.mov(s_and, view.dst);
            e.and_(s_and, view.src);
            e.mov(s_xor, view.dst);
            e.xor_(s_xor, view.src);

            emit_imul_const(e, s_or,  coefficients.c_or);
            emit_imul_const(e, s_and, coefficients.c_and);
            emit_imul_const(e, s_xor, coefficients.c_xor);

            // Combine: dst = c_or*OR + c_and*AND + c_xor*XOR.
            e.mov(view.dst, s_or);
            e.add(view.dst, s_and);
            e.add(view.dst, s_xor);

            // SUB post-correction: -2*src. Two `sub dst, src` ops
            // are byte-stable (3 bytes each w/ REX) and avoid any
            // overflow concerns the imm32 path has to manage.
            if (view.op == AluImm32Op::sub) {
                e.sub(view.dst, view.src);
                e.sub(view.dst, view.src);
            }
        });

    return {};
}

} // namespace mx::mutation::mba
