/**
 * @file mba_affine_emit.hpp
 * @brief Shared affine-MBA body builder for the imm32 ALU family.
 *
 * Tigress-style affine MBA expresses the target ALU operation
 * `f(x, K)` as a *random integer linear combination* of three
 * bitwise-basis functions of `(x, K)`:
 *
 *     f(x, K) ≡ c_or * (x | K) + c_and * (x & K) + c_xor * (x ^ K)
 *               + post_correction
 *
 * over Z/2^n. The crucial algebraic fact is the zero-identity
 *
 *     (x | K) - (x & K) - (x ^ K) ≡ 0  (mod 2^n).
 *
 * Adding any integer multiple of the zero-identity to a base shape
 * (such as `(x | K) + (x & K) = x + K`) yields a fresh, semantically
 * equivalent expression. Picking the multiplier `t` per call site
 * gives a 1-parameter family of shapes per ALU op — a continuum of
 * SMT-distinct rewrites that the existing fixed-shape rewriters
 * cannot produce.
 *
 * Per-op coefficient maps (parameterised by `t`):
 *
 *     ADD: ( 1 + t,   1 - t,    -t      )  yields x + K
 *     SUB: ( 1 + t,   1 - t,    -t      )  yields x + K, then -2K corrects
 *     XOR: ( 1 - t,   t - 1,    t       )  yields x ^ K
 *     OR : ( -t,      1 + t,    1 + t   )  yields x | K
 *     AND: ( 1 + t,   -t,       -(1+t)  )  yields x & K
 *
 * For SUB the post-correction subtracts `2K` from the affine sum
 * (encoded as two consecutive `sub dst, K` so `2K` cannot overflow
 * imm32 when `K`'s bit 31 is set).
 *
 * The body uses three scratch registers via `wrap_with_push_pop_3`,
 * one per basis term, so the per-site randomness in `t` shows up as
 * different `imul reg, reg, c` byte sequences and a different sign
 * mix in the combine step. Each scratch is fully restored by the
 * surrounding push/pop pair.
 *
 * Why a shared emitter rather than per-shape duplication: the body
 * shape is identical across all five op families up to the
 * coefficient triple and the SUB post-correction. Five copies would
 * be five places to keep in sync; a single emitter parameterised by
 * `AluImm32Op` is one place. The per-family rewriter files stay
 * small (decode, pick `t`, call this helper) and SRP-clean.
 */

#pragma once

#include <cstdint>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

/// Coefficient triple `(c_or, c_and, c_xor)` for the affine identity
/// `f(x, K) = c_or*(x|K) + c_and*(x&K) + c_xor*(x^K) + post`.
struct AffineCoefficients {
    std::int32_t c_or;
    std::int32_t c_and;
    std::int32_t c_xor;
};

/// Smallest absolute value of the affine parameter `t`.
/// `t ∈ {-1, 0, 1}` would collapse to one of the existing fixed
/// shapes (or to the bare op for trivial collapses), so the affine
/// rewriter starts from |t| ≥ 2 to guarantee a genuinely new
/// identity at every call site.
inline constexpr std::int32_t kAffineMinT = 2;

/// Largest absolute value of `t`. Capped at 15 so every coefficient
/// fits in the int8 imm-form of `imul reg, reg, ib` (`6B /r ib`),
/// keeping the body size predictable. Larger ranges can be opened
/// later if visual variety becomes a benchmark target.
inline constexpr std::int32_t kAffineMaxT = 15;

/// Pick a random `t` in `[kAffineMinT, kAffineMaxT]`. Always
/// positive — coefficients per op map negatives back into the
/// triple where useful (e.g. ADD's `c_xor = -t`).
[[nodiscard]] std::int32_t pick_affine_t(Randomizer& rng);

/// Compute the affine coefficient triple for the given op + `t`.
[[nodiscard]] AffineCoefficients affine_coefficients(
    AluImm32Op op, std::int32_t t);

/// Emit the affine-MBA body for `view.op view.dst, K` into `em`.
/// Uses three push/pop-protected scratch registers and builds the
/// `c_or*OR + c_and*AND + c_xor*XOR (+ post)` sum.
///
/// @returns the body in `em`'s buffer; the caller calls `em.build()`
///          to finalise.  Returns an error if any encoder helper
///          fails (currently impossible; reserved for future
///          encoder additions).
MxResult<void> emit_affine_alu_body(
    analysis::X86CodeEmitter& em,
    const AluImm32View&       view,
    AffineCoefficients        coefficients);

/// Emit the affine-MBA body with K *materialised through another MBA
/// layer* — the multi-step deep-chain variant.
///
/// Body skeleton (s_or/s_and/s_xor are scratches; K is `view.imm`):
///
///   push s_or; push s_and; push s_xor
///   k_emitter(em, s_or, K, rng)   // 1..3 instructions writing K
///   mov   s_and, s_or
///   mov   s_xor, s_or
///   or    s_or,  dst              // (K | dst) — OR is commutative
///   and   s_and, dst              // (K & dst) — AND is commutative
///   xor   s_xor, dst              // (K ^ dst) — XOR is commutative
///   <coefficient muls + combine + SUB post-correction>
///   pop  s_xor; pop s_and; pop s_or
///
/// `k_emitter` may be `direct_mov_imm32` (single layer; equivalent to
/// `emit_affine_alu_body` shape) or one of the MOV-imm step functions
/// (modular-inverse / xor-blind / rotate-blind) for a genuine 2-layer
/// deep chain. The composition stacks two MBA proofs in series — the
/// SMT solver must fold both layers to recover `K`.
///
/// **Operand size** — deep-affine emit is constrained to 32-bit
/// destination operands. The `MovImmEmitter` step functions emit
/// 32-bit ops that auto-zero-extend the high 32 bits of their
/// destination, which matches the natural operand width of `81 /op id`
/// without REX.W. For 64-bit ALU sites (`REX.W 81 /op id`), K would
/// need explicit sign-extension after materialisation; that's a
/// roadmap extension. Callers must decode with `view.is_64bit ==
/// false` before invoking this helper — passing a REX.W view is a
/// programmer error and yields a `pass_failed` result.
MxResult<void> emit_affine_alu_deep_body(
    analysis::X86CodeEmitter& em,
    const AluImm32View&       view,
    AffineCoefficients        coefficients,
    const MovImmEmitter&      k_emitter,
    Randomizer&               rng);

} // namespace mx::mutation::mba

// Forward-declare AluRrView to keep this header light — the r-r
// affine emitter only needs its layout in the cpp.
namespace mx::mutation::mba {
struct AluRrView;

/// Emit the affine-MBA body for `view.op view.dst, view.src` into
/// `em`. Same algebraic shape as the imm32 affine body but the
/// basis prep reads from a register source (`or scratch, view.src`)
/// instead of an immediate. SUB post-correction subtracts `view.src`
/// twice.
MxResult<void> emit_affine_alu_rr_body(
    analysis::X86CodeEmitter& em,
    const AluRrView&          view,
    AffineCoefficients        coefficients);

} // namespace mx::mutation::mba
