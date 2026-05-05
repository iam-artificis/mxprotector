/**
 * @file neg_rm_deep_add_rewriter.cpp
 * @brief `NEG r32` → 2-step deep chain (not + add-K + sub-(K-1)).
 *
 * Composes two MBA layers on the unary opcode:
 *
 *   1. Outer layer extends the existing `neg-rm-not-add1` identity
 *      `-x = ~x + 1` by splitting the `+1` into `+ K - (K - 1)` for
 *      a per-site random `K`. Algebra:
 *
 *          ~x + 1 ≡ ~x + K - (K - 1)  (mod 2^n).
 *
 *   2. Inner layer materialises `K` and `K - 1` through a per-site
 *      random MOV-imm MBA shape into a scratch register; the body
 *      uses the register forms `add dst, scratch` / `sub dst, scratch`
 *      so neither immediate appears literally in the emitted bytes.
 *
 * Body shape (s = scratch register):
 *
 *   not dst                     // dst = ~x
 *   push s
 *   <inner_emit_K_into_s>       // 1-3 instructions
 *   add dst, s                  // dst = ~x + K
 *   <inner_emit_(K-1)_into_s>   // 1-3 instructions
 *   sub dst, s                  // dst = ~x + K - (K - 1) = ~x + 1 = -x
 *   pop s
 *
 * `K` is forced ≥ 2 so `K - 1 ≥ 1` and the inner-layer chains for
 * both immediates are non-trivial. Bit 24 forces the value out of
 * imm8 range, keeping the body length predictable across sites.
 *
 * Constraint: 32-bit operand only (`!is_64bit`). Same rationale as
 * `not-rm-deep-xor`.
 *
 * Per-site variability: 3 inner shapes × 3 inner shapes × ~2^31
 * choices of K = the deepest defeat strength of any shipped unary
 * shape so far.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

namespace {

class NegRmDeepAddRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "neg-rm-deep-add";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        const auto view = decode_unary(insn, UnaryOp::neg);
        return view.has_value() && !view->is_64bit;
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_unary(insn, UnaryOp::neg);
        if (!view || view->is_64bit) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "neg-rm-deep-add: requires 32-bit `F7 /3` form"));
        }

        // Force K ≥ 2 (so K-1 ≥ 1 is non-trivial) and outside imm8
        // range so both inner chains are well-formed.
        const std::uint32_t k     = rng.next_u32() | 0x01000002u;
        const std::uint32_t k_m1  = k - 1u;

        const auto inner_k   = pick_random_mov_imm_emitter(rng);
        const auto inner_km1 = pick_random_mov_imm_emitter(rng);
        const x86::Reg scratch = pick_scratch_for(view->dst);

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        em.not_(view->dst);
        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                inner_k(e, scratch, k, rng);
                e.add(view->dst, scratch);
                inner_km1(e, scratch, k_m1, rng);
                e.sub(view->dst, scratch);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 9; // 1 not + 1 push + 2 inner + 2 alu + 1 pop
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_neg_rm_deep_add() {
    return std::make_unique<NegRmDeepAddRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
