/**
 * @file neg_rm_zero_sub_rewriter.cpp
 * @brief `NEG r` → `MOV s, r ; XOR r, r ; SUB r, s` (zero-sub identity).
 *
 * Identity: `-x = 0 - x` over Z/2^n. The body materialises `0` in
 * `dst` (via `xor dst, dst` after preserving x in a scratch) and
 * then subtracts the saved `x` from it. Neither NEG nor NOT appears
 * — the rewrite truly hides the original `F7 /3` signature.
 *
 * Why this shape complements `neg-rm-not-add1`:
 *   * `neg-rm-not-add1` uses NOT + ADD — frequency matchers tracking
 *     unary forms see a NOT pattern.
 *   * `neg-rm-zero-sub` uses MOV + XOR + SUB only — pure binary
 *     arithmetic, no unary opcodes.
 *
 * The MBA adapter picks one of the two shapes uniformly per site, so
 * roughly half the NEG sites get each treatment.
 *
 * Body length: 4 instructions (1 push + 3 body + 1 pop) ≈ 11 bytes.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class NegRmZeroSubRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "neg-rm-zero-sub";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_unary(insn, UnaryOp::neg).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_unary(insn, UnaryOp::neg);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "neg-rm-zero-sub: instruction not in F7 /3 form"));
        }

        const x86::Reg scratch = pick_scratch_for(view->dst);

        analysis::X86CodeEmitter em(view->is_64bit);
        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);   // scratch = x
                e.xor_(view->dst, view->dst); // dst = 0
                e.sub(view->dst, scratch);    // dst = 0 - x = -x
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 5; // push + 3 body + pop
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_neg_rm_zero_sub() {
    return std::make_unique<NegRmZeroSubRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
