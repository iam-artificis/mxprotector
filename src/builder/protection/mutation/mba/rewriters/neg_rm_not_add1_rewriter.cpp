/**
 * @file neg_rm_not_add1_rewriter.cpp
 * @brief `NEG r` → `NOT r ; ADD r, 1` (two's-complement identity).
 *
 * Identity: `-x = ~x + 1` over Z/2^n. The body emits a NOT followed
 * by an ADD-1 — neither contains the original NEG opcode, so a
 * frequency matcher that flags `F7 /3` as suspicious sees a
 * different signal post-rewrite. The trade is that ADD affects
 * EFLAGS while NEG sets a different mix of flags; the engine's
 * flag-aware filter keeps this shape away from sites where the
 * next instruction reads CF/OF/AF in NEG-specific ways.
 *
 * Body length: 2 instructions, 6 bytes (`F7 /2` + `83 /0 ib`).
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class NegRmNotAdd1Rewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "neg-rm-not-add1";
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
                "neg-rm-not-add1: instruction not in F7 /3 form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        em.not_(view->dst);
        em.add(view->dst, 1);

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 2;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_neg_rm_not_add1() {
    return std::make_unique<NegRmNotAdd1Rewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
