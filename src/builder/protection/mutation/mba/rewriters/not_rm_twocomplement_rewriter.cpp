/**
 * @file not_rm_twocomplement_rewriter.cpp
 * @brief `NOT r` → `NEG r ; SUB r, 1` (two's-complement identity).
 *
 * Identity: `~x = -x - 1` over Z/2^n. The body emits a NEG followed
 * by a SUB-1 — neither contains the original NOT opcode, so a
 * frequency matcher that flags `F7 /2` as suspicious sees a
 * different signal post-rewrite. The trade is that NEG and SUB
 * affect EFLAGS while NOT does not; the engine's flag-aware filter
 * (`safe_to_clobber_flags_after`) keeps this shape away from sites
 * where the next instruction reads EFLAGS.
 *
 * Body length: 2 instructions, 6 bytes (`F7 /3` + `83 /5 ib` with
 * the 64-bit REX.W variant). Below the 5-byte slot threshold for
 * the *body* is fine — the threshold applies to the *site* slot
 * the JMP rel32 lives in, not to the body.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class NotRmTwoComplementRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "not-rm-twocomplement";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_unary(insn, UnaryOp::not_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_unary(insn, UnaryOp::not_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "not-rm-twocomplement: instruction not in F7 /2 form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        em.neg(view->dst);
        em.sub(view->dst, 1);

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

std::unique_ptr<IMbaRewriter> make_not_rm_twocomplement() {
    return std::make_unique<NotRmTwoComplementRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
