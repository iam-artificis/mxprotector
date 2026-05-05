/**
 * @file or_imm_deep_affine_rewriter.cpp
 * @brief `OR r32, K` → affine MBA with deep-chain K materialisation.
 *
 * Twin of `add-imm-deep-affine` for the OR family. Coefficient
 * triple `(-t, 1+t, 1+t)` reduces to `AND + XOR = x | K` for any `t`.
 *
 * Same constraints as the ADD variant — 32-bit operand only, 3 inner
 * shapes × 14 affine `t` choices = 42 SMT-distinct identities per site.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

namespace {

class OrImmDeepAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "or-imm-deep-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::or_);
        return view.has_value() && !view->is_64bit;
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::or_);
        if (!view || view->is_64bit) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "or-imm-deep-affine: requires 32-bit `81 /1 id` form"));
        }

        const auto t = pick_affine_t(rng);
        const auto coefficients = affine_coefficients(view->op, t);
        const auto inner = pick_random_mov_imm_emitter(rng);

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        auto status = emit_affine_alu_deep_body(
            em, *view, coefficients, inner, rng);
        if (!status) return std::unexpected(status.error());

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 17;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_or_imm_deep_affine() {
    return std::make_unique<OrImmDeepAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
