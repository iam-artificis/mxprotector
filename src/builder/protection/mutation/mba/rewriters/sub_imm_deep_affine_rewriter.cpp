/**
 * @file sub_imm_deep_affine_rewriter.cpp
 * @brief `SUB r32, K` → affine MBA with deep-chain K materialisation.
 *
 * Twin of `add-imm-deep-affine` for the SUB family. The affine
 * coefficient triple is identical to ADD; the shared
 * `emit_affine_alu_deep_body` emits the SUB post-correction
 * (`dst -= K; dst -= K`) which subtracts `2K` to recover `x - K`.
 *
 * Same 32-bit operand constraint and 3-inner × 14-`t` variety as
 * `add-imm-deep-affine` — see that file for the algebraic rationale.
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

class SubImmDeepAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-imm-deep-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::sub);
        return view.has_value() && !view->is_64bit;
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::sub);
        if (!view || view->is_64bit) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "sub-imm-deep-affine: requires 32-bit `81 /5 id` form"));
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
        result.instruction_count = 19; // affine 17 + 2 SUB post-corrections
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_sub_imm_deep_affine() {
    return std::make_unique<SubImmDeepAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
