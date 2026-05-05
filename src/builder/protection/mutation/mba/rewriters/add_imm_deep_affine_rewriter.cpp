/**
 * @file add_imm_deep_affine_rewriter.cpp
 * @brief `ADD r32, K` → affine MBA with deep-chain K materialisation.
 *
 * Composes two MBA layers: the outer is the affine identity from
 * `add-imm-affine` (`(1+t)*(x|K) + (1-t)*(x&K) + (-t)*(x^K) = x + K`),
 * the inner materialises K through a per-site random MOV-imm MBA
 * shape (modular-inverse / xor-blind / rotate-blind). The basis prep
 * reads K from a scratch register instead of an imm32 operand, so the
 * proof obligation stacks two unrelated MBA tactics — the SMT solver
 * must fold both layers to recover `K` and then the affine sum to
 * recover `x + K`.
 *
 * Constraint: 32-bit operand only. The 64-bit `REX.W 81 /0 id` form
 * needs K sign-extended to 64 bits after materialisation; the inner
 * step functions zero-extend their destination, so 64-bit support
 * would need an additional `movsxd` step. Roadmapped for a future
 * expansion; today the deep-affine match predicate explicitly
 * rejects `view->is_64bit`.
 *
 * Per-site variability: 3 inner shapes × 14 affine `t` choices = 42
 * SMT-distinct identities per ADD site, in addition to the existing
 * 17 from the fixed + affine shapes.
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

class AddImmDeepAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-imm-deep-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::add);
        return view.has_value() && !view->is_64bit;
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::add);
        if (!view || view->is_64bit) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "add-imm-deep-affine: requires 32-bit `81 /0 id` form"));
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
        result.instruction_count = 17; // 3 push + ~11 mid + 3 pop
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_add_imm_deep_affine() {
    return std::make_unique<AddImmDeepAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
