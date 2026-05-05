/**
 * @file or_rr_affine_rewriter.cpp
 * @brief `OR r, r` (different regs) → random affine MBA identity.
 *
 * Same algebraic structure as the imm32 OR-affine shape:
 *
 *     dst = -t*(x | y) + (1 + t)*(x & y) + (1 + t)*(x ^ y) = x | y
 *
 * for any per-site `t ∈ [2, 15]`.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_rr_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class OrRrAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "or-rr-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_rr(insn, AluImm32Op::or_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_rr(insn, AluImm32Op::or_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "or-rr-affine: instruction not in 09 /r or 0B /r form"));
        }

        const auto t = pick_affine_t(rng);
        const auto coefficients = affine_coefficients(view->op, t);

        analysis::X86CodeEmitter em(view->is_64bit);
        auto status = emit_affine_alu_rr_body(em, *view, coefficients);
        if (!status) return std::unexpected(status.error());

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 15;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_or_rr_affine() {
    return std::make_unique<OrRrAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
