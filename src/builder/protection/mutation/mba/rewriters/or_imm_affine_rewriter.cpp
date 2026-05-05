/**
 * @file or_imm_affine_rewriter.cpp
 * @brief `OR r, K` → random affine MBA identity.
 *
 * For OR the affine triple is `(-t, 1+t, 1+t)`. Verification:
 *
 *     -t*OR + (1+t)*AND + (1+t)*XOR
 *   = (AND + XOR) + t*(-OR + AND + XOR)
 *   = (AND + XOR) + t * 0
 *   = AND + XOR
 *   = x | K.
 *
 * (Identity: `OR = AND + XOR`, equivalently `-OR + AND + XOR = 0`.)
 *
 * For `t ∈ [2, 15]` the coefficients land in `(c_or ∈ [-15, -2],
 * c_and ∈ [3, 16], c_xor ∈ [3, 16])`. None collapse to ±1 or 0, so
 * every `t` produces a body with three full `imul` multiplies in
 * the basis-prep stage.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class OrImmAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "or-imm-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::or_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::or_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "or-imm-affine: instruction not in 81 /1 id form"));
        }

        const auto t = pick_affine_t(rng);
        const auto coefficients = affine_coefficients(view->op, t);

        analysis::X86CodeEmitter em(view->is_64bit);
        auto status = emit_affine_alu_body(em, *view, coefficients);
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

std::unique_ptr<IMbaRewriter> make_or_imm_affine() {
    return std::make_unique<OrImmAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
