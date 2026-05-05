/**
 * @file and_imm_affine_rewriter.cpp
 * @brief `AND r, K` → random affine MBA identity.
 *
 * For AND the affine triple is `(1+t, -t, -(1+t))`. Verification:
 *
 *     (1+t)*OR + (-t)*AND + (-(1+t))*XOR
 *   = (OR - XOR) + t*(OR - AND - XOR)
 *   = (OR - XOR) + t * 0
 *   = OR - XOR
 *   = x & K.
 *
 * (Identity: `AND = OR - XOR`, equivalently `OR - AND - XOR = 0`.)
 *
 * For `t ∈ [2, 15]` the coefficients land in `(c_or ∈ [3, 16],
 * c_and ∈ [-15, -2], c_xor ∈ [-16, -3])`. None collapse to ±1 or
 * 0, so every `t` produces three full `imul` multiplies in the
 * basis-prep stage.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AndImmAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "and-imm-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::and_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::and_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "and-imm-affine: instruction not in 81 /4 id form"));
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

std::unique_ptr<IMbaRewriter> make_and_imm_affine() {
    return std::make_unique<AndImmAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
