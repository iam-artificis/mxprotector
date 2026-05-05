/**
 * @file xor_imm_affine_rewriter.cpp
 * @brief `XOR r, K` → random affine MBA identity.
 *
 * For XOR the affine triple is `(1-t, t-1, t)`. Verification:
 *
 *     (1-t)*OR + (t-1)*AND + t*XOR
 *   = (OR - AND) + t*(- OR + AND + XOR)
 *   = (OR - AND) + t * (-(OR - AND - XOR))
 *   = OR - AND
 *   = x ^ K.
 *
 * For `t ∈ [2, 15]` the coefficients land in `(c_or ∈ [-14,-1],
 * c_and ∈ [1, 14], c_xor ∈ [2, 15])`. At `t == 2` the AND coefficient
 * is exactly 1, which `emit_imul_const` turns into a no-op multiply
 * — body still computes the correct XOR identity, just with one
 * fewer `imul` than for larger `t`.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class XorImmAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-imm-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::xor_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::xor_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "xor-imm-affine: instruction not in 81 /6 id form"));
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

std::unique_ptr<IMbaRewriter> make_xor_imm_affine() {
    return std::make_unique<XorImmAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
