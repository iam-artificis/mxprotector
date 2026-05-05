/**
 * @file sub_rr_affine_rewriter.cpp
 * @brief `SUB r, r` → random affine MBA identity with -2*src correction.
 *
 * Reuses the ADD affine basis triple `(1+t, 1-t, -t)` to produce
 * `x + y`, then subtracts `2y` (encoded as two `sub dst, src` ops)
 * to land on `x - y`. Two register subtractions are byte-stable —
 * unlike the imm32 path which has to split `2K` to avoid sign-
 * extension overflow — so the SUB correction is a clean 6 bytes
 * (3 each with REX) regardless of operand width.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_rr_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class SubRrAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-rr-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_rr(insn, AluImm32Op::sub).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_rr(insn, AluImm32Op::sub);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "sub-rr-affine: instruction not in 29 /r or 2B /r form"));
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
        result.instruction_count = 17;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_sub_rr_affine() {
    return std::make_unique<SubRrAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
