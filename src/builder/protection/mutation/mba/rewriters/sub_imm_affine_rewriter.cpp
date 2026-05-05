/**
 * @file sub_imm_affine_rewriter.cpp
 * @brief `SUB r, K` → random affine MBA identity (with -2K correction).
 *
 * Reuses the ADD affine basis triple `(1+t, 1-t, -t)` to produce
 * `x + K`, then subtracts `2K` from the result so the body lands on
 * `x - K`. The `2K` correction is encoded as two consecutive
 * `sub dst, K` instructions; using a single `sub dst, 2K` would
 * sign-extend incorrectly when bit 31 of `K` is set.
 *
 * Per-site random `t ∈ [2, 15]` opens a 14-element family of
 * structurally-distinct shapes, complementing the three fixed SUB
 * shapes that pin a single coefficient triple each.
 *
 * Body length: 17 instructions (15 affine + 2 sub-correction). All
 * scratches restored via the 3-way push/pop wrapper.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class SubImmAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-imm-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::sub).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::sub);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "sub-imm-affine: instruction not in 81 /5 id form"));
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
        result.instruction_count = 17; // 15 affine + 2 sub-correction
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_sub_imm_affine() {
    return std::make_unique<SubImmAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
