/**
 * @file add_rr_affine_rewriter.cpp
 * @brief `ADD r, r` → random affine MBA identity (r-r form).
 *
 * Same affine-MBA structure as the imm32 ADD shape: emits
 *
 *     dst = (1 + t)*(x | y) + (1 - t)*(x & y) + (-t)*(x ^ y)
 *
 * for a per-site random `t ∈ [2, 15]` and reduces to `x + y` for
 * any value of `t`. Targets the 2/3-byte `01 /r` and `03 /r`
 * encodings — below the 5-byte JMP rel32 redirect threshold, so the
 * substitution relies on the engine's multi-instruction redirect
 * (Phase 11) to drag the next 1..3 instructions into the slot.
 *
 * Body uses three push/pop-protected scratch registers picked to
 * avoid both `dst` and `src`; `src` has to stay live across the
 * basis-prep stage so an aliasing scratch would silently miscompile
 * the OR/AND/XOR computations.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_rr_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AddRrAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-rr-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_rr(insn, AluImm32Op::add).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_rr(insn, AluImm32Op::add);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "add-rr-affine: instruction not in 01 /r or 03 /r form"));
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

std::unique_ptr<IMbaRewriter> make_add_rr_affine() {
    return std::make_unique<AddRrAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
