/**
 * @file or_imm_xor_or_and_rewriter.cpp
 * @brief `OR r, K` → `(x ^ K) | (x & K)` MBA rewrite.
 *
 * Pure-Boolean OR identity. Bit i of `(x^K) | (x&K)`:
 *
 *   * x_i=0, K_i=0  → (0|0) | (0&0) = 0  ; matches (x|K)_i = 0
 *   * x_i=1, K_i=0  → (1)   | (0)   = 1  ; matches 1
 *   * x_i=0, K_i=1  → (1)   | (0)   = 1  ; matches 1
 *   * x_i=1, K_i=1  → (0)   | (1)   = 1  ; matches 1
 *
 * So the expression equals `x | K` bit-by-bit. No carry, no
 * arithmetic — three pure Boolean ops.
 *
 * SMT-defeat angle: the absence of arithmetic means linear-tactic
 * folds don't trigger; the solver must bit-blast all three operands
 * and prove the boolean equivalence — exponential in operand
 * width. This shape complements the arithmetic OR-imm shapes by
 * landing in a different solver-tactic regime.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   xor   dst, K              ; dst = x ^ K
 *   or    dst, scratch        ; dst = (x ^ K) | (x & K) = x | K
 *   pop   scratch
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class OrImmXorOrAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "or-imm-xor-or-and";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::or_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::or_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "or-imm-xor-or-and: instruction not in 81 /1 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.xor_(view->dst, k);
                e.or_(view->dst, scratch);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 6;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_or_imm_xor_or_and() {
    return std::make_unique<OrImmXorOrAndRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
