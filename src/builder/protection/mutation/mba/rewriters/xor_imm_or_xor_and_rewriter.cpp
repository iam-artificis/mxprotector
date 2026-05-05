/**
 * @file xor_imm_or_xor_and_rewriter.cpp
 * @brief `XOR r, K` → `(x | K) ^ (x & K)` MBA rewrite.
 *
 * Pure-Boolean identity. Bit i of `(x|K) ^ (x&K)` is 1 iff bits
 * `(x|K)_i` and `(x&K)_i` differ — which holds iff exactly one
 * of `x_i, K_i` is set, i.e. `x_i ^ K_i = 1`. So the expression
 * computes `x ^ K` bit-by-bit with no carry, no shift, no
 * arithmetic at all.
 *
 * SMT-defeat angle: this shape contains zero arithmetic. A solver
 * inspecting the bytes sees three Boolean ops and no add/sub/shl,
 * so cached arithmetic-pattern tactics do not match. Reducing it
 * back to `x ^ K` requires bit-blasting all three operands and
 * proving the boolean equivalence — exponential in operand width.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   or    dst, K              ; dst = x | K
 *   xor   dst, scratch        ; dst = (x | K) ^ (x & K) = x ^ K
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

class XorImmOrXorAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-imm-or-xor-and";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::xor_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::xor_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "xor-imm-or-xor-and: instruction not in 81 /6 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.or_(view->dst, k);
                e.xor_(view->dst, scratch);
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

std::unique_ptr<IMbaRewriter> make_xor_imm_or_xor_and() {
    return std::make_unique<XorImmOrXorAndRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
