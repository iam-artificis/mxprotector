/**
 * @file xor_imm_add_minus_and_rewriter.cpp
 * @brief `XOR r, K` → `(x + K) - 2*(x & K)` MBA rewrite.
 *
 * Mixed arithmetic + bitwise identity. Derivation:
 *
 *     x + K        = (x ^ K) + 2*(x & K)        ; Knuth
 *     (x + K) - 2*(x & K) = x ^ K
 *
 * The body chains an ADD-style expansion into a SUB of the carry-
 * doubled AND. The solver must follow:
 *
 *     1. ADD with K (linear-arithmetic update),
 *     2. AND with K then SHL 1 (bitwise then shift),
 *     3. SUB the two,
 *
 * and prove the result equals `x ^ K`. Cached XOR tactics targeting
 * `x ^ K` (folding to a constant when both operands are constants)
 * do not apply because the overall expression mixes arithmetic and
 * bitwise reasoning.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   shl   scratch, 1          ; scratch = 2*(x & K)
 *   add   dst, K              ; dst = x + K
 *   sub   dst, scratch        ; dst = (x + K) - 2*(x & K) = x ^ K
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

class XorImmAddMinusAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-imm-add-minus-and";
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
                "xor-imm-add-minus-and: instruction not in 81 /6 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.shl(scratch, 1);
                e.add(view->dst, k);
                e.sub(view->dst, scratch);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 7;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_xor_imm_add_minus_and() {
    return std::make_unique<XorImmAddMinusAndRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
