/**
 * @file sub_imm_offset_rewriter.cpp
 * @brief `SUB r, K` → `(x ^ K) + 2*(x & K) - 2K` MBA rewrite.
 *
 * Reuses the additive Knuth identity to compute `x + K`, then
 * subtracts `2K` to recover `x - K`. Over Z/2^n:
 *
 *     (x ^ K) + 2*(x & K) = x + K           ; Knuth
 *     (x + K) - 2K        = x - K
 *
 * The chain mixes one Boolean-AND-then-shift into an XOR-then-ADD,
 * then folds in two consecutive subtracts. That gives the solver a
 * longer arithmetic chain (8 micro-ops in the body vs. 6 for the
 * Knuth subtractive form), with intermediate values that don't
 * pattern-match against any classical SUB tactic.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   shl   scratch, 1          ; scratch = 2*(x & K)
 *   xor   dst, K              ; dst = x ^ K
 *   add   dst, scratch        ; dst = (x^K) + 2*(x&K) = x + K
 *   sub   dst, K              ; dst = x + K - K = x
 *   sub   dst, K              ; dst = x - K
 *   pop   scratch
 *
 * Why two `sub dst, K` instead of `sub dst, 2K`: the constant `2K`
 * may overflow signed-int32 (e.g. K = 0xC0000000), in which case
 * the sign-extended encoding would no longer match `K << 1` over
 * Z/2^32. Subtracting `K` twice keeps the body free of any
 * width-dependent constant rewrite.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class SubImmOffsetRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-imm-offset";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::sub).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::sub);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "sub-imm-offset: instruction not in 81 /5 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.shl(scratch, 1);
                e.xor_(view->dst, k);
                e.add(view->dst, scratch);
                e.sub(view->dst, k);
                e.sub(view->dst, k);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 9;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_sub_imm_offset() {
    return std::make_unique<SubImmOffsetRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
