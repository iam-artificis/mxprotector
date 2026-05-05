/**
 * @file and_imm_add_minus_or_rewriter.cpp
 * @brief `AND r, K` → `(x + K) - (x | K)` MBA rewrite.
 *
 * Mixed arithmetic + bitwise identity. Derivation:
 *
 *     x + K       = (x ^ K) + 2*(x & K)        ; Knuth
 *     x | K       = (x ^ K) + (x & K)          ; disjoint-decomposition
 *     (x+K) - (x|K) = (x^K) + 2*(x&K) - (x^K) - (x&K) = x & K
 *
 * The body chains an ADD with K into a SUB of `x | K`. Cached AND
 * tactics keyed to the symmetric-difference / De Morgan patterns
 * do not match — the visible chain is `add ; or ; sub`.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   or    scratch, K          ; scratch = x | K
 *   add   dst, K              ; dst = x + K
 *   sub   dst, scratch        ; dst = (x + K) - (x | K) = x & K
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

class AndImmAddMinusOrRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "and-imm-add-minus-or";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::and_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::and_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "and-imm-add-minus-or: instruction not in 81 /4 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.or_(scratch, k);
                e.add(view->dst, k);
                e.sub(view->dst, scratch);
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

std::unique_ptr<IMbaRewriter> make_and_imm_add_minus_or() {
    return std::make_unique<AndImmAddMinusOrRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
