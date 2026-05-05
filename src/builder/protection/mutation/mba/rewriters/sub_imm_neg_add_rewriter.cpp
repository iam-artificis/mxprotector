/**
 * @file sub_imm_neg_add_rewriter.cpp
 * @brief `SUB r, K` → `x + (~K + 1)` two's-complement negation MBA.
 *
 * Identity: in two's-complement arithmetic over Z/2^n, `-K = ~K + 1`.
 * Therefore `x - K = x + (~K + 1)`. The body computes the negation
 * of K at *runtime* — the constant is loaded into a scratch reg,
 * NOTed, incremented, then added to dst. A solver inspecting the
 * bytes cannot fold `mov r, K; not r; add r, 1; add dst, r` into
 * `sub dst, K` without first proving the not-then-add chain
 * equals two's-complement negation, which standard linear-arithmetic
 * tactics do not perform.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, K          ; scratch = K
 *   not   scratch             ; scratch = ~K
 *   add   scratch, 1          ; scratch = ~K + 1 = -K
 *   add   dst, scratch        ; dst = x + (-K) = x - K
 *   pop   scratch
 *
 * Why we don't precompute `-K` as a constant: the whole point of
 * the rewrite is to *hide* the relationship to the original `sub
 * r, K`. Precomputing collapses the chain to `add dst, neg_K`,
 * which is encoded identically to the original (both `81 /op id`).
 * Materialising `-K` from the original `K` keeps the constant in
 * its original-looking shape until the runtime computation kicks in.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class SubImmNegAddRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-imm-neg-add";
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
                "sub-imm-neg-add: instruction not in 81 /5 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(k)));
                e.not_(scratch);
                e.add(scratch, 1);
                e.add(view->dst, scratch);
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

std::unique_ptr<IMbaRewriter> make_sub_imm_neg_add() {
    return std::make_unique<SubImmNegAddRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
