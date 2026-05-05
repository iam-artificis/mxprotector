/**
 * @file add_imm_or_and_rewriter.cpp
 * @brief `ADD r, K` → `(x | K) + (x & K)` MBA rewrite.
 *
 * Disjoint-decomposition identity. Bit i of `x | K` is 1 iff bit i
 * of x or K is 1; bit i of `x & K` is 1 iff both are. Summing them
 * counts each bit position once when either x or K has it (carry-
 * free) and twice when both have it (matching the 1+1 carry of
 * binary addition). Equivalent to `x + K` over Z/2^n for any n.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   or    dst, K              ; dst = x | K
 *   add   dst, scratch        ; dst = (x | K) + (x & K) = x + K
 *   pop   scratch
 *
 * SMT-defeat angle: the proof obligation is structurally different
 * from `(x^K) + 2*(x&K)`. A solver that has cached a tactic for
 * one identity has to re-derive for this one, so binary-wide
 * polymorphism (multiple shapes per family, picked per site) costs
 * the solver time on a per-site basis.
 *
 * Flags: AF differs from the native `add` (the `or` writes 0/0/-/-
 * to OF/CF/AF/SF and clears AF; the trailing `add` then sets OF/CF
 * based on the wrong operands). The MBA adapter advertises
 * `affects_observable_flags()` so the engine refuses to apply at
 * flag-sensitive call sites.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AddImmOrAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-imm-or-and";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::add).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::add);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "add-imm-or-and: instruction not in 81 /0 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.or_(view->dst, k);
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

std::unique_ptr<IMbaRewriter> make_add_imm_or_and() {
    return std::make_unique<AddImmOrAndRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
