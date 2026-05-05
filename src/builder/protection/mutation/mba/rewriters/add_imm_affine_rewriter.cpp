/**
 * @file add_imm_affine_rewriter.cpp
 * @brief `ADD r, K` → random affine MBA identity.
 *
 * Tigress-style affine MBA: the body emits
 *
 *     dst = (1 + t)*(x | K) + (1 - t)*(x & K) + (-t)*(x ^ K)
 *
 * for a per-site random `t ∈ [2, 15]`. The algebra reduces this to
 * `x + K` for any value of `t`, so the shape is fully equivalent to
 * `add r, K` while presenting the SMT solver with a different
 * coefficient triple every site.
 *
 * Why a fourth ADD shape, complementing the existing three: those
 * pin a single coefficient triple — `(1, 1, 0)`, `(2, 0, -1)`,
 * `(0, 2, 1)`. The affine shape opens a 14-element family of
 * triples, defeating frequency-based shape detection that keys on
 * the canonical Knuth/disjoint identities. Each pick of `t` is a
 * structurally fresh expression in the solver's view.
 *
 * Body shape (dst = view->dst, K = view->imm, scratches = r10/r11/r12):
 *
 *   push s_or ; push s_and ; push s_xor
 *   mov  s_or,  dst ; or  s_or,  K
 *   mov  s_and, dst ; and s_and, K
 *   mov  s_xor, dst ; xor s_xor, K
 *   imul s_or,  s_or,  (1+t)
 *   imul s_and, s_and, (1-t)   ; → neg when t==2 (c_and = -1)
 *   imul s_xor, s_xor, (-t)
 *   mov  dst, s_or
 *   add  dst, s_and
 *   add  dst, s_xor
 *   pop  s_xor ; pop s_and ; pop s_or
 *
 * The actual byte sequence varies with `t`: `imul reg, reg, c` picks
 * between the imm8 (`6B /r ib`) and imm32 (`69 /r id`) forms based
 * on magnitude, and the special-case rules in `emit_imul_const`
 * fold `c==-1` into `neg` and `c==1` into a no-op.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_affine_emit.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AddImmAffineRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-imm-affine";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::add).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::add);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "add-imm-affine: instruction not in 81 /0 id form"));
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
        result.instruction_count = 15; // 3 push + 9 mid + 3 pop
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_add_imm_affine() {
    return std::make_unique<AddImmAffineRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
