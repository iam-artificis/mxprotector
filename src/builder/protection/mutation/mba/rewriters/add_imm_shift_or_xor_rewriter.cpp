/**
 * @file add_imm_shift_or_xor_rewriter.cpp
 * @brief `ADD r, K` → `2*(x | K) - (x ^ K)` MBA rewrite.
 *
 * Shift-based additive identity. Derivation:
 *
 *     2*(x | K) = (x | K) + (x | K)
 *               = ((x ^ K) + (x & K)) + ((x ^ K) + (x & K))   ; via the disjoint-decomposition identity
 *               = 2*(x ^ K) + 2*(x & K)
 *     2*(x | K) - (x ^ K) = (x ^ K) + 2*(x & K) = x + K       ; via Knuth's identity
 *
 * Equivalent to `x + K` over Z/2^n for any n. Mixes a shift (SHL),
 * three Boolean ops (OR / XOR / OR again via the SUB chain) and one
 * subtract — a third structural shape distinct from
 * `(x ^ K) + 2*(x & K)` and `(x | K) + (x & K)`. SMT solvers that
 * cached a tactic for one cannot reuse it here.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   or    scratch, K          ; scratch = x | K
 *   shl   scratch, 1          ; scratch = 2*(x | K)
 *   xor   dst, K              ; dst = x ^ K
 *   sub   scratch, dst        ; scratch = 2*(x|K) - (x^K)
 *   mov   dst, scratch        ; dst = 2*(x|K) - (x^K) = x + K
 *   pop   scratch
 *
 * Flag preservation: same caveat as the other ADD-imm shapes —
 * AF/OF after the body do not match a native `add`. Gated by
 * `affects_observable_flags()` on the adapter.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AddImmShiftOrXorRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-imm-shift-or-xor";
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
                "add-imm-shift-or-xor: instruction not in 81 /0 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.or_(scratch, k);
                e.shl(scratch, 1);
                e.xor_(view->dst, k);
                e.sub(scratch, view->dst);
                e.mov(view->dst, scratch);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 8;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_add_imm_shift_or_xor() {
    return std::make_unique<AddImmShiftOrXorRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
