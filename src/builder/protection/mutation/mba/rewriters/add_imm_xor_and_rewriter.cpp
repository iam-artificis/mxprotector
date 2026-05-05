/**
 * @file add_imm_xor_and_rewriter.cpp
 * @brief `ADD r, K` → `(x ^ K) + 2*(x & K)` MBA rewrite.
 *
 * Rewrites the general `81 /0 id` (and REX.W variant) ALU
 * encoding via the additive MBA identity
 *     x + K ≡ (x ^ K) + 2 * (x & K).
 *
 * Why this identity matters for SMT defeat: the original `add`
 * is folded by every solver in O(1) — it's a linear update of
 * the symbolic expression. The MBA replacement mixes two
 * Boolean ops and an arithmetic shift into the result, blocking
 * the linear-arithmetic tactic and forcing the solver into bit
 * blasting. Bit blasting is exponential in the operand width;
 * 32-bit constants alone push Z3 from milliseconds to seconds.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   shl   scratch, 1          ; scratch = 2 * (x & K)
 *   xor   dst, K              ; dst = x ^ K
 *   add   dst, scratch        ; dst = (x ^ K) + 2*(x & K) = x + K
 *   pop   scratch
 *
 * Result: numerically identical to the original `add reg, K`.
 * Flags after the final ADD differ from the original in OF/AF
 * (same CF/ZF/SF/PF, see `mba_rewriter.hpp` for the full
 * preservation note).
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AddImmXorAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-imm-xor-and";
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
                "add-imm-xor-and: instruction not in 81 /0 id form"));
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

void register_add_imm_rewriters(MbaRewriterRegistry& registry) {
    registry.register_rewriter(std::make_unique<AddImmXorAndRewriter>());
}

} // namespace mx::mutation::mba
