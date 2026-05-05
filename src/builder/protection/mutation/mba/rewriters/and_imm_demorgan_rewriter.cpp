/**
 * @file and_imm_demorgan_rewriter.cpp
 * @brief `AND r, K` → `~(~x | ~K)` MBA rewrite via De Morgan's law.
 *
 * De Morgan's identity: `x & K = ~(~x | ~K)`. The body materialises
 * the AND entirely from negation + a single OR — three NOTs and one
 * OR, no arithmetic. A solver inspecting the chain cannot fold it
 * back to AND without first proving De Morgan symbolically, which
 * standard linear-arithmetic and bitvector-equivalence tactics do
 * lazily on demand.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, K          ; scratch = K  (sign-extended to dst width)
 *   not   scratch             ; scratch = ~K
 *   not   dst                 ; dst = ~x
 *   or    dst, scratch        ; dst = ~x | ~K
 *   not   dst                 ; dst = ~(~x | ~K) = x & K
 *   pop   scratch
 *
 * Why materialise `~K` at runtime: precomputing `~K` as a constant
 * collapses the chain to `or dst, ~K_const` which is encoded
 * identically to the original `and r, K`. Materialising preserves
 * the visible NOT chain so the structural difference shows up in
 * the disassembly.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

class AndImmDeMorganRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "and-imm-demorgan";
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
                "and-imm-demorgan: instruction not in 81 /4 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(k)));
                e.not_(scratch);
                e.not_(view->dst);
                e.or_(view->dst, scratch);
                e.not_(view->dst);
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

std::unique_ptr<IMbaRewriter> make_and_imm_demorgan() {
    return std::make_unique<AndImmDeMorganRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
