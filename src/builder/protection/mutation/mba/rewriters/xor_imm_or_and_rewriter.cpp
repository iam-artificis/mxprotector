/**
 * @file xor_imm_or_and_rewriter.cpp
 * @brief `XOR r, K` → `(x | K) - (x & K)` MBA rewrite.
 *
 * Targets the general `81 /6 id` (and REX.W) ALU encoding via the
 * symmetric-difference identity
 *     x ^ K ≡ (x | K) - (x & K).
 *
 * The output is the difference between the union and intersection
 * of `x` and `K` — a definition the SMT solver can technically
 * verify, but only after expanding both Boolean ops symbolically.
 * Combined with depth-1 rewrites of the inner OR/AND in subsequent
 * passes, the proof obligation grows fast.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   or    dst, K              ; dst = x | K
 *   sub   dst, scratch        ; dst = (x | K) - (x & K) = x ^ K
 *   pop   scratch
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_alu_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

namespace mx::mutation::mba {

namespace {

class XorImmOrAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-imm-or-and";
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
                "xor-imm-or-and: instruction not in 81 /6 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.or_(view->dst, k);
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

std::unique_ptr<IMbaRewriter> make_xor_imm_or_minus_and() {
    return std::make_unique<XorImmOrAndRewriter>();
}

} // namespace factories

void register_xor_imm_rewriters(MbaRewriterRegistry& registry) {
    registry.register_rewriter(factories::make_xor_imm_or_minus_and());
    registry.register_rewriter(factories::make_xor_imm_or_xor_and());
    registry.register_rewriter(factories::make_xor_imm_add_minus_and());
    registry.register_rewriter(factories::make_xor_imm_affine());
}

} // namespace mx::mutation::mba
