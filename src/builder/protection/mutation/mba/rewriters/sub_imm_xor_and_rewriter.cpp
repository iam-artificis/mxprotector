/**
 * @file sub_imm_xor_and_rewriter.cpp
 * @brief `SUB r, K` → `(x ^ K) - 2*(~x & K)` MBA rewrite.
 *
 * Targets the general `81 /5 id` (and REX.W) ALU encoding via the
 * subtractive MBA identity
 *     x - K ≡ (x ^ K) - 2 * (~x & K).
 *
 * The `~x` step adds a NOT inversion that the symbolic solver
 * can't pattern-match against the original SUB without first
 * rewriting through DeMorgan's laws — exactly the kind of
 * transformation Z3's default tactics struggle with.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   not   scratch             ; scratch = ~x
 *   and   scratch, K          ; scratch = ~x & K
 *   shl   scratch, 1          ; scratch = 2 * (~x & K)
 *   xor   dst, K              ; dst = x ^ K
 *   sub   dst, scratch        ; dst = (x ^ K) - 2*(~x & K) = x - K
 *   pop   scratch
 *
 * Per-family aggregator: this TU also hosts
 * `register_sub_imm_rewriters`, which registers all SUB-r,K MBA
 * shapes via the factory functions in `mba_rewriter_factories.hpp`.
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

class SubImmXorAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-imm-xor-and";
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
                "sub-imm-xor-and: instruction not in 81 /5 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.not_(scratch);
                e.and_(scratch, k);
                e.shl(scratch, 1);
                e.xor_(view->dst, k);
                e.sub(view->dst, scratch);
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

std::unique_ptr<IMbaRewriter> make_sub_imm_xor_not_and() {
    return std::make_unique<SubImmXorAndRewriter>();
}

} // namespace factories

void register_sub_imm_rewriters(MbaRewriterRegistry& registry) {
    // Four subtractive identities cover the same `81 /5 id` site;
    // the MBA adapter picks one uniformly per call so two
    // `sub r, K` instructions in the same binary look different.
    // The fixed shapes pin specific coefficient triples; the affine
    // shape opens a 14-element family parameterised by per-site `t`.
    registry.register_rewriter(factories::make_sub_imm_xor_not_and());
    registry.register_rewriter(factories::make_sub_imm_neg_add());
    registry.register_rewriter(factories::make_sub_imm_offset());
    registry.register_rewriter(factories::make_sub_imm_affine());
}

} // namespace mx::mutation::mba
