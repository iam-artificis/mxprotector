/**
 * @file or_imm_xor_and_rewriter.cpp
 * @brief `OR  r, K` → `(x ^ K) + (x & K)` MBA rewrite.
 *
 * Targets the general `81 /1 id` (and REX.W) ALU encoding via
 *     x | K ≡ (x ^ K) + (x & K).
 *
 * Algebraically: `x | K` is the union of bits, and we recover it
 * by summing the symmetric-difference (`x ^ K`, exclusive bits)
 * with the intersection (`x & K`, common bits). Each disjoint
 * portion contributes once.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   and   scratch, K          ; scratch = x & K
 *   xor   dst, K              ; dst = x ^ K
 *   add   dst, scratch        ; dst = (x ^ K) + (x & K) = x | K
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

class OrImmXorAndRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "or-imm-xor-and";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_alu_imm32(insn, AluImm32Op::or_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  /*rng*/) const override
    {
        const auto view = decode_alu_imm32(insn, AluImm32Op::or_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "or-imm-xor-and: instruction not in 81 /1 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.and_(scratch, k);
                e.xor_(view->dst, k);
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

std::unique_ptr<IMbaRewriter> make_or_imm_xor_plus_and() {
    return std::make_unique<OrImmXorAndRewriter>();
}

} // namespace factories

void register_or_imm_rewriters(MbaRewriterRegistry& registry) {
    registry.register_rewriter(factories::make_or_imm_xor_plus_and());
    registry.register_rewriter(factories::make_or_imm_add_minus_and());
    registry.register_rewriter(factories::make_or_imm_xor_or_and());
    registry.register_rewriter(factories::make_or_imm_affine());
}

} // namespace mx::mutation::mba
