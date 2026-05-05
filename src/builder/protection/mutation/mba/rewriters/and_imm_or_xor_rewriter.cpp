/**
 * @file and_imm_or_xor_rewriter.cpp
 * @brief `AND r, K` → `(x | K) - (x ^ K)` MBA rewrite.
 *
 * Targets the general `81 /4 id` (and REX.W) ALU encoding via
 *     x & K ≡ (x | K) - (x ^ K).
 *
 * Dual to the OR identity: the union minus the symmetric
 * difference gives the intersection. Same defeat properties as
 * the other Boolean rewrites — solver must expand both `|` and
 * `^` to verify the equality.
 *
 * Body shape (dst = x, K = imm32, scratch = r11 / r10):
 *
 *   push  scratch
 *   mov   scratch, dst        ; scratch = x
 *   xor   scratch, K          ; scratch = x ^ K
 *   or    dst, K              ; dst = x | K
 *   sub   dst, scratch        ; dst = (x | K) - (x ^ K) = x & K
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

class AndImmOrXorRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "and-imm-or-xor";
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
                "and-imm-or-xor: instruction not in 81 /4 id form"));
        }

        analysis::X86CodeEmitter em(view->is_64bit);
        const x86::Reg scratch = pick_scratch_for(view->dst);
        const auto k = static_cast<std::int32_t>(view->imm);

        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                e.mov(scratch, view->dst);
                e.xor_(scratch, k);
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

std::unique_ptr<IMbaRewriter> make_and_imm_or_minus_xor() {
    return std::make_unique<AndImmOrXorRewriter>();
}

} // namespace factories

void register_and_imm_rewriters(MbaRewriterRegistry& registry) {
    registry.register_rewriter(factories::make_and_imm_or_minus_xor());
    registry.register_rewriter(factories::make_and_imm_add_minus_or());
    registry.register_rewriter(factories::make_and_imm_demorgan());
}

} // namespace mx::mutation::mba
