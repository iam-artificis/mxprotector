/**
 * @file not_rm_deep_xor_rewriter.cpp
 * @brief `NOT r32` → 2-step deep chain (xor-cancel + MBA-materialised K).
 *
 * Composes two MBA layers on the unary opcode:
 *
 *   1. Outer layer is the existing `not-rm-xor-cancel` identity
 *      `~x = (x ^ K) ^ ~K = x ^ -1 = ~x`.
 *
 *   2. Inner layer materialises both `K` and `~K` through a per-site
 *      random MOV-imm MBA shape (modular-inverse / xor-blind /
 *      rotate-blind) into a scratch register. The xor-cancel uses the
 *      register form `xor dst, scratch` instead of the imm32 form,
 *      so the original NOT site emits zero unary opcodes AND zero
 *      direct imm32 xor opcodes — only register-register ops + the
 *      MBA inner-layer chain.
 *
 * Body shape (s = scratch register, picked via `pick_scratch_for(dst)`):
 *
 *   push s
 *   <inner_emit_K_into_s>      // 1-3 instructions
 *   xor dst, s                  // dst = x ^ K
 *   <inner_emit_~K_into_s>      // 1-3 instructions
 *   xor dst, s                  // dst = x ^ K ^ ~K = ~x
 *   pop s
 *
 * Constraint: 32-bit operand only (`!is_64bit`). The inner step
 * functions emit 32-bit ops that zero-extend the high half of `s` —
 * 64-bit support would need an explicit `movsxd` after each inner
 * materialisation. Roadmapped.
 *
 * Per-site variability: 3 inner shapes for K × 3 inner shapes for
 * ~K = 9 distinct emit-byte sequences, with each inner shape adding
 * its own per-site randomness on top.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_emit_helpers.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

namespace {

class NotRmDeepXorRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "not-rm-deep-xor";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        const auto view = decode_unary(insn, UnaryOp::not_);
        return view.has_value() && !view->is_64bit;
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_unary(insn, UnaryOp::not_);
        if (!view || view->is_64bit) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "not-rm-deep-xor: requires 32-bit `F7 /2` form"));
        }

        // Force `K` outside the trivial-collapse range. Bit 24 + bit 0
        // ensure K != 0 and K != ~0, both of which would degenerate
        // the xor-cancel to a no-op or to a single-xor shape.
        const std::uint32_t k = rng.next_u32() | 0x01000001u;

        const auto inner_k    = pick_random_mov_imm_emitter(rng);
        const auto inner_notk = pick_random_mov_imm_emitter(rng);
        const x86::Reg scratch = pick_scratch_for(view->dst);

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        wrap_with_push_pop(em, scratch,
            [&](analysis::X86CodeEmitter& e) {
                inner_k(e, scratch, k, rng);
                e.xor_(view->dst, scratch);
                inner_notk(e, scratch, ~k, rng);
                e.xor_(view->dst, scratch);
            });

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 8; // 1 push + 2 inner-K + 2 xor + 1 pop
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_not_rm_deep_xor() {
    return std::make_unique<NotRmDeepXorRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
