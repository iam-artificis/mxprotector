/**
 * @file not_rm_xor_cancel_rewriter.cpp
 * @brief `NOT r` → `XOR r, K ; XOR r, ~K` (xor-cancellation identity).
 *
 * Identity: `(x ^ K) ^ ~K = x ^ (K ^ ~K) = x ^ -1 = ~x` over Z/2^n.
 * The body emits two XORs with complementary 32-bit immediates;
 * neither contains the original NOT opcode, and the per-site random
 * `K` makes two NOT sites in the same binary produce visually
 * different bytes.
 *
 * Why the imm32 form (not imm8): the imm8 path (`83 /6 ib`) sign-
 * extends, so picking `K` outside [-128, 127] forces the encoder
 * to use `81 /6 id` (6 bytes incl. REX). That keeps the body length
 * stable across all `K` choices and avoids the imm8/imm32 boundary
 * fluctuating per site.
 *
 * Body length: 2 instructions, 12 bytes (`81 /6 id` × 2 with REX.W).
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_unary_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class NotRmXorCancelRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "not-rm-xor-cancel";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        return decode_unary(insn, UnaryOp::not_).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_unary(insn, UnaryOp::not_);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "not-rm-xor-cancel: instruction not in F7 /2 form"));
        }

        // Force `K` outside [-128, 127] so the encoder picks the
        // 6-byte imm32 form rather than the 4-byte imm8 form. Bit 24
        // outside the sign-bit guarantees the int32 value's
        // magnitude is large enough either way.
        const std::uint32_t k = rng.next_u32() | 0x01000001u;

        analysis::X86CodeEmitter em(view->is_64bit);
        em.xor_(view->dst, static_cast<std::int32_t>(k));
        em.xor_(view->dst, static_cast<std::int32_t>(~k));

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 2;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_not_rm_xor_cancel() {
    return std::make_unique<NotRmXorCancelRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
