/**
 * @file mov_imm_deep_rotate_rewriter.cpp
 * @brief 2-step deep chain: outer rotate-blind + inner modular/xor-blind.
 *
 * Outer layer: `mov dst, ror32(K, n) ; rol dst, n` for random
 * `n ∈ [1, 31]`. The deep-chain picks one of {modular_inverse,
 * xor_blind} per call site to materialise the leading
 * `ror32(K, n)`.
 *
 * Two inner choices, picked uniformly per site:
 *
 *   inner = modular_inverse: mov R' ; imul P ; rol n   (3 instructions,
 *                            ror32(K, n) = R' * P mod 2^32)
 *   inner = xor_blind:       mov A ; xor (A ^ ror32(K, n)) ; rol n
 *
 * The runtime ROL undoes the rotation introduced by the leading
 * `ror32(K, n)`, leaving `K` in `dst`. The inner layer adds a
 * multiplicative or XOR-cancellation step that the rotation tactic
 * cannot fold through symbolically.
 *
 * Body length: 3 instructions = 11–14 bytes.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

namespace {

class MovImmDeepRotateRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-deep-rotate";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        if (insn.mnemonic() != "mov") return false;
        return decode_mov_r32_imm32(insn).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_mov_r32_imm32(insn);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "mov-imm-deep-rotate: instruction not in B8+rd id form"));
        }

        const MovImmEmitter inner = (rng.next_range(0u, 1u) == 0u)
            ? MovImmEmitter{&emit_modular_inverse}
            : MovImmEmitter{&emit_xor_blind};

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        emit_rotate_blind_step(em, view->dst, view->imm, rng, inner);

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 3;
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_mov_imm_deep_rotate() {
    return std::make_unique<MovImmDeepRotateRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
