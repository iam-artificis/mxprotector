/**
 * @file mov_imm_deep_xor_rewriter.cpp
 * @brief 2-step deep chain: outer xor-blind + inner modular/rotate-blind.
 *
 * Outer layer: `mov dst, A ; xor dst, A^K` for random `A`. Instead
 * of materialising `A` via the trivial `direct_mov_imm32`, the
 * deep-chain picks one of {modular_inverse, rotate_blind} per call
 * site and uses it to materialise `A`.
 *
 * Two inner choices, picked uniformly per site:
 *
 *   inner = modular_inverse: mov A' ; imul P ; xor (A^K)   (3 instructions,
 *                            A = A' * P mod 2^32)
 *   inner = rotate_blind:    mov ror(A, n) ; rol n ; xor (A^K)
 *
 * The runtime XOR with `(A ^ K)` undoes the inner-layer A
 * computation, leaving `K` in `dst`. SMT-wise the inner layer
 * brings a multiplicative or rotation step into the chain that
 * a pure-XOR cancellation tactic cannot fold through.
 *
 * Body length: 3 instructions = 12–14 bytes.
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

class MovImmDeepXorRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-deep-xor";
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
                "mov-imm-deep-xor: instruction not in B8+rd id form"));
        }

        const MovImmEmitter inner = (rng.next_range(0u, 1u) == 0u)
            ? MovImmEmitter{&emit_modular_inverse}
            : MovImmEmitter{&emit_rotate_blind};

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        emit_xor_blind_step(em, view->dst, view->imm, rng, inner);

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

std::unique_ptr<IMbaRewriter> make_mov_imm_deep_xor() {
    return std::make_unique<MovImmDeepXorRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
