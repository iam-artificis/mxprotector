/**
 * @file mov_imm_deep_modular_rewriter.cpp
 * @brief 2-step deep chain: outer modular-inverse + inner xor/rotate-blind.
 *
 * Composes two MBA layers at the abstract-operation level. The
 * outer layer is `modular_inverse_step` — `mov dst, K' ; imul dst, P`
 * with `K' = K * inv(P)`. Instead of materialising `K'` via the
 * trivial `direct_mov_imm32`, the deep-chain rewriter picks one of
 * the *other two* shapes at random per call site and uses that
 * shape to materialise `K'`.
 *
 * Two inner choices, picked uniformly per site:
 *
 *   inner = xor_blind:    mov A ; xor B ; imul P    (3 instructions)
 *   inner = rotate_blind: mov ror(K', n) ; rol n ; imul P
 *
 * The runtime arithmetic is the same `K = K' * P (mod 2^32)` as the
 * single-layer modular_inverse, but the SMT solver now has to chase
 * two MBA layers stacked in series — `imul P` of (a chain that
 * itself reduces to `K'`). For the linear-arithmetic and bit-vector
 * tactics, the proof obligation is roughly the product of the per-
 * layer costs; nested chains escalate solver time multiplicatively.
 *
 * Body length: 3 instructions = 11–14 bytes. Fits the JMP rel32
 * redirect threshold with comfortable headroom.
 *
 * Why a deep-chain shape per outer layer, not per inner: every
 * outer layer determines its own finalizer (imul vs xor vs rol).
 * Picking the inner per call gives 2-fold variety inside each shape
 * (3 outer × 2 inner = 6 distinct emit-byte sequences).
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

class MovImmDeepModularRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-deep-modular";
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
                "mov-imm-deep-modular: instruction not in B8+rd id form"));
        }

        // Pick one of the *other* MOV-imm shapes as the inner step.
        // Excluding modular_inverse here matters: re-applying the
        // same shape would emit `mov K''; imul P'; imul P` which a
        // mid-strength solver folds back to `K'' * P' * P`. Mixing
        // shapes forces the solver to switch tactics between layers.
        const MovImmEmitter inner = (rng.next_range(0u, 1u) == 0u)
            ? MovImmEmitter{&emit_xor_blind}
            : MovImmEmitter{&emit_rotate_blind};

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        emit_modular_inverse_step(em, view->dst, view->imm, rng, inner);

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 3; // 2 inner + 1 outer finalizer
        return result;
    }
};

} // namespace

namespace factories {

std::unique_ptr<IMbaRewriter> make_mov_imm_deep_modular() {
    return std::make_unique<MovImmDeepModularRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
