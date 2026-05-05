/**
 * @file modular_inverse_rewriter.cpp
 * @brief `MOV r32, K` → `mov r32, K' ; imul r32, r32, P` polynomial rewrite.
 *
 * The chain encodes `K` as a permutation polynomial product
 *     K' * P ≡ K (mod 2^32),
 * where `P` is a per-site random odd 32-bit constant (odd ⇒
 * invertible in `Z/2^32`) and `K' = K * inv(P) mod 2^32`. At
 * runtime the multiplication recovers `K` exactly. For SMT solvers
 * the chain is harder than a direct `mov`: they must reason about
 * 32-bit modular multiplication symbolically — a known weak spot
 * for the linear-arithmetic and bit-vector tactics, since the
 * inverse is not derivable without computing `inv(P)` over
 * `Z/2^32`. Tools that rely on constant folding fall back to the
 * full multiplication; angr's symbolic execution path explodes on
 * chained applications of this transform.
 *
 * Why `mov r32` only: the 5-byte `B8 id` short form is the most
 * common compiler output for 32-bit constants and is the only
 * `mov`-imm encoding that fits the `JMP rel32` redirect with no
 * slack to spare. The 7-byte `48 C7 C0 id` REX.W variant could be
 * added later as a separate rewriter — kept out of scope here so
 * the file stays single-responsibility.
 *
 * Position-independence: the body uses only register / immediate
 * forms (no RIP-relative addressing, no branches). Position
 * preserved.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_groups.hpp"

#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

namespace mx::mutation::mba {

namespace {

class ModularInverseRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-modular-inverse";
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
                "mov-imm-modular-inverse: instruction not in B8+rd id form"));
        }

        // Run the body in 32-bit operand-size mode so the high 32
        // bits of `view->dst` get zero-extended exactly like the
        // original `mov r32, imm32` does.
        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        emit_modular_inverse_step(em, view->dst, view->imm, rng);

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

std::unique_ptr<IMbaRewriter> make_mov_imm_modular_inverse() {
    return std::make_unique<ModularInverseRewriter>();
}

} // namespace factories

void register_mov_imm_rewriters(MbaRewriterRegistry& registry) {
    // 32-bit MOV-imm shapes — share the `[REX.B] B8+rd id` encoding.
    // The MBA adapter picks one uniformly per `mov r32, imm32` site
    // so a 32-bit constant init looks different at every call.
    registry.register_rewriter(factories::make_mov_imm_modular_inverse());
    registry.register_rewriter(factories::make_mov_imm_xor_blind());
    registry.register_rewriter(factories::make_mov_imm_rotate_blind());

    // 32-bit MOV-imm 2-step deep chains. Each composes two MBA
    // layers at the abstract-operation level: outer shape
    // determines the finalizer, inner shape (picked per site)
    // materialises the leading immediate. Three deep shapes ×
    // 2 inner choices = 6 distinct emit-byte sequences on top of
    // the per-shape parameter randomness.
    registry.register_rewriter(factories::make_mov_imm_deep_modular());
    registry.register_rewriter(factories::make_mov_imm_deep_xor());
    registry.register_rewriter(factories::make_mov_imm_deep_rotate());

    // 64-bit MOV-imm shapes — share the `[REX.W (.B)] B8+rd iq`
    // encoding. Their bodies use `mov_abs64` to lock in the 10-byte
    // form regardless of how many high bits of the encoded value are
    // set (the size-optimal default would silently downgrade to the
    // 7-byte sign-extended shape). Three shapes per width keeps the
    // 64-bit MOV-imm site population polymorphic in lockstep with
    // the 32-bit set.
    registry.register_rewriter(factories::make_mov_imm64_modular_inverse());
    registry.register_rewriter(factories::make_mov_imm64_xor_blind());
    registry.register_rewriter(factories::make_mov_imm64_rotate_blind());
}

} // namespace mx::mutation::mba
