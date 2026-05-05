/**
 * @file mov_imm64_xor_blind_rewriter.cpp
 * @brief `MOV r64, K` → `mov r64, A ; xor r64, B32` blinding rewrite
 *        where `A ^ sext64(B32) = K`.
 *
 * 64-bit twin of `mov_imm_xor_blind_rewriter`. Splits the 64-bit
 * constant `K` into two halves: a 64-bit `A` (carried in the
 * 10-byte `mov r64, imm64`) and a 32-bit signed `B32` (carried in
 * the 7-byte `xor r/m64, imm32` whose immediate is sign-extended to
 * 64 bits on the instruction). At runtime
 *
 *     A ^ sext64(B32) = (K ^ sext64(B32)) ^ sext64(B32) = K.
 *
 * Per-site polymorphism comes entirely from the random `B32` —
 * `A` is fully determined by `K` and `B32`, so two MOV-imm64 sites
 * with the same target `K` get visibly different bytes.
 *
 * Why we accept the imm32 sign-extension limitation: the alternative
 * would be a `mov r2, A^K ; xor r1, r2` chain that needs a free
 * scratch register, which forces a push/pop spill and grows the body
 * substantially. The sign-extended xor closes the algebra exactly —
 * any final 64-bit `K` is reachable for any random `B32`, just by
 * picking `A = K ^ sext64(B32)`.
 *
 * SMT-defeat angle: the chain is trivial for a tactic that
 * symbolically evaluates the second instruction (the XOR is
 * literally `K = A ^ sext64(B32)`). It exists for *visual*
 * polymorphism (defeats binary diffing) and as a complementary
 * option to the stronger 64-bit modular-inverse shape. The MBA
 * adapter picks uniformly, so the modular-inverse shape's full
 * SMT-defeat strength still covers a third of MOV-imm64 sites.
 *
 * Body shape (dst = view->dst, K = view->imm 64-bit):
 *
 *   mov   dst, A                 ; dst = A                (10 bytes)
 *   xor   dst, B32               ; dst = A ^ sext64(B32)  (7 bytes)
 *
 * Total: 17 bytes — well above the JMP rel32 redirect threshold.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class MovImm64XorBlindRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm64-xor-blind";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        if (insn.mnemonic() != "mov") return false;
        return decode_mov_r64_imm64(insn).has_value();
    }

    [[nodiscard]] MxResult<MbaRewriteResult> rewrite(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        const auto view = decode_mov_r64_imm64(insn);
        if (!view) {
            return std::unexpected(error::protection(
                ProtectionErrorCode::pass_failed,
                "mov-imm64-xor-blind: instruction not in REX.W B8+rd iq form"));
        }

        // Force the imm32 outside [-128, 127] so `xor r/m64, imm32`
        // takes the full 7-byte `81 /6 id` shape rather than the
        // 4-byte imm8 form `83 /6 ib` (which is also sign-extended
        // but produces a much shorter body, undermining the visual
        // polymorphism the rewriter is here to provide).
        std::uint32_t b32_raw = rng.next_u32() | 0x01000001u;
        if (b32_raw == 0u) b32_raw = 0x01000001u; // belt-and-braces
        const std::int32_t b32 = static_cast<std::int32_t>(b32_raw);
        const std::uint64_t b_se = static_cast<std::uint64_t>(
            static_cast<std::int64_t>(b32));
        const std::uint64_t a = view->imm ^ b_se;

        analysis::X86CodeEmitter em(/*is_64bit=*/true);
        em.mov_abs64(view->dst, a);
        em.xor_(view->dst, b32);

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

std::unique_ptr<IMbaRewriter> make_mov_imm64_xor_blind() {
    return std::make_unique<MovImm64XorBlindRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
