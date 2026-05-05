/**
 * @file mov_imm64_modular_inverse_rewriter.cpp
 * @brief `MOV r64, imm64` → `mov r64, K' ; imul r64, r64, P` polynomial rewrite.
 *
 * 64-bit twin of `modular_inverse_rewriter.cpp`. The chain encodes
 * a 64-bit constant `K` as a permutation polynomial product
 *     K' * P_se ≡ K (mod 2^64),
 * where `P_se = sext64(P32)` is the imm32-immediate value the
 * `imul r64, r/m64, imm32` instruction actually multiplies by (the
 * imm32 is sign-extended to 64 bits per Intel SDM), and
 *     K' = K * inv(P_se) mod 2^64.
 *
 * Why this rewriter is its own translation unit and not a
 * specialisation of the 32-bit `modular_inverse_rewriter`:
 *
 *   * Different decoder (`decode_mov_r64_imm64`).
 *   * Different inverse (`modular_inverse_u64`, 6 Newton-Hensel
 *     iterations vs. 5 for u32).
 *   * Different mov-encoding contract — the body must use the
 *     10-byte `[REX.W] B8+rd iq` form (`mov_abs64`) so the encoded
 *     `K'` survives as a 64-bit constant. The default `mov(uint64_t)`
 *     downgrades to the 7-byte sign-extended form whenever the
 *     immediate fits in 32 bits, which would silently flip the high
 *     32 bits whenever bit 31 of `K'` is set.
 *
 * Body shape (dst = view->dst, K = view->imm 64-bit):
 *
 *   mov   dst, K'                ; dst = K'             (10 bytes)
 *   imul  dst, dst, P32          ; dst = K' * sext64(P) = K (≥ 7 bytes)
 *
 * Total: 17–18 bytes — well above the 5-byte JMP rel32 threshold.
 *
 * Position-independence: register / immediate operands only — no
 * RIP-relative addressing, no branches.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

namespace {

/// 64-bit modular inverse of an odd value via the Newton-Hensel
/// recursion. Doubles the number of correct bits per iteration; six
/// iterations cover all 64 bits. Pre-condition: `value & 1 == 1`.
[[nodiscard]] constexpr std::uint64_t modular_inverse_u64(
    std::uint64_t value) noexcept
{
    std::uint64_t inverse = value; // matches at the low 3 bits
    for (int i = 0; i < 6; ++i) {
        inverse = inverse * (2ull - value * inverse);
    }
    return inverse;
}

class MovImm64ModularInverseRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm64-modular-inverse";
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
                "mov-imm64-modular-inverse: instruction not in REX.W B8+rd iq form"));
        }

        // Force `P32 | 1` (odd ⇒ invertible) and force a non-imm8
        // value: bit 24 makes `static_cast<int32_t>(P32)` outside
        // [-128, 127] regardless of the sign bit, so `imul` always
        // takes the 6-byte `69 /r id` form. That keeps the body
        // length stable and avoids the imm8 short-form path.
        const std::uint32_t p32 =
            (rng.next_u32() | 0x01000001u);
        const std::uint64_t p_se =
            static_cast<std::uint64_t>(
                static_cast<std::int64_t>(
                    static_cast<std::int32_t>(p32)));
        const std::uint64_t inv_p = modular_inverse_u64(p_se);
        const std::uint64_t k_prime = view->imm * inv_p; // mod 2^64

        analysis::X86CodeEmitter em(/*is_64bit=*/true);
        em.mov_abs64(view->dst, k_prime);
        em.imul(view->dst, view->dst, static_cast<std::int32_t>(p32));

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

std::unique_ptr<IMbaRewriter> make_mov_imm64_modular_inverse() {
    return std::make_unique<MovImm64ModularInverseRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
