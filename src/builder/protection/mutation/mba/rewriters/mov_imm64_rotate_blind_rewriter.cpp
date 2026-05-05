/**
 * @file mov_imm64_rotate_blind_rewriter.cpp
 * @brief `MOV r64, K` → `mov r64, ror64(K, n) ; rol r64, n` blinding rewrite.
 *
 * 64-bit twin of `mov_imm_rotate_blind_rewriter`. Rotation blinding:
 * pre-rotate the 64-bit immediate right by `n` bits (in [1, 63]) at
 * build time, then rotate left by `n` at runtime to recover `K`.
 *
 * Per-site polymorphism comes from `n` and the resulting pre-rotated
 * immediate — two MOV-imm64 sites with the same target `K` get
 * visibly different bytes (different rotated immediates AND a
 * different rotation count). The rotation count is masked to 6 bits
 * by hardware (per Intel SDM for 64-bit-operand shifts/rotates), so
 * the natural range is [1, 63] — `n = 0` would collapse the chain
 * to the bare mov (no defeat upside).
 *
 * Why this shape complements the others: the body emits a `rol`
 * (`REX.W C1 /0 ib`) — an opcode neither the 64-bit modular-inverse
 * nor the xor-blind shape uses. That widens the per-site
 * instruction vocabulary, defeating frequency-pattern matching that
 * keys on specific opcodes (e.g. tools that flag every IMUL as
 * "suspicious obfuscation").
 *
 * Body shape (dst = view->dst, K = view->imm 64-bit, n = 1..63):
 *
 *   mov   dst, ror64(K, n)       ; dst = K rotated right by n   (10)
 *   rol   dst, n                 ; dst = K                       (4)
 *
 * Total: 14 bytes — well above the JMP rel32 redirect threshold.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

namespace {

/// Rotate `value` right by `count` bits (count in [1, 63]).
/// Pre-condition `count != 0` keeps the shift count in the
/// well-defined [1, 63] range — a 64-bit shift by 64 is UB.
[[nodiscard]] constexpr std::uint64_t ror64(
    std::uint64_t value, std::uint8_t count) noexcept
{
    return (value >> count) | (value << (64u - count));
}

class MovImm64RotateBlindRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm64-rotate-blind";
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
                "mov-imm64-rotate-blind: instruction not in REX.W B8+rd iq form"));
        }

        // Random rotation count in [1, 63]. A count of 0 would
        // collapse the chain to the bare `mov`; 64 is UB for a
        // 64-bit shift.
        const auto count = static_cast<std::uint8_t>(
            rng.next_range(1u, 63u));
        const std::uint64_t rotated = ror64(view->imm, count);

        analysis::X86CodeEmitter em(/*is_64bit=*/true);
        em.mov_abs64(view->dst, rotated);
        em.rol(view->dst, count);

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

std::unique_ptr<IMbaRewriter> make_mov_imm64_rotate_blind() {
    return std::make_unique<MovImm64RotateBlindRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
