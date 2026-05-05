/**
 * @file mov_imm_rotate_blind_rewriter.cpp
 * @brief `MOV r32, K` → `mov r32, ror(K, n) ; rol r32, n` rotation rewrite.
 *
 * Rotation blinding: pre-rotate the immediate right by `n` bits
 * (1..31) at build time, then rotate left by `n` at runtime to
 * recover `K`. Per-site polymorphism comes from `n` — two MOV-imm
 * sites with the same target K get visibly different bytes (different
 * pre-rotated immediates AND a different rotation count).
 *
 * Why this shape complements the others: the body emits a `rol`
 * (`C1 /0 ib`) — an opcode neither the modular-inverse nor the
 * xor-blind shape uses. That widens the per-site instruction
 * vocabulary, defeating frequency-pattern matching that keys on
 * specific opcodes (e.g. tools that flag every IMUL as "suspicious
 * obfuscation").
 *
 * Body shape (dst = view->dst, K = view->imm, n = 1..31):
 *
 *   mov   dst, ror(K, n)    ; dst = K rotated right by n
 *   rol   dst, n            ; dst = K
 *
 * Total: 8/9 bytes — above the 5-byte JMP rel32 redirect threshold.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

namespace {

/// Rotate `value` right by `count` bits (count in [1, 31]).
/// `(value >> count) | (value << (32 - count))` is the canonical
/// 32-bit ROR. Pre-condition `count != 0` keeps the shift count in
/// the well-defined [1, 31] range — a 32-bit shift by 32 is UB on
/// some compilers.
[[nodiscard]] constexpr std::uint32_t ror32(
    std::uint32_t value, std::uint8_t count) noexcept
{
    return (value >> count) | (value << (32u - count));
}

class MovImmRotateBlindRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-rotate-blind";
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
                "mov-imm-rotate-blind: instruction not in B8+rd id form"));
        }

        // Random rotation count in [1, 31]. A count of 0 would
        // collapse the chain to the bare `mov`; 32 is UB for
        // 32-bit shifts.
        const auto count = static_cast<std::uint8_t>(
            rng.next_range(1u, 31u));
        const std::uint32_t rotated = ror32(view->imm, count);

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        em.mov(view->dst, static_cast<std::uint64_t>(rotated));
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

std::unique_ptr<IMbaRewriter> make_mov_imm_rotate_blind() {
    return std::make_unique<MovImmRotateBlindRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
