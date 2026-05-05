/**
 * @file mov_imm_xor_blind_rewriter.cpp
 * @brief `MOV r32, K` → `mov r32, A ; xor r32, A^K` blinding rewrite.
 *
 * The constant K is split into two halves via XOR with a per-site
 * random `A`. At runtime `A ^ (A ^ K) = K`, so the chain is exactly
 * equivalent to a direct `mov`. Per-site polymorphism comes from
 * `A` — two MOV-imm sites with the same target K get visibly
 * different bytes in the disassembly.
 *
 * SMT-defeat angle: the chain is trivial for a tactic that
 * symbolically evaluates the second instruction (the XOR is
 * literally `K = A ^ B`). It exists for *visual* polymorphism
 * (defeats binary diffing) and as a complementary option to the
 * stronger modular-inverse shape. The MBA adapter picks uniformly,
 * so half the sites still get the modular-inverse shape's full
 * SMT-defeat strength.
 *
 * Body shape (dst = view->dst, K = view->imm):
 *
 *   mov   dst, A             ; dst = A           (5 / 6 bytes)
 *   xor   dst, A ^ K         ; dst = A ^ (A^K) = K  (6 bytes)
 *
 * Total: 11/12 bytes — well above the 5-byte JMP rel32 redirect
 * threshold.
 */

#include "mxprotector/protection/mutation/mba/mba_rewriter_factories.hpp"

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/mba/mov_imm_decoder.hpp"

namespace mx::mutation::mba {

namespace {

class MovImmXorBlindRewriter final : public IMbaRewriter {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "mov-imm-xor-blind";
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
                "mov-imm-xor-blind: instruction not in B8+rd id form"));
        }

        // Force `A != 0` and `A != K` so neither half of the chain
        // collapses to a no-op or to the bare original constant.
        std::uint32_t a = rng.next_u32();
        if (a == 0u || a == view->imm) a ^= 0xA5A5A5A5u;
        const std::uint32_t b = a ^ view->imm;

        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        em.mov(view->dst, static_cast<std::uint64_t>(a));
        em.xor_(view->dst, static_cast<std::int32_t>(b));

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

std::unique_ptr<IMbaRewriter> make_mov_imm_xor_blind() {
    return std::make_unique<MovImmXorBlindRewriter>();
}

} // namespace factories

} // namespace mx::mutation::mba
