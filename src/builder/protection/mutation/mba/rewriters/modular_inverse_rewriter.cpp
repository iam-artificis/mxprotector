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

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"

namespace mx::mutation::mba {

namespace {

/// 32-bit modular inverse of an odd value via the Newton-Hensel
/// recursion. Doubles the number of correct bits per iteration;
/// six iterations cover all 32 bits. Pre-condition: `value & 1 == 1`.
[[nodiscard]] constexpr std::uint32_t modular_inverse_u32(
    std::uint32_t value) noexcept
{
    std::uint32_t inverse = value; // matches at the low 3 bits
    for (int i = 0; i < 5; ++i) {
        inverse = inverse * (2u - value * inverse);
    }
    return inverse;
}

/// Decoded view of `[REX.B] B8+rd id` (`mov r32, imm32`).
struct MovR32Imm32View {
    x86::Reg      dst;
    std::uint32_t imm;
};

[[nodiscard]] std::optional<MovR32Imm32View> decode_mov_r32_imm32(
    const analysis::Instruction& insn) noexcept
{
    const auto bytes = insn.raw_bytes();
    if (bytes.size() < 5) return std::nullopt;

    std::size_t cursor = 0;
    if (x86::is_legacy_prefix(bytes[cursor])) return std::nullopt;

    bool rex_b = false;
    if (x86::is_rex(bytes[cursor])) {
        // REX.W means the encoding becomes `48 C7 C0 id` — out of
        // scope. Only accept REX with W=0 (extended low-3-bit
        // register) here.
        if (x86::rex_w(bytes[cursor])) return std::nullopt;
        rex_b = x86::rex_b(bytes[cursor]);
        ++cursor;
    }

    if (cursor >= bytes.size()) return std::nullopt;
    const std::uint8_t op = bytes[cursor];
    if (op < 0xB8 || op > 0xBF) return std::nullopt;
    ++cursor;

    if (cursor + 4 > bytes.size()) return std::nullopt;

    std::uint32_t imm = 0;
    for (std::uint8_t i = 0; i < 4; ++i) {
        imm |= static_cast<std::uint32_t>(bytes[cursor + i]) << (i * 8);
    }
    if (imm == 0) return std::nullopt; // zeroing is a different idiom

    std::uint8_t reg_id = static_cast<std::uint8_t>(op - 0xB8);
    if (rex_b) reg_id |= 0x08;

    MovR32Imm32View view{};
    view.dst = static_cast<x86::Reg>(reg_id);
    view.imm = imm;
    return view;
}

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

        // Pick an odd `P` so `inv(P) mod 2^32` exists. The lowest
        // bit forced to 1 — every other bit is fully random.
        const std::uint32_t p =
            (rng.next_u32() | 1u);
        const std::uint32_t inv_p = modular_inverse_u32(p);
        const std::uint32_t k_prime =
            static_cast<std::uint32_t>(
                static_cast<std::uint64_t>(view->imm) *
                static_cast<std::uint64_t>(inv_p));

        // Run the body in 32-bit operand-size mode so the high 32
        // bits of `view->dst` get zero-extended exactly like the
        // original `mov r32, imm32` does.
        analysis::X86CodeEmitter em(/*is_64bit=*/false);
        em.mov(view->dst, static_cast<std::uint64_t>(k_prime));
        em.imul(view->dst, view->dst, static_cast<std::int32_t>(p));

        auto code = em.build();
        if (!code) return std::unexpected(code.error());

        MbaRewriteResult result;
        result.bytes             = std::move(*code);
        result.instruction_count = 2;
        return result;
    }
};

} // namespace

void register_modular_inverse_rewriters(MbaRewriterRegistry& registry) {
    registry.register_rewriter(std::make_unique<ModularInverseRewriter>());
}

} // namespace mx::mutation::mba
