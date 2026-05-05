/**
 * @file mov_imm_emit.cpp
 * @brief Implementation — see header.
 *
 * Each step function follows the same skeleton:
 *
 *   1. Sample shape parameters from `rng` (P, A, n).
 *   2. Compute the *leading immediate* — what the inner mov has to
 *      materialise so the finalizer recovers `K`.
 *   3. Hand off to `inner(em, dst, leading_imm, rng)` for the mov.
 *      For single-layer rewrites this is `direct_mov_imm32`; for
 *      deep-chain rewrites the caller plugs in another shape's
 *      step function so the leading immediate becomes another MBA
 *      expansion in its own right.
 *   4. Emit the finalizer (imul / xor / rol).
 */

#include "mxprotector/protection/mutation/mba/mov_imm_emit.hpp"

#include <cstdint>

namespace mx::mutation::mba {

namespace {

/// 32-bit modular inverse of an odd value via Newton-Hensel.
/// Doubles correct bits per iteration; five iterations cover all
/// 32 bits. Pre-condition: `value & 1 == 1`.
[[nodiscard]] constexpr std::uint32_t modular_inverse_u32(
    std::uint32_t value) noexcept
{
    std::uint32_t inverse = value; // matches at the low 3 bits
    for (int i = 0; i < 5; ++i) {
        inverse = inverse * (2u - value * inverse);
    }
    return inverse;
}

/// Rotate `value` right by `count` bits (count in [1, 31]).
[[nodiscard]] constexpr std::uint32_t ror32(
    std::uint32_t value, std::uint8_t count) noexcept
{
    return (value >> count) | (value << (32u - count));
}

} // namespace

void direct_mov_imm32(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             imm,
    Randomizer&               /*rng*/)
{
    em.mov(dst, static_cast<std::uint64_t>(imm));
}

void emit_modular_inverse_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner)
{
    // Pick an odd `P` so `inv(P) mod 2^32` exists. Bit 0 forced to
    // 1 for invertibility; every other bit is fully random.
    const std::uint32_t p = (rng.next_u32() | 1u);
    const std::uint32_t inv_p = modular_inverse_u32(p);
    const std::uint32_t k_prime =
        static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(k) *
            static_cast<std::uint64_t>(inv_p));

    inner(em, dst, k_prime, rng);
    em.imul(dst, dst, static_cast<std::int32_t>(p));
}

void emit_xor_blind_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner)
{
    // Force `A != 0` and `A != K` so neither half of the chain
    // collapses to a no-op or to the bare original constant.
    std::uint32_t a = rng.next_u32();
    if (a == 0u || a == k) a ^= 0xA5A5A5A5u;
    const std::uint32_t b = a ^ k;

    inner(em, dst, a, rng);
    em.xor_(dst, static_cast<std::int32_t>(b));
}

void emit_rotate_blind_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner)
{
    // Random rotation count in [1, 31]. A count of 0 would collapse
    // the chain to the bare mov; 32 is UB for 32-bit shifts.
    const auto count = static_cast<std::uint8_t>(
        rng.next_range(1u, 31u));
    const std::uint32_t rotated = ror32(k, count);

    inner(em, dst, rotated, rng);
    em.rol(dst, count);
}

void emit_modular_inverse(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng)
{
    emit_modular_inverse_step(em, dst, k, rng);
}

void emit_xor_blind(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng)
{
    emit_xor_blind_step(em, dst, k, rng);
}

void emit_rotate_blind(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng)
{
    emit_rotate_blind_step(em, dst, k, rng);
}

} // namespace mx::mutation::mba
