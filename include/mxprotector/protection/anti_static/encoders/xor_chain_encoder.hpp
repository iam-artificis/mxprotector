/**
 * @file xor_chain_encoder.hpp
 * @brief Three-step `xor + add` chain encoder.
 *
 * Stub layout (28 bytes):
 *
 *     48 8D 05 <encoded_disp32>     lea rax, [rip + encoded]   (7)
 *     48 35    <K1>                 xor rax, sign_ext(K1)      (6)
 *     48 81 C0 <K2>                 add rax, sign_ext(K2)      (7)
 *     48 35    <K3>                 xor rax, sign_ext(K3)      (6)
 *     FF E0                         jmp rax                    (2)
 *
 * The chain converts to a single algebraic offset `K`:
 *
 *     rax = (((RIP + encoded) ^ K1) + K2) ^ K3 = target
 *
 * Two of the three operations are XORs whose imm32 are picked
 * with the high bit clear so the 64-bit sign-extend is a no-op
 * on the high half — the high 32 bits of `rax` (which carry the
 * runtime image base) survive untouched.
 *
 * Solving for `encoded`:
 *
 *     encoded = ((target - K_chain - RIP_after_lea) ^ K1)
 *             where K_chain collapses the chain to a single
 *             constant — see implementation.
 *
 * Static decompilers can chase the chain symbolically and recover
 * the target, but a naïve call-graph builder that walks `call
 * rel32 → followee` no longer sees a direct edge.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief Three-step XOR/ADD chain encoder — see header.
 */
class XorChainEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-chain";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 28;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
