/**
 * @file xor_chain4_encoder.hpp
 * @brief 4-step `xor rax, imm32` chain whose constants XOR to zero.
 *
 * Stub layout (37 bytes):
 *
 *     50                          push rax                    (1)
 *     48 8D 05 <std_disp32>       lea rax, [rip + std_disp]   (7)
 *     48 35    <K1>               xor rax, K1                 (6)
 *     48 35    <K2>               xor rax, K2                 (6)
 *     48 35    <K3>               xor rax, K3                 (6)
 *     48 35    <K4>               xor rax, K4 (= K1 ^ K2 ^ K3)(6)
 *     48 87 04 24                 xchg rax, [rsp]             (4)
 *     C3                          ret                         (1)
 *
 * Why this shape:
 *
 *   * `XOR` is associative + commutative so any permutation of
 *     the four steps gives the same final value. As long as
 *     `K1 ^ K2 ^ K3 ^ K4 == 0`, the chain is the identity and
 *     the LEA's `disp32` carries the standard rel32.
 *
 *   * Like `AddChain4Encoder`, every constant is independently
 *     random — there is no visible mirror or cancel pair. A pass
 *     looking for `xor K, xor K` (the previous `XorChainEncoder`'s
 *     fingerprint) sees four unrelated immediates instead.
 *
 *   * Same opcode shape across all four steps so a byte-pattern
 *     scan cannot tell which constants are being cancelled.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief 4-step `xor rax, imm32` chain — see header.
 */
class XorChain4Encoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor-chain-4";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 37;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
