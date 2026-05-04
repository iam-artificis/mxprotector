/**
 * @file add_chain4_encoder.hpp
 * @brief 4-step `add rax, imm32` chain with constants chosen so
 *        their signed sum is exactly zero.
 *
 * Stub layout (37 bytes):
 *
 *     50                          push rax                    (1)
 *     48 8D 05 <std_disp32>       lea rax, [rip + std_disp]   (7)
 *     48 05    <K1>               add rax, K1                 (6)
 *     48 05    <K2>               add rax, K2                 (6)
 *     48 05    <K3>               add rax, K3                 (6)
 *     48 05    <K4>               add rax, K4 (= -K1-K2-K3)   (6)
 *     48 87 04 24                 xchg rax, [rsp]             (4)
 *     C3                          ret                         (1)
 *
 * Why this shape:
 *
 *   * Algebraically the chain is the identity (`K1+K2+K3+K4=0`),
 *     so the LEA's `disp32` carries the standard rel32 the
 *     `CodeReferenceScanner` already keeps in sync.
 *
 *   * **No visible mirror** — every constant is a fresh random
 *     value. A reverse-engineering pass that pattern-matches on
 *     `add K, sub K` (the previous encoders' tell) sees four
 *     unrelated `add` immediates instead. Constant-folding the
 *     chain still recovers the target, but only after the engine
 *     proves all four constants sum to zero.
 *
 *   * **Single opcode shape** — every step is the same `48 05`
 *     short-`add rax, imm32` encoding, so a byte-pattern matcher
 *     looking for "add/sub pairs" sees only adds. Differentiates
 *     this encoder from the cancel-pair shapes in the other
 *     encoders.
 *
 * Future non-balanced variants will compose this encoder with the
 * existing `rel32_with_imm_offset` reference encoding.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief 4-step `add rax, imm32` chain — see header.
 */
class AddChain4Encoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-chain-4";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 37;  // 1 + 7 + 4*6 + 4 + 1
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
