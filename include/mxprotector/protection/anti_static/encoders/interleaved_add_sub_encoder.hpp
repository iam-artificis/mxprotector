/**
 * @file interleaved_add_sub_encoder.hpp
 * @brief Mixed `add` / `sub rax, imm32` chain whose signed sum is
 *        zero, with each constant a fresh random value.
 *
 * Stub layout (37 bytes):
 *
 *     50                          push rax                    (1)
 *     48 8D 05 <std_disp32>       lea rax, [rip + std_disp]   (7)
 *     48 05    <K1>               add rax, K1                 (6)
 *     48 2D    <K2>               sub rax, K2                 (6)
 *     48 05    <K3>               add rax, K3                 (6)
 *     48 2D    <K4>               sub rax, K4                 (6)
 *           where K4 = K1 + K3 - K2  → net K1 - K2 + K3 - K4 = 0
 *     48 87 04 24                 xchg rax, [rsp]             (4)
 *     C3                          ret                         (1)
 *
 * Why this shape:
 *
 *   * Two opcode shapes (`48 05` and `48 2D`) appear interleaved,
 *     so a byte-pattern scan looking for either of the simpler
 *     "all-add" / "all-xor" chains rules this one out.
 *
 *   * `K2` and `K4` are unrelated by sign or magnitude — `K4` is
 *     a derived value but it depends on three independent inputs,
 *     so an attacker matching on `add K, sub K` (the prior
 *     `AddOffsetEncoder`) sees four unrelated immediates instead.
 *
 *   * Like the rest of the balanced encoders, the LEA's `disp32`
 *     remains the standard rel32 — `CodeReferenceScanner` keeps
 *     it in sync when chaos shuffle moves the target.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief Interleaved 4-step add/sub chain — see header.
 */
class InterleavedAddSubEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "interleaved-add-sub";
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
