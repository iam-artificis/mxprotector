/**
 * @file add_offset_encoder.hpp
 * @brief One-instruction `lea + add + jmp` encoder.
 *
 * Stub layout (15 bytes):
 *
 *     48 8D 05 <encoded_disp32>     lea rax, [rip + encoded]    (7)
 *     48 05    <K_imm32>            add rax, sign_ext(K_imm32)  (6)
 *     FF E0                         jmp rax                     (2)
 *
 * Algebraic identity at runtime:
 *
 *     rax = (RIP_after_lea + encoded) + K = target_VA
 *  ⇒  encoded = (target - RIP_after_lea) - K
 *
 * `K` is a random signed `int32`; the encoder picks a value
 * outside `[-0x10, 0x10]` so the additive transformation is at
 * least visually non-trivial and not a likely no-op.
 *
 * Static decompilers that constant-fold across `add` resolve the
 * target from the disp32 plus K — but the call-graph builder
 * pass has already committed its edges by the time folding
 * happens, so the obfuscation still hides the original direct
 * edge from the first wave of static analysis.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief `lea + add + jmp` encoder — see header.
 */
class AddOffsetEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "add-offset";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 15;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
