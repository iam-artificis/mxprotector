/**
 * @file sub_neg_encoder.hpp
 * @brief `lea + neg + neg + sub + jmp` encoder.
 *
 * Stub layout (15 bytes):
 *
 *     48 8D 05 <encoded_disp32>     lea rax, [rip + encoded]   (7)
 *     48 F7 D8                      neg rax                    (3)
 *     48 F7 D8                      neg rax                    (3)
 *     48 2D    <K_imm32>            sub rax, sign_ext(K)       (7)
 *
 *  total: 7+3+3+7 = 20 — header `stub_size()` carries it.
 *
 * `neg rax` followed by `neg rax` is an identity but uses three
 * bytes the disassembler must walk through, so a casual byte-
 * pattern scanner sees instructions that look meaningful. The
 * algebraic chain reduces to:
 *
 *     rax = (RIP + encoded) - K
 *  ⇒  encoded = (target - RIP_after_lea) + K
 *
 * Different opcode mix than the `add-offset` encoder — the
 * registry's random pick produces visually distinct stubs.
 */

#pragma once

#include "mxprotector/protection/anti_static/indirect_call_encoder.hpp"

namespace mx::protection::anti_static {

/**
 * @brief `lea + neg + neg + sub + jmp` encoder — see header.
 */
class SubNegEncoder final : public IIndirectCallEncoder {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "sub-neg";
    }

    [[nodiscard]] std::uint32_t stub_size() const noexcept override {
        return 22; // 7 + 3 + 3 + 7 + 2 (jmp rax)
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
