/**
 * @file sub_neg_encoder.hpp
 * @brief Balanced `lea + neg + neg + sub + add + jmp` encoder.
 *
 * Stub layout (31 bytes):
 *
 *     50                            push rax                  (1)
 *     48 8D 05 <std_disp32>         lea rax, [rip + std_disp] (7)
 *     48 F7 D8                      neg rax                   (3)
 *     48 F7 D8                      neg rax                   (3)
 *     48 81 E8 <K_imm32>            sub rax, K                (7)
 *     48 05    <K_imm32>            add rax, K (cancels SUB)  (6)
 *     48 87 04 24                   xchg rax, [rsp]           (4)
 *     C3                            ret                       (1)
 *
 * Two cancel-pairs — `neg`/`neg` and `sub`/`add` — make the
 * chain algebraically the identity. LEA's disp32 carries the
 * standard rel32, so `CodeReferenceScanner` keeps it in sync
 * when chaos shuffle moves the target.
 *
 * Variety axis: third opcode mix in the registry (the pair
 * `neg rax` adds opcodes that don't appear in any other shipped
 * encoder, so visual fingerprinting fails to lump all three
 * encoders into one signature).
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
        return 32; // 1 + 7 + 3 + 3 + 7 + 6 + 4 + 1 (with rax preservation)
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
