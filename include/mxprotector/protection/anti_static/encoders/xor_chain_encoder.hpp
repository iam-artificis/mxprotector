/**
 * @file xor_chain_encoder.hpp
 * @brief Balanced four-step `xor / add / sub / xor` chain.
 *
 * Stub layout (38 bytes):
 *
 *     50                            push rax                   (1)
 *     48 8D 05 <std_disp32>         lea rax, [rip + std_disp]  (7)
 *     48 35    <K_xor>              xor rax, K_xor             (6)
 *     48 81 C0 <K_add>              add rax, K_add             (7)
 *     48 81 E8 <K_add>              sub rax, K_add (cancels)   (7)
 *     48 35    <K_xor>              xor rax, K_xor (cancels)   (6)
 *     48 87 04 24                   xchg rax, [rsp]            (4)
 *     C3                            ret                        (1)
 *
 * The XOR pair and the ADD/SUB pair both cancel — the chain is
 * algebraically the identity. The LEA's `disp32` is therefore the
 * standard rel32 displacement, and `CodeReferenceScanner` keeps
 * it in sync when chaos shuffle moves the target.
 *
 * Variety axis vs `AddOffsetEncoder`:
 *
 *   * Different opcode mix (XOR involved → different first-byte
 *     prefix in instruction bytes).
 *   * Two random per-stub constants instead of one.
 *   * Different stub size, so back-to-back stubs in the
 *     `.callstub` section break any "stride-N" pattern matcher.
 *
 * Sophisticated decompilers will fold the cancel; future
 * non-balanced encoders will go through the
 * `rel32_with_imm_offset` reference encoding to defeat them.
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
        return 39;
    }

    [[nodiscard]] EncodedStub emit(
        Rva         stub_rva,
        Rva         target_rva,
        Randomizer& rng) const override;
};

} // namespace mx::protection::anti_static
