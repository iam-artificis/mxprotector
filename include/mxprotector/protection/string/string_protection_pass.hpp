/**
 * @file string_protection_pass.hpp
 * @brief [BUILDER] StringProtectionPass — S2 orchestrator.
 *
 * Fifth and final stage of the S2 pipeline. Assembles the `.mxstr`
 * section from the building blocks produced by the leaf modules:
 *
 *   scanner      → printable-ASCII candidates in `.rdata`
 *   xref finder  → `LEA reg, [rip+disp32]` xrefs in executable sections
 *   encryptor    → per-string XOR ciphertexts
 *   codegen      → `mx_str_get` + per-xref trampolines
 *
 * Section layout (emitted back-to-back):
 *
 *   [0x000] mx_str_get         (shared decryptor, ~66 bytes)
 *   [    ] trampoline 0        (one per LEA xref, ~38-40 bytes each)
 *   [    ] trampoline 1
 *   [    ] ...
 *   [    ] descriptor table    (8 bytes per protected string)
 *   [    ] encrypted data pool (back-to-back ciphertext)
 *
 * Patching work done by the pass after adding the section:
 *
 *   1. The two `lea rip+disp32` slots inside `mx_str_get` that point
 *      at the descriptor table and the data pool — rewritten from
 *      zero to the actual disp32 now that both RVAs are known.
 *   2. The `call rel32` operand inside each trampoline — rewritten
 *      so the call lands on `mx_str_get`.
 *   3. Each LEA site in the target binary — overwritten with
 *      `call rel32 <trampoline>` + NOP padding so the destination
 *      register ends up holding the decrypted pointer just as the
 *      original LEA would have.
 *
 * String selection is conservative. A candidate must satisfy:
 *
 *   - At least one LEA xref was found.
 *   - No base relocation entry targets any byte inside the string.
 *     If a data pointer exists (static init array, vtable, RTTI
 *     string ref) the string is excluded so overwriting its bytes
 *     can't break a non-code consumer.
 *
 * Priority 500 — runs after mutation (100), obfuscation (200),
 * VM (300) and CFF flattening (400), and before the packer (800)
 * so the packer encrypts the finished `.mxstr` section along with
 * `.text`. The string section is added to the packer's target list
 * inside `collect_target_sections`.
 */

#pragma once

#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

class StringProtectionPass final : public IProtectionPass {
public:
    StringProtectionPass() = default;
    ~StringProtectionPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "StringProtectionPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::encryption;
    }

    [[nodiscard]] uint32_t priority() const noexcept override {
        return 500;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
