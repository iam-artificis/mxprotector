/**
 * @file packer_pass.hpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector.
 *
 * Encrypts the `.text` section (and optionally `.rdata`) with a stream cipher
 * whose per-build key is embedded inside an x64 decryption stub. The stub is
 * placed in a fresh `.mxpack` section, the PE entry point is redirected to
 * the stub, and the loader's relocation pass is disabled so the encrypted
 * bytes are not fixed up between build time and runtime.
 *
 * Pipeline priority: 800 — runs AFTER mutation / obfuscation / CFF / VM so
 * it packs every transformation.
 */

#pragma once

#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/pass.hpp"

namespace mx {

class ProtectionContext;

class PackerPass final : public IProtectionPass {
public:
    PackerPass() = default;
    ~PackerPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "PackerPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::packing;
    }

    [[nodiscard]] uint32_t priority() const noexcept override {
        return 800;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;
    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
