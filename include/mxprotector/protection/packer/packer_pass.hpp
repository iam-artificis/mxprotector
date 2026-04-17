/**
 * @file packer_pass.hpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector.
 *
 * Encrypts every target section (`.text` + optional VM blob + CFF
 * trampoline blob) with a multi-layer RC4 cascade whose per-layer
 * 32-byte keys and 256-byte S-box scratch live inside an x64
 * self-decrypting stub. The stub is placed in a fresh `.mxpack`
 * section, the PE entry point is redirected to it, base relocations
 * are stripped, and the Import Directory is zeroed out after the
 * first decrypt pass runs. Each build draws its own per-layer keys,
 * its own anti-debug probe variant, and a per-build random TLS
 * callback that corrupts one byte of a randomly-chosen layer's key
 * on debugged hosts — so clean hosts boot normally while debuggers
 * silently see the decrypt cascade diverge into garbage.
 *
 * Pipeline priority: 800 — runs AFTER mutation / obfuscation / CFF
 * / VM so it packs every upstream transformation. The
 * implementation file (`packer_pass.cpp`) is a thin orchestrator
 * delegating to six sibling compilation units
 * (`packer_ksa_vm_lifter`, `packer_stub_artifacts`,
 * `packer_stub_patcher`, `packer_tls_finalizer`,
 * `packer_section_encryptor`, plus the shared `stub_emitter` /
 * `cipher_body` / `stolen_bytes` / `rc4` / `stub_self_hash` /
 * `tls_callback` / `veh_int3_trap` modules).
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
