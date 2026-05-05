/**
 * @file x64_pe_stub_backend.hpp
 * @brief PE+x64 implementation of `IPackerStubBackend`.
 *
 * @details Thin facade over the four existing stub builders
 *          (`build_exe_stub_bytes`, `build_dll_full_stub_bytes`,
 *          `build_driver_stub_bytes`, `build_efi_stub_bytes`). The
 *          class is an empty value type — every call to `produce`
 *          forwards to the right builder for the requested kind and
 *          packs the result into the abstract `PackerStubResult`.
 *
 *          A future arm64 PE backend lands as `Arm64PeStubBackend`
 *          alongside this one; an ELF x64 backend as
 *          `X64ElfStubBackend`. Each picks its own factory.
 */

#pragma once

#include <memory>

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/protection/packer/packer_stub_backend.hpp"
#include "mxprotector/target/target_info.hpp"

namespace mx::packer {

class X64PeStubBackend final : public IPackerStubBackend {
public:
    [[nodiscard]] arch::ArchInfo arch() const noexcept override {
        return arch::ArchInfo::x64_baseline();
    }

    [[nodiscard]] target::ContainerFormat container() const noexcept override {
        return target::ContainerFormat::pe;
    }

    [[nodiscard]] bool
    supports(PackerStubKind /*kind*/) const noexcept override {
        return true;  // x64 PE backend covers all four kinds.
    }

    [[nodiscard]] MxResult<PackerStubResult>
    produce(PackerStubKind     kind,
            Randomizer&        rng,
            ByteView           stolen_bytes,
            StubEmissionParams params) override;
};

/**
 * @brief Factory that produces `X64PeStubBackend`.
 */
class X64PeStubBackendFactory final : public IPackerStubBackendFactory {
public:
    [[nodiscard]] arch::ArchFamily
    supported_family() const noexcept override {
        return arch::ArchFamily::x64;
    }

    [[nodiscard]] target::ContainerFormat
    supported_container() const noexcept override {
        return target::ContainerFormat::pe;
    }

    [[nodiscard]] MxResult<std::unique_ptr<IPackerStubBackend>>
    create(arch::ArchInfo info,
           target::ContainerFormat container) override;
};

} // namespace mx::packer
