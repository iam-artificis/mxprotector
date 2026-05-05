/**
 * @file x64_pe_stub_backend.cpp
 * @brief Implementation of `X64PeStubBackend` and its factory.
 *
 * @details Forwards each `produce(kind, ...)` call to the matching
 *          `build_xxx_stub_bytes` free function and packs the result
 *          into the abstract `PackerStubResult`.
 */

#include "mxprotector/protection/packer/x64_pe_stub_backend.hpp"

#include "mxprotector/protection/packer/stub_emitter.hpp"

namespace mx::packer {

MxResult<PackerStubResult>
X64PeStubBackend::produce(PackerStubKind     kind,
                          Randomizer&        rng,
                          ByteView           stolen_bytes,
                          StubEmissionParams params)
{
    PackerStubResult result;
    result.kind = kind;

    switch (kind) {
    case PackerStubKind::exe_executable: {
        auto [bytes, patches] = build_exe_stub_bytes(
            rng, stolen_bytes,
            params.section_count,
            params.layer_count,
            params.enable_veh_trap,
            params.apply_relocs_inline);
        result.bytes   = std::move(bytes);
        result.patches = patches;
        return result;
    }
    case PackerStubKind::dll_full: {
        auto [bytes, patches] = build_dll_full_stub_bytes(
            rng, stolen_bytes,
            params.section_count,
            params.layer_count,
            params.apply_relocs_inline);
        result.bytes   = std::move(bytes);
        result.patches = patches;
        return result;
    }
    case PackerStubKind::driver: {
        auto [bytes, patches] = build_driver_stub_bytes(
            rng, stolen_bytes,
            params.section_count,
            params.layer_count,
            params.apply_relocs_inline);
        result.bytes   = std::move(bytes);
        result.patches = patches;
        return result;
    }
    case PackerStubKind::efi: {
        auto [bytes, patches] = build_efi_stub_bytes(
            rng, stolen_bytes,
            params.section_count,
            params.layer_count,
            params.apply_relocs_inline);
        result.bytes   = std::move(bytes);
        result.patches = patches;
        return result;
    }
    }
    return std::unexpected(MxError(
        ProtectionErrorCode::pass_failed,
        "X64PeStubBackend: unknown PackerStubKind"));
}

MxResult<std::unique_ptr<IPackerStubBackend>>
X64PeStubBackendFactory::create(arch::ArchInfo info,
                                target::ContainerFormat container)
{
    if (info.family != arch::ArchFamily::x64) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "X64PeStubBackendFactory: requested arch family is not x64"));
    }
    if (container != target::ContainerFormat::pe) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            "X64PeStubBackendFactory: requested container is not PE"));
    }
    return std::make_unique<X64PeStubBackend>();
}

} // namespace mx::packer
