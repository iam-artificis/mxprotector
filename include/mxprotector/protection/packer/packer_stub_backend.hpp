/**
 * @file packer_stub_backend.hpp
 * @brief Abstract packer stub-assembly backend — one impl per
 *        (container × architecture) pair.
 *
 * @details Today's packer assembles its self-unpacking stub through
 *          four shape-specific free functions
 *          (`build_exe_stub_bytes`, `build_dll_full_stub_bytes`,
 *          `build_driver_stub_bytes`, `build_efi_stub_bytes`) that
 *          all hard-code PE+x64 byte emission. That's fine while x64
 *          is the only target; less fine when arm64 PE or ELF lands.
 *
 *          `IPackerStubBackend` is the seam for that future work. It
 *          declares an arch-agnostic, container-agnostic contract:
 *          "given a stub kind + emission params + stolen bytes,
 *          produce the stub buffer and its patch descriptor". A future
 *          arm64 backend lands as a sibling impl; the packer pipeline
 *          picks the right one through `IPackerStubBackendFactory`.
 *
 *          **Status:** seam declared, `X64PeStubBackend` is the only
 *          impl and ships in this branch. Today's `PackerPass` still
 *          calls the four free functions directly — migrating it to
 *          consume `IPackerStubBackend` is intentionally deferred to
 *          a follow-up branch (it touches lots of call paths and the
 *          existing static_assert + concept story is already
 *          type-safe). What R8.4 ships is the contract that future
 *          arm64 / ELF stub backends will plug into.
 *
 *          The result variant is shape-typed: `ExeStubPatches`,
 *          `DllFullStubPatches`, `DriverStubPatches`, `EfiStubPatches`.
 *          A pattern-matching consumer reads the right field by stub
 *          kind. Backends that don't support a particular kind (e.g.
 *          a future bare-metal backend rejecting `efi`) return a
 *          `pass_failed` MxStatus.
 */

#pragma once

#include <memory>
#include <utility>
#include <variant>

#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"
#include "mxprotector/target/target_info.hpp"

namespace mx::packer {

/**
 * @brief Stub kind selector.
 *
 * Drives both the stub layout (which prologue / epilogue, which
 * cipher body) and which `XxxStubPatches` variant the result carries.
 */
enum class PackerStubKind : uint8_t {
    exe_executable = 0,  ///< User-mode EXE. Win32 IAT, Hell's Gate, optional VEH.
    dll_full       = 1,  ///< Full-DLL stub (DllMain wrapper).
    driver         = 2,  ///< Kernel-mode .sys (DriverEntry wrapper).
    efi            = 3,  ///< UEFI application / runtime driver.
};

/**
 * @brief Variant holding the patches struct for whichever stub kind
 *        was produced.
 *
 * Kept in shape-stable order matching `PackerStubKind` so callers can
 * `std::visit` or `std::get_if` by index when convenient.
 */
using PackerStubPatches = std::variant<
    ExeStubPatches,
    DllFullStubPatches,
    DriverStubPatches,
    EfiStubPatches>;

/**
 * @brief Result of a single stub production: bytes + patch descriptor.
 */
struct PackerStubResult {
    ByteBuffer        bytes;     ///< Pre-patch stub buffer.
    PackerStubPatches patches;   ///< Shape-typed patch descriptor.
    PackerStubKind    kind = PackerStubKind::exe_executable;
};

/**
 * @brief Abstract packer stub backend.
 *
 * One impl per (container × architecture) pair. Today only
 * `X64PeStubBackend` exists. The interface is small on purpose:
 * arch-specific decisions (register layout, push/pop encoding,
 * cipher body bytes) live entirely inside the impl; container-
 * specific decisions (which prologue, which patches set) live
 * inside the impl too. Callers select the kind and feed parameters.
 *
 * Thread-safety: one instance per pipeline, single-threaded use.
 */
class IPackerStubBackend {
public:
    virtual ~IPackerStubBackend() = default;

    /// @brief Architecture this backend produces stubs for.
    [[nodiscard]] virtual arch::ArchInfo arch() const noexcept = 0;

    /// @brief Container format this backend produces stubs for.
    [[nodiscard]] virtual target::ContainerFormat
        container() const noexcept = 0;

    /// @brief Whether this backend can produce a stub of the given kind.
    /// `produce(kind, ...)` may still fail for other reasons; this
    /// answers the static "is this kind even on the menu" question.
    [[nodiscard]] virtual bool
        supports(PackerStubKind kind) const noexcept = 0;

    /// @brief Produce a stub of the given kind.
    /// @return The stub buffer + its patch descriptor on success;
    ///         `MxError(pass_failed)` if `kind` isn't supported.
    [[nodiscard]] virtual MxResult<PackerStubResult>
        produce(PackerStubKind     kind,
                Randomizer&        rng,
                ByteView           stolen_bytes,
                StubEmissionParams params) = 0;
};

/**
 * @brief Factory selector — picks the backend for a (container, arch)
 *        pair.
 */
class IPackerStubBackendFactory {
public:
    virtual ~IPackerStubBackendFactory() = default;

    /// @brief Architecture family this factory can produce backends for.
    [[nodiscard]] virtual arch::ArchFamily
        supported_family() const noexcept = 0;

    /// @brief Container format this factory can produce backends for.
    [[nodiscard]] virtual target::ContainerFormat
        supported_container() const noexcept = 0;

    /// @brief Construct a backend. Returns `pass_failed` on mismatch.
    [[nodiscard]] virtual MxResult<std::unique_ptr<IPackerStubBackend>>
        create(arch::ArchInfo info,
               target::ContainerFormat container) = 0;
};

} // namespace mx::packer
