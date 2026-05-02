/**
 * @file target_info.hpp
 * @brief Target platform descriptor (OS × container × architecture).
 *
 * MxProtector currently only produces Windows PE x64 binaries, but the whole
 * pipeline is being laid out so that other targets can be plugged in later:
 *
 *     Windows PE x64     (native — full support)
 *     Linux   ELF x64    (planned — primary secondary target)
 *     Linux   ELF arm64  (planned — secondary)
 *     macOS   Mach-O     (planned — tertiary)
 *
 * `TargetInfo` is the single enum-ish value that everyone uses to decide
 * whether a given pass, helper, or runtime feature applies to the target
 * currently being built. It is intentionally small and POD-like: pass it by
 * value, compare with the factory helpers, never subclass it.
 *
 * Architectural conventions
 * -------------------------
 *   - A *pass* that works on any target (e.g. generic mutation over raw
 *     bytes with a lifter) checks nothing — it just operates on
 *     `IBinaryImage` (see `binary_image.hpp`).
 *   - A *pass* that only works on Windows PE (e.g. the current `PackerPass`
 *     which emits a PE-style self-unpacking stub) guards its
 *     `is_applicable()` with `ctx.target().is_windows_pe()`.
 *   - A *helper* that encodes machine code (e.g. the VM runtime generator)
 *     uses an architecture-specific encoder selected by `TargetInfo::arch`.
 *     Today only x86/x64 exists; arm64 is a future extension point.
 *
 * The pipeline never assumes PE at its top level — only individual passes do,
 * and they opt in explicitly.
 */

#pragma once

#include <cstdint>

namespace mx::target {

/// Host operating system of the target binary.
enum class Os : uint8_t {
    windows  = 0,
    linux_   = 1,   ///< Trailing underscore: `linux` is a common predefined macro.
    macos    = 2,
    freebsd  = 3,
    unknown  = 0xFF,
};

/// Container format — how the OS loader parses the file on disk.
enum class ContainerFormat : uint8_t {
    pe     = 0,   ///< Windows PE (EXE / DLL / SYS)
    elf    = 1,   ///< Linux / *BSD ELF
    macho  = 2,   ///< macOS Mach-O
    unknown = 0xFF,
};

/// Instruction-set architecture of the target binary.
enum class Arch : uint8_t {
    x64    = 0,
    x86    = 1,
    arm64  = 2,
    unknown = 0xFF,
};

/// Role the binary plays at runtime. Cross-platform by design:
///
///   `executable`      — Windows EXE / ELF executable / stand-alone binary.
///   `dynamic_library` — Windows DLL / ELF .so / Mach-O .dylib.
///   `kernel_driver`   — Windows .sys / Linux .ko / macOS .kext.
///   `efi_application` — UEFI binary (subsystems 10..13). Shares no
///                       runtime infrastructure with Win32 user-mode:
///                       no PEB, no IAT, no VEH, no TLS callbacks.
///                       Treat as fundamentally distinct from
///                       `executable` — most user-mode passes
///                       (Hell's Gate, anti-debug, VEH guard) MUST
///                       be gated off for it.
///
/// This is derived from the input binary at parse time (e.g. PE
/// `Subsystem==NATIVE` → `kernel_driver`, `Subsystem ∈ 10..13` →
/// `efi_application`). Passes that are only valid for a subset of
/// kinds (user-mode VEH, ntdll imports, ...) must gate on the
/// predicate form — prefer `is_user_mode()` / `is_kernel_driver()` /
/// `is_efi_application()` over raw enum comparisons.
enum class BinaryKind : uint8_t {
    executable      = 0,
    dynamic_library = 1,
    kernel_driver   = 2,
    efi_application = 3,
    unknown         = 0xFF,
};

/// How the protected binary will reach its entry point at runtime.
///
///   `os_loaded`     — The platform image loader runs before the stub:
///                     imports resolved, base relocations applied, TLS
///                     callbacks invoked. Default for ordinary EXEs /
///                     DLLs / OS-installed drivers.
///   `manual_mapped` — A third-party mapper dropped the image into
///                     memory and jumped to its entry. Nothing the OS
///                     loader usually does is guaranteed: the stub must
///                     not rely on a populated IAT, applied relocations,
///                     or auto-invoked TLS callbacks. Used by kdmapper
///                     (kernel drivers) and manual DLL injectors.
///
/// Unlike `os/container/arch` this cannot be detected from the file —
/// it's a *deployment* choice the user tells us via `--load-mode`.
enum class LoadMode : uint8_t {
    os_loaded      = 0,
    manual_mapped  = 1,
};

/**
 * @brief Immutable descriptor of the target platform for one build.
 *
 * Passes consult this via `ProtectionContext::target()`. It is set once in
 * `main()` after the binary has been parsed (so OS/container/arch are derived
 * from the actual file, not guessed).
 */
struct TargetInfo {
    Os              os;
    ContainerFormat container;
    Arch            arch;
    BinaryKind      kind       = BinaryKind::executable;  ///< EXE / DLL / SYS role.
    LoadMode        load_mode  = LoadMode::os_loaded;     ///< User-driven (CLI).

    // ------------------------------------------------------------------------
    // Factory helpers — spell out the exact target you care about.
    // ------------------------------------------------------------------------

    [[nodiscard]] static constexpr TargetInfo windows_pe_x64() noexcept {
        return {Os::windows, ContainerFormat::pe, Arch::x64};
    }
    [[nodiscard]] static constexpr TargetInfo linux_elf_x64() noexcept {
        return {Os::linux_, ContainerFormat::elf, Arch::x64};
    }
    [[nodiscard]] static constexpr TargetInfo linux_elf_arm64() noexcept {
        return {Os::linux_, ContainerFormat::elf, Arch::arm64};
    }
    [[nodiscard]] static constexpr TargetInfo macos_macho_x64() noexcept {
        return {Os::macos, ContainerFormat::macho, Arch::x64};
    }
    [[nodiscard]] static constexpr TargetInfo macos_macho_arm64() noexcept {
        return {Os::macos, ContainerFormat::macho, Arch::arm64};
    }
    [[nodiscard]] static constexpr TargetInfo unknown_target() noexcept {
        return {Os::unknown, ContainerFormat::unknown, Arch::unknown};
    }

    // ------------------------------------------------------------------------
    // Predicates — prefer these over raw enum comparisons at call sites.
    // ------------------------------------------------------------------------

    [[nodiscard]] constexpr bool is_windows() const noexcept { return os == Os::windows; }
    [[nodiscard]] constexpr bool is_linux()   const noexcept { return os == Os::linux_;  }
    [[nodiscard]] constexpr bool is_macos()   const noexcept { return os == Os::macos;   }

    [[nodiscard]] constexpr bool is_pe()    const noexcept { return container == ContainerFormat::pe;    }
    [[nodiscard]] constexpr bool is_elf()   const noexcept { return container == ContainerFormat::elf;   }
    [[nodiscard]] constexpr bool is_macho() const noexcept { return container == ContainerFormat::macho; }

    [[nodiscard]] constexpr bool is_x64()   const noexcept { return arch == Arch::x64;   }
    [[nodiscard]] constexpr bool is_x86()   const noexcept { return arch == Arch::x86;   }
    [[nodiscard]] constexpr bool is_arm64() const noexcept { return arch == Arch::arm64; }

    /// @brief True iff this is the currently fully-supported build target.
    [[nodiscard]] constexpr bool is_windows_pe_x64() const noexcept {
        return is_windows() && is_pe() && is_x64();
    }

    // ------------------------------------------------------------------------
    // Binary-kind predicates — cheap, readable gates for passes that care.
    // ------------------------------------------------------------------------

    [[nodiscard]] constexpr bool is_executable()      const noexcept { return kind == BinaryKind::executable;      }
    [[nodiscard]] constexpr bool is_dynamic_library() const noexcept { return kind == BinaryKind::dynamic_library; }
    [[nodiscard]] constexpr bool is_kernel_driver()   const noexcept { return kind == BinaryKind::kernel_driver;   }
    [[nodiscard]] constexpr bool is_efi_application() const noexcept { return kind == BinaryKind::efi_application; }

    /// True iff this binary lives in the UEFI environment.
    ///
    /// Today there is a single `efi_application` variant covering all
    /// four UEFI subsystems (EFI_APPLICATION / BOOT_SERVICE_DRIVER /
    /// RUNTIME_DRIVER / ROM); they share the "no Win32 infra" property
    /// any pass actually cares about. If we ever need finer-grained
    /// gating, split the enum and update this helper.
    [[nodiscard]] constexpr bool is_efi() const noexcept {
        return is_efi_application();
    }

    /// True for Win32 user-mode targets (EXE / DLL). False for
    /// kernel drivers, UEFI binaries, and `unknown`. Intended for
    /// passes that assume the target runs with a user-mode PEB /
    /// IAT / VEH / TLS-callback dispatcher (Hell's Gate, anti-debug
    /// probes, the VEH guard, the user-mode packer stub).
    [[nodiscard]] constexpr bool is_user_mode() const noexcept {
        return is_executable() || is_dynamic_library();
    }

    // ------------------------------------------------------------------------
    // Load-mode predicates — whether the OS loader ran before our stub.
    // ------------------------------------------------------------------------

    [[nodiscard]] constexpr bool is_os_loaded()      const noexcept { return load_mode == LoadMode::os_loaded;     }
    [[nodiscard]] constexpr bool is_manually_mapped() const noexcept { return load_mode == LoadMode::manual_mapped; }

    [[nodiscard]] constexpr bool operator==(const TargetInfo&) const noexcept = default;
};

/// Human-readable name of the OS, for logs/CLI output.
[[nodiscard]] constexpr const char* os_name(Os os) noexcept {
    switch (os) {
        case Os::windows: return "Windows";
        case Os::linux_:  return "Linux";
        case Os::macos:   return "macOS";
        case Os::freebsd: return "FreeBSD";
        case Os::unknown: return "unknown";
    }
    return "?";
}

/// Human-readable name of the container, for logs/CLI output.
[[nodiscard]] constexpr const char* container_name(ContainerFormat fmt) noexcept {
    switch (fmt) {
        case ContainerFormat::pe:     return "PE";
        case ContainerFormat::elf:    return "ELF";
        case ContainerFormat::macho:  return "Mach-O";
        case ContainerFormat::unknown:return "unknown";
    }
    return "?";
}

/// Human-readable name of the architecture, for logs/CLI output.
[[nodiscard]] constexpr const char* arch_name(Arch arch) noexcept {
    switch (arch) {
        case Arch::x64:     return "x86_64";
        case Arch::x86:     return "x86";
        case Arch::arm64:   return "arm64";
        case Arch::unknown: return "unknown";
    }
    return "?";
}

/// Human-readable name of the binary kind, for logs/CLI output.
[[nodiscard]] constexpr const char* binary_kind_name(BinaryKind k) noexcept {
    switch (k) {
        case BinaryKind::executable:      return "executable";
        case BinaryKind::dynamic_library: return "dynamic_library";
        case BinaryKind::kernel_driver:   return "kernel_driver";
        case BinaryKind::efi_application: return "efi_application";
        case BinaryKind::unknown:         return "unknown";
    }
    return "?";
}

/// Human-readable name of the load mode, for logs/CLI output.
[[nodiscard]] constexpr const char* load_mode_name(LoadMode m) noexcept {
    switch (m) {
        case LoadMode::os_loaded:     return "os_loaded";
        case LoadMode::manual_mapped: return "manual_mapped";
    }
    return "?";
}

} // namespace mx::target
