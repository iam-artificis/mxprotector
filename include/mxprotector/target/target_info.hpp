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

} // namespace mx::target
