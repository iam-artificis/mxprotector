/**
 * @file binary_image.hpp
 * @brief Abstract binary-image interface for cross-platform MxProtector.
 *
 * Today everything downstream of `ProtectionContext` talks to a concrete
 * `mx::PeImage`. That's fine while PE is the only target, but makes it
 * painful to bolt on Linux/ELF or macOS/Mach-O later.
 *
 * `IBinaryImage` is the seam we want to grow into. It describes *just* the
 * binary-image operations every protection pass needs, expressed in terms
 * that apply to PE, ELF and Mach-O alike:
 *
 *   - load-time layout (image base, entry point)
 *   - a list of sections the pass can read, write, add or remove
 *   - a way to report the target OS / container / architecture
 *
 * What is *not* here on purpose:
 *
 *   - anything PE-specific (import directory, TLS directory, rich header)
 *   - anything ELF-specific (program headers, dynamic tags)
 *   - raw byte layout of the container (that is the job of the parser /
 *     builder, not of the in-memory image)
 *
 * Platform-specific bits live behind narrower interfaces
 * (`IImportTable`, `IRelocationTable`, `IRuntimeLoader`, ...) that callers
 * fetch via a capability query. That keeps the core interface small and
 * keeps passes from accidentally coupling to a single container format.
 *
 * ## Adoption plan
 *
 * This file is a **design sketch** at the moment — the interface is
 * declared, but no concrete class implements it yet. Migration is phased:
 *
 *   Phase 1 (this file):  define `IBinaryImage` + `TargetInfo`.
 *   Phase 2:              make `PeImage` implement `IBinaryImage`.
 *   Phase 3:              retype `ProtectionContext::image_` to the
 *                         interface; passes keep compiling because the
 *                         interface covers everything they use today.
 *   Phase 4:              add `ElfImage` / `ElfParser` / `ElfBuilder`;
 *                         passes that were container-agnostic light up
 *                         for ELF targets for free.
 *   Phase 5:              per-target runtime stubs (Linux signal-based
 *                         anti-debug, macOS ptrace checks, ...).
 *
 * Passes that are container-aware (e.g. PackerPass assembling a PE-style
 * self-unpacking stub) stay coupled to the concrete container and opt out
 * via `ctx.target().is_windows_pe()` in `is_applicable()`.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/target/target_info.hpp"

namespace mx::target {

/**
 * @brief Flags describing how a section is mapped at runtime.
 *
 * These map cleanly onto PE `IMAGE_SCN_MEM_*`, ELF `PF_*` and Mach-O
 * `VM_PROT_*`. The loader translates the triple to the container-native
 * flag set when the image is written out.
 */
enum class SectionFlags : uint32_t {
    none    = 0,
    read    = 1u << 0,
    write   = 1u << 1,
    execute = 1u << 2,
    /// Section contributes to the in-memory footprint but has no bytes on disk
    /// (PE: BSS-like; ELF: SHT_NOBITS; Mach-O: S_ZEROFILL).
    zero_fill = 1u << 3,
};

[[nodiscard]] constexpr SectionFlags operator|(SectionFlags a, SectionFlags b) noexcept {
    return static_cast<SectionFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
[[nodiscard]] constexpr bool has_flag(SectionFlags v, SectionFlags f) noexcept {
    return (static_cast<uint32_t>(v) & static_cast<uint32_t>(f)) != 0;
}

/**
 * @brief Portable view of a loadable section.
 *
 * Not all fields are meaningful for every container — e.g. Mach-O sections
 * carry a segment name, which is exposed via `segment` (empty for PE/ELF).
 */
struct SectionView {
    std::string  name;              ///< PE: `.text`. ELF: `.text`. Mach-O: section name within segment.
    std::string  segment;           ///< Mach-O: `__TEXT`. Empty for PE/ELF.
    Rva          rva            = 0; ///< Offset from the image base when loaded.
    uint32_t     virtual_size   = 0; ///< Size in memory (bytes).
    uint32_t     raw_size       = 0; ///< Size on disk (may be < virtual_size).
    SectionFlags flags          = SectionFlags::none;
    ByteView     data;              ///< Bytes on disk. Empty for zero-fill sections.
};

/**
 * @brief Abstract in-memory representation of a parsed target binary.
 *
 * Concrete classes — today only `PeImage`, tomorrow `ElfImage` and
 * `MachOImage` — implement this. Passes should only ever talk to the
 * interface.
 *
 * Thread-safety: instances are owned by the pipeline and mutated
 * single-threaded. No concurrent access.
 */
class IBinaryImage {
public:
    virtual ~IBinaryImage() = default;

    // ------------------------------------------------------------------------
    // Target identification
    // ------------------------------------------------------------------------

    /// @brief OS / container / arch of this binary.
    [[nodiscard]] virtual TargetInfo target() const noexcept = 0;

    /// @brief Image base reported by the container. May be 0 for PIE/ASLR.
    [[nodiscard]] virtual uint64_t image_base() const noexcept = 0;

    /// @brief Entry-point RVA relative to `image_base()`.
    [[nodiscard]] virtual Rva entry_point_rva() const noexcept = 0;

    /// @brief Redirects the entry point. Used by the packer and by
    ///        future ELF entry-hook passes.
    virtual void set_entry_point_rva(Rva new_rva) = 0;

    // ------------------------------------------------------------------------
    // Sections
    // ------------------------------------------------------------------------

    /// @brief Read-only view of the current sections.
    [[nodiscard]] virtual std::vector<SectionView> sections() const = 0;

    /// @brief Find a section by name. Returns `nullopt` if not present.
    ///        Deliberately string-based so passes never bake in section ids.
    [[nodiscard]] virtual MxResult<SectionView>
        find_section(std::string_view name) const = 0;

    /// @brief Append a new section. Returns its assigned index.
    ///
    /// Implementations are responsible for alignment and container-specific
    /// layout (e.g. PE's file-alignment / section-alignment rules). Callers
    /// just hand over the raw bytes and desired permissions.
    virtual MxResult<uint32_t>
        add_section(std::string_view name, ByteView data,
                    SectionFlags flags) = 0;

    /// @brief Overwrite bytes inside an existing section by index.
    ///        `offset + data.size()` must fit inside the section's raw size.
    virtual MxStatus
        patch_section_bytes(uint32_t section_index,
                            uint32_t offset, ByteView data) = 0;

    // ------------------------------------------------------------------------
    // Container / architecture conveniences
    // ------------------------------------------------------------------------

    /// @brief True iff the image is 64-bit (x86_64, aarch64, ...).
    [[nodiscard]] virtual bool is_64bit() const noexcept = 0;
};

/**
 * @brief Parser factory — detects container format from the raw file bytes.
 *
 * The concrete parser is picked by magic: `MZ` → PE parser, `\x7fELF` → ELF
 * parser, `\xCF\xFA\xED\xFE` / `\xCE\xFA\xED\xFE` → Mach-O parser. The
 * factory's responsibility is container detection only; architecture
 * mismatch (e.g. 32-bit PE on a 64-bit-only pipeline) is reported by the
 * concrete parser.
 */
class IBinaryImageParser {
public:
    virtual ~IBinaryImageParser() = default;

    /// @brief True iff this parser recognizes `data` as its container.
    [[nodiscard]] virtual bool can_parse(ByteView data) const noexcept = 0;

    /// @brief Parse `data` into a fresh `IBinaryImage`.
    [[nodiscard]] virtual MxResult<std::unique_ptr<IBinaryImage>>
        parse(ByteView data) = 0;
};

/**
 * @brief Builder factory — serializes an `IBinaryImage` back to bytes.
 *
 * Paired with `IBinaryImageParser`: each container has its own parser +
 * builder, and the pipeline wires them up for the detected target.
 */
class IBinaryImageBuilder {
public:
    virtual ~IBinaryImageBuilder() = default;

    /// @brief Which containers this builder can serialize.
    [[nodiscard]] virtual ContainerFormat container() const noexcept = 0;

    /// @brief Rebuild the on-disk bytes from the in-memory image.
    [[nodiscard]] virtual MxResult<ByteBuffer>
        build(const IBinaryImage& image) = 0;
};

} // namespace mx::target
