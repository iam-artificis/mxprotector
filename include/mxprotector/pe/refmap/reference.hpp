/**
 * @file reference.hpp
 * @brief Data model for the general-purpose RVA-reference tracker.
 *
 * Anywhere we move a byte to a new RVA, every RVA-bearing field
 * that points at it has to be rewritten so the binary still loads
 * and runs. Rather than thread per-category logic through every
 * transform, we lift the concept of "a reference" into a small
 * value type and an explicit collection. Scanner phases (code
 * rel32 / RIP-relative, `.pdata` RUNTIME_FUNCTION,
 * `.reloc`-applied absolute VAs, …) append to one shared
 * `ReferenceTable`; a patcher walks it once and rewrites every
 * entry given an `RvaRemapper`.
 *
 * First consumers:
 *
 *   * Feature B.4 chaos fragment interleaver — moves byte chunks
 *     inside the unified section.
 *   * Future mutation-overflow rules that emit position-dependent
 *     bytes referring to other points in the image.
 *   * Future instruction-insertion transforms — inserting NOPs /
 *     junk between live instructions shifts every RVA past the
 *     insertion point, and references downstream need remapping.
 *
 * This file is data-only — no PE I/O, no Zydis, no allocations
 * beyond the inner `vector`. Dependent modules pull only the types
 * they need; tests instantiate the table without dragging in the
 * scanners.
 *
 * Why orthogonal `width` × `encoding` rather than a fat enum:
 *
 *   * The patcher's encoding logic is a small switch on `encoding`,
 *     reading `width` to determine byte count. Keeping them separate
 *     means a future encoding (e.g. RIP-relative on a different size)
 *     does not require multiplying enum cases.
 *   * The scanners speak in terms of *what they emit*, not how the
 *     bits land. `code_rel32` and a future `code_rel16` would share
 *     `encoding = rel`; only `width` differs.
 */

#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::pe::refmap {

/**
 * @brief How many bytes the reference's slot occupies on disk.
 *
 * Mapped 1-to-1 to PE-format reference widths the chaos pipeline
 * cares about:
 *
 *   * `byte1` — `rel8` short branches (`Jcc`/`JMP rel8`/`LOOP`).
 *   * `byte4` — `rel32` (`CALL`/`JMP rel32`/`Jcc rel32`),
 *               `RIP+disp32` memory operand, every 32-bit RVA in
 *               PE headers and directories.
 *   * `byte8` — 64-bit absolute VA stored in data and fixed up by
 *               `IMAGE_REL_BASED_DIR64` entries in `.reloc`.
 */
enum class ReferenceWidth : std::uint8_t {
    byte1 = 1,
    byte4 = 4,
    byte8 = 8,
};

/**
 * @brief How the slot bytes encode the reference target.
 *
 *   * `rel`       — signed displacement: the slot stores
 *                   `target_rva - (location_rva + width)`. The
 *                   displacement is RIP-relative, so both source
 *                   and target moves contribute.
 *   * `rva`       — unsigned 32-bit RVA, written verbatim. Used by
 *                   PE headers and directory tables.
 *   * `absolute_va` — 64-bit absolute VA (`image_base + target_rva`).
 *                     The patcher rewrites the full VA when the
 *                     target moves; the loader's
 *                     `IMAGE_REL_BASED_DIR64` entry then re-applies
 *                     the runtime-load delta on top.
 */
enum class ReferenceEncoding : std::uint8_t {
    rel,
    rva,
    absolute_va,
    /// `rel32` whose anchor is **4 bytes before** the slot, not
    /// `slot + width` — used by the VM `CallPop` trampoline shape:
    ///
    ///   call $+5                E8 00 00 00 00
    ///   add  qword [rsp], imm32 48 81 04 24 imm32
    ///   ret                     C3
    ///
    /// `imm32` encodes `target_rva - (call_after_rva)` where
    /// `call_after_rva = slot_rva - 4`. The patcher rewrites the
    /// `imm32` slot bytes; the surrounding `call`/`ret` opcodes
    /// stay verbatim.
    rel32_call_pop_anchored,
};

/**
 * @brief Where the reference came from. Diagnostic-only — the
 *        patcher does not branch on it. Used in logs so a build
 *        operator can correlate a missing remap with the scanner
 *        that produced the reference.
 */
enum class ReferenceOrigin : std::uint8_t {
    code_branch_or_call,
    code_rip_relative,
    data_directory_entry,
    entry_point,
    pdata_runtime_function,
    reloc_absolute_va,
    import_descriptor,        ///< IMAGE_IMPORT_DESCRIPTOR.{Name,OriginalFirstThunk,FirstThunk}
    import_thunk,             ///< INT/IAT thunk → IMAGE_IMPORT_BY_NAME (low 4B of 8B slot)
    export_directory,         ///< IMAGE_EXPORT_DIRECTORY.{Name,AddressOf*}
    export_function_rva,      ///< Single EAT entry → function/forwarder RVA
    export_name_rva,          ///< Single name pointer → ASCIIZ name string RVA
    delay_import_descriptor,  ///< IMAGE_DELAYLOAD_DESCRIPTOR.{DllNameRVA,*RVA}
    delay_import_thunk,       ///< Delay-load thunk → IMAGE_IMPORT_BY_NAME
    tls_directory,            ///< IMAGE_TLS_DIRECTORY field (absolute VA)
    tls_callback,              ///< Single callback in TLS callback array (absolute VA)
    load_config_directory,    ///< IMAGE_LOAD_CONFIG_DIRECTORY VA-bearing field
    load_config_table_entry,  ///< Single entry in CFG/SEH/etc. table (absolute VA / RVA)
    resource_data_entry,      ///< IMAGE_RESOURCE_DATA_ENTRY.OffsetToData (RVA)
    unwind_exception_handler, ///< UNWIND_INFO.ExceptionHandler (RVA, .reloc-free)
    unwind_chain_info,        ///< UNWIND_INFO.ChainInfo RUNTIME_FUNCTION RVAs (.reloc-free)
    switch_jump_table_entry,  ///< MSVC x64 switch JT entry (4-byte RVA, .reloc-free)
    vm_call_pop_trampoline,   ///< imm32 in `add qword [rsp], imm32` of CallPop trampoline
};

[[nodiscard]] constexpr std::string_view origin_name(
    ReferenceOrigin o) noexcept
{
    switch (o) {
        case ReferenceOrigin::code_branch_or_call:    return "code-rel";
        case ReferenceOrigin::code_rip_relative:      return "code-rip";
        case ReferenceOrigin::data_directory_entry:   return "data-dir";
        case ReferenceOrigin::entry_point:            return "entry";
        case ReferenceOrigin::pdata_runtime_function: return "pdata";
        case ReferenceOrigin::reloc_absolute_va:      return "reloc-va";
        case ReferenceOrigin::import_descriptor:      return "import-desc";
        case ReferenceOrigin::import_thunk:           return "import-thunk";
        case ReferenceOrigin::export_directory:       return "export-dir";
        case ReferenceOrigin::export_function_rva:    return "export-fn";
        case ReferenceOrigin::export_name_rva:        return "export-name";
        case ReferenceOrigin::delay_import_descriptor: return "delay-desc";
        case ReferenceOrigin::delay_import_thunk:     return "delay-thunk";
        case ReferenceOrigin::tls_directory:          return "tls-dir";
        case ReferenceOrigin::tls_callback:           return "tls-cb";
        case ReferenceOrigin::load_config_directory:  return "lcfg-dir";
        case ReferenceOrigin::load_config_table_entry: return "lcfg-tab";
        case ReferenceOrigin::resource_data_entry:    return "rsrc-data";
        case ReferenceOrigin::unwind_exception_handler: return "unwind-eh";
        case ReferenceOrigin::unwind_chain_info:      return "unwind-chain";
        case ReferenceOrigin::switch_jump_table_entry: return "switch-jt";
        case ReferenceOrigin::vm_call_pop_trampoline:  return "vm-callpop";
    }
    return "unknown";
}

/**
 * @brief One RVA-bearing slot somewhere in the image.
 *
 *   * `location_rva` — RVA of the first byte of the slot.
 *   * `target_rva`   — RVA the slot currently points at, *before*
 *                       any chaos remap. The patcher remaps this
 *                       through `RvaRemapper` to compute the new
 *                       target.
 *   * `width`        — bytes the slot occupies.
 *   * `encoding`     — how the slot encodes the target (see enum).
 *   * `origin`       — diagnostic tag.
 */
struct Reference {
    Rva               location_rva;
    Rva               target_rva;
    ReferenceWidth    width;
    ReferenceEncoding encoding;
    ReferenceOrigin   origin;

    [[nodiscard]] constexpr bool operator==(const Reference&) const noexcept = default;
};

/**
 * @brief Append-only collection of `Reference` values.
 *
 * Each scanner appends; the patcher consumes once. Move-only so the
 * pipeline's ownership story stays trivial.
 */
class ReferenceTable {
public:
    ReferenceTable() = default;

    ReferenceTable(const ReferenceTable&)            = delete;
    ReferenceTable& operator=(const ReferenceTable&) = delete;
    ReferenceTable(ReferenceTable&&) noexcept            = default;
    ReferenceTable& operator=(ReferenceTable&&) noexcept = default;

    /// Append one reference. No deduplication — scanners are
    /// responsible for not registering the same slot twice.
    void add(Reference r) { slots_.push_back(r); }

    /// Reserve capacity to avoid reallocations when the scanners
    /// know the lower-bound count.
    void reserve(std::size_t n) { slots_.reserve(n); }

    [[nodiscard]] std::span<const Reference> slots() const noexcept {
        return {slots_.data(), slots_.size()};
    }

    [[nodiscard]] std::size_t size() const noexcept { return slots_.size(); }
    [[nodiscard]] bool        empty() const noexcept { return slots_.empty(); }

private:
    std::vector<Reference> slots_;
};

} // namespace mx::pe::refmap
