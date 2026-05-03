/**
 * @file reference.hpp
 * @brief Data model for the chaos fragment interleaver's reference
 *        tracker.
 *
 * Feature B.4 — when `ChaosLayout` shuffles bytes inside the merged
 * unified section, every RVA-bearing field that points at a moved
 * byte must be rewritten so the binary still loads and runs. Rather
 * than thread per-category logic through the shuffler, we lift the
 * concept of "a reference" into a small value type and an explicit
 * collection. Each scanner phase (code rel32, RIP-relative, .pdata
 * RUNTIME_FUNCTION, .reloc-applied absolute VAs, …) appends to one
 * shared `ReferenceTable`; the patcher then walks it once and
 * rewrites every entry given an `RvaRemapper`.
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

namespace mx::pe::chaos {

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

} // namespace mx::pe::chaos
