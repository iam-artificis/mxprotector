/**
 * @file chaos_layout.hpp
 * @brief `ILayoutPolicy` that rewrites every section's intent to
 *        RWX / `mixed_code_data` so the resulting PE looks like one
 *        unified read-write-execute region to any tool that walks
 *        the section table.
 *
 * Feature B (`--chaos`) layered roll-out:
 *
 *   * B.1 — `resolve()` rewrites every intent to
 *     `{mixed_code_data, rwx}` and `finalize()` stamps every
 *     existing section's `characteristics` with the chaos bit-mask
 *     so legacy `SectionManager::add_section(name, data, mask)`
 *     paths (no `SectionEmitter`/`intent` plumbing) still end up
 *     RWX anyway.
 *
 *   * B.2 — CLI flag (`--chaos`) +
 *     `ProtectionConfig::chaos_layout`. `main()` swaps the active
 *     policy on `ProtectionContext` to a `ChaosLayout` when the
 *     flag is set.
 *
 *   * B.3 — `finalize()` additionally collapses the entire section
 *     table into a single unified RWX/`mixed_code_data` section
 *     covering `[min(va), max(va + virtual_size))`. Every original
 *     section's bytes land at the *same RVA* they had before; gaps
 *     between original section bodies (the natural section-alignment
 *     padding) are filled with `0xCC` (INT3). Because RVAs are
 *     preserved bit-for-bit, every internal RVA reference
 *     (`DataDirectory` entries, `.reloc` page RVAs, `.pdata`
 *     RUNTIME_FUNCTION fields, internal directory pointers)
 *     resolves to the same byte after the merge — no reference
 *     patcher needed.
 *
 *   * B.4 (future) — fragment-level shuffling. Slice the unified
 *     section into chunks and reorder them at new RVAs, with a
 *     reference patcher updating every RVA-bearing field
 *     (`rel32` in code, RIP-relative LEAs, …) in lockstep. Strictly
 *     more complex than B.3; gated behind a comprehensive
 *     reference-tracker module so shuffled binaries still load and
 *     run on every supported PE shape.
 *
 * Why a separate policy class rather than a `StandardLayout`
 * subclass: `StandardLayout` is `final` on purpose (the no-op
 * pass-through is a documented contract). Composition is the
 * mechanism — every concrete policy stands alone.
 *
 * Threading: stateless; safe to share across threads. The pipeline
 * is single-threaded by construction so the question is academic.
 */

#pragma once

#include "mxprotector/pe/layout_policy.hpp"

namespace mx::pe {

/**
 * @brief `ILayoutPolicy` for `--chaos` mode — see file header.
 *
 * The class is intentionally tiny: every method is a few lines.
 * Like `StandardLayout`, it is `final` and stateless; the per-build
 * variance comes from the `Randomizer` that future B.3 fragment
 * shuffling will accept.
 */
class ChaosLayout final : public ILayoutPolicy {
public:
    /**
     * @brief Construct with the byte-level shuffle pass enabled or
     *        disabled.
     *
     * `enable_fragment_shuffle = false` (default) keeps `finalize`'s
     * behaviour at the B.3 contract: characteristics rewrite +
     * single unified section with RVAs preserved bit-for-bit.
     *
     * `enable_fragment_shuffle = true` activates the B.4 chunk
     * shuffler — free RVA ranges get randomly permuted and every
     * scanned reference is patched in lockstep. See file header for
     * the (current) deep-directory coverage caveat.
     */
    explicit ChaosLayout(bool enable_fragment_shuffle = false) noexcept
        : enable_fragment_shuffle_(enable_fragment_shuffle) {}

    /**
     * @brief Rewrite every emitted section's intent to RWX / mixed.
     *
     * Independent of the requested intent. The `section_name`
     * argument is intentionally ignored — chaos mode does not
     * special-case any section. `RX` becomes `RWX`; `R` becomes
     * `RWX`; `code` becomes `mixed_code_data`; etc. The legacy PE
     * loader honours these flags exactly, so the loaded image
     * presents one unified read/write/execute region.
     */
    [[nodiscard]] SectionIntent resolve(
        std::string_view section_name,
        SectionIntent    requested) const noexcept override;

    /**
     * @brief Stamp every existing section with chaos bits, then
     *        collapse the section table into a single unified RWX /
     *        mixed section.
     *
     * Two-step transform:
     *
     *   1. OR the chaos bit-mask into every section's
     *      `characteristics`. Catches sections built via the
     *      legacy `SectionManager::add_section(name, data, mask)`
     *      path that bypasses the `SectionEmitter`/`resolve()`
     *      seam.
     *   2. If the image has more than one section, replace the
     *      whole table with a single section covering
     *      `[min(va), max(va + virtual_size))`. Original section
     *      bodies are copied into the merged buffer at their
     *      original RVA offsets; the gaps between bodies are
     *      filled with `0xCC` (INT3) so a disassembler walking the
     *      unified region sees recognisable padding and any errant
     *      jump into the gap traps. `NumberOfSections` in the
     *      FileHeader is updated to 1.
     *
     * Returns empty status unconditionally — the merge cannot fail
     * at the format level (every original byte's RVA is preserved
     * verbatim, so no internal RVA reference can dangle).
     */
    [[nodiscard]] MxStatus finalize(PeImage& image) const override;

    /// @brief Returns the literal `"chaos"` for log/sidecar correlation.
    [[nodiscard]] std::string_view name() const noexcept override;

private:
    bool enable_fragment_shuffle_ = false;
};

} // namespace mx::pe
