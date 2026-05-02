/**
 * @file chaos_layout.hpp
 * @brief `ILayoutPolicy` that rewrites every section's intent to
 *        RWX / `mixed_code_data` so the resulting PE looks like one
 *        unified read-write-execute region to any tool that walks
 *        the section table.
 *
 * Feature B (`--chaos`) layered roll-out:
 *
 *   * B.1 — this file. `resolve()` rewrites every intent to
 *     `{mixed_code_data, rwx}`. `finalize()` walks the in-memory
 *     section list once after every pass has emitted, and stamps
 *     each existing section's `characteristics` to the same
 *     bit-mask, so passes that built sections via the legacy
 *     `SectionManager::add_section(name, data, mask)` path (no
 *     `SectionEmitter`-mediated `intent` plumbing) end up RWX
 *     anyway. No section merging or fragment shuffling yet — that
 *     is B.3.
 *
 *   * B.2 — CLI flag (`--chaos`) +
 *     `ProtectionConfig::chaos_layout`. `main()` swaps the active
 *     policy on `ProtectionContext` to a `ChaosLayout` when the
 *     flag is set.
 *
 *   * B.3 — fragment interleaver. `finalize()` cuts every section
 *     into small chunks and replaces the section table with a
 *     single unified RWX section whose bytes are the chunks
 *     shuffled into a random order. Reference patcher updates every
 *     RVA-bearing field (rel32 in code, RIP-relative LEAs,
 *     `DataDirectory` entries, `.reloc` page RVAs, `.pdata`
 *     RUNTIME_FUNCTION entries, …) so the binary still loads and
 *     runs.
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
     * @brief Stamp every existing section's `characteristics` field
     *        to the chaos bit-mask.
     *
     * Catches sections built via the legacy `SectionManager::
     * add_section(name, data, mask)` path that bypasses the
     * `SectionEmitter`/`resolve()` seam — passes that compute their
     * own `IMAGE_SCN_*` literal at the call site (e.g. legacy
     * pre-R2.3 paths and any future opt-out callers) still end up
     * RWX because finalize sweeps the entire section list.
     *
     * Returns empty status unconditionally — the per-section
     * characteristics rewrite cannot fail at the format level.
     */
    [[nodiscard]] MxStatus finalize(PeImage& image) const override;

    /// @brief Returns the literal `"chaos"` for log/sidecar correlation.
    [[nodiscard]] std::string_view name() const noexcept override;
};

} // namespace mx::pe
