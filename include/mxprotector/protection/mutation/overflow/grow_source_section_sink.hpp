/**
 * @file grow_source_section_sink.hpp
 * @brief `IExpansionSink` that grows the *source* section in place by
 *        appending the inflated body within the section-alignment
 *        slack at the section's tail.
 *
 * @note Position independence requirement. The expanded bytes land at
 *       a new RVA different from the original site, so any relative
 *       operand inside them (`rel32` in `JMP`/`CALL`, `RIP+disp32` in
 *       memory operands, …) would point at the wrong target if not
 *       re-encoded for the new placement. Today's substitution rules
 *       deliberately avoid emitting relative operands (the engine
 *       skips branches/calls and rules emit only register-only ops),
 *       so the unpatched copy is safe. Future rules that need
 *       relative operands must declare per-byte relocation hints and
 *       have the engine re-encode after `plant()` returns. The engine
 *       will also fail-closed via a Zydis pre-flight that rejects any
 *       replacement containing a relative operand it cannot adjust.
 *
 * This is Feature A's preferred sink shape — the user wants mutation
 * to "extend the same section" whenever possible, falling back to a
 * JMP-out only when extension is genuinely impossible. The slack-only
 * growth strategy threads that needle: it grows the byte the
 * substituted instruction lives in, and only that byte's section,
 * without shifting any other section's RVA. Data directories
 * (`Imports`, `Exports`, `Relocations`, …) and every internal RVA
 * reference therefore stay valid without a single fixup.
 *
 * Why slack growth is RVA-stable: a section's footprint is its
 * `virtual_size` rounded up to `section_alignment`. The next section
 * starts at `align_up(prev.va + prev.virtual_size, sa)`. As long as
 * the appended bytes keep `virtual_size` ≤ that aligned boundary, the
 * `align_up` snaps to the same value as before — every subsequent
 * section's RVA is unchanged. The sink fails fast (returns
 * `section_slack_exhausted`) the moment the next byte would push past
 * the boundary, so the caller can dispatch the spill to a fallback
 * sink.
 *
 * Safety:
 *   * Only the source section is modified.
 *   * `virtual_size` may grow but the next section's RVA never moves.
 *   * Raw layout (file offsets) is recomputed by `recalculate_layout`,
 *     which only touches `raw_offset` / `raw_size` of subsequent
 *     sections — it never moves their virtual addresses, which is
 *     what every RVA-based reference depends on.
 *   * The PE writer (`PeBuilder`) re-pages the file from the new
 *     section table on every build, so file offset shifts are not
 *     observable at load time.
 */

#pragma once

#include <cstdint>
#include <string_view>

#include "mxprotector/protection/mutation/overflow/expansion_sink.hpp"

namespace mx::pe {
class SectionEmitter;
}

namespace mx::mutation::overflow {

/**
 * @brief In-place source-section growth sink — see file header.
 *
 * Threading: not safe for concurrent use; the mutation pipeline is
 * single-threaded by construction.
 */
class GrowSourceSectionSink final : public IExpansionSink {
public:
    /**
     * @brief Wire to the active section emitter.
     *
     * @param emitter Active section emitter; lifetime must outlive
     *                the sink.
     */
    explicit GrowSourceSectionSink(pe::SectionEmitter& emitter) noexcept;

    /**
     * @brief Plant the request — see `IExpansionSink::plant`.
     *
     * Locates the section that contains `request.site_rva`, computes
     * the section's slack (= `align_up(virtual_size, section_alignment)
     * - virtual_size`), and appends `expanded_bytes + JMP-back` if it
     * fits. Returns `MxError(section_slack_exhausted)` when the
     * payload would push past the slack boundary — the caller is
     * expected to retry with a fallback sink.
     */
    [[nodiscard]] MxResult<ExpansionPlan> plant(
        const ExpansionRequest& request) override;

    [[nodiscard]] std::string_view name() const noexcept override;

private:
    pe::SectionEmitter& emitter_;
};

} // namespace mx::mutation::overflow
