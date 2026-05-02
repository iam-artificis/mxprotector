/**
 * @file separate_overflow_sink.hpp
 * @brief `IExpansionSink` that allocates a fresh dedicated section
 *        per expansion event.
 *
 * Strategy: every `plant()` creates a brand-new PE section named
 * `<base_name><suffix>` and places `expanded_bytes + JMP-back` into
 * it. Suffixes come from a per-sink monotonic counter rendered as
 * two-digit lowercase hex (`"00"`, `"01"`, …, `"ff"`). With the
 * 8-character PE name limit, `<base_name>` is therefore capped at
 * 6 characters by the constructor.
 *
 * Why per-spill sections: every overflow site lives in its own page,
 * frustrating clustering heuristics that scan a single MxProtector
 * section for a JMP-table-shaped layout. Cost: section-table noise —
 * a build with hundreds of expansions blows past PE's 96-section cap,
 * so this sink is best for low-spill builds (smoke tests, samples)
 * or when paired with a per-region rotation policy higher up.
 *
 * Safety: identical to `ExtendInPlaceSink` — every newly-allocated
 * section is appended at the end of the image, which never shifts
 * any existing section's RVA. Pre-existing PE sections (`.text`,
 * `.rdata`, …) are never touched.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "mxprotector/protection/mutation/overflow/expansion_sink.hpp"

namespace mx::pe {
class SectionEmitter;
}

namespace mx::mutation::overflow {

/// Hard cap on the per-sink expansion count. PE caps at 96 sections;
/// the sink reserves no more than `kMaxSpillCount` of them. After the
/// cap, `plant()` fails with `section_out_of_bounds`.
inline constexpr std::uint32_t kMaxSpillCount = 0x100;

/**
 * @brief Per-spill overflow sink — see file header.
 */
class SeparateOverflowSink final : public IExpansionSink {
public:
    /**
     * @brief Wire to the active section emitter and pick the section
     *        name prefix.
     *
     * @param emitter   Active section emitter. Lifetime must outlive
     *                  the sink.
     * @param base_name Section name prefix (≤ 6 chars). Each `plant`
     *                  call appends a 2-char hex suffix from an
     *                  internal counter.
     */
    SeparateOverflowSink(pe::SectionEmitter& emitter,
                         std::string         base_name) noexcept;

    /**
     * @brief Plant the request — see `IExpansionSink::plant`.
     *
     * Allocates a fresh section, then patches the JMP-back placeholder
     * into the section's tail once the actual base RVA is known.
     */
    [[nodiscard]] MxResult<ExpansionPlan> plant(
        const ExpansionRequest& request) override;

    [[nodiscard]] std::string_view name() const noexcept override;

    /// @brief Number of `plant()` calls served so far. Useful for
    /// tests; production callers should not depend on it.
    [[nodiscard]] std::uint32_t spill_count() const noexcept {
        return next_index_;
    }

private:
    pe::SectionEmitter& emitter_;
    std::string         base_name_;
    std::uint32_t       next_index_ = 0;

    /// Build the next section name (`base_name` + 2-digit hex suffix).
    [[nodiscard]] std::string next_section_name() const;
};

} // namespace mx::mutation::overflow
