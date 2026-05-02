/**
 * @file fallback_expansion_sink.hpp
 * @brief Composite `IExpansionSink` that tries a primary sink, then
 *        a fallback when the primary returns `section_slack_exhausted`.
 *
 * The mutation overflow path wants two strategies in lockstep:
 *
 *   1. Prefer to grow the source section in place
 *      (`GrowSourceSectionSink`) — this keeps mutated bytes adjacent
 *      to surrounding code, defeats simple "find code outside the
 *      original section" heuristics, and never adds a new section.
 *
 *   2. Fall back to a JMP-out spill (`ExtendInPlaceSink` or
 *      `SeparateOverflowSink`) when the source section's tail slack
 *      is exhausted.
 *
 * `FallbackExpansionSink` is the seam that composes the two without
 * teaching `MutationEngine` about either concrete shape. The engine
 * sees one `IExpansionSink&`; the chain decides where the bytes
 * land.
 *
 * Why a dedicated class rather than inline if-else in the engine:
 * SOLID separation. Different builds may want different chains
 * (grow→overflow, grow→separate, overflow→separate, etc.); the
 * choice is configuration, not engine logic. The engine remains
 * untouched as new chains are added.
 *
 * Discrimination rule: only `PeErrorCode::section_slack_exhausted`
 * triggers the fallback. Any other failure (corrupted PE, name
 * collision, …) is propagated unchanged — we do not paper over
 * genuine errors with a silent retry.
 */

#pragma once

#include <string_view>

#include "mxprotector/protection/mutation/overflow/expansion_sink.hpp"

namespace mx::mutation::overflow {

/**
 * @brief Two-stage expansion sink — see file header.
 */
class FallbackExpansionSink final : public IExpansionSink {
public:
    /**
     * @brief Wire to the primary and fallback sinks.
     *
     * @param primary   Sink consulted first. Both lifetimes must
     *                  outlive this composite.
     * @param fallback  Sink consulted only when the primary returns
     *                  `PeErrorCode::section_slack_exhausted`.
     */
    FallbackExpansionSink(IExpansionSink& primary,
                          IExpansionSink& fallback) noexcept;

    /**
     * @brief Plant via primary, fall back to secondary on
     *        slack-exhausted, propagate every other error.
     */
    [[nodiscard]] MxResult<ExpansionPlan> plant(
        const ExpansionRequest& request) override;

    [[nodiscard]] std::string_view name() const noexcept override;

    /// @brief Number of plants served by the primary sink. Useful for
    /// tests that want to assert the chain actually exercised it.
    [[nodiscard]] std::uint32_t primary_plant_count() const noexcept {
        return primary_count_;
    }

    /// @brief Number of plants served by the fallback sink.
    [[nodiscard]] std::uint32_t fallback_plant_count() const noexcept {
        return fallback_count_;
    }

private:
    IExpansionSink& primary_;
    IExpansionSink& fallback_;
    std::uint32_t   primary_count_  = 0;
    std::uint32_t   fallback_count_ = 0;
};

} // namespace mx::mutation::overflow
