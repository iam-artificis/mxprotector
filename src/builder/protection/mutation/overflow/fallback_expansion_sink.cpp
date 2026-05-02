/**
 * @file fallback_expansion_sink.cpp
 * @brief Implementation — see header for rationale.
 */

#include "mxprotector/protection/mutation/overflow/fallback_expansion_sink.hpp"

#include "mxprotector/core/result.hpp"

namespace mx::mutation::overflow {

FallbackExpansionSink::FallbackExpansionSink(
    IExpansionSink& primary,
    IExpansionSink& fallback) noexcept
    : primary_(primary)
    , fallback_(fallback)
{}

MxResult<ExpansionPlan> FallbackExpansionSink::plant(
    const ExpansionRequest& request)
{
    auto primary_res = primary_.plant(request);
    if (primary_res) {
        ++primary_count_;
        return primary_res;
    }

    const auto code = primary_res.error().code();
    if (code != static_cast<std::uint16_t>(
            mx::PeErrorCode::section_slack_exhausted))
    {
        // Genuine error — propagate without falling back.
        return primary_res;
    }

    auto fallback_res = fallback_.plant(request);
    if (fallback_res) {
        ++fallback_count_;
    }
    return fallback_res;
}

std::string_view FallbackExpansionSink::name() const noexcept {
    return "fallback";
}

} // namespace mx::mutation::overflow
