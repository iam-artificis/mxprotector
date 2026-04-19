/**
 * @file guard_collector.hpp
 * @brief Collect + validate MX_GUARD regions into `PendingGuard` records.
 *
 * Phase 0 of the GuardPass pipeline. Walks `ctx.markers()`, rejects
 * regions that fail static validation (empty body, oversized for one
 * page, patch window too small to hold a jmp rel32, source read
 * failure, page-layout failure), and returns one `PendingGuard` per
 * surviving region. Rejected regions are logged via `ctx.log_fmt`
 * and silently skipped — they do not fail the whole pass.
 */

#pragma once

#include <vector>

#include "mxprotector/protection/guard/guard_pending.hpp"

namespace mx {
class ProtectionContext;
class Randomizer;
} // namespace mx

namespace mx::guard {

/// Collect every `MarkerType::guard_begin` region from `ctx.markers()`
/// that passes static validation and assign each a dense, 0-based
/// `guard_id` in marker order.
///
/// Returns an empty vector when nothing was accepted — the pipeline
/// logs and skips in that case.
[[nodiscard]] std::vector<PendingGuard> collect_pending_guards(
    ProtectionContext& ctx,
    Randomizer&        rng);

} // namespace mx::guard
