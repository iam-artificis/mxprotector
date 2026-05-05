/**
 * @file mba_rewriter_factories.hpp
 * @brief Per-shape factory functions for the shipped MBA rewriters.
 *
 * Each MBA shape lives in its own translation unit under
 * `protection/mutation/mba/rewriters/` and exposes exactly one
 * factory function declared here. The per-family aggregator
 * (`register_<family>_rewriters` in `mba_rewriter_groups.hpp`) calls
 * the factories in turn so a single ALU op (e.g. `ADD r, K`) ends
 * up with N matching MBA rewriters; the substitution adapter picks
 * one uniformly at random per site.
 *
 * Why factories instead of per-shape `register_*` entry points:
 * the registry's `register_rewriter` takes a `unique_ptr` and the
 * per-family aggregator wants to inject *the same* unique_ptr into
 * the same registry. Splitting a `register_*` slot per shape would
 * force every shape file to know about the registry type and its
 * concrete `register_rewriter` shape — that pulls more includes
 * into every TU. Factories keep the dependency surface minimal.
 *
 * Each function is `[[nodiscard]]` so a future caller cannot
 * silently drop a freshly-created rewriter.
 *
 * SRP — one factory == one shape. Adding a shape is a new file +
 * one new declaration here + one new call inside the matching
 * per-family aggregator (`register_*_imm_rewriters`).
 */

#pragma once

#include <memory>

namespace mx::mutation::mba {

class IMbaRewriter;

namespace factories {

// ---------------------------------------------------------------------------
// ADD r, K shapes — `81 /0 id` (and REX.W variant).
// ---------------------------------------------------------------------------

/// `(x ^ K) + 2*(x & K)` — Knuth additive identity.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_imm_xor_and();

/// `(x | K) + (x & K)` — disjoint-decomposition identity.
/// Bitwise: `x | K` is the union; `x & K` is the intersection;
/// the sum recovers `x + K` because every bit position is counted
/// once when present in exactly one operand and twice (i.e.
/// summed correctly with carry) when present in both.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_imm_or_and();

/// `2*(x | K) - (x ^ K)` — shift-based identity.
/// Derivation: `2*(x|K) = 2*(x^K) + 2*(x&K)`, so subtracting `x^K`
/// leaves `(x^K) + 2*(x&K) = x + K`. Mixes a shift with two
/// Boolean ops + one subtract — a different SMT proof shape from
/// the other two.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_imm_shift_or_xor();

} // namespace factories
} // namespace mx::mutation::mba
