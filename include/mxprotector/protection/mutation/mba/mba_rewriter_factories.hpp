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

// ---------------------------------------------------------------------------
// SUB r, K shapes — `81 /5 id` (and REX.W variant).
// ---------------------------------------------------------------------------

/// `(x ^ K) - 2*(~x & K)` — Knuth subtractive identity (with NOT).
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_imm_xor_not_and();

/// `x + (~K + 1)` — two's-complement negation, computed at runtime.
/// Derivation: `-K = ~K + 1` (mod 2^n), so `x - K = x + (~K + 1)`.
/// Forces the solver to chase the NOT through a +1, then prove the
/// resulting addition equals the original subtraction; cached
/// linear-arithmetic tactics on `sub r, K` do not apply.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_imm_neg_add();

/// `(x ^ K) + 2*(x & K) - 2K` — offset form, reusing the ADD
/// identity then subtracting `2K` to recover `x - K`.
/// Derivation: `(x^K) + 2*(x&K) = x + K`; subtracting `2K` yields
/// `x - K` over Z/2^n. The body chains an ADD-style MBA expansion
/// into a final SUB, exposing the solver to a longer arithmetic
/// chain than either pure additive or pure subtractive identity.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_imm_offset();

// ---------------------------------------------------------------------------
// XOR r, K shapes — `81 /6 id` (and REX.W variant).
// ---------------------------------------------------------------------------

/// `(x | K) - (x & K)` — symmetric-difference identity (existing).
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_imm_or_minus_and();

/// `(x | K) ^ (x & K)` — XOR-of-OR-and-AND identity.
/// Bit i of `(x|K)^(x&K)` is 1 iff `(x|K)_i ≠ (x&K)_i`, which holds
/// iff exactly one of `x_i, K_i` is set — i.e. precisely the bit
/// definition of `x ^ K`. Pure-Boolean expression with no carry,
/// so SMT solvers cannot fold it via linear arithmetic.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_imm_or_xor_and();

/// `(x + K) - 2*(x & K)` — additive identity then subtract carry.
/// Derivation: `x + K = (x^K) + 2*(x&K)` (Knuth), so subtracting
/// `2*(x & K)` recovers `x ^ K`. The body chains an ADD-style
/// expansion into a final SUB; the proof obligation mixes
/// arithmetic with bitwise reasoning.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_imm_add_minus_and();

// ---------------------------------------------------------------------------
// OR r, K shapes — `81 /1 id` (and REX.W variant).
// ---------------------------------------------------------------------------

/// `(x ^ K) + (x & K)` — disjoint-decomposition (existing).
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_imm_xor_plus_and();

/// `x + K - (x & K)` — additive identity minus intersection.
/// Derivation: `x + K = (x^K) + 2*(x&K)`, so subtracting `(x&K)`
/// leaves `(x^K) + (x&K) = x | K`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_imm_add_minus_and();

/// `(x ^ K) | (x & K)` — pure-Boolean OR-of-XOR-and-AND.
/// Bit i of `(x^K) | (x&K)`: if both x_i and K_i are 0, both
/// operands contribute 0 → 0. If exactly one is 1, `(x^K)_i = 1` →
/// 1. If both are 1, `(x&K)_i = 1` → 1. Matches `x | K` bit-by-bit.
/// Pure Boolean, no carry, no arithmetic.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_imm_xor_or_and();

} // namespace factories
} // namespace mx::mutation::mba
