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

/// Affine-MBA shape: `(1+t)*(x|K) + (1-t)*(x&K) + (-t)*(x^K)` for
/// per-site random `t ∈ [2, 15]`. Opens a 14-element family of
/// SMT-distinct identities in the same coefficient space the three
/// fixed shapes draw from, defeating frequency-pattern matchers
/// that key on the canonical Knuth/disjoint coefficient triples.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_imm_affine();

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

/// Affine-MBA shape: applies the ADD affine identity then subtracts
/// `2K` (split as two `sub dst, K` to avoid imm32 overflow) to
/// recover `x - K`. Per-site random `t ∈ [2, 15]`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_imm_affine();

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

/// Affine-MBA shape: `(1-t)*(x|K) + (t-1)*(x&K) + t*(x^K)` for
/// per-site random `t ∈ [2, 15]`. Reduces to `OR - AND = x ^ K`
/// for any `t`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_imm_affine();

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

/// Affine-MBA shape: `-t*(x|K) + (1+t)*(x&K) + (1+t)*(x^K)` for
/// per-site random `t ∈ [2, 15]`. Reduces to `AND + XOR = x | K`
/// for any `t`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_imm_affine();

// ---------------------------------------------------------------------------
// AND r, K shapes — `81 /4 id` (and REX.W variant).
// ---------------------------------------------------------------------------

/// `(x | K) - (x ^ K)` — symmetric-difference inverse (existing).
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_imm_or_minus_xor();

/// `(x + K) - (x | K)` — additive identity minus union.
/// Derivation: `x + K = (x^K) + 2*(x&K)` and `x | K = (x^K) + (x&K)`,
/// so `(x + K) - (x | K) = (x^K) + 2*(x&K) - (x^K) - (x&K) = x & K`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_imm_add_minus_or();

/// `~(~x | ~K)` — De Morgan's law, pure Boolean.
/// `~(~x | ~K) = x & K` directly. Body chains three NOT ops with
/// one OR — the AND is materialised entirely from negation, with
/// no arithmetic and no SUB.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_imm_demorgan();

/// Affine-MBA shape: `(1+t)*(x|K) + (-t)*(x&K) + (-(1+t))*(x^K)`
/// for per-site random `t ∈ [2, 15]`. Reduces to `OR - XOR = x & K`
/// for any `t`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_imm_affine();

// ---------------------------------------------------------------------------
// imm32 ALU 2-step deep-chain shapes — same `81 /op id` (and short-form)
// match surface as the affine shapes, but K is materialised through a
// random MOV-imm MBA layer (modular-inverse / xor-blind / rotate-blind)
// before the affine basis prep runs. Stacks two MBA proofs in series.
//
// Constraint: 32-bit operand only (`is_64bit == false`). The MOV-imm
// step functions emit 32-bit ops that zero-extend their destination —
// 64-bit sign-extension of K would need an explicit `movsxd` after
// materialisation, which is roadmapped, not shipped here.
// ---------------------------------------------------------------------------

[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_imm_deep_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_imm_deep_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_imm_deep_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_imm_deep_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_imm_deep_affine();

// ---------------------------------------------------------------------------
// ALU r-r (register-register) shapes — `01/03/09/0B/21/23/29/2B/31/33 /r`
// with mod = 3. Two encoding directions per op fold into one normalised
// `(dst, src)` view at decode time. All five affine shapes share the
// same coefficient algebra as the imm32 family but read from a register
// source instead of an immediate.
// ---------------------------------------------------------------------------

[[nodiscard]] std::unique_ptr<IMbaRewriter> make_add_rr_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_sub_rr_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_xor_rr_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_or_rr_affine();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_and_rr_affine();

// ---------------------------------------------------------------------------
// Unary (NOT/NEG) shapes — `[REX] F7 /<2|3>` with mod = 3. Each op
// gets two shape options:
//   * NOT: `~x = -x - 1` (NEG + SUB) and `~x = (x^K) ^ ~K` (XOR + XOR).
//   * NEG: `-x = ~x + 1` (NOT + ADD) and `-x = 0 - x` (MOV + XOR + SUB).
// 2-byte (no REX) or 3-byte (with REX) sites — picked up via the
// engine's multi-instruction redirect.
// ---------------------------------------------------------------------------

[[nodiscard]] std::unique_ptr<IMbaRewriter> make_not_rm_twocomplement();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_not_rm_xor_cancel();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_neg_rm_not_add1();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_neg_rm_zero_sub();

// 2-step deep-chain unary shapes — same `[REX] F7 /<2|3>` match
// surface as the single-layer unary shapes, but every immediate (K,
// ~K, K-1, …) is materialised through a per-site random MOV-imm MBA
// shape (modular-inverse / xor-blind / rotate-blind) before the
// outer body runs. Stacks two MBA proofs in series.
//
// Constraint: 32-bit operand only. Same zero-extension contract as
// the imm32 deep-affine shapes — REX.W support roadmapped.

[[nodiscard]] std::unique_ptr<IMbaRewriter> make_not_rm_deep_xor();
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_neg_rm_deep_add();

// ---------------------------------------------------------------------------
// MOV r32, imm32 shapes — `[REX.B] B8+rd id` (5/6 bytes).
// ---------------------------------------------------------------------------

/// Permutation polynomial: `mov r, K' ; imul r, r, P` with
/// `K' * P ≡ K (mod 2^32)` (existing). Strongest of the three —
/// SMT solvers must invert modular multiplication symbolically.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_modular_inverse();

/// XOR blinding: `mov r, A ; xor r, A ^ K` for random `A`.
/// At runtime `A ^ (A ^ K) = K`. Per-site polymorphism comes from
/// `A` — two MOV-imm sites with the same target K get visibly
/// different bytes. Cheap (2 instructions); SMT-friendly tactic
/// would still need to evaluate the XOR symbolically.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_xor_blind();

/// Rotation blinding: `mov r, ror(K, n) ; rol r, n` for random
/// `n` in [1, 31]. The rotation undoes the pre-rotated immediate;
/// resulting r == K. Body is 2 instructions and emits a ROL — an
/// opcode the modular-inverse and XOR shapes don't use, expanding
/// the per-site instruction-vocabulary at MOV-imm sites.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_rotate_blind();

// ---------------------------------------------------------------------------
// MOV r32, imm32 — 2-step deep chains.
//
// Each deep-chain shape composes two MBA layers at the abstract-
// operation level. The outer layer is a familiar single-shape
// rewrite (modular_inverse / xor_blind / rotate_blind); the inner
// layer is one of the *other two* shapes, picked uniformly at
// random per call site, used to materialise the leading immediate
// the outer layer would otherwise emit via a bare `mov`. The result
// is a 3-instruction body that stacks two MBA proofs in series —
// SMT solvers must apply tactics from both layers to fold the chain.
// ---------------------------------------------------------------------------

/// Outer modular-inverse + inner ∈ {xor-blind, rotate-blind}.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_deep_modular();

/// Outer xor-blind + inner ∈ {modular-inverse, rotate-blind}.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_deep_xor();

/// Outer rotate-blind + inner ∈ {modular-inverse, xor-blind}.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm_deep_rotate();

// ---------------------------------------------------------------------------
// MOV r64, imm64 shapes — `[REX.W (.B)] B8+rd iq` (10/11 bytes).
//
// 64-bit twins of the imm32 MOV shapes above. Their bodies emit the
// 10-byte `mov r64, imm64` form (via `X86CodeEmitter::mov_abs64`)
// rather than the size-optimal default that would silently downgrade
// to the 7-byte sign-extended `48 C7 C0 id` shape, which inverts
// the high 32 bits whenever bit 31 of the encoded value is set.
// ---------------------------------------------------------------------------

/// 64-bit permutation polynomial: `mov r64, K' ; imul r64, r64, P32`
/// with `K' * sext64(P32) ≡ K (mod 2^64)` for a per-site random odd
/// `P32`. Strongest 64-bit MOV-imm shape — SMT solvers must invert
/// 64-bit modular multiplication symbolically, a known-hard tactic
/// for bit-vector and linear-arithmetic backends.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm64_modular_inverse();

/// 64-bit XOR blinding: `mov r64, A ; xor r64, B32` for random
/// `B32` (sign-extended to 64 bits by hardware) and
/// `A = K ^ sext64(B32)`. Per-site polymorphism comes entirely from
/// `B32` — `A` is fully determined by `K` and `B32`.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm64_xor_blind();

/// 64-bit rotation blinding: `mov r64, ror64(K, n) ; rol r64, n` for
/// random `n` in [1, 63]. Body emits ROL — an opcode neither the
/// 64-bit modular-inverse nor the xor-blind shape uses, broadening
/// the per-site MOV-imm64 instruction vocabulary.
[[nodiscard]] std::unique_ptr<IMbaRewriter> make_mov_imm64_rotate_blind();

} // namespace factories
} // namespace mx::mutation::mba
