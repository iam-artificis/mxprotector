/**
 * @file mov_imm_emit.hpp
 * @brief Composable `mov r32, imm32` body emitters for the MBA family.
 *
 * Every MOV-imm32 MBA shape ultimately produces a chain of the form
 *
 *     emit_inner_mov(dst, leading_imm) ; finalizer(dst, params)
 *
 * where `leading_imm` is a per-shape transform of the original `K`
 * (e.g. `K * inv(P)` for modular-inverse, `K ^ A` for xor-blind,
 * `ror32(K, n)` for rotate-blind), and `finalizer` is the per-shape
 * undo step (`imul P`, `xor B`, `rol n`).
 *
 * Hoisting that two-stage structure into shared step functions has
 * three payoffs:
 *
 *   1. **Code-reuse** — the per-shape rewriters become thin
 *      adapters (decode + call step + build), eliminating the
 *      duplicated "compute params, emit two instructions"
 *      boilerplate.
 *
 *   2. **Multi-step deep chains** — the *inner* mov is parameterised
 *      via a `MovImmEmitter` callback. Pass `direct_mov_imm32` for
 *      the bare `em.mov(dst, leading_imm)` and the result is
 *      identical to the single-shape rewrite. Pass *another shape's*
 *      step function and the result is a 2-step deep chain that
 *      materialises `leading_imm` via a fresh MBA layer before the
 *      outer finalizer runs. The composition recurses if needed —
 *      the inner-step-of-inner-step etc.
 *
 *   3. **No byte-level surgery** — the deep-chain composition
 *      happens at the abstract-operation level, not the byte level.
 *      No mini-disassembler, no length-decoder, no ABI footguns.
 *
 * Each step function emits its mov + finalizer using only register
 * and immediate operands — no RIP-relative addressing, no branches.
 * Position is preserved across the rewrite.
 */

#pragma once

#include <cstdint>
#include <functional>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"
#include "mxprotector/core/randomizer.hpp"

namespace mx::mutation::mba {

/// Type-erased emitter that materialises `dst = imm` (mod 2^32) into
/// `em` using whatever 32-bit MBA shape the caller chooses. The
/// trivial "just emit `mov dst, imm`" form is `direct_mov_imm32`;
/// the three shipped MOV-imm MBA shapes (`emit_modular_inverse_step`,
/// `emit_xor_blind_step`, `emit_rotate_blind_step`) plug in here as
/// the inner step of a deep-chain rewrite.
using MovImmEmitter = std::function<
    void(analysis::X86CodeEmitter&, x86::Reg, std::uint32_t, Randomizer&)>;

/// Bare `mov dst, imm32` (5/6 bytes incl. REX.B). The default inner
/// step for the three single-layer MOV-imm rewriters and the
/// terminal step in any multi-step chain.
void direct_mov_imm32(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             imm,
    Randomizer&               rng);

/// Emit `mov dst, K' ; imul dst, dst, P` where `K' * P ≡ K mod 2^32`.
/// `inner` produces the leading mov; defaulting to `direct_mov_imm32`
/// reproduces the single-layer `mov-imm-modular-inverse` body.
/// Passing another step here gives a deep-chain rewrite where `K'`
/// itself is materialised via a second MBA layer.
void emit_modular_inverse_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner = direct_mov_imm32);

/// Emit `mov dst, A ; xor dst, A^K` for random A. Same composition
/// contract as `emit_modular_inverse_step`.
void emit_xor_blind_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner = direct_mov_imm32);

/// Emit `mov dst, ror32(K, n) ; rol dst, n` for random n in [1, 31].
/// Same composition contract as the others.
void emit_rotate_blind_step(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng,
    const MovImmEmitter&      inner = direct_mov_imm32);

// ---------------------------------------------------------------------------
// `MovImmEmitter`-compatible wrappers — same 4-argument signature as
// the typedef. Taking the address of a function with default args
// strips the default, so `&emit_modular_inverse_step` is the 5-arg
// form and cannot bind to `MovImmEmitter`. These thin wrappers fix
// that for the deep-chain composition path: pass `&emit_modular_inverse`
// as the `inner` of another step to compose two MBA layers.
// ---------------------------------------------------------------------------

void emit_modular_inverse(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng);

void emit_xor_blind(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng);

void emit_rotate_blind(
    analysis::X86CodeEmitter& em,
    x86::Reg                  dst,
    std::uint32_t             k,
    Randomizer&               rng);

} // namespace mx::mutation::mba
