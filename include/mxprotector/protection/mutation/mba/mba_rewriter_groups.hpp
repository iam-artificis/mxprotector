/**
 * @file mba_rewriter_groups.hpp
 * @brief Registration entry points for the shipped MBA rewriter families.
 *
 * Each rewriter family lives in its own translation unit under
 * `protection/mutation/mba/rewriters/`. The concrete classes stay
 * inside their TU's anonymous namespace; only the
 * `register_*_rewriters` function is exported. The registry's
 * `create_default()` is a thin sequence of these calls — adding a
 * new family is a new file under `rewriters/`, one declaration
 * here, and one call inside `MbaRewriterRegistry::create_default`.
 *
 * Why per-family TUs: SRP at the file level. Each shape has its
 * own match predicate, encoding helpers, and per-site randomization
 * policy. Sharing a single TU mixes those concerns and makes the
 * file rapidly cross the project's ~300 LOC cap.
 */

#pragma once

namespace mx::mutation::mba {

class MbaRewriterRegistry;

/**
 * @brief `ADD r/m32-or-r/m64, imm32` → `(x ^ K) + 2*(x & K)`.
 *
 * Targets the `81 /0 id` (and REX.W variant) general-form ALU
 * encoding (≥ 6 bytes incl. ModR/M). Smaller forms (`83 /0 ib`,
 * `04 ib`, …) are skipped — the engine needs ≥ 5 bytes to plant
 * the `JMP rel32` redirect, and the imm32 form is the SMT-relevant
 * shape anyway.
 */
void register_add_imm_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief `SUB r/m32-or-r/m64, imm32` → `(x ^ K) - 2*(~x & K)`.
 *
 * Same `81 /5 id` encoding family + REX.W variant.
 */
void register_sub_imm_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief `XOR r/m32-or-r/m64, imm32` → `(x | K) - (x & K)`.
 *
 * Same `81 /6 id` encoding family + REX.W variant.
 */
void register_xor_imm_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief `OR  r/m32-or-r/m64, imm32` → `(x ^ K) + (x & K)`.
 *
 * Same `81 /1 id` encoding family + REX.W variant.
 */
void register_or_imm_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief `AND r/m32-or-r/m64, imm32` → `(x | K) - (x ^ K)`.
 *
 * Same `81 /4 id` encoding family + REX.W variant.
 */
void register_and_imm_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief r-r (register-register) ALU MBA family.
 *
 * Five affine shapes — one per ALU op (ADD/SUB/XOR/OR/AND) —
 * targeting the `01 /r .. 33 /r` group-1 r-r encodings (mod = 3).
 * Each shape opens a 14-element coefficient family parameterised
 * by a per-site random `t ∈ [2, 15]`, matching the variety of the
 * imm32 affine shapes.
 *
 * The targeted instructions are 2 bytes (no REX) or 3 bytes (with
 * REX) — below the 5-byte JMP rel32 redirect threshold — so this
 * family relies on the engine's multi-instruction redirect
 * mechanism (`MutationEngine::mutate_region`'s consume-next-N path,
 * Phase 11) to widen the slot at substitution time.
 */
void register_rr_affine_rewriters(MbaRewriterRegistry& registry);

/**
 * @brief `MOV r, imm` MBA family — covers both the 5/6-byte
 *        `[REX.B] B8+rd id` (mov r32, imm32) and the 10/11-byte
 *        `[REX.W (.B)] B8+rd iq` (mov r64, imm64) encodings.
 *
 * Three shapes per encoding width (modular-inverse, xor-blind,
 * rotate-blind). Each shape is a separate translation unit under
 * `rewriters/` exposing exactly one factory; this aggregator wires
 * all six into the registry.
 *
 * Strongest defeat (modular-inverse) emits a permutation-polynomial
 * chain `mov K' ; imul P` with `P * K' ≡ K`, forcing the SMT
 * solver to invert modular multiplication symbolically. The two
 * blinding shapes (xor / rotate) are visually polymorphic but
 * trivially foldable; they widen the per-site instruction
 * vocabulary at MOV-imm sites so opcode-frequency tooling cannot
 * fingerprint the chain.
 */
void register_mov_imm_rewriters(MbaRewriterRegistry& registry);

} // namespace mx::mutation::mba
