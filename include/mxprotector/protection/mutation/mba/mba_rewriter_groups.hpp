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
 * @brief `MOV r32, imm32` → `mov reg, K' ; imul reg, reg, P`
 *        where `P * K' ≡ K (mod 2^32)`.
 *
 * Permutation-polynomial obfuscation: `P` is an odd (hence
 * invertible) constant; `K'` is `K * inv(P) mod 2^32`. The runtime
 * arithmetic is purely modular, so the chain is provably
 * equivalent — but SMT solvers must perform integer modular
 * multiplication symbolically, which is much slower than constant
 * folding. Targets the 5-byte `B8 id` short form (32-bit operand
 * size) where `imm32 != 0`.
 */
void register_modular_inverse_rewriters(MbaRewriterRegistry& registry);

} // namespace mx::mutation::mba
