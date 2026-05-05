/**
 * @file substitution_rule_groups.hpp
 * @brief Registration entry points for the built-in substitution rule families.
 *
 * Every rule family that `SubstitutionRuleRegistry::create_default`
 * wires up lives in its own translation unit so its specific
 * encoding logic stays local and the registry TU can be a thin list
 * of `register_*_rules` calls. New rule families are added by
 * dropping a new file under `src/builder/protection/mutation/rules/`
 * and appending one declaration here + one call inside the factory.
 *
 * The rule classes themselves are implementation details and stay
 * inside the family TU's anonymous namespace; only the registration
 * function is exported.
 */

#pragma once

namespace mx {

class SubstitutionRuleRegistry;

namespace mutation::rules {

/**
 * @brief Opcode-swap family.
 *
 * Two operand flavours on one shared class: "same-reg only"
 * (xor ↔ sub when both operands are the same register) and "any
 * reg-reg" (test ↔ and ↔ or where operand semantics still match
 * under `reg, reg` mod=3 addressing). Ten table rows in total.
 */
void register_opcode_swap_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief Direction-flip family.
 *
 * `OP r/m, r` ↔ `OP r, r/m` re-encoding for `reg, reg` (mod=3)
 * operands — the two forms are semantically identical and give the
 * obfuscator a cheap byte-level reshuffle. Nine table rows.
 */
void register_direction_flip_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief Imm8 arithmetic-negation family.
 *
 * `ADD r/m, imm8` ↔ `SUB r/m, -imm8` and the reverse. Two table
 * rows. Skips `imm == 0` and `imm == -128` (the latter has no
 * positive 8-bit negation).
 */
void register_imm8_negation_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief Shift ↔ add self-rewrites.
 *
 * `shl reg, 1` ↔ `add reg, reg`. Two classes because `matches` and
 * `apply` diverge between directions. No tables — the rule count is
 * fixed at two and the pattern logic doesn't factor cleanly.
 */
void register_shift_add_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief Semantic transforms (non-equivalent bytes with matching
 *        side-effects).
 *
 * `cmp reg, 0` → `test reg, reg`, `mov reg, 0` → `xor reg, reg`,
 * and `not reg` → `xor reg, -1`. Each output is smaller than the
 * input, so the remainder is padded with NOPs to preserve the
 * original instruction length.
 */
void register_semantic_transform_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief `inc reg` ↔ `add reg, 1` / `dec reg` ↔ `sub reg, 1`.
 *
 * Only applies when the original is ≥ 3 bytes so the `ADD r/m, 1` /
 * `SUB r/m, 1` form fits without changing the length. Two classes.
 */
void register_inc_dec_rules(SubstitutionRuleRegistry& registry);

/**
 * @brief Mixed-Boolean-Arithmetic family adapter.
 *
 * Wraps the entire `mba::MbaRewriterRegistry` (additive / Boolean
 * MBA identities for `ADD/SUB/XOR/OR/AND r, imm32` plus
 * permutation-polynomial obfuscation for `MOV r32, imm32`) behind
 * a single substitution-rule slot. The wrapped registry is the
 * extension point: new MBA shapes plug into
 * `MbaRewriterRegistry::create_default` without touching this
 * substitution registry — see
 * `protection/mutation/mba/mba_rewriter_groups.hpp`.
 *
 * MBA bytes are always longer than the original instruction's
 * slot, so the engine routes them through the expansion sink and
 * patches a `JMP rel32` at the original site. Sites shorter than
 * 5 bytes are skipped automatically.
 */
void register_mba_rules(SubstitutionRuleRegistry& registry);

} // namespace mutation::rules

} // namespace mx
