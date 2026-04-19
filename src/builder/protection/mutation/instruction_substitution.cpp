/**
 * @file instruction_substitution.cpp
 * @brief `SubstitutionRuleRegistry` — registry methods and default factory.
 *
 * Every concrete rule lives under `mutation/rules/`, grouped by the
 * encoding shape it rewrites (opcode-swap, direction-flip,
 * imm8-negation, shift↔add, semantic transforms, inc/dec). Adding a
 * new family means one more `.cpp` under `rules/`, one declaration in
 * `substitution_rule_groups.hpp`, and one call inside
 * `create_default` below.
 */

#include "mxprotector/protection/mutation/substitution_rules.hpp"

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

namespace mx {

void SubstitutionRuleRegistry::add_rule(std::unique_ptr<ISubstitutionRule> rule) {
    if (rule) {
        rules_.push_back(std::move(rule));
    }
}

std::vector<const ISubstitutionRule*> SubstitutionRuleRegistry::find_matching(
    const analysis::Instruction& insn) const
{
    std::vector<const ISubstitutionRule*> result;
    for (const auto& rule : rules_) {
        if (rule->matches(insn)) {
            result.push_back(rule.get());
        }
    }
    return result;
}

SubstitutionRuleRegistry SubstitutionRuleRegistry::create_default() {
    SubstitutionRuleRegistry registry;
    mutation::rules::register_opcode_swap_rules(registry);
    mutation::rules::register_direction_flip_rules(registry);
    mutation::rules::register_imm8_negation_rules(registry);
    mutation::rules::register_shift_add_rules(registry);
    mutation::rules::register_semantic_transform_rules(registry);
    mutation::rules::register_inc_dec_rules(registry);
    return registry;
}

} // namespace mx
