/**
 * @file mba_substitution_rule.cpp
 * @brief Adapter from `IMbaRewriter` registry to `ISubstitutionRule`.
 *
 * The mutation engine drives substitution through
 * `ISubstitutionRule`. Rather than have every MBA rewriter expose
 * itself as a substitution rule directly (every rewriter would
 * carry a name, a matches predicate, and an apply method), the
 * adapter wraps the whole MBA registry behind one rule slot:
 *
 *   * `matches(insn)` — true iff any rewriter in the registry
 *     matches.
 *   * `apply(insn, rng)` — pick a matching rewriter uniformly at
 *     random and emit its bytes. The engine routes the result
 *     through the expansion sink because MBA bytes are always
 *     longer than the original instruction's slot.
 *
 * Why one slot, not N: the substitution registry is iterated per
 * site to find every matching rule. Putting six rewriters as six
 * separate slots would force the registry to redundantly run six
 * matching predicates per site even though at most one rewriter
 * ever applies. Wrapping under one slot collapses that to a
 * single decoder run inside the registry's `find_matching` step
 * (`MbaRewriterRegistry::find_matching` does its own per-rewriter
 * walk), so total work is linear in matching rewriters, not in
 * registered rewriters × call sites.
 *
 * SOLID:
 *   * SRP — the adapter only adapts; it does not own the rewriter
 *     set or pick policy beyond uniform random.
 *   * DIP — depends on `IMbaRewriter` + `MbaRewriterRegistry`;
 *     production code never reaches concrete rewriter types.
 *   * OCP — adding a new MBA family does not touch this file.
 */

#include "mxprotector/protection/mutation/substitution_rule_groups.hpp"

#include <memory>
#include <utility>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/protection/mutation/mba/mba_rewriter.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace mx::mutation::rules {

namespace {

/// Single `ISubstitutionRule` slot wrapping a whole MBA registry.
class MbaSubstitutionRule final : public ISubstitutionRule {
public:
    explicit MbaSubstitutionRule(
        std::shared_ptr<const mba::MbaRewriterRegistry> registry) noexcept
        : registry_(std::move(registry))
    {}

    [[nodiscard]] std::string_view name() const noexcept override {
        return "mba-substitution";
    }

    [[nodiscard]] bool matches(
        const analysis::Instruction& insn) const override
    {
        if (!registry_) return false;
        return !registry_->find_matching(insn).empty();
    }

    [[nodiscard]] ByteBuffer apply(
        const analysis::Instruction& insn,
        Randomizer&                  rng) const override
    {
        if (!registry_) return {};

        const auto matching = registry_->find_matching(insn);
        if (matching.empty()) return {};

        const auto picked = rng.next_range(
            0, static_cast<std::uint32_t>(matching.size() - 1));
        const auto* rewriter = matching[picked];

        auto emitted = rewriter->rewrite(insn, rng);
        if (!emitted) return {};

        return std::move(emitted->bytes);
    }

private:
    std::shared_ptr<const mba::MbaRewriterRegistry> registry_;
};

} // namespace

void register_mba_rules(SubstitutionRuleRegistry& registry) {
    auto mba_registry = std::make_shared<mba::MbaRewriterRegistry>(
        mba::MbaRewriterRegistry::create_default());

    registry.add_rule(std::make_unique<MbaSubstitutionRule>(
        std::move(mba_registry)));
}

} // namespace mx::mutation::rules
