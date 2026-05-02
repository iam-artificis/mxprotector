/**
 * @file standard_layout.hpp
 * @brief Default `ILayoutPolicy` — passes' intents reach the writer
 *        unchanged and the post-emission image is left as-is.
 *
 * This is the policy every existing build uses today. Encoding it as
 * an explicit `ILayoutPolicy` implementation rather than "no policy
 * at all" gives R2.3 a uniform call-shape (every pass funnels
 * through `policy.resolve(...)`) and lets R2.5 always invoke
 * `policy.finalize(...)` without a null-check. The override-free
 * pass-through nature is the contract that pins the no-op semantics.
 */

#pragma once

#include "mxprotector/pe/layout_policy.hpp"

namespace mx::pe {

/**
 * @brief Pass-through policy. `resolve` returns its argument; the
 *        finalize hook is a no-op.
 *
 * Stateless — instantiate freely. The class is `final` so the
 * compiler can devirtualise the calls; a build that wants to extend
 * `StandardLayout` should compose, not subclass.
 */
class StandardLayout final : public ILayoutPolicy {
public:
    /**
     * @brief Pass `requested` through unchanged.
     *
     * The contract is that the standard layout never rewrites a
     * pass's intent — every characteristics bit the pass asked for
     * lands in the PE exactly as requested.
     */
    [[nodiscard]] SectionIntent resolve(
        std::string_view section_name,
        SectionIntent    requested) const noexcept override;

    /**
     * @brief No-op image finalisation.
     *
     * Standard layout does not reorder, merge, or interleave; the
     * sections appear in the PE in pass-emit order with the
     * characteristics each pass requested. Returning empty status
     * unconditionally lets the caller chain without branching.
     */
    [[nodiscard]] MxStatus finalize(PeImage& image) const override;

    /// @brief Returns the literal `"standard"`.
    [[nodiscard]] std::string_view name() const noexcept override;
};

} // namespace mx::pe
