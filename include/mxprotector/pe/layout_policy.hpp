/**
 * @file layout_policy.hpp
 * @brief Strategy interface controlling section emission semantics.
 *
 * The `ILayoutPolicy` is the single seam between "what a pass wants to
 * emit" and "how the resulting PE is laid out". Today every emission
 * site goes straight through `SectionManager::add_section(name, data,
 * mask)` and the mask is hard-coded at the call. That works for the
 * standard build but blocks any global reshape — most importantly the
 * upcoming `--chaos` mode which must:
 *
 *   1. Override every section's permissions to RWX (so a single
 *      section can hold both code and data without the loader
 *      complaining about W^X).
 *   2. Override every section's content type to `mixed_code_data` so
 *      tools cannot split sections back apart by the content-bit.
 *   3. After all passes finish, optionally collapse / interleave
 *      sections to defeat the "one section per pass" identity.
 *
 * R2.2 only introduces the interface, the default `StandardLayout`
 * implementation, and the `ProtectionContext` plug — passes still
 * call `SectionManager::add_section` directly and the policy is not
 * yet wired into the emission path. R2.3 plugs the policy in front
 * of every emission site via the new `SectionEmitter` facade. R2.5
 * runs the `finalize()` hook from `PeBuilder::build()`. Chaos mode
 * lands as a separate `ChaosLayout` implementation later, after the
 * abstraction is stable.
 *
 * Design rules:
 *   - Pure interface — no state on the ABC, every method is virtual.
 *     Concrete policies own whatever bookkeeping they need.
 *   - Methods are `noexcept` where the contract allows. `finalize`
 *     can fail (e.g. chaos mode might detect a section it cannot
 *     safely merge) so it returns `MxStatus`.
 *   - Pass identity must be preserved across `resolve()`. The policy
 *     can rewrite *intent* but must not change the section name or
 *     bytes — those are pass-owned.
 */

#pragma once

#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/section_intent.hpp"

namespace mx {
class PeImage; // forward — finalize takes a mutable image
}

namespace mx::pe {

/**
 * @brief Strategy controlling how passes' section intents become
 *        actual PE sections.
 *
 * Every emission goes through two seams:
 *
 *   1. `resolve(name, intent)` — converts the pass-declared intent
 *      into the intent the writer actually uses. `StandardLayout`
 *      passes the intent through unchanged; `ChaosLayout` (future)
 *      rewrites every entry to RWX + `mixed_code_data`.
 *   2. `finalize(image)` — runs once after every pass has finished
 *      emitting sections, before `PeBuilder::build()` serialises the
 *      image. `StandardLayout` is a no-op; chaos mode collapses /
 *      interleaves sections here.
 *
 * The `name` parameter on `resolve()` is a hint — policies that
 * need to special-case specific sections (e.g. "always keep
 * `.mxguard` as RX even in chaos mode") can branch on it. Most
 * policies ignore it.
 */
class ILayoutPolicy {
public:
    virtual ~ILayoutPolicy() = default;

    /**
     * @brief Translate a pass's section intent.
     *
     * Called once per emission site, just before
     * `SectionManager::add_section`. The returned intent is the one
     * the manager sees; the pass never observes the override.
     *
     * @param section_name  Name the pass picked (post-section-name-pool
     *                      randomisation, so already in its final form).
     * @param requested     What the pass said it needs.
     * @return              The intent the writer should actually emit.
     *                      `StandardLayout` returns it unchanged.
     */
    [[nodiscard]] virtual SectionIntent resolve(
        std::string_view section_name,
        SectionIntent    requested) const noexcept = 0;

    /**
     * @brief Post-emission image rewrite hook.
     *
     * Runs from `PeBuilder::build()` (R2.5) once every pass has
     * finished emitting sections, before the final serialisation.
     * Concrete policies can reorder, merge, or interleave sections
     * here — anything that needs the *full* layout to be visible.
     *
     * @param image  The image about to be serialised; the policy may
     *               mutate `image.sections()`.
     * @return       Empty status on success; an `MxError` to abort
     *               the build (e.g. chaos detected an unmergeable
     *               section it does not know how to handle).
     */
    [[nodiscard]] virtual MxStatus finalize(PeImage& image) const = 0;

    /**
     * @brief Human-readable label for diagnostics / logs.
     *
     * `"standard"` for the default policy, `"chaos"` for the future
     * unified-RWX policy. Used by the build header dump and the MCP
     * sidecar so a measurement run can correlate a metric with the
     * layout that produced it.
     */
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

} // namespace mx::pe
