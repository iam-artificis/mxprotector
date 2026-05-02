/**
 * @file section_emitter.hpp
 * @brief Intent-driven facade in front of `SectionManager`.
 *
 * Every pass that needs to add or grow a section funnels through
 * this single entry point. The emitter does three things the bare
 * `SectionManager` does not:
 *
 *   1. Resolves the pass-declared `SectionIntent` through the active
 *      `ILayoutPolicy` (R2.2). A standard build forwards intent
 *      unchanged; a chaos build (future) overrides every entry to
 *      RWX/`mixed_code_data`.
 *   2. Translates the intent into the on-wire `IMAGE_SCN_*` bit-mask
 *      via `make_section_characteristics` (R2.1), so passes never
 *      reach for raw PE constants.
 *   3. Provides two extra primitives the bare manager does not have
 *      and which the upcoming mutation-overflow feature (A) needs:
 *      `append_to_section` (grow an existing section) and
 *      `allocate_overflow_section` (spill into a fresh section so the
 *      caller can trampoline back via a JMP).
 *
 * `SectionEmitter` is stateless beyond the references it holds — it
 * owns no bookkeeping. Construct one per emission site (or per pass);
 * the cost is one pointer.
 *
 * Threading: not safe for concurrent use. The pipeline is
 * single-threaded by construction.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/layout_policy.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace mx::pe {

/**
 * @brief Result of `allocate_overflow_section` — the caller needs
 *        both the section index (to index back into `pe_image()`) and
 *        the section RVA (to compute a JMP rel32 target from the
 *        spill site).
 */
struct OverflowAllocation {
    std::uint32_t section_index; ///< Index into `PeImage::sections()`.
    Rva           base_rva;      ///< RVA of the new section's first byte.
};

/**
 * @brief Intent-driven facade in front of `SectionManager`.
 *
 * Construct from a manager + the active layout policy, then call
 * `append_section` / `append_to_section` / `allocate_overflow_section`.
 * Every characteristics decision flows through the policy + intent
 * mapping — a future chaos override only has to replace the policy.
 */
class SectionEmitter {
public:
    /**
     * @brief Wire the emitter to a manager and a policy.
     *
     * Both references must outlive the emitter. The standard pattern
     * is to construct on the stack of an emission helper:
     *
     *     SectionEmitter emit{SectionManager{ctx.pe_image()},
     *                          ctx.layout_policy()};
     *     auto idx = emit.append_section(...);
     */
    SectionEmitter(SectionManager& mgr, const ILayoutPolicy& policy) noexcept
        : mgr_(mgr), policy_(policy) {}

    SectionEmitter(const SectionEmitter&)            = delete;
    SectionEmitter& operator=(const SectionEmitter&) = delete;

    /// @brief Read-only access to the bound image. Forwards to the
    /// underlying `SectionManager::image()`. Sinks and pipeline
    /// helpers (e.g. mutation overflow) read the image to predict
    /// the next section's RVA or patch a section's bytes after
    /// allocation; production callers should keep going through the
    /// emit primitives.
    [[nodiscard]] const PeImage& image() const noexcept { return mgr_.image(); }

    /// @brief Mutable access to the bound image — same rationale as
    /// the const overload. The mutation overflow sinks need to write
    /// the JMP-back into the section's tail after `append_section`
    /// has assigned its RVA.
    [[nodiscard]] PeImage& image() noexcept { return mgr_.image(); }

    /**
     * @brief Append a fresh section to the image.
     *
     * @param name     Final, in-PE name (already pulled from the
     *                 section-name pool by the caller).
     * @param bytes    Section contents.
     * @param intent   Pass-declared intent. The active layout policy
     *                 may rewrite it before the bytes hit the writer.
     * @return         Index of the new section in `PeImage::sections()`,
     *                 or an `MxError` from the underlying manager.
     */
    [[nodiscard]] MxResult<std::uint32_t> append_section(
        std::string_view name,
        ByteView         bytes,
        SectionIntent    intent);

    /**
     * @brief Append bytes to an existing section, growing it.
     *
     * Used by the upcoming mutation-overflow feature A. The section
     * permissions are not touched — the caller is responsible for
     * ensuring the existing section already has whatever access the
     * appended bytes need (grow `.mxvm` with more code: fine; grow
     * `.mxstr` with executable bytes: caller should reach for
     * `allocate_overflow_section` instead).
     *
     * @param name     Existing section name. Must exist in the image
     *                 — `MxError(section_not_found)` otherwise.
     * @param bytes    Bytes to append. Empty input is a no-op that
     *                 succeeds with offset = current size.
     * @return         Offset within the section where the appended
     *                 bytes begin (so the caller can compute the
     *                 RVA via `section.virtual_address + offset`).
     */
    [[nodiscard]] MxResult<std::size_t> append_to_section(
        std::string_view name,
        ByteView         bytes);

    /**
     * @brief Allocate a fresh section dedicated to spilled bytes.
     *
     * Used by the upcoming mutation-overflow feature A: when an
     * in-place mutation grows past its budget, the caller spills the
     * mutated body into a new section and emits a JMP from the
     * original site to this section's RVA.
     *
     * R2.3 stops at allocation — the JMP emission belongs to feature
     * A and depends on the source-site target arch's encoding. The
     * returned `OverflowAllocation` carries everything the caller
     * needs to compute a rel32 (or similar) jump target.
     *
     * @param name     Section name (caller picks; typically a
     *                 randomised entry from the section-name pool).
     * @param bytes    Bytes to place into the new section.
     * @param intent   Section content / permissions. Goes through the
     *                 active policy like `append_section`.
     * @return         `{section_index, base_rva}` on success.
     */
    [[nodiscard]] MxResult<OverflowAllocation> allocate_overflow_section(
        std::string_view name,
        ByteView         bytes,
        SectionIntent    intent);

private:
    SectionManager&      mgr_;
    const ILayoutPolicy& policy_;

    /// Resolve `intent` through the policy and translate to the
    /// `IMAGE_SCN_*` bit-mask. Helper kept private — every emission
    /// path must funnel through it identically.
    [[nodiscard]] std::uint32_t characteristics_for(
        std::string_view name,
        SectionIntent    intent) const noexcept;
};

} // namespace mx::pe
