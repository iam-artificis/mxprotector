/**
 * @file extend_in_place_sink.hpp
 * @brief `IExpansionSink` that grows a single MxProtector-owned
 *        overflow section, creating it lazily on first call.
 *
 * Strategy: every call appends `expanded_bytes + JMP-back` to one
 * shared overflow section (named at construction). On the first call
 * the section is allocated via `SectionEmitter::append_section`;
 * later calls grow it via `append_to_section`. The cached `base_rva_`
 * is set on first allocation and never changes — `append_to_section`
 * resizes the section but the section's *starting* RVA is fixed,
 * which is what every subsequent `ExpansionPlan` needs.
 *
 * Why a single shared section: easier to find clusters of mutated
 * bodies in the binary at build time (debugging) and lower
 * section-count noise in the resulting PE. The trade-off vs
 * `SeparateOverflowSink` is granularity — one section per build vs
 * one per spill — and is decided at construction.
 *
 * Safety: only the owned overflow section is modified. The first
 * `append_section` call appends a new section at the end of the
 * image, which never shifts the RVA of any existing section. Each
 * subsequent `append_to_section` resizes the *last* section and
 * still does not shift any other section's RVA, so data-directory
 * entries stay valid.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "mxprotector/protection/mutation/overflow/expansion_sink.hpp"

namespace mx::pe {
class SectionEmitter;
}

namespace mx::mutation::overflow {

/**
 * @brief Single-section overflow sink — see file header.
 */
class ExtendInPlaceSink final : public IExpansionSink {
public:
    /**
     * @brief Wire to the active section emitter and pick the
     *        overflow section name.
     *
     * @param emitter      Active section emitter. Lifetime must
     *                     outlive the sink.
     * @param section_name Name of the overflow section
     *                     (e.g. `".mxmut"`, ≤ 8 chars per PE spec).
     */
    ExtendInPlaceSink(pe::SectionEmitter& emitter,
                      std::string         section_name) noexcept;

    /**
     * @brief Plant the request — see `IExpansionSink::plant`.
     *
     * First call allocates the overflow section with
     * `expanded_bytes + JMP-back`; subsequent calls append the same
     * shape to the existing section. The JMP-back is encoded *before*
     * the bytes are written, by predicting the section's base RVA
     * from the image's last section.
     */
    [[nodiscard]] MxResult<ExpansionPlan> plant(
        const ExpansionRequest& request) override;

    [[nodiscard]] std::string_view name() const noexcept override;

    /// @brief Whether the overflow section has been created yet.
    /// @details Useful for tests that want to assert the lazy-create
    /// path before the first plant call. Not part of the
    /// `IExpansionSink` contract.
    [[nodiscard]] bool section_exists() const noexcept {
        return base_rva_.has_value();
    }

    /// @brief Cached base RVA of the overflow section (0 before the
    /// first plant). Useful for tests; production callers reach for
    /// the `ExpansionPlan::overflow_rva` instead.
    [[nodiscard]] Rva base_rva_for_test() const noexcept {
        return base_rva_.value_or(0);
    }

private:
    pe::SectionEmitter& emitter_;
    std::string         section_name_;
    std::optional<Rva>  base_rva_;
};

} // namespace mx::mutation::overflow
