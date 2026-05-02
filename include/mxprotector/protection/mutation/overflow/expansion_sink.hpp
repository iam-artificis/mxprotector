/**
 * @file expansion_sink.hpp
 * @brief Strategy for placing inflated mutated bytes outside of the
 *        original instruction's slot.
 *
 * Feature A — mutation overflow handling. When `MutationEngine`
 * substitutes an instruction with a longer byte sequence, the original
 * `site_size` bytes do not have room for the replacement. The engine
 * emits a `JMP rel32` at the original site (5 bytes; the trailing
 * `site_size - 5` bytes are filled with `0x90` NOPs), and asks an
 * `IExpansionSink` to plant the inflated body at a reachable RVA.
 * The body itself ends with a JMP back to the byte after the original
 * site so the surrounding control flow is preserved.
 *
 * Two concrete sinks ship with this layer:
 *
 *   * `ExtendInPlaceSink` — appends to a single MxProtector-owned
 *     overflow section, creating it lazily on first call. Subsequent
 *     calls grow that one section. Lower section-table noise; still
 *     safe because the owned section is the last one in the image
 *     during MutationPass and growth never shifts other sections.
 *
 *   * `SeparateOverflowSink` — allocates a fresh dedicated section
 *     per expansion. Higher entropy, defeats per-section clustering
 *     heuristics, but consumes section-table slots (PE caps at 96).
 *
 * Both produce identical JMP-back semantics; the difference is purely
 * in *where* the body lives. The engine picks one per build.
 *
 * Safety invariant: both sinks only ever touch sections they own.
 * Pre-existing PE sections (`.text`, `.rdata`, …) are never resized,
 * so the loader's `DataDirectory` RVAs remain valid.
 */

#pragma once

#include <cstdint>
#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::mutation {

/**
 * @brief Description of a single mutation expansion event.
 *
 *   * `site_rva`        — RVA of the first byte of the original
 *                         instruction. The engine uses this to compute
 *                         the JMP-out (site → overflow) and the sink
 *                         uses it to compute the JMP-back's target
 *                         (overflow tail → site_rva + site_size).
 *   * `site_size`       — Original instruction length. Must be ≥ 5
 *                         (room for `JMP rel32`); the engine rejects
 *                         expansions on shorter slots before reaching
 *                         the sink.
 *   * `expanded_bytes`  — The mutated body to plant. The sink appends
 *                         a 5-byte JMP rel32 after these bytes;
 *                         callers must not include the JMP-back
 *                         themselves.
 */
struct ExpansionRequest {
    Rva           site_rva;
    std::uint32_t site_size;
    ByteView      expanded_bytes;
};

/**
 * @brief Result of `IExpansionSink::plant`.
 *
 *   * `overflow_rva`    — RVA of the first byte of the planted body.
 *                         The caller writes a `JMP rel32` from
 *                         `site_rva` targeting this RVA.
 *   * `overflow_size`   — Total bytes written, equal to
 *                         `expanded_bytes.size() + 5` (JMP-back).
 */
struct ExpansionPlan {
    Rva           overflow_rva;
    std::uint32_t overflow_size;
};

/**
 * @brief Strategy for placing an inflated mutated body.
 *
 * Pure interface — no state on the ABC. Concrete sinks own their
 * own bookkeeping (cached overflow section index, name policy, …)
 * and are constructed once per `MutationPass` invocation.
 *
 * Threading: not safe for concurrent use; the mutation pipeline is
 * single-threaded by construction.
 */
class IExpansionSink {
public:
    virtual ~IExpansionSink() = default;

    /**
     * @brief Plant the expanded bytes plus a trailing JMP-back.
     *
     * Pre-conditions: `request.site_size >= 5`,
     * `!request.expanded_bytes.empty()`. The sink fail-closes by
     * returning an `MxError` for any other condition (section
     * allocation failed, reachable rel32 range exceeded, …).
     *
     * @param request  Source-site descriptor.
     * @return         `{overflow_rva, overflow_size}` on success;
     *                 a propagated `MxError` on failure.
     */
    [[nodiscard]] virtual MxResult<ExpansionPlan> plant(
        const ExpansionRequest& request) = 0;

    /// @brief Human-readable name for diagnostics + logs.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

} // namespace mx::mutation
