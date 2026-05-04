/**
 * @file reference_overlap_filter.hpp
 * @brief Drop bogus `rel` references whose byte range overlaps a
 *        structurally-encoded slot.
 *
 * **Why this filter exists.**
 *
 * `CodeReferenceScanner` walks every code section byte-by-byte with
 * Zydis. Inside the VM blob the bytes are a mix of *real handler
 * instructions* and *embedded jump-table entries* (4-byte
 * XOR-encrypted signed deltas). Zydis has no way to tell the two
 * apart at decode time — the JT bytes routinely happen to decode as
 * valid x86 instructions whose `rel32` / RIP-relative slots fall
 * inside the JT entry's 4 bytes.
 *
 * Without this filter, the resulting bogus `rel` references survive
 * into the patcher, which then writes a relative displacement on top
 * of the JT entry. After chaos shuffle moves the dispatcher's target,
 * the corrupted entry decrypts to a random VA — the dispatcher does
 * an indirect jump, and the process crashes the moment that handler
 * is reached. Stress tests measured this as a ≈0.5 % flake rate
 * before the filter; afterwards the rate is zero.
 *
 * **What this filter does.**
 *
 *   1. Collect every "hard" reference — i.e. anything the patcher
 *      writes via a structural encoder (`xor_encoded_signed_delta_imm32`,
 *      `rel32_call_pop_anchored`, `rel32_with_imm_offset`, `rva` in
 *      data, `absolute_va` in data). These slots have a meaning
 *      independent of x86 instruction shape; their bytes are never
 *      part of an instruction's operand.
 *   2. Drop every "soft" reference (`code_branch_or_call` /
 *      `code_rip_relative` with `ReferenceEncoding::rel`) whose
 *      `[location_rva, location_rva + width)` range overlaps a hard
 *      slot.
 *
 * Hard slots survive verbatim; legitimate code-relative references
 * outside JT bytes survive verbatim. Only the bogus ones — emitted
 * because Zydis happily decoded JT bytes into ghost instructions —
 * disappear.
 *
 * **Why a separate file.**
 *
 *   * SOLID/SRP: the existing scanners each emit references; the
 *     patcher each consumes them. Filtering is a third concern with
 *     its own responsibility (de-duplicate / arbitrate overlaps) and
 *     belongs in its own translation unit.
 *   * The filter is testable in isolation — feed it any
 *     `ReferenceTable`, assert which entries survive — without
 *     spinning up a full PE.
 *   * Future scanners (e.g. an MBA-noise scanner) can register their
 *     own "hard" encodings and the filter handles overlap arbitration
 *     uniformly without touching the patcher.
 *
 * **Determinism.** The output preserves the input order of surviving
 * references — the patcher continues to rely on order-of-write for
 * legitimate overlaps elsewhere.
 */

#pragma once

#include <cstdint>
#include <span>

#include "mxprotector/pe/data_region.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::refmap {

/**
 * @brief Counters returned alongside the filtered table — useful for
 *        diagnostics and unit tests.
 */
struct OverlapFilterStats {
    /// Total references in the input table.
    std::uint32_t total = 0;
    /// References classified as "hard" (kept verbatim).
    std::uint32_t hard_kept = 0;
    /// "Soft" references whose byte range did not overlap any hard
    /// slot — kept.
    std::uint32_t soft_kept = 0;
    /// "Soft" references whose byte range overlapped a hard slot —
    /// dropped.
    std::uint32_t soft_dropped = 0;
    /// "Soft" references whose byte range overlapped an externally
    /// provided `pe::DataRegion` (VM bytecode, handler table) —
    /// dropped. Counted separately from `soft_dropped` so callers
    /// can verify the data-region path is wired correctly.
    std::uint32_t soft_dropped_in_data_region = 0;
};

/**
 * @brief Stateless arbitrator for overlapping references.
 *
 * Constructed and invoked per chaos build; carries no per-call
 * state, so a single instance can be reused. Implementing it as a
 * class (rather than a free function) leaves room for future
 * configuration knobs (e.g. an injection seam to override which
 * encodings count as "hard") without breaking the call site.
 */
class ReferenceOverlapFilter {
public:
    ReferenceOverlapFilter() = default;

    /**
     * @brief Filter `input` and return a fresh `ReferenceTable`
     *        whose entries are guaranteed not to clobber any hard
     *        slot or data region.
     *
     * `data_regions` is the union of every `SectionInfo::data_regions`
     * entry the protector passes have populated. Each region is a
     * "patcher-keep-out" byte range (VM handler table, encrypted
     * bytecode) that the filter treats with the same priority as a
     * hard reference's slot. Pass an empty span when no passes
     * register data ranges (the filter then degenerates to the
     * hard-vs-soft-only behaviour).
     *
     * Pre-conditions: none. Neither `input` nor `data_regions` need
     * be sorted.
     *
     * Post-conditions:
     *   * Every "hard" reference in the input appears in the output
     *     in input order.
     *   * Every "soft" reference whose byte range does *not* overlap
     *     any hard slot or data region appears in the output in
     *     input order.
     *   * No other references appear in the output.
     *
     * Side effects: none on `input`; the filter is non-destructive
     * so the caller may keep the original table for debugging.
     */
    [[nodiscard]] ReferenceTable filter(
        const ReferenceTable&        input,
        std::span<const DataRegion>  data_regions = {},
        OverlapFilterStats*          stats_out    = nullptr) const;
};

} // namespace mx::pe::refmap
