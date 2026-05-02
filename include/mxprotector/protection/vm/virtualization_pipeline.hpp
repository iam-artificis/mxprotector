/**
 * @file virtualization_pipeline.hpp
 * @brief Stateful pipeline implementing `VirtualizationPass::execute`.
 *
 * R3.2 split-out: `VirtualizationPass::execute` was a single ~320 LOC
 * function — well past the 50 LOC per-function cap. The pipeline
 * naturally decomposes into four phases:
 *
 *   1. Lift every VM-marker region into a `PendingRegion` (lifter
 *      output + junk insertion + optional cross-VM split).
 *   2. Lay out the pending blobs as a single `.mxvm` section blob.
 *   3. Emit the section, then write tracing-MCP hints (flag-gated).
 *   4. Patch every original region with `CALL vm_entry + NOPs`.
 *
 * `VirtualizationPipeline` owns one shared `Randomizer`, the lifter
 * and the runtime generator across all regions in a build. The
 * pass-level `is_applicable()` gate is unchanged.
 *
 * Design rules (matches `PackerPipeline`):
 *   - Single-shot. Construct, call `execute()`, throw away.
 *   - All cross-step state is private; nothing leaks. Tests can hold
 *     a pipeline instance and inspect its outputs only after
 *     `execute()` returns, but the typical caller is the pass itself.
 *   - The pass facade in `virtualization_pass.cpp` becomes a thin
 *     `is_applicable` + `execute` wrapper that defers to this class.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/vm/vm_lifter.hpp"
#include "mxprotector/protection/vm/vm_runtime_gen.hpp"

namespace mx {

class ProtectionContext;

namespace vm {

/// One region picked up from the marker scan and lifted to a single
/// emit-ready VM blob. The emit phase concatenates these into the
/// `.mxvm` section; the patch phase rewrites every original region
/// with `CALL vm_entry + NOPs`.
struct PendingRegion {
    Rva           begin_marker_rva;
    Rva           body_start_rva;
    Rva           body_end_rva;
    std::uint32_t total_patch_size;
    ByteBuffer    vm_blob;
    std::uint32_t entry_offset_in_blob;
    std::uint32_t blob_offset_in_section = 0;
};

/// Stateful orchestrator for one virtualization pass run.
class VirtualizationPipeline {
public:
    explicit VirtualizationPipeline(ProtectionContext& ctx) noexcept;

    /// Execute every phase. Returns the underlying section-emission
    /// error if the `.mxvm` section cannot be added; otherwise empty
    /// status (skipped regions are logged but not propagated as
    /// errors — the build continues without virtualization for that
    /// region).
    [[nodiscard]] MxStatus execute();

private:
    /// Assemble the build-wide VM gen options from the protection
    /// config + target descriptor (ImageBase key gating, anti-tamper
    /// suppression for non-user-mode targets).
    [[nodiscard]] vm::VmGenOptions build_default_options() const;

    /// Lift one source region to a `PendingRegion`, including junk
    /// insertion and the optional cross-VM split. Returns nullopt
    /// when the region must be skipped (too small, lift error,
    /// runtime-gen failure).
    [[nodiscard]] std::optional<PendingRegion> lift_region(
        const MarkedRegion&       region,
        const vm::VmGenOptions&   default_opts);

    /// Concatenate every pending blob with 16-byte INT3 padding into
    /// the final `.mxvm` byte buffer. Updates each pending's
    /// `blob_offset_in_section`.
    [[nodiscard]] ByteBuffer assemble_section_data(
        std::vector<PendingRegion>& pendings) const;

    /// Emit the `.mxvm` section. Returns its index in
    /// `pe_image().sections()` or the underlying section-emitter
    /// error.
    [[nodiscard]] MxResult<std::uint32_t> emit_section(
        const ByteBuffer& section_data);

    /// Source-linked labels for the tracing MCP (flag-gated).
    void emit_trace_hints(
        Rva                              mxvm_rva,
        const std::vector<PendingRegion>& pendings) const;

    /// Patch every original region in `.text` with `CALL vm_entry +
    /// NOPs` covering the begin marker + body + end marker.
    void patch_call_sites(
        Rva                               mxvm_rva,
        const std::vector<PendingRegion>& pendings) const;

    ProtectionContext& ctx_;
    Randomizer rng_{};
    vm::VmLifter           lifter_;
    vm::VmRuntimeGenerator gen_;
};

} // namespace vm
} // namespace mx
