/**
 * @file guard_pending.hpp
 * @brief Cross-phase carrier for an MX_GUARD region inside the
 *        GuardPass pipeline.
 *
 * The collector (`guard_collector.hpp`) fills one `PendingGuard` per
 * surviving region. Downstream phases read it:
 *
 *   * section assembler — writes `page_offset_in_section` as each
 *     page is concatenated into the `.mxguard` buffer;
 *   * region finalizer  — patches the source section's begin-marker
 *     span, writes the 64-byte descriptor table entry, XOR-encrypts
 *     the body bytes in place;
 *   * handler back-patcher — re-reads `guard_id` to locate each
 *     descriptor's stored-key slot for the post-CRC XOR-mask pass.
 *
 * Keeping the struct in its own header avoids a circular include
 * between the collector (producer) and the assembler / finalizer /
 * back-patcher (consumers).
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"

namespace mx::guard {

/// Per-guard intermediate state that flows from collection through
/// section assembly and patching. Fields are populated in the order
/// the pipeline phases run, so early phases read only the fields
/// the collector / assembler have filled by then.
struct PendingGuard {
    /// Index into `pe_image().sections()` identifying the section
    /// that holds the source begin-marker. The jmp rel32 patch goes
    /// into this section.
    uint32_t source_section_index = 0;

    /// RVA of the first byte of the begin-marker (i.e. the byte the
    /// source-side jmp rel32 will overwrite).
    Rva source_begin_marker_rva = 0;

    /// RVA of the first body byte inside the source section.
    Rva source_body_start_rva = 0;

    /// RVA of the first byte AFTER the body (= start of the end-marker).
    Rva source_body_end_rva = 0;

    /// Total byte span to overwrite in the source section:
    /// begin_marker + body + end_marker. Must be ≥ 5 (room for a
    /// jmp rel32) or the collector rejects the region.
    uint32_t source_total_patch_size = 0;

    /// RVA where the VEH's exit handler should redirect control
    /// after re-encrypting the body. Points at the byte right past
    /// the end-marker in the source section.
    Rva return_rva = 0;

    /// Owning copy of the source body bytes. Consumed by
    /// `build_guard_page` during collection; held here for
    /// post-collection auditability.
    ByteBuffer body_bytes;

    /// Page built by `build_guard_page` — contains the 5-byte entry
    /// int3+tag window, the body copy (encrypted in place later),
    /// the exit int3+tag window, and a random junk tail.
    GuardPageLayout layout{};

    /// Dense 0-based identifier assigned by the collector in marker
    /// order. Used as the index into the descriptor table.
    uint32_t guard_id = 0;

    /// Offset of this guard's page within the assembled `.mxguard`
    /// section buffer. Filled by the section assembler.
    uint32_t page_offset_in_section = 0;
};

} // namespace mx::guard
