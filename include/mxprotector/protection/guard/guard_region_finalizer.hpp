/**
 * @file guard_region_finalizer.hpp
 * @brief Per-guard finalisation — Phase 5 of the GuardPass pipeline.
 *
 * For each `PendingGuard`:
 *   1. Patch the source section's begin-marker span with
 *      `jmp rel32 <page_entry_int3> + NOP pad`, so the CPU walks
 *      into the guard page and hits its entry int3.
 *   2. Write the 64-byte descriptor table entry (RVAs, body size,
 *      open_count = 0, per-guard 32-byte key).
 *   3. XOR-encrypt the body bytes in place with the fresh per-guard
 *      key. Plaintext int3+tag windows at both page boundaries are
 *      deliberately left untouched so the CPU always lands on a
 *      valid breakpoint instruction regardless of encryption state.
 *
 * Individual failures (out-of-range source indices, buffer overruns)
 * are logged and skipped for that guard; the overall pass continues.
 * The function returns success unless a hard precondition fails.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"
#include "mxprotector/protection/guard/guard_pending.hpp"

namespace mx {
class ProtectionContext;
class Randomizer;
namespace pe { struct SectionInfo; }
} // namespace mx

namespace mx::guard {

/// Finalise every guard's source section patch + descriptor table
/// entry + body encryption. `guard_section` must already be
/// committed (so `virtual_address` is valid). Fills
/// `out_descriptors` with one `GuardDescriptor` per successfully
/// finalised guard.
[[nodiscard]] MxStatus finalize_guard_regions(
    ProtectionContext&               ctx,
    pe::SectionInfo&                 guard_section,
    const std::vector<PendingGuard>& pendings,
    uint32_t                         descriptor_table_offset,
    Randomizer&                      rng,
    std::vector<GuardDescriptor>&    out_descriptors);

} // namespace mx::guard
