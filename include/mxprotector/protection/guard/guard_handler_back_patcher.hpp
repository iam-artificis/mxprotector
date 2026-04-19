/**
 * @file guard_handler_back_patcher.hpp
 * @brief Back-patch VEH/TLS rel32/imm32 slots and compute the
 *        self-CRC — Phase 6 of the GuardPass pipeline.
 *
 * Runs AFTER the per-guard region finalizer so every handler byte
 * we patch has settled at its final position.
 *
 * Ordering invariant:
 *   1. Write VEH module_base / descriptor-table / call-decrypt /
 *      self-hash slots.
 *   2. Compute `fnv1a_32` over the patched VEH handler bytes.
 *   3. Bake the computed hash into the TLS installer (`crc_expected_imm32`).
 *   4. XOR-mask every per-guard stored key with the same 4-byte
 *      hash so dumped key bytes don't reveal the real encryption key.
 *
 * Any later write to the VEH handler byte range would invalidate
 * the baked CRC and cause the runtime installer to silently skip
 * `AddVectoredExceptionHandler` — the first guard int3 would then
 * terminate the process.
 */

#pragma once

#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/protection/guard/guard_pending.hpp"
#include "mxprotector/protection/guard/guard_section_assembler.hpp"

namespace mx {
class ProtectionContext;
namespace pe { struct SectionInfo; }
} // namespace mx

namespace mx::guard {

/// Back-patch the VEH handler + TLS installer bytes of the already-
/// committed `.mxguard` section and XOR-mask every stored descriptor
/// key with the resulting handler CRC.
[[nodiscard]] MxStatus back_patch_guard_handlers(
    ProtectionContext&               ctx,
    pe::SectionInfo&                 guard_section,
    const GuardSectionAssembly&      asm_out,
    const std::vector<PendingGuard>& pendings);

} // namespace mx::guard
