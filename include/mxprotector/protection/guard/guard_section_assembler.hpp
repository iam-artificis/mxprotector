/**
 * @file guard_section_assembler.hpp
 * @brief Compose the `.mxguard` section buffer + capture offsets
 *        downstream phases need.
 *
 * Lays the section out in the fixed order:
 *
 * ```
 *     [guard_page_0 .. N-1]          (one kGuardPageSize page per guard)
 *     [descriptor_table]             (N × kGuardDescriptorStride zero-filled bytes)
 *     [veh_handler]                  (emitted via emit_guard_veh_handler)
 *     [decrypt_vm_blob]              (from lift_guard_decrypt_to_vm)
 *     [tls_installer]                (emitted via emit_guard_tls_installer)
 * ```
 *
 * The first page lands at offset 0 and every subsequent page stays
 * on a `kGuardPageSize` boundary because the section alignment is a
 * multiple of that — the loader maps the section so every page is
 * naturally page-aligned at runtime.
 *
 * Returns one `GuardSectionAssembly` carrying the buffer and every
 * offset the finalizer / back-patcher need once the section has
 * been committed to the PE image.
 *
 * Mutates `pendings` — each entry's `page_offset_in_section` is
 * filled in the order the pages are appended.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/guard/guard_pending.hpp"
#include "mxprotector/protection/guard/guard_tls_installer.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

namespace mx {
class ProtectionContext;
class Randomizer;
} // namespace mx

namespace mx::guard {

/// Offsets, patch descriptors, and the assembled byte buffer for
/// the `.mxguard` section. All offsets are section-relative —
/// the pipeline adds `guard_section_rva` after the section commit
/// to get runtime RVAs.
struct GuardSectionAssembly {
    ByteBuffer            section_data;
    uint32_t              descriptor_table_offset = 0;
    uint32_t              descriptor_count        = 0;
    uint32_t              veh_handler_offset      = 0;
    uint32_t              decrypt_unit_offset     = 0;
    uint32_t              decrypt_vm_entry_offset = 0;
    uint32_t              tls_installer_offset    = 0;
    GuardVehEmit          veh_patches{};
    GuardTlsInstallerEmit tls_patches{};
};

/// Compose the full `.mxguard` section buffer, lifting the decrypt
/// unit into a VM blob along the way. Fails with an `MxError` only
/// if the VM lift / generate step fails — everything else is pure
/// `push_back` and cannot fail at this layer.
[[nodiscard]] MxResult<GuardSectionAssembly> assemble_guard_section(
    ProtectionContext&         ctx,
    std::vector<PendingGuard>& pendings,
    Randomizer&                rng);

} // namespace mx::guard
