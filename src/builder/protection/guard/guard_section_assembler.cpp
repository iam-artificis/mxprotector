/**
 * @file guard_section_assembler.cpp
 * @brief Implementation of `assemble_guard_section` — see header.
 */

#include "mxprotector/protection/guard/guard_section_assembler.hpp"

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_decrypt_vm_lifter.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"
#include "mxprotector/protection/guard/guard_page_layout.hpp"
#include "mxprotector/protection/guard/guard_tls_installer.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

namespace mx::guard {

MxResult<GuardSectionAssembly> assemble_guard_section(
    ProtectionContext&         ctx,
    std::vector<PendingGuard>& pendings,
    Randomizer&                rng)
{
    GuardSectionAssembly out;

    // ------------------------------------------------------------------
    // Phase 1 — concatenate every guard page.
    //
    // Each page is kGuardPageSize bytes; since the PE section
    // alignment is a multiple of that, the first page at offset 0 is
    // naturally page-aligned and every subsequent page stays aligned.
    // ------------------------------------------------------------------
    out.section_data.reserve(pendings.size() * kGuardPageSize + 512);
    for (auto& pg : pendings) {
        pg.page_offset_in_section =
            static_cast<uint32_t>(out.section_data.size());
        out.section_data.insert(out.section_data.end(),
            pg.layout.bytes.begin(), pg.layout.bytes.end());
    }

    // ------------------------------------------------------------------
    // Phase 2 — descriptor table.
    //
    // The VEH handler linearly scans this table on every int3 fault,
    // so its layout is a hard contract: kGuardDescriptorStride bytes
    // per descriptor, fields in the exact order the handler's
    // `cmp [rsi + N]` / `mov eax, [rsi + N]` bytes hard-code.
    // Entries are zero-filled here and populated by the region
    // finalizer once the section has an RVA.
    // ------------------------------------------------------------------
    out.descriptor_table_offset =
        static_cast<uint32_t>(out.section_data.size());
    out.descriptor_count = static_cast<uint32_t>(pendings.size());
    out.section_data.resize(
        out.descriptor_table_offset +
        out.descriptor_count * kGuardDescriptorStride);

    // ------------------------------------------------------------------
    // Phase 3 — VEH handler body. Appended right after the descriptor
    // table; the handler back-patcher fills in every rel32/imm32 slot
    // described by `veh_patches` once final RVAs are known.
    // ------------------------------------------------------------------
    out.veh_handler_offset =
        static_cast<uint32_t>(out.section_data.size());
    {
        RawEmitter tmp{};
        out.veh_patches = emit_guard_veh_handler(tmp, rng);
        out.section_data.insert(out.section_data.end(),
            tmp.buf.begin(), tmp.buf.end());
    }

    // ------------------------------------------------------------------
    // Phase 3b — VM-lift the decrypt unit and append the resulting
    // runtime blob. The VEH handler's two `call rel32` slots will be
    // back-patched to point at `decrypt_unit_offset + decrypt_vm_entry_offset`.
    // ------------------------------------------------------------------
    out.decrypt_unit_offset =
        static_cast<uint32_t>(out.section_data.size());
    {
        auto vm_res = lift_guard_decrypt_to_vm(ctx, rng);
        if (!vm_res) {
            return std::unexpected(vm_res.error());
        }
        out.decrypt_vm_entry_offset = vm_res->entry_offset;
        out.section_data.insert(out.section_data.end(),
            vm_res->blob.begin(), vm_res->blob.end());
    }

    // ------------------------------------------------------------------
    // Phase 3c — TLS installer thunk. The packer picks this up via
    // `ctx.extra_tls_callback_va()` and calls it before user code; the
    // thunk walks the VEH handler, computes its CRC against the
    // baked-in expected hash, and on match calls
    // `RtlAddVectoredExceptionHandler` to register the VEH.
    // ------------------------------------------------------------------
    out.tls_installer_offset =
        static_cast<uint32_t>(out.section_data.size());
    {
        RawEmitter tmp{};
        out.tls_patches = emit_guard_tls_installer(tmp, rng);
        out.section_data.insert(out.section_data.end(),
            tmp.buf.begin(), tmp.buf.end());
    }

    return out;
}

} // namespace mx::guard
