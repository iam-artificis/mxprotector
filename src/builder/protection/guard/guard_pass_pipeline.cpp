/**
 * @file guard_pass_pipeline.cpp
 * @brief Implementation of `GuardPassPipeline::execute` — see header.
 */

#include "mxprotector/protection/guard/guard_pass_pipeline.hpp"

#include <vector>

#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/guard/guard_collector.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"
#include "mxprotector/protection/guard/guard_handler_back_patcher.hpp"
#include "mxprotector/protection/guard/guard_region_finalizer.hpp"
#include "mxprotector/protection/guard/guard_section_assembler.hpp"

namespace mx::guard {

MxStatus GuardPassPipeline::execute()
{
    ctx_.log("GuardPass: начало релокации MX_GUARD регионов");

    // The runtime-guards subsystem depends on the packer stub's TLS
    // callback inheritance path to register the VEH install thunk.
    // Without a packer stub the callback is never wired up, the VEH
    // never runs, and the first guard int3 crashes the process.
    // Fail early with a clear message so the user can fix the config
    // rather than debug a mystery crash.
    if (!ctx_.config().enable_packer) {
        return std::unexpected(MxError{
            ErrorCategory::protection,
            static_cast<uint16_t>(ProtectionErrorCode::pass_failed),
            "GuardPass: MX_GUARD требует --packer (VEH инсталлируется "
            "через TLS callback в packer stub)"});
    }

    Randomizer rng;

    // --- Phase 0 — collect + validate --------------------------------
    auto pendings = collect_pending_guards(ctx_, rng);
    if (pendings.empty()) {
        ctx_.log("GuardPass: нет подходящих MX_GUARD регионов, пропуск");
        return {};
    }
    ctx_.log_fmt("GuardPass: собрано {} регионов к релокации", pendings.size());

    // --- Phases 1..3c — compose section buffer -----------------------
    auto assembly = assemble_guard_section(ctx_, pendings, rng);
    if (!assembly) {
        return std::unexpected(assembly.error());
    }

    // --- Phase 4 — inject .mxguard section ---------------------------
    //
    // R + W + X characteristics. The WRITE bit is required because
    // the VEH decrypts and re-encrypts guard bodies in place at
    // runtime. Going through `NtProtectVirtualMemory` to toggle W
    // per-call would need a cached syscall pointer in a writable
    // scratch slot — which itself needs a writable section. Baking W
    // into .mxguard at build time is simpler, matches .mxpack's R+W+X
    // layout, and avoids a second "small writable tail" fingerprint.
    SectionManager sec_mgr(ctx_.pe_image());
    pe::SectionEmitter emit{sec_mgr, ctx_.layout_policy()};
    const std::string& guard_section_name = ctx_.section_names().guard;
    auto add_result = emit.append_section(
        guard_section_name,
        ByteView{assembly->section_data.data(), assembly->section_data.size()},
        pe::SectionIntent{pe::SectionContentType::code,
                          pe::SectionPermissions::rwx});
    if (!add_result) {
        return std::unexpected(add_result.error());
    }

    const uint32_t guard_section_index = *add_result;
    auto&          guard_section       =
        ctx_.pe_image().sections()[guard_section_index];
    const Rva      guard_section_rva   = guard_section.virtual_address;

    ctx_.log_fmt("GuardPass: секция '{}' добавлена: RVA=0x{:08X}, {} байт "
                 "(pages={}, descriptor_count={}, veh@0x{:X}, "
                 "decrypt@0x{:X}, tls_install@0x{:X})",
        guard_section_name,
        guard_section_rva,
        assembly->section_data.size(),
        pendings.size(),
        assembly->descriptor_count,
        guard_section_rva + assembly->veh_handler_offset,
        guard_section_rva + assembly->decrypt_unit_offset,
        guard_section_rva + assembly->tls_installer_offset);

    // --- Phase 5 — per-guard descriptor + source-side jmp + body XOR -
    std::vector<GuardDescriptor> descriptors;
    descriptors.reserve(pendings.size());

    if (auto s = finalize_guard_regions(
            ctx_, guard_section, pendings,
            assembly->descriptor_table_offset, rng,
            descriptors); !s)
    {
        return s;
    }

    // Source-linked labels for the tracing MCP (flag-gated). One label
    // per relocated guard body — final body_start_rva and body_size are
    // known from the finalized descriptors.
    if (ctx_.config().emit_trace_hints) {
        auto& hints = ctx_.trace_hints();
        for (const auto& desc : descriptors) {
            hints.add_guard_region(desc.guard_id,
                                   desc.body_start_rva,
                                   desc.body_size);
        }
    }

    // --- Phase 6 — back-patch VEH+TLS with final RVAs + CRC + mask ---
    if (auto s = back_patch_guard_handlers(
            ctx_, guard_section, *assembly, pendings); !s)
    {
        return s;
    }

    // --- Phase 7 — hand the TLS installer VA to the packer -----------
    //
    // PackerPass reads `ctx.extra_tls_callback_va()` while building
    // its own TLS callback array and appends the installer right
    // after its anti-debug callback. The VA is absolute (image_base +
    // installer_rva) because the packer serialises TLS callback
    // pointers as absolute 64-bit addresses.
    const uint64_t image_base =
        static_cast<uint64_t>(ctx_.pe_image().image_base());
    const uint64_t installer_va =
        image_base + guard_section_rva + assembly->tls_installer_offset;
    ctx_.set_extra_tls_callback_va(installer_va);
    ctx_.log_fmt("GuardPass: TLS installer VA=0x{:016X} → "
                 "ctx.extra_tls_callback_va", installer_va);

    ctx_.log_fmt("GuardPass: релокация завершена, {} активных guard'ов",
        descriptors.size());
    return {};
}

} // namespace mx::guard
