/**
 * @file packer_stub_patcher.cpp
 * @brief Post-inject stub patch-up — implementation.
 *
 * Split out of `packer_pass.cpp` (R2.4). Every byte written here
 * matches the inlined version that used to live inside
 * `PackerPipeline::step5_inject_and_patch`; the only change is that
 * the patcher consumes `{rva, size}` pairs through
 * `std::span<const TargetSection>` instead of the pipeline's
 * private `EncryptedTarget` vector.
 */

#include "mxprotector/protection/packer/packer_stub_patcher.hpp"

#include <variant>

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"

namespace mx::packer {

void apply_post_inject_patches(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     section_data,
    Rva                             stub_rva,
    uint32_t                        layer_count,
    const CipherBodyPatches&        patches,
    const StubArtifactsInfo&        artifacts,
    std::span<const TargetSection>  sections)
{
    // Per-layer patching: every layer has its own `lea rsi, key_K`
    // and its own per-section `lea rdi / mov ecx` pair.
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        const auto& lp = patches.layers[layer];

        // lea rsi, [rip + rel] → this layer's 32-byte RC4 key.
        {
            const Rva lea_end_rva = stub_rva + lp.rel_to_key_at + 4;
            const Rva key_rva     = stub_rva + artifacts.key_offsets_in_stub[layer];
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(section_data, lp.rel_to_key_at, rel);
        }

        // Per-section: lea rdi → section base, mov ecx → section size.
        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& ds  = lp.sections[i];
            const auto& tgt = sections[i];

            const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(section_data, ds.patch_lea_at, rel);
            write_i32(section_data, ds.patch_size_at,
                      static_cast<int32_t>(tgt.size));
        }
    }

    // lea r8, [rip + rel] → 256-byte S-box scratch area.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_sbox_at + 4;
        const Rva sbox_rva    = stub_rva + artifacts.sbox_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(sbox_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(section_data, patches.rel_to_sbox_at, rel);
    }

    // P3 — if the KSA block was successfully lifted, overwrite the
    // plaintext KSA bytes with `call rel32 <vm_entry>` + NOP pad.
    if (artifacts.packer_vm_lift_succeeded) {
        const Rva vm_entry_rva =
            stub_rva +
            static_cast<Rva>(artifacts.packer_vm_blob_offset) +
            static_cast<Rva>(artifacts.packer_vm_entry_offset);
        const uint32_t ksa_off = patches.ksa_block_start_offset;
        const Rva    call_rva    = stub_rva + ksa_off;
        const Rva    call_end_rva = call_rva + 5;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(vm_entry_rva) -
            static_cast<int64_t>(call_end_rva));

        MutableByteView ksa_span{
            section_data.data() + ksa_off,
            patches.ksa_block_end_offset - ksa_off};
        asm64::write_call_rel32(ksa_span.subspan(0, 5), rel);
        if (ksa_span.size() > 5) {
            asm64::fill_nop(ksa_span.subspan(5));
        }
        ctx.log_fmt("PackerPass: P3 KSA replaced with call vm_entry @ RVA=0x{:08X}",
            vm_entry_rva);
    }

    // ImageBase rip-relative computation. The `lea rbx, [rip + 0];
    // sub rbx, imm32` pair in the reprotect block needs `imm32 =
    // stub_section_rva + imagebase_lea_anchor_offset` so that at
    // runtime `rbx = current_rip - imm32 = module_base`. This works
    // for both EXE (host == packed module) and DLL (host != packed
    // module) — we never read PEB.ImageBaseAddress.
    {
        const uint32_t imm32 =
            stub_rva + patches.imagebase_lea_anchor_offset;
        write_i32(section_data, patches.imagebase_sub_imm32_at,
                  static_cast<int32_t>(imm32));
    }

    // lea r14, [rip + rel] → reprotect section table + fill data.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_reprotect_table_at + 4;
        const Rva table_rva   = stub_rva + artifacts.reprotect_table_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(table_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(section_data, patches.rel_to_reprotect_table_at, rel);

        for (size_t i = 0; i < sections.size(); ++i) {
            const uint32_t entry_off =
                artifacts.reprotect_table_offset_in_stub + static_cast<uint32_t>(i * 8);
            write_i32(section_data, entry_off + 0,
                      static_cast<int32_t>(sections[i].rva));
            write_i32(section_data, entry_off + 4,
                      static_cast<int32_t>(sections[i].size));
        }
    }

    // Stage 3 — post-decrypt reloc applier. The four imm slots land
    // at stub-buffer offsets recorded by `emit_reloc_applier`; all
    // are zero when the applier was not emitted (OS-load mode), so
    // the `applier_end_offset > applier_begin_offset` check gates
    // every write below. Details in `reloc_applier.hpp`.
    //
    // Source of the reloc table: the stub-private blob embedded in
    // `.mxpack` by `append_stub_artifacts`, NOT the PE header's
    // `DataDirectory[BASERELOC]`. The directory there points at
    // mapper-applicable entries (vtables, globals); they have
    // already been relocated by the time the stub runs. The blob
    // holds only the entries that target encrypted sections, kept
    // out of mapper sight by `partition_encrypted_relocs`. When
    // partitioning produced no entries (no relocs, or no relocs
    // target the encrypted sections), `stub_private_relocs_size`
    // is zero — the patches go to `{rva = 0, size = 0}` and the
    // applier's `cmp rcx, rdx; jae .done` short-circuits.
    if (patches.reloc_applier.applier_end_offset >
        patches.reloc_applier.applier_begin_offset)
    {
        const auto& ra = patches.reloc_applier;

        // `sub rax, imm32` imm32: anchor = stub_rva + lea_anchor_offset
        const int32_t runtime_base_sub = static_cast<int32_t>(
            stub_rva + ra.lea_runtime_base_anchor_offset);
        write_i32(section_data, ra.sub_runtime_base_imm32_at,
                  runtime_base_sub);

        // `mov rbx, imm64`: preferred ImageBase.
        const uint64_t preferred_base =
            static_cast<uint64_t>(ctx.pe_image().image_base());
        for (int i = 0; i < 8; ++i) {
            section_data[ra.preferred_base_imm64_at + i] =
                static_cast<uint8_t>((preferred_base >> (8 * i)) & 0xFF);
        }

        // `mov ecx, reloc_rva` + `mov edx, reloc_size`: location of
        // the stub-private blob inside this very `.mxpack` section.
        const Rva private_rva = artifacts.stub_private_relocs_size > 0
            ? stub_rva + artifacts.stub_private_relocs_offset_in_stub
            : 0;
        write_i32(section_data, ra.reloc_rva_imm32_at,
                  static_cast<int32_t>(private_rva));
        write_i32(section_data, ra.reloc_size_imm32_at,
                  static_cast<int32_t>(artifacts.stub_private_relocs_size));

        ctx.log_fmt(
            "PackerPass: manual-map reloc applier patched — "
            "stub-private blob RVA=0x{:08X} size={} байт, "
            "preferred_base=0x{:016X}, applier @ stub+0x{:X}..0x{:X}",
            private_rva,
            artifacts.stub_private_relocs_size,
            preferred_base,
            ra.applier_begin_offset, ra.applier_end_offset);
    }

    // IAT destruction: patch lea rdi → Import Directory + the size.
    {
        Rva impdir_rva = 0;
        uint32_t impdir_size = 0;
        std::visit([&](const auto& nt) {
            if (pe::IMAGE_DIRECTORY_ENTRY_IMPORT < nt.OptionalHeader.NumberOfRvaAndSizes) {
                impdir_rva  = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                impdir_size = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
        }, ctx.pe_image().nt_headers());

        if (impdir_rva != 0 && impdir_size >= 4) {
            const Rva lea_end_rva = stub_rva + patches.rel_to_impdir_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(impdir_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(section_data, patches.rel_to_impdir_at, rel);
            write_i32(section_data, patches.impdir_size_at,
                      static_cast<int32_t>(impdir_size / 4));
            ctx.log_fmt("PackerPass: IAT destruction — Import Directory 0x{:08X} ({} байт) "
                        "будет обнулён при запуске",
                impdir_rva, impdir_size);
        } else {
            write_i32(section_data, patches.impdir_size_at, 0);
        }
    }
}

// ============================================================================
// Kernel-driver post-inject patcher.
//
// Mirrors the subset of `apply_post_inject_patches` that the driver
// cipher body actually needs. We deliberately do NOT call the user-
// mode function and mask-out — the user-mode function unconditionally
// writes into `rel_to_impdir_at`, `rel_to_reprotect_table_at`, and
// `imagebase_sub_imm32_at`, all of which are zero for the driver body
// and would therefore corrupt the stub prologue at offset 0.
// ============================================================================

void apply_driver_post_inject_patches(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     section_data,
    Rva                             stub_rva,
    uint32_t                        layer_count,
    const CipherBodyPatches&        patches,
    const StubArtifactsInfo&        artifacts,
    std::span<const TargetSection>  sections)
{
    // Per-layer patching — `lea rsi, key_K` + per-section `lea rdi` +
    // `mov ecx, size`. Identical math to the user-mode patcher.
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        const auto& lp = patches.layers[layer];

        {
            const Rva lea_end_rva = stub_rva + lp.rel_to_key_at + 4;
            const Rva key_rva     = stub_rva + artifacts.key_offsets_in_stub[layer];
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(section_data, lp.rel_to_key_at, rel);
        }

        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& ds  = lp.sections[i];
            const auto& tgt = sections[i];

            const Rva lea_end_rva = stub_rva + ds.patch_lea_at + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(tgt.rva) - static_cast<int64_t>(lea_end_rva));
            write_i32(section_data, ds.patch_lea_at, rel);
            write_i32(section_data, ds.patch_size_at,
                      static_cast<int32_t>(tgt.size));
        }
    }

    // Shared `lea r8, sbox` rel32.
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_sbox_at + 4;
        const Rva sbox_rva    = stub_rva + artifacts.sbox_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(sbox_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(section_data, patches.rel_to_sbox_at, rel);
    }

    // P3 — optional KSA VM-lift overwrite.
    if (artifacts.packer_vm_lift_succeeded) {
        const Rva vm_entry_rva =
            stub_rva +
            static_cast<Rva>(artifacts.packer_vm_blob_offset) +
            static_cast<Rva>(artifacts.packer_vm_entry_offset);
        const uint32_t ksa_off = patches.ksa_block_start_offset;
        const Rva    call_rva     = stub_rva + ksa_off;
        const Rva    call_end_rva = call_rva + 5;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(vm_entry_rva) -
            static_cast<int64_t>(call_end_rva));

        MutableByteView ksa_span{
            section_data.data() + ksa_off,
            patches.ksa_block_end_offset - ksa_off};
        asm64::write_call_rel32(ksa_span.subspan(0, 5), rel);
        if (ksa_span.size() > 5) {
            asm64::fill_nop(ksa_span.subspan(5));
        }
        ctx.log_fmt("PackerPass: driver — P3 KSA replaced with call vm_entry "
                    "@ RVA=0x{:08X}",
            vm_entry_rva);
    }

    // Stage-3 reloc applier (driver path always opts in). Source is
    // the stub-private blob — same partition strategy as user-mode,
    // see the explanatory comment in `apply_post_inject_patches`.
    if (patches.reloc_applier.applier_end_offset >
        patches.reloc_applier.applier_begin_offset)
    {
        const auto& ra = patches.reloc_applier;

        const int32_t runtime_base_sub = static_cast<int32_t>(
            stub_rva + ra.lea_runtime_base_anchor_offset);
        write_i32(section_data, ra.sub_runtime_base_imm32_at,
                  runtime_base_sub);

        const uint64_t preferred_base =
            static_cast<uint64_t>(ctx.pe_image().image_base());
        for (int i = 0; i < 8; ++i) {
            section_data[ra.preferred_base_imm64_at + i] =
                static_cast<uint8_t>((preferred_base >> (8 * i)) & 0xFF);
        }

        const Rva private_rva = artifacts.stub_private_relocs_size > 0
            ? stub_rva + artifacts.stub_private_relocs_offset_in_stub
            : 0;
        write_i32(section_data, ra.reloc_rva_imm32_at,
                  static_cast<int32_t>(private_rva));
        write_i32(section_data, ra.reloc_size_imm32_at,
                  static_cast<int32_t>(artifacts.stub_private_relocs_size));

        ctx.log_fmt(
            "PackerPass: driver — reloc applier patched: "
            "stub-private blob RVA=0x{:08X} size={} байт, "
            "preferred_base=0x{:016X}",
            private_rva,
            artifacts.stub_private_relocs_size,
            preferred_base);
    }
}

} // namespace mx::packer
