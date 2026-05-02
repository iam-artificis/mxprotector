/**
 * @file packer_setup.cpp
 * @brief Implementation of the pre-stub setup helpers for the packer
 *        pipeline. See `packer_setup.hpp` for rationale.
 */

#include "mxprotector/protection/packer/packer_setup.hpp"

#include <algorithm>
#include <cstring>
#include <variant>

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_emitter.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"
#include "mxprotector/protection/packer/dll_characteristics_audit.hpp"

namespace mx::packer {

void apply_dll_characteristics_audit(ProtectionContext& ctx) {
    std::uint16_t cleared = 0;
    const bool is_driver = ctx.target().is_kernel_driver();
    std::visit([&](auto& nt) {
        const auto r = packer::audit_dll_characteristics(
            nt.OptionalHeader.DllCharacteristics, is_driver);
        nt.OptionalHeader.DllCharacteristics = r.output;
        cleared = r.cleared;
    }, ctx.pe_image().nt_headers());

    if (cleared == 0) return;

    if (cleared & pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF) {
        ctx.log("PackerPass: DllCharacteristics: GUARD_CF cleared "
                "(injected sections lack CFG bitmap entries)");
    }
    if (cleared & pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
        ctx.log("PackerPass: DllCharacteristics: FORCE_INTEGRITY cleared "
                "(driver target — packed bytes invalidate any "
                "Microsoft signature)");
    }
}

void disable_relocations(PeImage& image) {
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;

        nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        nt.OptionalHeader.DllCharacteristics &=
            static_cast<std::uint16_t>(~pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS32> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC <
                nt.OptionalHeader.NumberOfRvaAndSizes)
            {
                nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt.OptionalHeader.DataDirectory[
                    pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }
        }
    }, image.nt_headers());

    image.set_relocations({});

    for (auto& sec : image.sections()) {
        if (sec.name == ".reloc") {
            std::fill(sec.data.begin(), sec.data.end(),
                      static_cast<std::uint8_t>(0));
        }
    }
}

std::vector<std::size_t> collect_target_sections(
    const PeImage&        image,
    const SectionNameMap& names)
{
    std::vector<std::size_t> indices;
    for (std::size_t i = 0; i < image.sections().size(); ++i) {
        const auto& sec = image.sections()[i];
        if (sec.data.empty()) continue;
        if (sec.name == ".text"     ||
            sec.name == names.cff   ||
            sec.name == names.vm)
        {
            indices.push_back(i);
        }
    }
    return indices;
}

std::optional<OepStealResult> prepare_oep_steal(
    ProtectionContext& ctx,
    std::string_view   steal_label)
{
    apply_dll_characteristics_audit(ctx);

    const bool is_driver   = ctx.target().is_kernel_driver();
    const bool is_efi      = ctx.target().is_efi_application();
    const bool keep_relocs = is_driver || is_efi ||
                             ctx.target().is_manually_mapped();
    if (!keep_relocs) {
        disable_relocations(ctx.pe_image());
        ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");
    } else if (is_driver) {
        ctx.log("PackerPass: .reloc preserved, RELOCS_STRIPPED not forced "
                "(driver stub emits no absolute VAs; mapper may load at "
                "any base)");
    } else if (is_efi) {
        ctx.log("PackerPass: .reloc preserved, RELOCS_STRIPPED not forced "
                "(UEFI firmware applies non-encrypted relocs at load; "
                "encrypted-section relocs partitioned for inline applier)");
    } else {
        // User-mode manual-map. Force RELOCS_STRIPPED so a relocation-
        // respecting loader lands the image at the preferred base —
        // the stub's TLS callback array holds absolute VAs that
        // require it. Leave the `.reloc` directory bytes intact for
        // mappers that ignore the flag; partitioning guarantees they
        // do not corrupt ciphertext.
        std::visit([&](auto& nt) {
            nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        }, ctx.pe_image().nt_headers());
        ctx.log("PackerPass: manual-map — RELOCS_STRIPPED set "
                "(TLS absolute VAs require preferred base); "
                ".reloc preserved for mappers that ignore the flag");
    }

    const Rva oep_rva = ctx.pe_image().entry_point_rva();
    if (oep_rva == 0) {
        ctx.log("PackerPass: entry point == 0, пропуск");
        return std::nullopt;
    }

    auto& sections = ctx.pe_image().sections();
    std::size_t section_index = sections.size();
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const auto& s = sections[i];
        if (oep_rva >= s.virtual_address &&
            oep_rva < s.virtual_address + s.virtual_size)
        {
            section_index = i;
            break;
        }
    }
    if (section_index == sections.size()) {
        ctx.log("PackerPass: entry RVA вне секций, пропуск");
        return std::nullopt;
    }

    OepStealResult result{};
    result.section_index = section_index;
    result.oep_rva       = oep_rva;

    auto& oep_target = sections[section_index];
    const std::uint32_t oep_off = oep_rva - oep_target.virtual_address;
    result.plan = plan_stolen_bytes(
        ByteView{oep_target.data.data(), oep_target.data.size()},
        oep_off, oep_rva);

    if (result.plan.size > 0) {
        result.stolen_bytes.assign(
            oep_target.data.begin() + oep_off,
            oep_target.data.begin() + oep_off + result.plan.size);
        std::fill(oep_target.data.begin() + oep_off,
                  oep_target.data.begin() + oep_off + result.plan.size,
                  static_cast<std::uint8_t>(0xCC));
        ctx.log_fmt("PackerPass: украдено {} байт {} (0x{:08X}), {} CALL-fixup",
            result.plan.size, steal_label, oep_rva,
            static_cast<std::uint32_t>(result.plan.relocs.size()));
    } else {
        ctx.log_fmt("PackerPass: {} небезопасен для stolen bytes — пропуск",
            steal_label);
    }

    return result;
}

MxResult<PackerStubInjection> finalize_packer_stub(
    ProtectionContext&       ctx,
    ByteBuffer&&             stub_buf,
    pe::SectionIntent        intent,
    const OepStealResult&    steal,
    const CommonStubPatches& common)
{
    SectionManager sec_mgr(ctx.pe_image());
    pe::SectionEmitter emit{sec_mgr, ctx.layout_policy()};
    const std::string& packer_section_name = ctx.section_names().packer;
    auto add_res = emit.append_section(
        packer_section_name,
        ByteView{stub_buf.data(), stub_buf.size()},
        intent);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const std::uint32_t pack_idx = *add_res;
    auto& pack_sec = ctx.pe_image().sections()[pack_idx];
    const Rva stub_rva = pack_sec.virtual_address;

    ctx.log_fmt("PackerPass: секция '{}' добавлена: RVA=0x{:08X}, размер={} байт",
        packer_section_name, stub_rva,
        static_cast<std::uint32_t>(pack_sec.data.size()));

    // jmp rel32 → real entry + stolen_size
    {
        const Rva resume_rva  = steal.oep_rva + steal.plan.size;
        const Rva jmp_end_rva = stub_rva + common.rel_to_oep_at + 4;
        const std::int32_t rel = static_cast<std::int32_t>(
            static_cast<std::int64_t>(resume_rva) -
            static_cast<std::int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, common.rel_to_oep_at, rel);
    }

    // Fix up CALL rel32 inside the stolen payload so each target RVA
    // stays identical after the move into the stub section.
    for (const auto& r : steal.plan.relocs) {
        const std::uint32_t rel_abs_offset =
            common.stolen_bytes_offset + r.offset_in_stolen;
        const std::uint32_t instr_end_abs =
            common.stolen_bytes_offset + r.instr_end_in_stolen;
        const Rva new_instr_end_rva = stub_rva + instr_end_abs;
        const std::int32_t new_rel = static_cast<std::int32_t>(
            static_cast<std::int64_t>(r.original_target_rva) -
            static_cast<std::int64_t>(new_instr_end_rva));
        write_i32(pack_sec.data, rel_abs_offset, new_rel);
    }

    ctx.pe_image().set_entry_point_rva(stub_rva);
    std::visit([&](auto& nt) {
        nt.OptionalHeader.AddressOfEntryPoint = stub_rva;
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: entry перенаправлен 0x{:08X} -> 0x{:08X}",
        steal.oep_rva, stub_rva);

    return PackerStubInjection{pack_idx, stub_rva};
}

} // namespace mx::packer
