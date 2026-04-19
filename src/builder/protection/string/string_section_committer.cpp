/**
 * @file string_section_committer.cpp
 * @brief Implementation of `commit_string_section` — see header.
 */

#include "mxprotector/protection/string/string_section_committer.hpp"

#include <algorithm>
#include <cstring>

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/pe/section_manager.hpp"

namespace mx::string_protect {

namespace {

/// Write `value` little-endian into `buf[offset..offset+4]`. No-op
/// if the offset would exceed the buffer size — callers enforce
/// bounds, this is a last-resort guard.
void write_i32_le(std::vector<uint8_t>& buf, size_t offset, int32_t value) noexcept {
    if (offset + 4 > buf.size()) return;
    buf[offset + 0] = static_cast<uint8_t>(value & 0xFF);
    buf[offset + 1] = static_cast<uint8_t>((value >> 8)  & 0xFF);
    buf[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

/// Rewrite a LEA site in place with `call rel32 <trampoline>` plus
/// NOP padding up to the original instruction length. Operates on
/// the SectionInfo holding the LEA — discovered by RVA lookup.
void rewrite_lea_as_call(
    PeImage& image,
    Rva      lea_rva,
    uint8_t  lea_length,
    Rva      trampoline_rva) noexcept
{
    auto* sec = const_cast<pe::SectionInfo*>(image.section_by_rva(lea_rva));
    if (sec == nullptr) return;
    const uint32_t off = lea_rva - sec->virtual_address;
    if (off + lea_length > sec->data.size()) return;
    if (lea_length < 5) return;  // call rel32 needs 5 bytes minimum

    // call rel32 = E8 <rel32>, rel32 = target - (lea_rva + 5)
    const int32_t rel = static_cast<int32_t>(
        static_cast<int64_t>(trampoline_rva) -
        (static_cast<int64_t>(lea_rva) + 5));

    MutableByteView span{sec->data.data() + off, lea_length};
    asm64::write_call_rel32(span.subspan(0, 5), rel);
    // NOP pad the remainder. A single 0x90 per byte is uglier than
    // a multi-byte NOP but correctness-identical; the tail is at
    // most 2 bytes for a standard 7-byte LEA.
    if (span.size() > 5) {
        asm64::fill_nop(span.subspan(5));
    }
}

/// Zero the plaintext bytes of the given string range in its owning
/// source section. Called after the ciphertext and xrefs have been
/// committed, so the final binary has no plaintext copy of the
/// string to feed `strings`.
void wipe_plaintext(PeImage& image, Rva start, uint32_t length) noexcept {
    auto* sec = const_cast<pe::SectionInfo*>(image.section_by_rva(start));
    if (sec == nullptr) return;
    const uint32_t off = start - sec->virtual_address;
    if (off + length > sec->data.size()) return;
    std::fill(sec->data.begin() + off,
              sec->data.begin() + off + length,
              static_cast<uint8_t>(0));
}

} // anonymous namespace

MxStatus commit_string_section(
    ProtectionContext&         ctx,
    const GatheredStrings&     gathered,
    const StringArtifacts&     artifacts,
    const StringSectionLayout& layout)
{
    auto& image = ctx.pe_image();

    // (8) Add the section — SectionManager assigns its final RVA.
    //
    // The section holds both code (mx_str_get + trampolines) and
    // data (descriptor table + ciphertext pool). WRITABLE is
    // required because the decryptor does in-place XOR over the
    // data pool on first call per string and flips the sticky flag
    // inside the descriptor. EXECUTE lets the trampolines and
    // mx_str_get run. READ is included for clarity even though
    // EXECUTE implies it on x64.
    constexpr uint32_t str_section_characteristics =
        pe::IMAGE_SCN_CNT_CODE     |
        pe::IMAGE_SCN_MEM_EXECUTE  |
        pe::IMAGE_SCN_MEM_READ     |
        pe::IMAGE_SCN_MEM_WRITE;

    const std::string& str_section_name = ctx.section_names().str;
    SectionManager sec_mgr(image);
    auto add_res = sec_mgr.add_section(
        str_section_name,
        ByteView{layout.section_buf.data(), layout.section_buf.size()},
        str_section_characteristics);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t added_idx   = *add_res;
    auto&          added_sec   = image.sections()[added_idx];
    const Rva      section_rva = added_sec.virtual_address;

    // (9) Patch the rip+disp32 slots inside `mx_str_get`.
    //
    //   disp32_abs  = decryptor_offset + disp32_offset_in_code
    //   lea_end_rva = section_rva + disp32_abs + 4
    //   rel32       = target_rva - lea_end_rva
    //
    // Stub / VM variants use two LEAs (desc_table, data_pool). The
    // S3 ephemeral variant adds a third LEA for the scratch ring.
    {
        const auto patch_lea =
            [&](size_t disp_offset_in_code, size_t target_offset) noexcept
        {
            const size_t  disp_abs    =
                layout.decryptor_offset + disp_offset_in_code;
            const Rva     target_rva  = section_rva + static_cast<Rva>(target_offset);
            const Rva     lea_end_rva =
                section_rva + static_cast<Rva>(disp_abs) + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(target_rva) -
                static_cast<int64_t>(lea_end_rva));
            write_i32_le(added_sec.data, disp_abs, rel);
        };

        patch_lea(artifacts.decryptor_desc_disp32_off, layout.desc_table_offset);
        patch_lea(artifacts.decryptor_data_disp32_off, layout.data_pool_offset);
        if (gathered.is_ephemeral_mode) {
            patch_lea(artifacts.decryptor_ring_disp32_off,
                      layout.scratch_ring_offset);
        }
    }

    // (10) Patch each trampoline's `call rel32 → mx_str_get`.
    {
        const Rva decryptor_target_rva =
            section_rva + static_cast<Rva>(layout.decryptor_offset);
        for (size_t i = 0; i < artifacts.trampolines.size(); ++i) {
            const size_t tr_off       = layout.trampoline_offsets[i];
            const size_t call_rel_abs =
                tr_off + artifacts.trampolines[i].call_rel32_offset;
            const Rva    call_end_rva =
                section_rva + static_cast<Rva>(call_rel_abs) + 4;
            const int32_t rel = static_cast<int32_t>(
                static_cast<int64_t>(decryptor_target_rva) -
                static_cast<int64_t>(call_end_rva));
            write_i32_le(added_sec.data, call_rel_abs, rel);
        }
    }

    // (10a) S2c — if the VM-lifted loop was generated, overwrite
    // the plaintext decrypt loop inside `mx_str_get` with
    // `call vm_entry` + NOP padding. Execution flow becomes:
    //
    //   [header + claim + setup]  (bytes 0..72, unchanged)
    //   [call vm_entry]           (bytes 73..77, 5 bytes)
    //   [nop slide]               (bytes 78..83, 6 bytes)
    //   [mark_done + restore]     (bytes 84..92, unchanged)
    //
    // When the VM's exit handler runs its own `ret`, control
    // returns to byte 78, slides through the NOPs to `.mark_done`
    // at byte 84, then the plaintext done-flag store, `mov rax, r9`,
    // and final `ret` run verbatim. The `jz .mark_done` fast-skip
    // for empty strings at byte 71 still targets byte 84 directly,
    // so the rcx==0 short path bypasses the VM entirely.
    if (layout.vm_lift_succeeded) {
        const Rva vm_entry_rva =
            section_rva +
            static_cast<Rva>(layout.vm_blob_offset) +
            static_cast<Rva>(layout.vm_blob_entry_offset);
        const size_t loop_start_abs =
            layout.decryptor_offset + kMxStrGetLoopOffset;
        const Rva    loop_start_rva =
            section_rva + static_cast<Rva>(loop_start_abs);
        const Rva    call_end_rva   = loop_start_rva + 5;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(vm_entry_rva) -
            static_cast<int64_t>(call_end_rva));

        // Loop window must be at least 5 bytes so we can fit a
        // `call rel32`. Asserted at build time to catch codegen
        // drift rather than at runtime in the protected binary.
        static_assert(kMxStrGetLoopSize >= 5,
                      "VM loop window must hold at least a call rel32");

        // NOP pad from byte loop_start+5 up to `.mark_done` at
        // decryptor_offset + kMxStrGetLoopEndOffset.
        const size_t loop_end_abs =
            layout.decryptor_offset + kMxStrGetLoopEndOffset;
        MutableByteView span{
            added_sec.data.data() + loop_start_abs,
            loop_end_abs - loop_start_abs};
        asm64::write_call_rel32(span.subspan(0, 5), rel);
        if (span.size() > 5) {
            asm64::fill_nop(span.subspan(5));
        }
        ctx.log_fmt("StringProtectionPass: --strings=vm: mx_str_get XOR "
                    "loop replaced with call vm_entry @ RVA=0x{:08X}",
            vm_entry_rva);
    }

    // (11) Rewrite each source LEA in place with
    //      `call rel32 <trampoline>` + NOP pad.
    for (size_t i = 0; i < gathered.usable_xrefs.size(); ++i) {
        const auto& x         = gathered.usable_xrefs[i];
        const Rva   tramp_rva =
            section_rva + static_cast<Rva>(layout.trampoline_offsets[i]);
        rewrite_lea_as_call(image, x.xref_rva, x.insn_length, tramp_rva);
    }

    // (12) Wipe plaintext of every kept string — one wipe per
    //      string (bytes are the same regardless of xref count).
    for (const auto& ks : gathered.kept_strings) {
        wipe_plaintext(image, ks.rva_start, ks.length);
    }

    ctx.log_fmt(
        "StringProtectionPass: защищено {} строк, переписано {} LEA xref'ов, "
        "режим={}, секция '{}' RVA=0x{:08X} размер={} байт",
        artifacts.encrypted.size(),
        gathered.usable_xrefs.size(),
        string_protection_mode_name(ctx.config().string_protection),
        str_section_name,
        section_rva,
        static_cast<uint32_t>(added_sec.data.size()));

    return {};
}

} // namespace mx::string_protect
