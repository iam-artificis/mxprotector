/**
 * @file guard_region_finalizer.cpp
 * @brief Implementation of `finalize_guard_regions` — see header.
 */

#include "mxprotector/protection/guard/guard_region_finalizer.hpp"

#include <array>
#include <cstring>

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

namespace mx::guard {

namespace {

/// Size of the 5-byte `jmp rel32` that replaces the begin-marker.
constexpr uint32_t kJmpRel32Size = 5;

/// Write `jmp rel32 <target>` at `offset`, pad the rest with NOPs.
///
/// Pre-conditions (caller-verified):
///   * `patch_size >= kJmpRel32Size`
///   * `offset + patch_size <= section.data.size()`
void write_jmp_rel32_and_pad(
    pe::SectionInfo& section,
    uint32_t         offset,
    uint32_t         patch_size,
    Rva              source_rva,
    Rva              target_rva) noexcept
{
    const auto rel32 = static_cast<int32_t>(
        static_cast<int64_t>(target_rva) -
        static_cast<int64_t>(source_rva) -
        static_cast<int64_t>(kJmpRel32Size));

    MutableByteView span{section.data.data() + offset, patch_size};
    asm64::write_jmp_rel32(span.subspan(0, kJmpRel32Size), rel32);
    if (patch_size > kJmpRel32Size) {
        asm64::fill_nop(span.subspan(kJmpRel32Size));
    }
}

/// Little-endian 32-bit write at a precomputed offset.
void write_u32_le(ByteBuffer& buf, uint32_t offset, uint32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

} // anonymous namespace

MxStatus finalize_guard_regions(
    ProtectionContext&               ctx,
    pe::SectionInfo&                 guard_section,
    const std::vector<PendingGuard>& pendings,
    uint32_t                         descriptor_table_offset,
    Randomizer&                      rng,
    std::vector<GuardDescriptor>&    out_descriptors)
{
    auto&     sections          = ctx.pe_image().sections();
    const Rva guard_section_rva = guard_section.virtual_address;

    for (const auto& pg : pendings) {
        const Rva page_rva =
            guard_section_rva + pg.page_offset_in_section;
        const Rva entry_int3_rva = page_rva + pg.layout.entry_int3_offset;
        const Rva body_start_rva = page_rva + pg.layout.body_offset;
        const Rva exit_int3_rva  = page_rva + pg.layout.exit_int3_offset;

        // ---- Source-side jmp patching ----
        if (pg.source_section_index >= sections.size()) {
            ctx.log_fmt("  GuardPass: guard #{} source_section_index {} "
                        "вне границ, пропуск",
                pg.guard_id, pg.source_section_index);
            continue;
        }
        auto& src_sec = sections[pg.source_section_index];
        if (pg.source_begin_marker_rva < src_sec.virtual_address) {
            ctx.log_fmt("  GuardPass: guard #{} begin_rva вне секции, "
                        "пропуск",
                pg.guard_id);
            continue;
        }
        const uint32_t src_offset =
            pg.source_begin_marker_rva - src_sec.virtual_address;
        if (src_offset + pg.source_total_patch_size > src_sec.data.size()) {
            ctx.log_fmt("  GuardPass: guard #{} patch-range вне буфера, "
                        "пропуск",
                pg.guard_id);
            continue;
        }
        write_jmp_rel32_and_pad(
            src_sec,
            src_offset,
            pg.source_total_patch_size,
            pg.source_begin_marker_rva,
            entry_int3_rva);

        // ---- Descriptor table entry ----
        //
        // The 64-byte descriptor layout must match the offsets the
        // VEH handler's emitted byte stream bakes in:
        //
        //   +0x00  entry_int3_rva           (walked by cmp [rsi])
        //   +0x04  exit_int3_rva            (walked by cmp [rsi+4])
        //   +0x08  body_start_rva           (loaded by mov eax, [rsi+8])
        //   +0x0C  return_rva               (loaded by mov eax, [rsi+12])
        //   +0x10  body_size                (loaded by mov ecx, [rsi+0x10])
        //   +0x14  open_count = 0           (LOCK XADD target)
        //   +0x18..+0x38  per-guard XOR key (indexed by [rsi+r9+0x18])
        //   +0x38..+0x40  reserved (zero)
        //
        // The key is generated fresh per guard from the same randomiser
        // the page layout uses. Every guard gets its own 32 random
        // bytes — two guards never share a key, so leaking one body's
        // plaintext does not compromise any other body.
        const uint32_t entry_offset_in_section =
            descriptor_table_offset + pg.guard_id * kGuardDescriptorStride;

        write_u32_le(guard_section.data, entry_offset_in_section + 0x00,
                     entry_int3_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x04,
                     exit_int3_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x08,
                     body_start_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x0C,
                     pg.return_rva);
        write_u32_le(guard_section.data, entry_offset_in_section + 0x10,
                     pg.layout.body_size);
        // open_count is already zero from the initial resize of
        // section_data, but be explicit for auditability.
        write_u32_le(guard_section.data, entry_offset_in_section + 0x14, 0);

        // --- Per-guard key ---
        std::array<uint8_t, kGuardDescriptorKeySize> key{};
        for (auto& b : key) b = rng.next_u8();
        std::memcpy(
            guard_section.data.data()
                + entry_offset_in_section + kGuardDescriptorKeyOffset,
            key.data(),
            key.size());

        // --- XOR-encrypt body bytes in place ---
        //
        // The body currently sits at [page_offset + body_offset ..
        // page_offset + body_offset + body_size) as plaintext (it was
        // written verbatim by build_guard_page). Encrypt it in place
        // with the freshly-generated key so that the dump-on-disk
        // `.mxguard` section shows ciphertext for every guard body;
        // the VEH decrypts on entry and re-encrypts on exit via the
        // same XOR pass (XOR is self-inverse).
        //
        // The int3+tag windows at [page_offset + 0..5) and
        // [page_offset + body_offset + body_size .. + body_offset +
        // body_size + 5) are deliberately NOT touched — they are the
        // plaintext "skip windows" the CPU needs to execute to raise
        // STATUS_BREAKPOINT.
        {
            const uint32_t body_start_in_section =
                pg.page_offset_in_section + pg.layout.body_offset;
            for (uint32_t i = 0; i < pg.layout.body_size; ++i) {
                guard_section.data[body_start_in_section + i] ^=
                    key[i % kGuardDescriptorKeySize];
            }
        }

        GuardDescriptor d{};
        d.source_section_index    = pg.source_section_index;
        d.source_begin_marker_rva = pg.source_begin_marker_rva;
        d.source_body_start_rva   = pg.source_body_start_rva;
        d.source_body_end_rva     = pg.source_body_end_rva;
        d.source_total_patch_size = pg.source_total_patch_size;
        d.return_rva              = pg.return_rva;
        d.guard_id                = pg.guard_id;
        d.page_rva                = page_rva;
        d.body_offset             = pg.layout.body_offset;
        d.body_size               = pg.layout.body_size;
        d.entry_int3_rva          = entry_int3_rva;
        d.exit_int3_rva           = exit_int3_rva;
        d.body_start_rva          = body_start_rva;
        out_descriptors.push_back(d);

        ctx.log_fmt("  GuardPass: guard #{} [RVA 0x{:08X}..0x{:08X}] "
                    "({} байт) → page 0x{:08X}, body 0x{:08X}, "
                    "exit 0x{:08X}, return 0x{:08X}",
            d.guard_id,
            d.source_begin_marker_rva,
            d.source_begin_marker_rva + d.source_total_patch_size,
            d.body_size,
            d.page_rva,
            d.body_start_rva,
            d.exit_int3_rva,
            d.return_rva);
    }

    return {};
}

} // namespace mx::guard
