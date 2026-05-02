/**
 * @file guard_handler_back_patcher.cpp
 * @brief Implementation of `back_patch_guard_handlers` — see header.
 */

#include "mxprotector/protection/guard/guard_handler_back_patcher.hpp"

#include <array>
#include <cstring>

#include "mxprotector/common/hash/fnv1a.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/guard/guard_descriptor.hpp"

namespace mx::guard {

namespace {

/// Little-endian writes at precomputed offsets. Matching the shape
/// used by the pre-decomposition inline helpers so the byte layout
/// of every patch is unchanged.
void write_u32_le(ByteBuffer& buf, uint32_t offset, uint32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

void write_i32_le(ByteBuffer& buf, uint32_t offset, int32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

} // anonymous namespace

MxStatus back_patch_guard_handlers(
    ProtectionContext&               ctx,
    pe::SectionInfo&                 guard_section,
    const GuardSectionAssembly&      a,
    const std::vector<PendingGuard>& pendings)
{
    const Rva guard_section_rva = guard_section.virtual_address;
    const Rva veh_handler_rva   = guard_section_rva + a.veh_handler_offset;

    // --- VEH: module_base sub imm32 -----------------------------------
    // The handler reads its runtime RIP via `lea rbx, [rip + 0]` and
    // immediately subtracts a build-time imm32 equal to that LEA's
    // rip so `rbx = module_base`. The imm32 is the RVA of the byte
    // right after the lea (its anchor).
    const uint32_t module_base_anchor_rva =
        veh_handler_rva + a.veh_patches.module_base_lea_anchor_offset;
    write_i32_le(
        guard_section.data,
        a.veh_handler_offset + a.veh_patches.module_base_sub_imm32_offset,
        static_cast<int32_t>(module_base_anchor_rva));

    // --- VEH: descriptor table rel32 ----------------------------------
    const Rva descriptor_table_rva =
        guard_section_rva + a.descriptor_table_offset;
    const Rva veh_table_rel32_end_rva =
        veh_handler_rva + a.veh_patches.descriptor_table_rel32_end_offset;
    const int32_t table_rel32 = static_cast<int32_t>(
        static_cast<int64_t>(descriptor_table_rva) -
        static_cast<int64_t>(veh_table_rel32_end_rva));
    write_i32_le(
        guard_section.data,
        a.veh_handler_offset + a.veh_patches.descriptor_table_rel32_offset,
        table_rel32);

    // --- VEH: descriptor count imm32 ----------------------------------
    write_u32_le(
        guard_section.data,
        a.veh_handler_offset + a.veh_patches.descriptor_count_imm32_offset,
        a.descriptor_count);

    // --- TLS installer: handler rel32 ---------------------------------
    // Both the TLS installer and the VEH handler live inside the
    // same `.mxguard` section, so the rel32 is simply the section-
    // relative offset difference.
    const uint32_t tls_handler_rel32_end_in_section =
        a.tls_installer_offset + a.tls_patches.handler_rel32_end_offset;
    const int32_t handler_rel32 = static_cast<int32_t>(
        static_cast<int64_t>(a.veh_handler_offset) -
        static_cast<int64_t>(tls_handler_rel32_end_in_section));
    write_i32_le(
        guard_section.data,
        a.tls_installer_offset + a.tls_patches.handler_rel32_offset,
        handler_rel32);

    // Handler byte count — the handler proper, EXCLUDING the decrypt
    // unit (which lives as a separate callable blob right after the
    // handler). Used by both the self-hash walk and the CRC.
    const uint32_t veh_handler_size =
        a.decrypt_unit_offset - a.veh_handler_offset;

    // --- VEH: two `call rel32 → decrypt_vm_entry` slots ---------------
    // Both calls target the same VM entry but from different
    // emission sites; the rel32s differ because the call-end offsets
    // differ.
    {
        const uint32_t decrypt_entry =
            a.decrypt_unit_offset + a.decrypt_vm_entry_offset;

        const uint32_t entry_slot_in_section =
            a.veh_handler_offset +
            a.veh_patches.entry_call_decrypt_rel32_offset;
        const int32_t entry_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(decrypt_entry) -
            static_cast<int64_t>(entry_slot_in_section + 4));
        write_i32_le(guard_section.data, entry_slot_in_section, entry_rel32);

        const uint32_t exit_slot_in_section =
            a.veh_handler_offset +
            a.veh_patches.exit_call_decrypt_rel32_offset;
        const int32_t exit_rel32 = static_cast<int32_t>(
            static_cast<int64_t>(decrypt_entry) -
            static_cast<int64_t>(exit_slot_in_section + 4));
        write_i32_le(guard_section.data, exit_slot_in_section, exit_rel32);
    }

    // --- Self-hash walk patch slots (BEFORE CRC!) ---------------------
    //
    // These write to HANDLER bytes and MUST happen before the CRC
    // computation below, otherwise the build-time CRC would be
    // computed on the pre-patch zeros while the runtime CRC walk
    // sees the patched values → mismatch → installer skips
    // AddVectoredExceptionHandler → first guard int3 goes unhandled.
    write_i32_le(
        guard_section.data,
        a.veh_handler_offset + a.veh_patches.self_hash_sub_imm32_offset,
        static_cast<int32_t>(a.veh_patches.self_hash_lea_anchor_offset));

    write_u32_le(
        guard_section.data,
        a.veh_handler_offset + a.veh_patches.self_hash_size_imm32_offset,
        veh_handler_size);

    // --- Self-CRC over the VEH handler bytes --------------------------
    //
    // The TLS installer walks the handler byte-range at runtime and
    // computes fnv1a_32 over it, comparing against this build-time
    // baked expected value. Any write to the handler range that
    // happens AFTER this point will shift the hash and break the
    // installer's registration path.
    const uint32_t handler_crc = mx::hash::fnv1a_32(
        ByteView{
            guard_section.data.data() + a.veh_handler_offset,
            veh_handler_size});

    // --- TLS installer: crc_walk_rel32 / size / expected imm32 --------
    const uint32_t crc_walk_rel32_end_in_section =
        a.tls_installer_offset + a.tls_patches.crc_walk_rel32_end_offset;
    const int32_t crc_walk_rel32 = static_cast<int32_t>(
        static_cast<int64_t>(a.veh_handler_offset) -
        static_cast<int64_t>(crc_walk_rel32_end_in_section));
    write_i32_le(
        guard_section.data,
        a.tls_installer_offset + a.tls_patches.crc_walk_rel32_offset,
        crc_walk_rel32);

    write_u32_le(
        guard_section.data,
        a.tls_installer_offset + a.tls_patches.crc_size_imm32_offset,
        veh_handler_size);

    write_u32_le(
        guard_section.data,
        a.tls_installer_offset + a.tls_patches.crc_expected_imm32_offset,
        handler_crc);

    ctx.log_fmt("GuardPass: VEH handler CRC = 0x{:08X} over {} bytes @ 0x{:X}",
        handler_crc, veh_handler_size, veh_handler_rva);

    // --- XOR-mask stored per-guard keys with the handler CRC ----------
    //
    // Each per-guard stored key is XOR'd with the 4-byte hash
    // (cycling every 4 bytes). At runtime the VEH's decrypt_body
    // subroutine XORs each stored_key byte with the corresponding
    // hash byte (via the rolling r8d register initialised from r11d)
    // before applying it to the body. The XOR is its own inverse,
    // so the two passes cancel and the body is decrypted with the
    // ORIGINAL key. An attacker reading the descriptor sees
    // `stored_key = real_key ^ hash_mask` — useless without
    // replicating the handler hash walk.
    const std::array<uint8_t, 4> hash_mask = {
        static_cast<uint8_t>(handler_crc),
        static_cast<uint8_t>(handler_crc >> 8),
        static_cast<uint8_t>(handler_crc >> 16),
        static_cast<uint8_t>(handler_crc >> 24),
    };
    for (const auto& pg : pendings) {
        const uint32_t key_offset_in_section =
            a.descriptor_table_offset
            + pg.guard_id * kGuardDescriptorStride
            + kGuardDescriptorKeyOffset;
        for (uint32_t i = 0; i < kGuardDescriptorKeySize; ++i) {
            guard_section.data[key_offset_in_section + i] ^=
                hash_mask[i % 4];
        }
    }

    return {};
}

} // namespace mx::guard
