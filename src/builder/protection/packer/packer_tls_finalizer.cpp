/**
 * @file packer_tls_finalizer.cpp
 * @brief P4 TLS finaliser — implementation.
 *
 * Split out of `packer_pass.cpp` (R2.5). Every byte written by this
 * function matches the inlined version that used to live inside
 * `PackerPipeline::step6_finalize_tls`.
 */

#include "mxprotector/protection/packer/packer_tls_finalizer.hpp"

#include <variant>

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"

namespace mx::packer {

void finalize_tls_metadata(
    mx::ProtectionContext&   ctx,
    ByteBuffer&              section_data,
    Rva                      stub_rva,
    const StubArtifactsInfo& artifacts)
{
    const auto image_base =
        static_cast<uint64_t>(ctx.pe_image().image_base());
    const uint64_t cb_body_va =
        image_base + stub_rva + artifacts.tls_cb.body_offset;
    const uint64_t tls_dir_va =
        image_base + stub_rva + artifacts.tls_dir_offset_in_stub;
    const uint64_t cb_array_va =
        image_base + stub_rva + artifacts.tls_cb_array_offset_in_stub;

    // 1. Patch the `xor byte [rip + rel32], imm8` inside the
    //    callback body to point at one byte of a per-build random
    //    cipher layer's RC4 key. Corrupting ANY layer's key is
    //    sufficient to cascade: a wrong S-box for one layer produces
    //    a wrong PRGA output which means the other layers decrypt
    //    the intermediate bytes into garbage. Randomising the target
    //    layer per build denies reversers a stable pivot — extracting
    //    the corruption site from one binary tells them nothing
    //    about the next. The rel32 is computed from the end of the
    //    xor instruction (`xor_instruction_end`) to the target byte.
    const uint32_t key_target_offset_in_stub =
        artifacts.key_offsets_in_stub[artifacts.tls_cb.key_layer_index] +
        artifacts.tls_cb.key_byte_offset_in_key;
    const int32_t xor_rel32 = static_cast<int32_t>(
        static_cast<int64_t>(key_target_offset_in_stub) -
        static_cast<int64_t>(artifacts.tls_cb.xor_instruction_end));
    write_i32(section_data, artifacts.tls_cb.xor_key_rel32_offset, xor_rel32);

    // 2. Fill the callback array: our packer callback first, then
    //    (optional) the runtime-guards VEH installer from
    //    `ctx.extra_tls_callback_va`, then every existing callback
    //    from the input TLS directory in its original order, then a
    //    NULL terminator.
    //
    // Ordering rationale: packer_cb MUST run first so the anti-debug
    // key-corruption gag fires before any other callback has a chance
    // to inspect the stub. The guard installer MUST run before any
    // existing user callback because user callbacks may execute code
    // that later triggers guarded paths — if the VEH isn't installed
    // yet, those int3s crash the process. So:
    //     [packer_cb][guard_install_cb?][user_cb_0][user_cb_1]...[NULL]
    uint32_t write_off = artifacts.tls_cb_array_offset_in_stub;
    write_u64_le(section_data, write_off, cb_body_va);
    write_off += 8;
    if (artifacts.has_extra_tls_cb) {
        write_u64_le(section_data, write_off, ctx.extra_tls_callback_va());
        write_off += 8;
    }
    if (artifacts.existing_tls_opt.has_value()) {
        for (const uint64_t old_cb : artifacts.existing_tls_opt->callbacks) {
            write_u64_le(section_data, write_off, old_cb);
            write_off += 8;
        }
    }
    write_u64_le(section_data, write_off, 0);  // terminator

    // 3. Fill the TLS directory. Non-callback fields come from the
    //    existing directory when present, so C++
    //    `__declspec(thread)` data still works.
    uint64_t index_va        = 0;
    uint64_t start_va        = 0;
    uint64_t end_va          = 0;
    uint32_t zero_fill       = 0;
    uint32_t characteristics = 0;
    if (artifacts.existing_tls_opt.has_value()) {
        const auto& ex  = *artifacts.existing_tls_opt;
        start_va        = ex.start_va;
        end_va          = ex.end_va;
        index_va        = ex.index_va;
        zero_fill       = ex.size_of_zero_fill;
        characteristics = ex.characteristics;
    } else {
        // No existing TLS — point AddressOfIndex at our own 4-byte
        // scratch slot inside .mxpack.
        index_va = image_base + stub_rva + artifacts.tls_index_slot_offset_in_stub;
    }
    write_u64_le(section_data, artifacts.tls_dir_offset_in_stub + 0x00, start_va);
    write_u64_le(section_data, artifacts.tls_dir_offset_in_stub + 0x08, end_va);
    write_u64_le(section_data, artifacts.tls_dir_offset_in_stub + 0x10, index_va);
    write_u64_le(section_data, artifacts.tls_dir_offset_in_stub + 0x18, cb_array_va);
    write_u32_le(section_data, artifacts.tls_dir_offset_in_stub + 0x20, zero_fill);
    write_u32_le(section_data, artifacts.tls_dir_offset_in_stub + 0x24, characteristics);

    // 4. Point the PE header's TLS data directory at our new
    //    in-.mxpack directory.
    const Rva tls_dir_rva =
        static_cast<Rva>(stub_rva + artifacts.tls_dir_offset_in_stub);
    std::visit([&](auto& nt) {
        if (pe::IMAGE_DIRECTORY_ENTRY_TLS < nt.OptionalHeader.NumberOfRvaAndSizes) {
            nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
                = tls_dir_rva;
            nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].Size
                = 40;
        }
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: P4 TLS callback planted @ RVA=0x{:08X}, "
                "chain length {} (existing={}, ours=1), "
                "corrupts key[layer={}, byte={}]",
        stub_rva + artifacts.tls_cb.body_offset,
        static_cast<uint32_t>(artifacts.tls_cb_array_entries - 1),
        artifacts.existing_tls_opt.has_value()
            ? static_cast<uint32_t>(artifacts.existing_tls_opt->callbacks.size())
            : 0u,
        artifacts.tls_cb.key_layer_index,
        artifacts.tls_cb.key_byte_offset_in_key);
    (void)tls_dir_va;  // reserved for future use (direct self-reference)
}

} // namespace mx::packer
