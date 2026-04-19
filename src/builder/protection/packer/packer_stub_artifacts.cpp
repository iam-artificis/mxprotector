/**
 * @file packer_stub_artifacts.cpp
 * @brief Stub-tail artefact layout — implementation.
 *
 * Split out of `packer_pass.cpp` (R2.3). The sequence of appends and
 * alignment pads is byte-for-byte identical to the inlined block that
 * used to live in `PackerPipeline::step4_append_artifacts`. The only
 * observable differences are:
 *   - the P3 VM-lift is now delegated to
 *     `packer::try_lift_ksa_to_vm` (R2.2), behaviour unchanged;
 *   - every recorded offset is returned in a `StubArtifactsInfo`
 *     struct instead of being written to session-local fields.
 */

#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"

#include "mxprotector/core/asm_builder.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/protection/packer/packer_ksa_vm_lifter.hpp"
#include "mxprotector/protection/packer/rc4.hpp"

namespace mx::packer {

StubArtifactsInfo append_stub_artifacts(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     stub_buf,
    Randomizer&                     rng,
    const std::vector<ByteBuffer>&  layer_keys,
    uint32_t                        layer_count,
    size_t                          section_count,
    uint32_t                        ksa_block_start_offset,
    uint32_t                        ksa_block_end_offset)
{
    StubArtifactsInfo out{};

    // Append each layer's 32-byte RC4 key to the stub buffer and
    // record the stub-relative offsets so each layer's
    // `lea rsi, key_K` rel32 can be patched after the stub section
    // is injected.
    out.key_offsets_in_stub.resize(layer_count);
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        out.key_offsets_in_stub[layer] =
            static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(),
                        layer_keys[layer].begin(),
                        layer_keys[layer].end());
    }

    // S-box scratch: 256 bytes. At runtime the KSA overwrites the
    // whole region — the build-time content doesn't matter, we just
    // need the space inside the section so `lea r8, sbox` points at
    // valid memory.
    out.sbox_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), kSboxSize, uint8_t{0});

    // P3 — VM-protected KSA. Delegates to packer_ksa_vm_lifter, which
    // appends the VM runtime blob to `stub_buf` on success (plus the
    // needed 16-byte padding) and leaves the buffer untouched on any
    // failure path. The caller uses `packer_vm_lift_succeeded` to
    // decide whether to overwrite the plaintext KSA bytes with
    // `call rel32 <vm_entry>`.
    const auto p3 = try_lift_ksa_to_vm(
        ctx, stub_buf,
        ksa_block_start_offset,
        ksa_block_end_offset,
        rng);
    out.packer_vm_blob_offset    = p3.vm_blob_offset_in_stub;
    out.packer_vm_entry_offset   = p3.vm_entry_offset;
    out.packer_vm_lift_succeeded = p3.succeeded;

    // Embed the reprotect section table right after the VM blob.
    out.reprotect_table_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), section_count * 8, uint8_t{0});

    // --------------------------------------------------
    // P4 — TLS callback artefacts.
    //
    // Layout appended to the end of stub_buf (all inside the same
    // .mxpack section, so everything lives in one R+W+X page the
    // loader maps as one unit):
    //
    //     [callback body]           ~32 bytes
    //     [8-byte alignment pad]
    //     [IMAGE_TLS_DIRECTORY64]   40 bytes
    //     [8-byte alignment pad]
    //     [callback array]          (N+2) × 8 bytes, NULL terminated
    //     [optional index slot]     4 bytes, only if no existing TLS
    //
    // For inputs that already ship with a TLS directory (C++
    // programs with `__declspec(thread)` statics, for instance) we
    // parse the existing one first and preserve its fields —
    // StartAddressOfRawData / EndAddressOfRawData / AddressOfIndex /
    // SizeOfZeroFill / Characteristics — verbatim. The finalizer
    // prepends our new callback to the front of the existing
    // callback array so the anti-debug probe fires before any
    // CRT-registered TLS initialiser, and every original callback
    // still runs in its original order afterward.
    //
    // Everything past this point lives at a fixed offset inside
    // `stub_buf`; the runtime RVA of each slot is
    // `stub_rva + offset_in_stub_buf`. The TLS finalizer back-patches
    // these (along with the RC4-key rel32 inside the callback body)
    // after the .mxpack section has been placed.
    out.existing_tls_opt = read_existing_tls_directory(ctx.pe_image());

    // Align to 8 bytes before the callback body so every downstream
    // 8-byte field lands at a naturally-aligned offset.
    while (stub_buf.size() % 8 != 0) stub_buf.push_back(asm64::kInt3);

    out.tls_cb = emit_tls_callback_body(stub_buf, rng, layer_count);

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(asm64::kInt3);
    out.tls_dir_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), 40, uint8_t{0});  // IMAGE_TLS_DIRECTORY64

    while (stub_buf.size() % 8 != 0) stub_buf.push_back(asm64::kInt3);
    out.tls_cb_array_offset_in_stub =
        static_cast<uint32_t>(stub_buf.size());

    // Callback array sizing: packer_cb + (optional guard installer) +
    // existing user callbacks + NULL terminator. The guard installer
    // slot is only reserved when an earlier pass (GuardPass) set
    // `ctx.extra_tls_callback_va`; otherwise we keep the old layout.
    out.has_extra_tls_cb = ctx.extra_tls_callback_va() != 0;
    out.tls_cb_array_entries =
        (out.existing_tls_opt.has_value()
            ? out.existing_tls_opt->callbacks.size()
            : 0)
        + (out.has_extra_tls_cb ? 1u : 0u)
        + 2u;  // +1 for our packer cb, +1 for the NULL terminator
    stub_buf.insert(stub_buf.end(),
                    out.tls_cb_array_entries * 8,
                    uint8_t{0});

    // Index slot — only needed when the input had no TLS directory of
    // its own. If an existing directory was found its AddressOfIndex
    // already points at a valid 4-byte slot in one of the preserved
    // input sections, so we reuse that.
    if (!out.existing_tls_opt.has_value()) {
        while (stub_buf.size() % 4 != 0) stub_buf.push_back(asm64::kInt3);
        out.tls_index_slot_offset_in_stub =
            static_cast<uint32_t>(stub_buf.size());
        stub_buf.insert(stub_buf.end(), 4, uint8_t{0});
    }

    return out;
}

} // namespace mx::packer
