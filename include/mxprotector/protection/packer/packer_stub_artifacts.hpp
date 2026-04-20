/**
 * @file packer_stub_artifacts.hpp
 * @brief Post-emit stub-tail layout: layer keys, sbox, P3 VM blob,
 *        reprotect table, P4 TLS artefacts.
 *
 * After `StubEmitter::emit` produces the stub code bytes,
 * `append_stub_artifacts` walks a fixed layout and appends every
 * piece of data the runtime stub references:
 *
 *     [stub code]                    ← produced by Emitter
 *     [layer 0 key … layer N-1 key]  ← one 32-byte RC4 key per layer
 *     [sbox scratch]                 ← 256-byte RC4 S-box scratch
 *     [pad to 16]  [P3 VM blob]      ← optional — lifted KSA runtime
 *     [reprotect table]              ← `section_count * 8` zero bytes
 *     [pad to 8]   [TLS callback body]
 *     [pad to 8]   [IMAGE_TLS_DIRECTORY64]
 *     [pad to 8]   [TLS callback array]
 *     [pad to 4]   [TLS index slot]  ← only when no existing TLS
 *
 * Every offset inside the stub buffer is recorded in the returned
 * `StubArtifactsInfo` so the downstream patcher + TLS finalizer
 * steps can compute the corresponding runtime RVAs once the .mxpack
 * section is placed.
 *
 * The P3 VM-lift is an optional sub-step (internally delegated to
 * `packer::try_lift_ksa_to_vm`); a failure is logged and leaves the
 * `vm_lift_succeeded` flag false, letting the caller decide whether
 * to overwrite the plaintext KSA with a call into the VM runtime.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/tls_callback.hpp"

namespace mx { class ProtectionContext; }

namespace mx::packer {

/**
 * @brief All stub-relative offsets recorded while `append_stub_artifacts`
 *        walked its layout.
 *
 * The caller uses these to compute runtime RVAs and patch every
 * rel32 / imm32 / uint64_t inside the stub after the .mxpack section
 * is placed.
 */
struct StubArtifactsInfo {
    /// `key_offsets_in_stub[k]` — stub-relative offset of layer k's
    /// 32-byte RC4 key.
    std::vector<uint32_t> key_offsets_in_stub;

    /// Offset of the 256-byte RC4 S-box scratch.
    uint32_t sbox_offset_in_stub = 0;

    /// P3 VM-lift result. `vm_lift_succeeded == false` means the
    /// plaintext KSA was kept and the VM-blob fields are unused.
    size_t   packer_vm_blob_offset    = 0;
    uint32_t packer_vm_entry_offset   = 0;
    bool     packer_vm_lift_succeeded = false;

    /// Offset of the `section_count * 8` zero bytes that the runtime
    /// reprotect loop reads as `{Rva rva, uint32_t size}` entries.
    uint32_t reprotect_table_offset_in_stub = 0;

    /// Stub-private reloc blob (see `reloc_partition.hpp`). Zero when
    /// the caller did not hand us a blob or the blob was empty —
    /// the patcher treats zero-size as "no work for the applier".
    uint32_t stub_private_relocs_offset_in_stub = 0;
    uint32_t stub_private_relocs_size           = 0;

    /// Parsed input TLS directory (if any). Preserved so the caller
    /// can keep non-callback fields verbatim.
    std::optional<ExistingTlsDirectory> existing_tls_opt;

    /// Metadata recorded while `emit_tls_callback_body` ran.
    TlsCallbackEmit tls_cb{};

    /// Offsets of the three TLS-layout chunks inside the stub.
    uint32_t tls_dir_offset_in_stub        = 0;
    uint32_t tls_cb_array_offset_in_stub   = 0;
    /// Zero when an existing TLS directory supplied `AddressOfIndex`.
    uint32_t tls_index_slot_offset_in_stub = 0;

    /// True if `ctx.extra_tls_callback_va()` was nonzero at append
    /// time (i.e. GuardPass reserved a TLS slot for its VEH
    /// installer).
    bool   has_extra_tls_cb     = false;
    /// Total slots in the callback array, including our callback,
    /// the optional guard installer, every existing user callback,
    /// and the trailing NULL.
    size_t tls_cb_array_entries = 0;
};

/**
 * @brief Append every post-emit stub tail artefact to `stub_buf`
 *        and record their offsets.
 *
 * @param ctx                    Protection context — read for the
 *                               disassembler (P3 VM-lift gate),
 *                               pe_image (EXE/DLL key-gate), TLS
 *                               directory parsing, and log channel.
 * @param stub_buf               Stub bytes under construction —
 *                               every appended artefact grows this
 *                               buffer.
 * @param rng                    Randomiser used by the P3 VM-runtime
 *                               generator and the TLS callback body
 *                               emitter.
 * @param layer_keys             Per-layer 32-byte RC4 keys; the
 *                               function inserts their bytes
 *                               verbatim into the buffer.
 * @param layer_count            Number of cipher layers — must
 *                               equal `layer_keys.size()` and be ≥ 1.
 * @param section_count          Number of sections the reprotect
 *                               table entries cover.
 * @param ksa_block_start_offset Start of the layer-0 KSA slice
 *                               inside `stub_buf` (from
 *                               `CipherBodyPatches`).
 * @param ksa_block_end_offset   One-past-last byte of the slice.
 * @param stub_private_relocs    Optional stub-private reloc blob
 *                               from `partition_encrypted_relocs`.
 *                               Empty / default-constructed view
 *                               means no blob — the function
 *                               leaves the corresponding
 *                               `StubArtifactsInfo` fields at
 *                               zero and the patcher will patch
 *                               `{reloc_rva=0, reloc_size=0}`,
 *                               turning the applier's loop into
 *                               a no-op.
 */
[[nodiscard]] StubArtifactsInfo append_stub_artifacts(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     stub_buf,
    Randomizer&                     rng,
    const std::vector<ByteBuffer>&  layer_keys,
    uint32_t                        layer_count,
    size_t                          section_count,
    uint32_t                        ksa_block_start_offset,
    uint32_t                        ksa_block_end_offset,
    ByteView                        stub_private_relocs = {});

} // namespace mx::packer
