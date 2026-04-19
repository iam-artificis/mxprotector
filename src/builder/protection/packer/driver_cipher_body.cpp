/**
 * @file driver_cipher_body.cpp
 * @brief Kernel-mode cipher body — implementation.
 *
 * See `driver_cipher_body.hpp` for the rationale and the list of
 * pieces that intentionally do not exist in the driver variant. This
 * file is the byte-level emission.
 */

#include "mxprotector/protection/packer/driver_cipher_body.hpp"

#include "mxprotector/protection/obfuscation/hash_opaque_predicate.hpp"
#include "mxprotector/protection/packer/reloc_applier.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"

namespace mx::packer {

void emit_driver_decrypt_body(RawEmitter&        e,
                              CipherBodyPatches& patches,
                              Randomizer&        rng,
                              uint32_t           section_count,
                              uint32_t           layer_count,
                              bool               apply_relocs_inline)
{
    // Per-layer patch storage — same contract as user-mode.
    patches.layers.resize(layer_count);
    for (auto& lp : patches.layers) lp.sections.reserve(section_count);

    // ----------------------------------------------------------------
    // G6 — Hash-based opaque predicate. Pure integer, kernel-safe.
    //
    // Kept here for the same reason as in user-mode: it inflates the
    // static analysis surface with a reachable-but-dead `false` branch
    // and forces SAT/SMT solvers into a multiplicative chain they
    // can't invert cheaply.
    // ----------------------------------------------------------------
    {
        const obf::HashOpaqueParams hp =
            obf::randomize_hash_opaque_params(rng);
        obf::emit_hash_opaque_predicate(e, hp, rng);
    }

    // ----------------------------------------------------------------
    // Replace the user-mode anti-debug probe with a zero bias.
    //
    // The user-mode body reads `PEB.BeingDebugged` / `NtGlobalFlag` /
    // `KdDebuggerEnabled` and folds the result into `r15d` so that
    // layer 0's KSA seeds `j` with 1 instead of 0 under a debugger,
    // silently garbling the decrypt. None of those indicators exist in
    // kernel mode the way the probe reads them (`gs:[0x60]` is KPCR,
    // not PEB). MVP keeps the layer-0 seed at zero — the protection
    // still relies on the multi-layer RC4 chain + `r14d`-folded self-
    // hash for anti-tamper; we just drop the kernel-incompatible
    // debugger-detection bit.
    //
    //   xor r15, r15                              4D 31 FF
    e.u8(0x4D); e.u8(0x31); e.u8(0xFF);

    // ----------------------------------------------------------------
    // P6 — Stub-self-integrity hash. Writes the 32-bit FNV-1a hash of
    // `[stub_start, stub_start + hash_range_end_offset)` into `r14d`,
    // which every per-layer `emit_key_derivation_loop` then chains
    // through the effective-key derivation. Pure integer — identical
    // emission to the user-mode cipher body.
    // ----------------------------------------------------------------
    patches.self_hash = emit_stub_self_hash(e);

    // ----------------------------------------------------------------
    // Shared multi-layer RC4 KSA+PRGA. Every byte of this block is
    // the same as the user-mode path — see `cipher_body.hpp` for the
    // contract.
    //
    // Preconditions established above:
    //   r14d = integrity hash (via emit_stub_self_hash)
    //   r15d = 0               (via xor r15, r15)
    // ----------------------------------------------------------------
    emit_multi_layer_decrypt(e, patches, section_count, layer_count);

    // ----------------------------------------------------------------
    // Optional Stage-3 post-decrypt base-relocation applier.
    //
    // For drivers this is a common path: `MmLoadSystemImage` freely
    // relocates drivers away from the preferred base when that range
    // is taken, and every manual-mapper worth its salt does the same
    // thing. The reloc applier must run while target sections are
    // still writable — there is no reprotect loop in the driver body,
    // so the applier can even run later, but keeping the position
    // symmetric with the user-mode body (between decrypt and
    // end-of-cipher-body marker) makes the hash range easy to reason
    // about.
    // ----------------------------------------------------------------
    if (apply_relocs_inline) {
        emit_reloc_applier(e, patches.reloc_applier);
    }

    // End of the hashed range. The build-time driver that computes
    // the expected FNV-1a reads exactly
    // `[stub_start, stub_start + hash_range_end_offset)`; everything
    // appended to the stub buffer after this point (stolen bytes,
    // `jmp real_entry`, key blobs, sbox scratch, reloc data) lives
    // outside the hashed window.
    patches.hash_range_end_offset = static_cast<uint32_t>(e.size());
}

} // namespace mx::packer
