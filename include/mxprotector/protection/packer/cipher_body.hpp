/**
 * @file cipher_body.hpp
 * @brief Shared RC4 decrypt body emitter for the packer stub.
 *
 * The packer stub (EXE or full-DLL shape) wraps a common "decrypt
 * payload" region in a policy-specific save/restore shell. This module
 * owns that common region: multi-layer RC4 KSA+PRGA, the reprotect
 * loop that revokes WRITE from each decrypted section via
 * `NtProtectVirtualMemory`, and the Import Directory wipe that clobbers
 * the resolved IAT names after decryption.
 *
 * ## P2 multi-layer layout
 *
 * The runtime stub applies `layer_count` cipher rounds, each with its
 * own 32-byte RC4 key embedded elsewhere in the `.mxpack` section.
 * Layers run in DECRYPT order — `N-1, N-2, ..., 1, 0`. Layer 0 is the
 * innermost (runtime-LAST) layer, and the only one whose KSA reads the
 * anti-debug bias from `r15d`. Build-time encryption applies the same
 * rounds in reverse order (`0, 1, ..., N-1`), so the cascade symmetric-
 * unwinds to plaintext on a clean host and silently garbles the output
 * when a debugger trips the bias.
 *
 * ## Relationship to P3 (VM-protected KSA)
 *
 * Only layer 0's KSA range is exposed to the P3 VM lifter via
 * `ksa_block_start_offset` / `ksa_block_end_offset`. Outer layers'
 * KSAs stay as plaintext x64 to keep the lifted surface bounded. The
 * orchestration in `packer_pass.cpp` optionally overwrites layer 0's
 * KSA bytes with `call rel32 <vm_entry>` + NOP padding after lifting.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::packer {

/**
 * @brief Patch sites for one encrypted section inside one cipher layer.
 *
 * The runtime stub's per-section PRGA decrypt loop begins with
 * `lea rdi, [rip + rel32]` + `mov ecx, imm32`; the caller fills in
 * both slots after the stub section is injected and its runtime RVA
 * is known.
 */
struct DecryptSection {
    Rva      rva          = 0;  ///< runtime RVA of the section to decrypt
    uint32_t size         = 0;  ///< size in bytes
    uint32_t patch_lea_at = 0;  ///< stub-relative offset of the `lea rdi` rel32
    uint32_t patch_size_at = 0; ///< stub-relative offset of the `mov ecx` imm32
};

/**
 * @brief Patch sites for one cipher layer.
 *
 * Layer 0 is the innermost layer (runtime decrypted LAST, bias-seeded).
 * `rel_to_key_at` is the `lea rsi, [rip + rel32]` rel32 that selects
 * this layer's embedded 32-byte RC4 key; the caller patches it after
 * placing the stub section and the per-layer key blobs inside it.
 * `sections` holds one entry per encrypted section in the order the
 * layer's PRGA loops walk them.
 */
struct LayerPatches {
    uint32_t                    rel_to_key_at = 0;
    std::vector<DecryptSection> sections;
};

/**
 * @brief Patches produced by `emit_decrypt_body`.
 *
 * `layers[k]` describes layer `k`'s key LEA and per-section loops.
 * `rel_to_sbox_at` is the shared S-box scratch `lea r8, [rip + rel32]`
 * (one for the whole body — every layer rebuilds the S-box in place).
 * `ksa_block_start/end_offset` bracket layer 0's KSA so the P3 VM
 * lifter can optionally replace that range with a call into a lifted
 * VM runtime. The reprotect / ImageBase / import-directory fields are
 * for the trailing reprotect loop + IAT wipe emitted at the end of
 * the body; the caller patches them after stub-section injection.
 */
struct CipherBodyPatches {
    std::vector<LayerPatches> layers;

    uint32_t rel_to_sbox_at              = 0;
    uint32_t ksa_block_start_offset      = 0;
    uint32_t ksa_block_end_offset        = 0;

    uint32_t rel_to_impdir_at            = 0;
    uint32_t impdir_size_at              = 0;

    uint32_t rel_to_reprotect_table_at   = 0;
    uint32_t reprotect_table_offset      = 0;
    uint32_t reprotect_entry_count       = 0;

    uint32_t imagebase_lea_anchor_offset = 0;
    uint32_t imagebase_sub_imm32_at      = 0;
};

/**
 * @brief Append the shared RC4 decrypt body + reprotect + IAT wipe to
 *        an emitter.
 *
 * Emission order:
 *   1. Anti-debug probe (one of three polymorphic variants) leaves
 *      the bias in `edx`.
 *   2. `mov r15d, edx` captures the bias for later layer 0 seeding.
 *   3. `lea r8, [rip + sbox]` selects the shared S-box scratch.
 *   4. For `k = layer_count-1 → 0`: `lea rsi, key_k`, KSA phase 1/2/3,
 *      per-section PRGA loops. Layer 0 brackets its KSA with
 *      `ksa_block_start/end_offset`.
 *   5. Reprotect loop (Hell's Gate resolver → `NtProtectVirtualMemory`
 *      over an embedded `{rva, size}` table).
 *   6. Import Directory wipe (`rep stosd` over the import dir bytes).
 *
 * Register contract: clobbers rax, rbx, rcx, rdx, rsi, rdi, r8, r9,
 * r10, r12, r13, r14, r15 (r11 is the only volatile GPR left alone).
 * Callers save whatever they need preserved across the body. rsp at
 * entry must be 16-aligned after any caller-side saves so the
 * reprotect block's `and rsp, -16` is a no-op.
 *
 * @param e              Emitter to append bytes to.
 * @param patches        Patch descriptor — filled in during emission.
 * @param rng            Randomiser for the anti-debug probe variant.
 * @param section_count  Number of target sections each layer decrypts.
 * @param layer_count    Number of cipher layers (≥ 1).
 */
void emit_decrypt_body(RawEmitter&        e,
                       CipherBodyPatches& patches,
                       Randomizer&        rng,
                       uint32_t           section_count,
                       uint32_t           layer_count);

} // namespace mx::packer
