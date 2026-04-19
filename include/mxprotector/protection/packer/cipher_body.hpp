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
#include "mxprotector/protection/packer/reloc_applier.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"

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

    /**
     * P6 — stub-self-integrity slots.
     *
     * `self_hash` holds the `mov ecx, <count>` imm32 patch offset (and
     * the emit-time-baked `lea rsi` disp32 and `hash_range_start`) that
     * the runtime FNV-1a loop at the head of the body uses. The caller
     * patches `count_imm32_offset` with the total byte count of the
     * hashed range once the full stub has been emitted.
     *
     * `hash_range_end_offset` is set at the END of `emit_decrypt_body`
     * and points one past the last byte of the cipher body. Combined
     * with `hash_range_start = 0`, it defines the byte range
     * `[0, hash_range_end_offset)` that both the build-time hash
     * computation and the runtime self-hash loop walk. The range
     * deliberately stops at the end of the decrypt body — pops,
     * stolen bytes, `jmp OEP`, key blobs, sbox scratch, VM blob,
     * reprotect table, and the TLS callback plumbing all live
     * AFTER this point and are OUTSIDE the hashed region. Including
     * the key blobs would break the clean-run path: the TLS callback
     * is a no-op on clean hosts so the bytes match build-time at
     * runtime, but any future mutation of the data tail (e.g., an
     * on-disk layout change) would risk silent hash drift — keeping
     * the hash range code-only makes the invariant easy to reason
     * about.
     */
    StubSelfHashEmit self_hash{};
    uint32_t         hash_range_end_offset = 0;

    /**
     * Stage 3 — optional post-decrypt base-relocation applier.
     *
     * Populated only when the caller sets `apply_relocs_inline = true`
     * on `emit_decrypt_body`. When disabled, the field stays at its
     * default-constructed state and the post-inject patcher skips
     * every slot it references.
     */
    RelocApplierPatches reloc_applier{};
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
 * When `enable_veh_trap` is true, the body plants the G3 Phase 2
 * Vectored Exception Handler + INT3 trap at the very top, BEFORE
 * the anti-debug probe. The trap is opt-in and EXE-only; callers
 * are responsible for gating on `pe_type == executable` and the
 * config flag before setting the parameter to true. See
 * `veh_int3_trap.hpp` for the rationale.
 *
 * When `apply_relocs_inline` is true (Stage 3 manual-map mode), the
 * body emits the post-decrypt `.reloc` applier between the final
 * decrypt layer and the reprotect loop. See `reloc_applier.hpp`.
 *
 * @param e                   Emitter to append bytes to.
 * @param patches             Patch descriptor — filled in during emission.
 * @param rng                 Randomiser for the anti-debug probe variant,
 *                            the G6 opaque predicate, and (optionally)
 *                            the VEH trap salt and junk tail.
 * @param section_count       Number of target sections each layer decrypts.
 * @param layer_count         Number of cipher layers (≥ 1).
 * @param enable_veh_trap     Opt-in flag for the G3 Phase 2 VEH INT3
 *                            trap. Must be false for DLL stubs.
 * @param apply_relocs_inline Opt-in flag for the Stage 3 post-decrypt
 *                            base-relocation applier. Enabled by the
 *                            caller only when the target's `LoadMode`
 *                            is `manual_mapped`.
 */
void emit_decrypt_body(RawEmitter&        e,
                       CipherBodyPatches& patches,
                       Randomizer&        rng,
                       uint32_t           section_count,
                       uint32_t           layer_count,
                       bool               enable_veh_trap,
                       bool               apply_relocs_inline);

/**
 * @brief Append the multi-layer RC4 decrypt block.
 *
 * Emits (in this order):
 *   1. `lea r8, [rip + sbox]` — sets the shared S-box pointer.
 *   2. For `k = layer_count - 1 → 0`:
 *      * `lea rsi, [rip + key_k]`
 *      * `emit_key_derivation_loop` (effective key, reads r14d)
 *      * KSA phase 1 (init S[k] = k)
 *      * KSA phase 2 (mix with key; layer 0 seeds `j` from r15d, outer
 *        layers seed `j = 0`)
 *      * PRGA state reset (`xor r9,r9; xor r10,r10`)
 *      * Per-section PRGA decrypt loop.
 *
 * Writes to `patches.rel_to_sbox_at`, `patches.ksa_block_start_offset`
 * / `ksa_block_end_offset` (layer 0 only), and `patches.layers[k]`
 * (rel_to_key_at + per-section slots).
 *
 * Preconditions on entry:
 *   - `r14d` already contains the stub integrity hash
 *     (use `emit_stub_self_hash` upstream).
 *   - `r15d` contains the layer-0 KSA `j` seed. In the user-mode path
 *     that's the anti-debug bias (0 on a clean host, 1 under a
 *     debugger); in the kernel-driver path the caller emits
 *     `xor r15, r15` so the decrypt runs with a zero bias.
 *   - The `rsi/r8` S-box + key pointers are computed inside this
 *     function via the rel32 slots; the caller patches them after
 *     section injection.
 *
 * Register contract:
 *   - Clobbered: rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10.
 *   - Preserved: r11, r12, r13 (untouched), r14 (hash carrier), r15
 *     (bias; conceptually read-only within the loop).
 *
 * Shared by the user-mode cipher body (`emit_decrypt_body`) and the
 * kernel-driver cipher body (`driver_cipher_body.cpp`). Any change
 * to the byte-for-byte emission is caught by the byte-pin tests
 * around P3 VM-liftability and KSA block bracketing.
 *
 * @param e              Emitter to append to.
 * @param patches        Fills `rel_to_sbox_at`, `ksa_block_start/end`,
 *                        and every `layers[k]` slot.
 * @param section_count  Number of target sections the PRGA loop walks.
 * @param layer_count    Number of cipher layers (≥ 1).
 */
void emit_multi_layer_decrypt(RawEmitter&        e,
                              CipherBodyPatches& patches,
                              uint32_t           section_count,
                              uint32_t           layer_count);

} // namespace mx::packer
