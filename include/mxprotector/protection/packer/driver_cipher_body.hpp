/**
 * @file driver_cipher_body.hpp
 * @brief Kernel-mode cipher body for the `.sys` packer stub.
 *
 * The user-mode cipher body (see `cipher_body.hpp`) wraps the RC4
 * KSA+PRGA block in a lot of Win32 user-mode machinery:
 *   - An anti-debug probe that reads `gs:[0x60]` (PEB) and normalises
 *     one of BeingDebugged / NtGlobalFlag / KdDebuggerEnabled into
 *     `edx ∈ {0, 1}`.
 *   - A Hell's Gate resolver + `NtProtectVirtualMemory` call that
 *     revokes WRITE on every decrypted section after the PRGA loops
 *     finish.
 *   - An Import Directory wipe that zeroes the resolved IAT to
 *     frustrate dump/reconstruction tools.
 *
 * None of those are available in ring0. `gs:` points at the KPCR, not
 * the PEB. `RtlAddVectoredExceptionHandler` / `NtProtectVirtualMemory`
 * do not exist in kernel mode. Drivers have their imports resolved by
 * a completely different loader (`MmLoadSystemImage`) so the user-mode
 * IAT-wipe shape does not apply.
 *
 * The driver cipher body therefore emits a much thinner shell:
 *
 *   1. `xor r15, r15`           — the layer-0 KSA `j` seed is zero.
 *                                 There is no debugger-bias concept in
 *                                 ring0 (no `BeingDebugged` to
 *                                 consult); the cipher still benefits
 *                                 from the multi-layer + `r14d` self-
 *                                 hash chain, which are pure integer.
 *   2. `emit_stub_self_hash`    — same FNV-1a walker used by user-
 *                                 mode. Pure integer, kernel-safe.
 *                                 Output: `r14d` = hash.
 *   3. `emit_multi_layer_decrypt` — shared RC4 KSA+PRGA block.
 *                                 Reads `r14d` (hash) and `r15d`
 *                                 (bias = 0). Writes plaintext into
 *                                 every target section.
 *   4. (optional) `emit_reloc_applier` — Stage-3 post-decrypt base-
 *                                 relocation applier. Enabled when
 *                                 the caller passes
 *                                 `apply_relocs_inline = true` (e.g.
 *                                 manual-mapped or non-preferred-base
 *                                 OS-load drivers).
 *   5. `hash_range_end_offset`  — marker one past the last byte of
 *                                 the cipher body so the build-time
 *                                 driver can compute the self-hash
 *                                 byte count.
 *
 * What is intentionally *not* emitted:
 *   - No VEH INT3 trap (no VEH in ring0).
 *   - No PEB dereference / anti-debug probe.
 *   - No Hell's Gate ntdll-resolver.
 *   - No reprotect loop (sections stay whatever the image characteristics
 *     had them as; MVP accepts RWX — HVCI-hostile but functional).
 *   - No IAT wipe (drivers resolve imports through the kernel loader,
 *     not the user-mode loader; wiping would be the wrong shape).
 *
 * The resulting body reuses `emit_multi_layer_decrypt` as-is, which
 * means every per-layer / per-section patch the cipher body produced
 * pre-extraction is still there and still routed through
 * `CipherBodyPatches.layers[k]` + `rel_to_sbox_at`. The caller
 * patches the same fields it would for a user-mode build; the
 * user-mode-only fields (`imagebase_lea_anchor_offset`,
 * `rel_to_reprotect_table_at`, `rel_to_impdir_at`, ...) simply stay
 * at zero because the driver body never emits them, and the driver-
 * specific stub patcher (see `packer_driver_stub_patcher.cpp`) skips
 * those slots entirely.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"

namespace mx::packer {

/**
 * @brief Append the kernel-driver cipher body to an emitter.
 *
 * @param e                    Emitter to append to.
 * @param patches              Patch descriptor. On return, the fields
 *                             `layers`, `rel_to_sbox_at`,
 *                             `ksa_block_start_offset`,
 *                             `ksa_block_end_offset`, `self_hash`,
 *                             `hash_range_end_offset`, and (if
 *                             `apply_relocs_inline`) `reloc_applier`
 *                             are populated. All other
 *                             `CipherBodyPatches` members stay at
 *                             their default-constructed zero state
 *                             because the driver body never emits the
 *                             reprotect / IAT wipe / imagebase blocks
 *                             they index into.
 * @param rng                  Randomiser. Used only by the reloc
 *                             applier entropy seeding today; reserved
 *                             for future per-build variants of the
 *                             driver body.
 * @param section_count        Number of target sections the PRGA loop
 *                             iterates over (passed straight to
 *                             `emit_multi_layer_decrypt`).
 * @param layer_count          Number of cipher layers (≥ 1).
 * @param apply_relocs_inline  Stage-3 opt-in: emit the post-decrypt
 *                             `.reloc` applier between the final
 *                             decrypt layer and the end of the cipher
 *                             body. For drivers this is the common
 *                             path when the loader may place the image
 *                             at a non-preferred base (manual-mapped
 *                             or OS `MmLoadSystemImage` relocating).
 *
 * Register contract (clobbered): rax, rbx, rcx, rdx, rsi, rdi, r8,
 * r9, r10, r11, r12 (via reloc applier), r13 (unused), r14 (hash
 * carrier), r15 (zeroed as the bias seed).
 *
 * Register contract (preserved via stack saves done by the outer
 * `build_driver_stub_bytes` wrapper): rcx/rdx (DriverEntry args), rbp,
 * rbx (caller nonvolatiles).
 */
void emit_driver_decrypt_body(RawEmitter&        e,
                              CipherBodyPatches& patches,
                              Randomizer&        rng,
                              uint32_t           section_count,
                              uint32_t           layer_count,
                              bool               apply_relocs_inline);

} // namespace mx::packer
