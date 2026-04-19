/**
 * @file packer_stub_patcher.hpp
 * @brief Post-inject rel32 / imm32 / anchor patches for the packer
 *        stub, analogue of `x64_blob_patcher` on the VM side.
 *
 * After `finalize_packer_stub` has placed the .mxpack section and
 * stamped the entry jmp, the stub bytes are at a known runtime RVA
 * (`stub_rva`) but many slots inside them still carry build-time
 * placeholders:
 *
 *   - per-layer `lea rsi, key_K` rel32 — → this layer's 32-byte key;
 *   - per-layer per-section `lea rdi, section_i` rel32
 *     + `mov ecx, size` imm32;
 *   - shared `lea r8, sbox` rel32;
 *   - the G6 reprotect block's `sub rbx, imm32` anchor;
 *   - `lea r14, reprotect_table` rel32 + the table entries themselves;
 *   - `lea rdi, import_dir` rel32 + `mov ecx, impdir_size/4` imm32
 *     (the IAT wipe);
 *   - optionally, overwriting the plaintext layer-0 KSA bytes with
 *     `call rel32 <vm_entry>` + NOP padding when the P3 lift
 *     succeeded.
 *
 * `apply_post_inject_patches` walks every slot described in
 * `patches` + `artifacts` and writes the finalised values into
 * `section_data`. It does NOT cover the P4 TLS finalise (callback
 * array / directory / data directory) — that runs in its own step
 * after the patcher, because it needs the same section bytes but
 * owns a different concern.
 *
 * Nothing here can fail: all inputs are produced by modules that
 * already validated their shape (emitter patches, appended artefacts,
 * injected section); the patcher simply applies the finalised math.
 * Error logging is limited to the two informational messages the
 * original inline code produced — P3 KSA replacement and IAT
 * destruction plan.
 */

#pragma once

#include <cstdint>
#include <span>

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"
#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"

namespace mx { class ProtectionContext; }

namespace mx::packer {

/**
 * @brief One encrypted target section — just the `{rva, size}` pair
 *        the patcher needs.
 *
 * The caller (`PackerPipeline`) keeps an `EncryptedTarget` vector
 * with an extra `image_index` field for P6 encryption; the patcher
 * only cares about `rva` + `size` for rel32 + imm32 math and the
 * reprotect-table entries, so it takes a thinner view.
 */
struct TargetSection {
    Rva      rva  = 0;
    uint32_t size = 0;
};

/**
 * @brief Apply every post-inject rel32 / imm32 / anchor patch to
 *        the stub section bytes.
 *
 * @param ctx           Protection context — read for the Import
 *                      Directory (IAT wipe target) and for the two
 *                      log messages (P3 KSA replacement, IAT
 *                      destruction).
 * @param section_data  Mutable stub section bytes, e.g.
 *                      `ctx.pe_image().sections()[pack_idx].data`.
 * @param stub_rva      Runtime RVA of `section_data[0]`.
 * @param layer_count   Number of cipher layers — must equal
 *                      `patches.layers.size()`.
 * @param patches       Cipher-body patch descriptor returned by the
 *                      stub emitter.
 * @param artifacts     Stub-tail artefact offsets returned by
 *                      `append_stub_artifacts`.
 * @param sections      Target sections in the same order as the
 *                      emitter's per-section loop slots.
 */
void apply_post_inject_patches(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     section_data,
    Rva                             stub_rva,
    uint32_t                        layer_count,
    const CipherBodyPatches&        patches,
    const StubArtifactsInfo&        artifacts,
    std::span<const TargetSection>  sections);

/**
 * @brief Apply post-inject patches for the kernel-driver stub.
 *
 * The driver cipher body (see `driver_cipher_body.hpp`) emits a
 * strict subset of the user-mode cipher body: no reprotect loop, no
 * IAT wipe, no imagebase rip-relative computation. The corresponding
 * `CipherBodyPatches` slots stay at their zero default, and *must
 * not* be written to — their zero offset aliases the very start of
 * the stub buffer, where patching would corrupt the pre-decrypt
 * prologue.
 *
 * This function writes only the patches the driver body actually
 * produces:
 *   - per-layer `lea rsi, key_K` rel32,
 *   - per-layer per-section `lea rdi` + `mov ecx, size`,
 *   - shared `lea r8, sbox` rel32,
 *   - P3 KSA VM-lift overwrite (if the lift succeeded),
 *   - Stage-3 reloc applier (if emitted).
 *
 * Parameters have the same meaning as `apply_post_inject_patches`.
 */
void apply_driver_post_inject_patches(
    mx::ProtectionContext&          ctx,
    ByteBuffer&                     section_data,
    Rva                             stub_rva,
    uint32_t                        layer_count,
    const CipherBodyPatches&        patches,
    const StubArtifactsInfo&        artifacts,
    std::span<const TargetSection>  sections);

} // namespace mx::packer
