/**
 * @file packer_ksa_vm_lifter.hpp
 * @brief P3 — optional VM-lift of the packer stub's RC4 KSA range.
 *
 * Layer 0's KSA is the only KSA range `emit_decrypt_body` brackets
 * with `ksa_block_start_offset` / `ksa_block_end_offset` — the outer
 * layers' KSAs stay as plaintext x64 to keep the lifted surface
 * bounded. This module owns the optional step that takes those
 * KSA bytes, tries to re-emit them through the existing VM engine
 * (`vm::VmLifter` + `vm::VmRuntimeGenerator`), and appends the
 * resulting runtime blob to the same stub buffer. The caller
 * (`PackerPipeline::step4_append_artifacts`) then overwrites the
 * original plaintext KSA bytes with `call rel32 <vm_entry>` + NOP
 * padding once the stub section's runtime RVA is known
 * (step5_inject_and_patch).
 *
 * Every failure mode (no disassembler in ctx, empty KSA slice, lift
 * failure, runtime-generation failure) is silently tolerated — the
 * stub keeps the plaintext KSA in place and runs a plain x64 KSA at
 * runtime. The function logs the reason and returns
 * `succeeded = false`.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/types.hpp"

namespace mx { class ProtectionContext; }

namespace mx::packer {

/**
 * @brief Result of `try_lift_ksa_to_vm`.
 *
 * When `succeeded` is true, the VM runtime blob has been appended to
 * the caller's stub buffer at `vm_blob_offset_in_stub` (after padding
 * the buffer up to a 16-byte boundary), and the VM entry is at
 * `vm_blob_offset_in_stub + vm_entry_offset`. When it is false none
 * of the other fields are meaningful and the stub buffer is
 * unchanged.
 */
struct KsaVmLiftResult {
    size_t   vm_blob_offset_in_stub = 0;
    uint32_t vm_entry_offset        = 0;
    bool     succeeded              = false;
};

/**
 * @brief Try to lift the KSA byte range into the VM engine and
 *        append the resulting runtime blob to `stub_buf`.
 *
 * The KSA slice is `stub_buf[ksa_block_start_offset ..
 * ksa_block_end_offset)`. If `ctx.disassembler()` is null or the
 * slice is empty, the function returns immediately with
 * `succeeded = false` and leaves `stub_buf` untouched.
 *
 * On success the function:
 *   - pads `stub_buf` up to the next 16-byte boundary with `0xCC`,
 *   - appends the generated VM runtime blob,
 *   - records the (post-pad) offset of the blob start and the VM
 *     entry offset within the blob.
 *
 * @param ctx                     Protection context — supplies the
 *                                disassembler, pe_image (for the EXE
 *                                vs DLL ImageBase-key gate), and the
 *                                log channel used on every branch.
 * @param stub_buf                Stub bytes under construction;
 *                                mutated on success.
 * @param ksa_block_start_offset  Start of the layer-0 KSA slice
 *                                inside `stub_buf`.
 * @param ksa_block_end_offset    One-past-last byte of the slice.
 * @param rng                     Randomiser threaded into the VM
 *                                runtime generator.
 */
[[nodiscard]] KsaVmLiftResult try_lift_ksa_to_vm(
    mx::ProtectionContext& ctx,
    ByteBuffer&            stub_buf,
    uint32_t               ksa_block_start_offset,
    uint32_t               ksa_block_end_offset,
    Randomizer&            rng);

} // namespace mx::packer
