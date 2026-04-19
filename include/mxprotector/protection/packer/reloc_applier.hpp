/**
 * @file reloc_applier.hpp
 * @brief Post-decrypt base-relocation applier — header.
 *
 * Stage 3 of driver / manually-mapped support. When the protected
 * binary is built with `--load-mode=manual`, the packer cannot rely on
 * an OS image loader applying the `.reloc` directory before control
 * reaches the stub — most manual mappers either honour
 * `IMAGE_FILE_RELOCS_STRIPPED` (and skip reloc application entirely)
 * or refuse to load a binary whose preferred base is already taken.
 *
 * The packer's answer is to keep the `.reloc` directory intact on disk
 * with the `RELOCS_STRIPPED` bit SET — the mapper therefore leaves the
 * ciphertext alone — and have the stub walk that same `.reloc`
 * directory itself after decryption, adding the runtime-vs-preferred
 * base delta to every `IMAGE_REL_BASED_DIR64` entry.
 *
 * The applier emits the following asm (~116 bytes):
 *
 *   ; (1) runtime_base into rax via rip-relative arithmetic
 *       lea rax, [rip + 0]                    ; rax = runtime VA of next insn
 *       sub rax, <imm32 anchor_rva>           ; rax -= (stub_rva + anchor)
 *                                             ; → rax = current module base
 *   ; (2) delta into r11
 *       mov rbx, <imm64 preferred_base>
 *       mov r11, rax
 *       sub r11, rbx
 *       test r11, r11
 *       je   .done                            ; delta == 0 → nothing to fix up
 *   ; (3) reloc table walk: rcx = start, rdx = end
 *       mov ecx, <imm32 reloc_rva>
 *       add rcx, rax
 *       mov edx, <imm32 reloc_size>
 *       add rdx, rcx
 *   ; (4) block loop
 *     .block_loop:
 *       cmp rcx, rdx
 *       jae .done
 *       mov r12d, [rcx]       ; page RVA
 *       mov r8d,  [rcx + 4]   ; block size
 *       lea r9,   [rcx + r8]  ; block end
 *       add rcx,  8           ; move past block header
 *     .entry_loop:
 *       cmp rcx, r9
 *       jae .next_block
 *       movzx r10d, word [rcx]
 *       mov   ebx, r10d
 *       shr   ebx, 12         ; type
 *       cmp   ebx, 10         ; IMAGE_REL_BASED_DIR64
 *       jne   .skip_entry
 *       and   r10d, 0xFFF     ; offset within page
 *       lea   rbx, [rax + r12]        ; page base
 *       add   [rbx + r10], r11        ; apply delta
 *     .skip_entry:
 *       add rcx, 2
 *       jmp .entry_loop
 *     .next_block:
 *       mov rcx, r9
 *       jmp .block_loop
 *     .done:
 *
 * Register contract (within the applier):
 *   Clobbered:      rax, rbx, rcx, rdx, r8, r9, r10, r11, r12
 *   Preserved:      all nonvolatile regs except the ones above
 *   Required on entry: none (computes everything rip-relative)
 *   Provided on exit:  rax = runtime_base, r11 = delta
 *
 * The applier is meant to run AFTER the multi-layer decrypt loops
 * complete and BEFORE the reprotect loop revokes WRITE on the target
 * sections — the reloc target pages must still be writable when the
 * applier runs.
 *
 * The emitter is pure / stateless. It records four patch sites in
 * `RelocApplierPatches`; the packer's post-inject patcher fills those
 * slots once the stub section RVA is final.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::packer {

/**
 * @brief Patch sites produced by `emit_reloc_applier`.
 *
 * All offsets are stub-buffer-relative (i.e. absolute within the
 * `.mxpack` section). The patcher adds `stub_rva` when computing
 * runtime values.
 */
struct RelocApplierPatches {
    /// Offset at which `rax` is computed (end of the leading
    /// `lea rax, [rip + 0]`). The patcher writes
    /// `imm32 = stub_rva + lea_runtime_base_anchor_offset` into
    /// `sub_runtime_base_imm32_at` so that `rax -= imm32` yields the
    /// module's runtime base.
    uint32_t lea_runtime_base_anchor_offset = 0;

    /// imm32 slot inside `sub rax, <imm32>`.
    uint32_t sub_runtime_base_imm32_at = 0;

    /// imm64 slot inside `mov rbx, <imm64 preferred_base>`.
    uint32_t preferred_base_imm64_at = 0;

    /// imm32 slot inside `mov ecx, <reloc_rva>`.
    uint32_t reloc_rva_imm32_at = 0;

    /// imm32 slot inside `mov edx, <reloc_size>`.
    uint32_t reloc_size_imm32_at = 0;

    /// Stub-buffer-relative begin/end of the applier block. Useful
    /// for tests and for log lines that want to report the applier's
    /// footprint separately from the rest of the cipher body.
    uint32_t applier_begin_offset = 0;
    uint32_t applier_end_offset   = 0;
};

/**
 * @brief Append the post-decrypt reloc applier to an emitter.
 *
 * @param e        Emitter to append to. The applier is byte-for-byte
 *                 stable given a fixed emitter state; no randomisation
 *                 is performed — the per-build entropy already lives in
 *                 the surrounding cipher body (anti-debug variant, key
 *                 blobs, opaque predicate, ...) so adding another RNG
 *                 source would have no measurable effect on the cost
 *                 of static analysis.
 * @param patches  Patch descriptor — filled in during emission.
 */
void emit_reloc_applier(RawEmitter&           e,
                        RelocApplierPatches&  patches);

/**
 * @brief Expected byte size of `emit_reloc_applier`'s emission.
 *
 * Hard-coded so a single unit test can assert the applier is
 * byte-stable — any intentional edit must update this constant
 * AND the matching hex array in the test, making the change
 * reviewable at a glance.
 */
inline constexpr uint32_t kRelocApplierEmittedSize = 116;

} // namespace mx::packer
