/**
 * @file obfuscated_jt_scanner.hpp
 * @brief Emit references for the obfuscated tail-dispatch jump table
 *        (B.4.16).
 *
 * MxProtector's VM tail dispatch (`x64_handlers.cpp::emit_tail_dispatch`)
 * lowers handler-to-handler transitions through a 7-instruction
 * dispatcher whose fixed shape is:
 *
 *   lea    base_reg, [rip + jt_disp32]              ; r64 = jt_base
 *   mov    eax, dword ptr [base_reg + rax*4]        ; load entry
 *   xor    eax, KEY                                  ; decrypt (imm32)
 *   movsxd rax, eax                                  ; sign-extend
 *   add    base_reg, rax                             ; jt_base + delta
 *   jmp    base_reg          OR        push base_reg ; ret
 *
 * Each on-disk JT slot stores `(target_rva - jt_base_rva) XOR KEY`
 * in 32 bits; the dispatcher decodes the delta at runtime and lands
 * on a handler whose offset relative to the jump-table base RVA is
 * the decoded delta.
 *
 * The build emits the imm32 KEY as a deferred patch (`emit_xor_eax_imm32`
 * with placeholder, back-filled via `table_key_patches`). By the time
 * the chaos shuffle scans the image, the key has already been
 * patched into the `xor eax, imm32` slot. We can therefore extract
 * KEY from the immediate and decode every JT entry to recover its
 * target RVA.
 *
 * The scanner only handles the **imm32-key variant** of the
 * dispatcher (opcode `35 imm32`). The alternative variant
 * `xor eax, [rsp + imagebase_key_disp]` (opcode `33 44 24 disp8`)
 * uses a runtime-computed key that has no static representation in
 * the instruction stream — those dispatchers are skipped here. (As
 * of B.4.16 the build pipeline emits the imm32 form by default; if
 * the stack-key form becomes prevalent we will need a sibling
 * scanner that pins the targets instead.)
 *
 * Reference output:
 *   * `location_rva` — RVA of the 4-byte JT slot
 *   * `target_rva`   — *decrypted* target RVA (`jt_base + sign_ext(delta)`)
 *   * `width`        — `byte4`
 *   * `encoding`     — `xor_encoded_signed_delta_imm32`
 *   * `origin`       — `obfuscated_jt_entry`
 *   * `aux`          — packed `(jt_base_rva << 32) | KEY` so the
 *                       patcher can recompute and re-encrypt the
 *                       delta after the target moves.
 *
 * SOLID:
 *   * SRP — exactly one pattern, exactly one reference type.
 *   * OCP — adding the scanner is a one-line change in
 *     `chaos_layout.cpp::scan_all_references`. Other dispatcher
 *     shapes (LEA-less, base-load via MOV, ARM64 `adrp+ldr`, …)
 *     plug in as siblings.
 *
 * Threading: stateless apart from a Zydis decoder per call. Re-create
 * per scan.
 */

#pragma once

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

class ReferenceTable;

/**
 * @brief Obfuscated tail-dispatch JT scanner — see header.
 */
class ObfuscatedJtScanner {
public:
    ObfuscatedJtScanner() = default;

    /**
     * @brief Walk every code section, recognise the dispatcher
     *        pattern, decrypt every reachable JT entry, and emit
     *        one reference per surviving entry.
     *
     * No-op when the image is not 64-bit. Decoder errors, byte
     * mismatches, and entries whose decrypted target falls outside
     * any code section's virtual range are absorbed silently —
     * scanners must not throw.
     */
    void scan(
        const PeImage&  image,
        ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
