/**
 * @file handler_table_integrity_refinalizer.hpp
 * @brief Re-finalise the post-shuffle handler-table XOR-sum integrity
 *        check (B.4.16.1).
 *
 * The VM entry stub emits an integrity check that XORs every entry
 * of the handler-table together and compares the result against a
 * deferred expected value:
 *
 *   lea  rbx, [rip + handler_table_rel32]           ; rbx = JT base
 *   mov  ecx, total_handlers
 *   xor  edx, edx
 * .loop:
 *   xor  edx, dword ptr [rbx]
 *   add  rbx, 4
 *   dec  ecx
 *   jnz  .loop
 *   xor  edx, <expected>                            ; placeholder imm32
 *   xor  eax, edx                                    ; corrupt key on mismatch
 *
 * The `expected` value is computed at build time as the XOR of all
 * handler-table entries (after the table-key encryption has already
 * landed). When chaos shuffle re-encrypts those entries via
 * `ObfuscatedJtScanner` (because the dispatch targets moved), the
 * stored expected sum is no longer valid — at runtime `edx` ends
 * up non-zero, the check XORs garbage into the VM key slot, and
 * the next dispatch lands on a wild address.
 *
 * `HandlerTableIntegrityRefinalizer` runs as the final step inside
 * `apply_fragment_shuffle`, before `SelfCrcRefinalizer` (the integrity
 * check sits *inside* the self-CRC byte range, so the self-CRC
 * computation needs to see the updated `xor edx, <expected>` slot
 * in order to settle on a stable hash).
 *
 * The refinaliser walks every code section, recognises the fixed
 * 32-byte signature, decodes `handler_table_rva` (from the LEA's
 * `rel32`) and `total_handlers` (from the `mov ecx, imm32`),
 * recomputes `expected = XOR(entry_0 .. entry_N-1)` over the
 * post-shuffle bytes, and writes the new value into the
 * `xor edx, imm32` slot.
 *
 * SOLID:
 *   * SRP — exactly one task: refresh the integrity-check imm32.
 *   * OCP — adding it is a one-line change in
 *     `chaos_layout.cpp::apply_fragment_shuffle`.
 *
 * Threading: not safe for concurrent invocation against the same
 * `PeImage`.
 */

#pragma once

#include <cstddef>

namespace mx {
class PeImage;
}

namespace mx::pe::chaos {

/**
 * @brief Handler-table integrity-check refinaliser — see header.
 */
class HandlerTableIntegrityRefinalizer {
public:
    HandlerTableIntegrityRefinalizer() = default;

    /**
     * @brief Walk every code section in `image`, find the fixed
     *        32-byte integrity-check signature, recompute the XOR
     *        sum over the post-shuffle handler-table bytes, and
     *        patch the `xor edx, imm32` placeholder.
     *
     * No-op when:
     *   * The image is not 64-bit.
     *   * No code section contains the recognised signature.
     *
     * Decoder errors and read-past-section conditions are absorbed
     * silently — the refinaliser must never throw.
     *
     * @return Number of integrity checks refinalised. Useful for
     *         diagnostics; callers may discard the value.
     */
    std::size_t refinalize(PeImage& image) const;
};

} // namespace mx::pe::chaos
