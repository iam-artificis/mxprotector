/**
 * @file cipher_body_reprotect.hpp
 * @brief Private helper — Hell's-Gate-driven reprotect block emitter.
 *
 * Splits the ~200-byte post-decrypt VirtualProtect loop out of
 * `cipher_body.cpp::emit_decrypt_body`. The block:
 *
 *   1. Saves rsp into r12 and 16-aligns the stack frame.
 *   2. Resolves `NtProtectVirtualMemory` via Hell's Gate (PEB walk +
 *      salted DJB2 over export name) into r13. On failure (r13 == 0)
 *      it skips the loop entirely so target sections stay RWX
 *      instead of the stub crashing on a null call.
 *   3. Computes our own ImageBase rip-relative (rbx) so the call works
 *      for both EXE and DLL hosts.
 *   4. Walks an embedded `{rva, size}` table (r14, count in r15),
 *      calling NtProtectVirtualMemory(NtCurrentProcess, &base, &size,
 *      PAGE_EXECUTE_READ, &old_protect) per entry.
 *   5. Restores rsp from r12.
 *
 * Lives in `src/builder/protection/packer/` — internal to the packer.
 * Public consumers (`packer_pass`, `stub_emitter`) talk only through
 * `cipher_body.hpp::emit_decrypt_body`.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/packer/cipher_body.hpp"

namespace mx::packer {

/**
 * @brief Append the reprotect (PAGE_EXECUTE_READ) loop to @p e.
 *
 * Patches written to @p patches:
 *   - `reprotect_entry_count`
 *   - `imagebase_lea_anchor_offset`, `imagebase_sub_imm32_at`
 *   - `rel_to_reprotect_table_at`
 *
 * @param e             Emitter the bytes are appended to.
 * @param rng           RNG for the per-build Hell's-Gate salt.
 * @param patches       Cipher-body patch slot collector (mutated).
 * @param section_count Number of `{rva, size}` entries the loop walks.
 */
void emit_reprotect_block(RawEmitter&        e,
                          Randomizer&        rng,
                          CipherBodyPatches& patches,
                          uint32_t           section_count);

} // namespace mx::packer
