/**
 * @file pre_scanned_ref_slot.hpp
 * @brief Pre-computed reference-slot override emitted by passes that
 *        know `(slot, target, K)` directly — the chaos refmap reads
 *        these alongside `CodeReferenceScanner` output (B.4.22).
 *
 * **Why this type exists.**
 *
 * `CodeReferenceScanner` walks every code section byte-by-byte with
 * Zydis and emits a `ReferenceEncoding::rel` reference for each
 * RIP-relative slot it sees. The reference's target is computed
 * from the on-disk `disp32` as `slot + 4 + disp32`. That's the
 * right answer for a *pure* `rel32` slot; it is **not** the right
 * answer for a slot whose effective displacement is `(target -
 * slot - 4) - K`, where `K` is a non-zero algebraic offset folded
 * into a chain of arithmetic instructions following the LEA.
 *
 * Non-balanced indirect-call stubs (B.4.22) take this shape:
 *
 *   ```
 *   lea  rax, [rip + encoded_disp32]   ; rax = RIP + encoded
 *   add  rax, K                         ; rax = RIP + encoded + K = target
 *   xchg rax, [rsp]
 *   ret
 *   ```
 *
 * `encoded_disp32 = target_rva - lea_anchor - K`, so the on-disk
 * `disp32` does **not** decode to the actual target. The scanner
 * has no way to know `K` from the bytes alone — `K` is the random
 * choice the encoder made when it laid down the `add rax, K`
 * instruction. The emitting pass must hand `(slot, target, K)`
 * directly to the chaos pipeline.
 *
 * That is the role of `PreScannedRefSlot`: each entry carries the
 * exact triple, and the chaos pipeline:
 *
 *   1. Appends a `Reference` (encoded as
 *      `ReferenceEncoding::rel32_with_imm_offset`) for every entry.
 *   2. Drops any `rel`-encoded reference at the same `slot_rva` —
 *      the scanner's wrong-target version is overridden by the
 *      pass's known-correct triple.
 *
 * **Why a separate header.**
 *
 *   * Lives in `mxprotector/pe/` so `SectionInfo` can hold a
 *     `std::vector<PreScannedRefSlot>` without depending on the
 *     refmap layer.
 *   * Refmap depends on PE types; PE types do not depend on refmap,
 *     so the type belongs here even though the chaos pipeline
 *     converts it into a `refmap::Reference` at scan time.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::pe {

/**
 * @brief One pre-computed `rel32` slot override.
 *
 * Carried in `SectionInfo::pre_scanned_refs`. The chaos refmap
 * converts each entry to a `refmap::Reference` with
 * `ReferenceEncoding::rel32_with_imm_offset` (`K` packed into the
 * low 32 bits of `aux`), and drops any duplicate `rel` reference at
 * `slot_rva` that `CodeReferenceScanner` produced.
 *
 *   * `slot_rva`   — RVA of the first byte of the 4-byte disp32 slot.
 *   * `target_rva` — RVA the chain resolves to after the `K` fold.
 *   * `imm_offset` — `K`, the signed algebraic constant added to
 *                    the LEA result by the chain that follows.
 *                    `K = 0` is allowed (it degenerates to a plain
 *                    `rel`), but the standard scanner already
 *                    handles that case so passes typically only
 *                    emit `PreScannedRefSlot` for `K != 0`.
 */
struct PreScannedRefSlot {
    Rva           slot_rva   = 0;
    Rva           target_rva = 0;
    std::int32_t  imm_offset = 0;
};

} // namespace mx::pe
