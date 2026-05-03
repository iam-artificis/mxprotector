/**
 * @file switch_jump_table_scanner.hpp
 * @brief Emit references for MSVC x64 switch jump-table entries (B.4.13).
 *
 * MSVC x64 lowers a `switch` statement whose case set is dense to a
 * dispatcher of the form
 *
 *   ; r10 holds the image base (set up earlier in the function via
 *   ; `lea r10, [rip - <imagebase_offset>]`).
 *   mov  r11d, dword ptr [r10 + r11*4 + JT_RVA]   ; load entry
 *   add  r11, r10                                  ; rebase
 *   jmp  r11                                       ; dispatch
 *
 * `JT_RVA` is the displacement of the jump-table base inside the
 * image. The table sits in `.rdata` and stores **4-byte target RVAs**
 * (or, for the `movsxd` variant, signed 4-byte values whose
 * zero-/sign-extended form is added to the image base — same end
 * result for any entry in the user-mode RVA range). Entries point at
 * code in `.text` (or whichever section carries the dispatched
 * function's body).
 *
 * Critically, **none of these entries live in `.reloc`** — they are
 * already image-relative and the loader never applies a relocation
 * delta to them. `RelocAbsoluteVaScanner` therefore does not see
 * them, yet they point at code that the chaos shuffle moves. Without
 * a dedicated scanner, the post-shuffle binary keeps stale RVAs in
 * the table and the dispatcher's `jmp r11` lands on the wrong byte.
 *
 * The scanner has two phases:
 *
 *   1. Walk every code section with a `Zydis` decoder, recognise the
 *      `mov r32 / movsxd r64 + add + jmp r64` triple, and collect
 *      every distinct `JT_RVA` displacement.
 *   2. For each collected base, walk 4-byte slots forward emitting a
 *      `Reference` per slot whose value lands inside *some* code
 *      section's `[virtual_address, virtual_address + virtual_size)`
 *      range. Stops at the first slot that is not a valid code RVA
 *      (default case markers / next table / padding all read as
 *      out-of-range), capped by a defensive 1024-entry maximum.
 *
 * SOLID:
 *   * SRP — exactly one PE-format concern (switch JT tables in
 *     `.rdata`-style sections).
 *   * OCP — adding/removing the scanner is a one-line change in
 *     `chaos_layout.cpp::scan_all_references`. Other patterns (LEA-
 *     based dispatchers, ARM64 `adrp+ldr`) plug in as siblings
 *     under `refmap/`.
 *
 * Threading: stateless apart from the per-call Zydis decoder —
 * re-create the scanner per call.
 */

#pragma once

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

class ReferenceTable;

/**
 * @brief MSVC x64 switch-dispatcher jump-table scanner — see header.
 */
class SwitchJumpTableScanner {
public:
    SwitchJumpTableScanner() = default;

    /**
     * @brief Scan every code section for dispatcher patterns and
     *        emit one reference per surviving jump-table entry.
     *
     * No-op when:
     *   * The image is not 64-bit — the only architecture the chaos
     *     pipeline supports today.
     *   * No code section yields a valid dispatcher triple.
     *
     * Decoder failures, malformed entries, and reads past a section
     * boundary are absorbed silently — scanners must not throw.
     */
    void scan(
        const PeImage&  image,
        ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
