/**
 * @file vm_call_pop_trampoline_scanner.hpp
 * @brief Emit references for the VM `CallPop` trampoline imm32
 *        slot (B.4.14).
 *
 * MxProtector's VM dispatcher emits one of three trampoline shapes
 * (Direct / PushRet / CallPop) at every handler-to-handler tail
 * dispatch. Two of them already carry rel32-encoded targets that
 * `CodeReferenceScanner` (Zydis-driven) sees:
 *
 *   * `Direct`  — `jmp rel32` (5 bytes). Standard `rel32` branch.
 *   * `PushRet` — `lea rax, [rip + rel32]; push rax; ret`. The `lea`
 *                 is an ordinary RIP-relative load.
 *
 * The third shape — `CallPop` — uses an imm32 the assembler does
 * not expose as relative:
 *
 *   call $+5                E8 00 00 00 00
 *   add  qword [rsp], imm32 48 81 04 24 imm32
 *   ret                     C3
 *
 * `imm32 = handler_offset - anchor` where `anchor` is the byte right
 * after the `call` (i.e. `call_rva + 5`). Semantically this is a
 * rel32 branch whose anchor is **4 bytes before the slot**, not the
 * standard `slot + width`. `CodeReferenceScanner` therefore does not
 * recognise the slot as carrying a target RVA.
 *
 * Without a dedicated scanner, the chaos shuffle moves trampolines
 * and their handler targets to new RVAs but the imm32 field stays at
 * its original `target - anchor` delta, sending the eventual `ret`
 * to a stale address. The crash signature is "execution lands in
 * the middle of a NOP" (mid-instruction RIP) at low single-digit
 * percent of stress runs.
 *
 * The scanner walks every code section, recognises the exact 14-byte
 * pattern, and emits one `Reference` per match:
 *
 *   * `location_rva` = imm32 slot (call_rva + 9)
 *   * `target_rva`   = call_rva + 5 + imm32 (decoded target)
 *   * `width`        = `byte4`
 *   * `encoding`     = `rel32_call_pop_anchored` (anchor at slot - 4)
 *   * `origin`       = `vm_call_pop_trampoline`
 *
 * SOLID:
 *   * SRP — exactly one pattern, exactly one reference type.
 *   * OCP — adding/removing the scanner is a one-line change in
 *     `chaos_layout.cpp::scan_all_references`.
 *
 * Threading: stateless apart from the per-call decoder. Re-create
 * the scanner per call.
 */

#pragma once

namespace mx {
class PeImage;
}

namespace mx::pe::refmap {

class ReferenceTable;

/**
 * @brief MxProtector VM `CallPop` trampoline scanner — see header.
 */
class VmCallPopTrampolineScanner {
public:
    VmCallPopTrampolineScanner() = default;

    /**
     * @brief Scan every code section for the 14-byte CallPop
     *        trampoline pattern and emit one reference per match.
     *
     * No-op when the image is not 64-bit. Decoder failures, byte
     * mismatches, and `imm32 == 0` (which would be a self-pointing
     * trampoline — never emitted by the VM but defensively
     * filtered) are silently skipped.
     */
    void scan(
        const PeImage&  image,
        ReferenceTable& table) const;
};

} // namespace mx::pe::refmap
