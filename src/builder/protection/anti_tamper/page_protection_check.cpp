/**
 * @file page_protection_check.cpp
 * @brief Anti-tamper probe — verifies the VM stub section is not writable.
 *
 * A reverser's default workflow for patching protected code is:
 *
 *   1. Attach a debugger and find the instruction of interest.
 *   2. Call `VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)`
 *      to add the write bit to the enclosing page.
 *   3. Write the patched byte(s) in place.
 *   4. (Optionally) `VirtualProtect` back to the original mask.
 *
 * Steps 1-3 are extremely common; step 4 is often skipped because it
 * doesn't affect correctness of the patched code path. This check
 * catches the common case by asking the kernel, via
 * `NtQueryVirtualMemory` with `MemoryBasicInformation`, what the
 * current protection mask is on a page inside our own VM stub
 * section. In a clean state the packer stub has already revoked
 * WRITE from `.mxvm` (see the Hell's Gate / NtProtectVirtualMemory
 * loop in `packer_pass.cpp`), so `MBI.Protect` is
 * `PAGE_EXECUTE_READ` (0x20). Any variant of
 * `PAGE_{READWRITE,WRITECOPY,EXECUTE_READWRITE,EXECUTE_WRITECOPY}`
 * has the low two bits of the high nibble set, so masking with
 * `0xCC` is zero on healthy state and non-zero if a VirtualProtect
 * added WRITE.
 *
 * The probe target is the check's own rip: `lea rdx, [rip + 0]`
 * lands on whichever byte follows the LEA in the entry stub, which
 * is always inside `.mxvm`. Using `rip` rather than a hard-coded
 * section RVA is important because:
 *
 *   * The `.mxvm` section name is randomised per build
 *     (`ctx.section_names().vm`), so a literal name constant would
 *     be a fingerprint. rip-relative has no name.
 *   * The section RVA is only known after `SectionManager` places
 *     the section — we'd otherwise need another late patch site.
 *   * rip is trivially self-validating: if the check is running,
 *     the rip pointer is by definition inside executable code the
 *     attacker is probing.
 *
 * The syscall scaffold and r12/r13 conventions follow the same
 * pattern as `hw_breakpoint_check.cpp`; see that file's header
 * comment for the rationale on register choices.
 *
 * Emitted byte sequence (~85 bytes):
 *
 *     49 89 E4                       mov   r12, rsp                 ; save rsp
 *     48 81 EC 80 00 00 00           sub   rsp, 0x80
 *     48 83 E4 F0                    and   rsp, -16
 *
 *     C7 44 24 64 00 00 00 00        mov   dword [rsp+0x64], 0      ; zero MBI.Protect
 *
 *     48 C7 C1 FF FF FF FF           mov   rcx, -1                  ; arg1 = NtCurrentProcess
 *     48 8D 15 00 00 00 00           lea   rdx, [rip + 0]           ; arg2 = probe address (in .mxvm)
 *     45 31 C0                       xor   r8d, r8d                 ; arg3 = MemoryBasicInformation (0)
 *     4C 8D 4C 24 40                 lea   r9, [rsp+0x40]           ; arg4 = &MBI
 *     48 C7 44 24 28 30 00 00 00     mov   qword [rsp+0x28], 0x30   ; arg5 = sizeof(MBI)
 *     48 8D 44 24 70                 lea   rax, [rsp+0x70]
 *     48 89 44 24 30                 mov   [rsp+0x30], rax          ; arg6 = &ReturnLength
 *
 *     49 89 CA                       mov   r10, rcx                 ; syscall ABI
 *     44 89 E8                       mov   eax, r13d                ; SSN from Hell's Gate
 *     0F 05                          syscall
 *
 *     8B 44 24 64                    mov   eax, [rsp+0x64]          ; MBI.Protect
 *     25 CC 00 00 00                 and   eax, 0xCC                ; keep only write bits
 *     F7 D8                          neg   eax                      ; CF iff non-zero
 *     19 C0                          sbb   eax, eax                 ; 0 or -1
 *
 *     4C 89 E4                       mov   rsp, r12                 ; restore rsp
 *
 *     25 ?? ?? ?? ??                 and   eax, <mask>              ; 0 or mask
 *     31 44 24 ??                    xor   [rsp + key_disp], eax    ; corrupt key on WRITE detected
 *
 * Stack layout inside the aligned 0x80-byte frame:
 *
 *     [rsp+0x00..0x1F]   shadow / unused
 *     [rsp+0x20..0x27]   unused
 *     [rsp+0x28..0x2F]   arg5 Length (0x30)
 *     [rsp+0x30..0x37]   arg6 &ReturnLength
 *     [rsp+0x38..0x3F]   unused
 *     [rsp+0x40..0x6F]   MEMORY_BASIC_INFORMATION (0x30 bytes)
 *       offset 0x24 inside MBI = [rsp+0x64]  ← Protect dword
 *     [rsp+0x70..0x77]   ReturnLength scratch
 *     [rsp+0x78..0x7F]   padding
 */

#include "mxprotector/protection/anti_tamper/check.hpp"
#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

#include <memory>

namespace mx::anti_tamper {

class PageProtectionCheck final : public ICheck {
public:
    PageProtectionCheck() = default;

    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng,
              const CheckContext& /*ctx*/) const override
    {
        const uint32_t corruption = rng.next_u32() | 1;

        // mov r12, rsp                         49 89 E4
        e.u8(0x49); e.u8(0x89); e.u8(0xE4);

        // sub rsp, 0x80                        48 81 EC 80 00 00 00
        e.u8(0x48); e.u8(0x81); e.u8(0xEC);
        e.u32(0x00000080u);

        // and rsp, -16                         48 83 E4 F0
        e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);

        // Zero MBI.Protect so a failed syscall leaves a benign value:
        // mov dword [rsp+0x64], 0              C7 44 24 64 00 00 00 00
        e.u8(0xC7); e.u8(0x44); e.u8(0x24); e.u8(0x64);
        e.u32(0x00000000u);

        // mov rcx, -1                          48 C7 C1 FF FF FF FF
        e.u8(0x48); e.u8(0xC7); e.u8(0xC1);
        e.u32(0xFFFFFFFFu);

        // lea rdx, [rip + 0]                   48 8D 15 00 00 00 00
        // Resolves to an address a few bytes forward inside this very
        // check's emitted code, which is inside the VM entry stub,
        // which lives in .mxvm.
        e.u8(0x48); e.u8(0x8D); e.u8(0x15);
        e.u32(0x00000000u);

        // xor r8d, r8d                         45 31 C0
        // MemoryInformationClass = MemoryBasicInformation = 0
        e.u8(0x45); e.u8(0x31); e.u8(0xC0);

        // lea r9, [rsp + 0x40]                 4C 8D 4C 24 40
        e.u8(0x4C); e.u8(0x8D); e.u8(0x4C); e.u8(0x24); e.u8(0x40);

        // mov qword [rsp + 0x28], 0x30         48 C7 44 24 28 30 00 00 00
        // Length parameter (5th arg); sizeof(MEMORY_BASIC_INFORMATION) = 0x30
        e.u8(0x48); e.u8(0xC7); e.u8(0x44); e.u8(0x24); e.u8(0x28);
        e.u32(0x00000030u);

        // lea rax, [rsp + 0x70]                48 8D 44 24 70
        e.u8(0x48); e.u8(0x8D); e.u8(0x44); e.u8(0x24); e.u8(0x70);
        // mov [rsp + 0x30], rax                48 89 44 24 30
        // ReturnLength pointer (6th arg)
        e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x30);

        // mov r10, rcx                         49 89 CA
        e.u8(0x49); e.u8(0x89); e.u8(0xCA);

        // mov eax, r13d                        44 89 E8
        // SSN placed by the Hell's Gate resolver. On resolver failure
        // r13 is 0, the syscall silently fails, MBI.Protect stays 0
        // (we explicitly zeroed it above), and the final XOR is a no-op.
        e.u8(0x44); e.u8(0x89); e.u8(0xE8);

        // syscall                              0F 05
        e.u8(0x0F); e.u8(0x05);

        // mov eax, [rsp + 0x64]                8B 44 24 64
        // MBI.Protect
        e.u8(0x8B); e.u8(0x44); e.u8(0x24); e.u8(0x64);

        // and eax, 0xCC                        25 CC 00 00 00
        // PAGE_READWRITE (0x04) | PAGE_WRITECOPY (0x08)
        //   | PAGE_EXECUTE_READWRITE (0x40) | PAGE_EXECUTE_WRITECOPY (0x80)
        e.u8(0x25); e.u32(0x000000CCu);

        // neg eax                              F7 D8
        // CF set iff eax was non-zero (any write bit present).
        e.u8(0xF7); e.u8(0xD8);
        // sbb eax, eax                         19 C0
        e.u8(0x19); e.u8(0xC0);

        // mov rsp, r12                         4C 89 E4
        e.u8(0x4C); e.u8(0x89); e.u8(0xE4);

        // and eax, <mask32>                    25 imm32
        e.u8(0x25); e.u32(corruption);

        // xor [rsp + key_disp], eax            31 44 24 disp8
        e.u8(0x31); e.u8(0x44); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "page_protection";
    }

    [[nodiscard]] const char* required_syscall_name() const noexcept override {
        return "NtQueryVirtualMemory";
    }
};

std::unique_ptr<ICheck> make_page_protection_check() {
    return std::make_unique<PageProtectionCheck>();
}

} // namespace mx::anti_tamper
