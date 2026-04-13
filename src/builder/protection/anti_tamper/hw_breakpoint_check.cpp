/**
 * @file hw_breakpoint_check.cpp
 * @brief Anti-tamper probe — sweeps DR0..DR3 via direct syscall.
 *
 * x86-64 has four debug-address registers (DR0..DR3) that latch a
 * virtual address each, plus DR7 which controls trap conditions.
 * Hardware breakpoints set by debuggers and DBI frameworks live in
 * those registers — they're invisible to ordinary code reads, but
 * `NtGetContextThread` (or the user-mode `GetThreadContext` wrapper)
 * exposes them via the CONTEXT structure when CONTEXT_DEBUG_REGISTERS
 * is set in the requested flags.
 *
 * Naïve implementation: call `GetThreadContext`. Problem: any EDR or
 * Frida-style hooker has hooked `kernel32!GetThreadContext` and the
 * underlying `ntdll!NtGetContextThread`. The hook can lie about
 * DR0..DR3, returning zeros to hide the attacker's own breakpoints.
 *
 * **This check bypasses user-mode hooks completely** by issuing the
 * `syscall` instruction directly with the build-time-resolved SSN of
 * `NtGetContextThread`. The kernel sees the real DR values and the
 * hook never gets a chance to intercept.
 *
 * Emitted byte sequence (~92 bytes):
 *
 *     49 89 E4                       mov   r12, rsp                ; save rsp (r12 — see note)
 *     48 81 EC E0 04 00 00           sub   rsp, 0x4E0              ; allocate CONTEXT + 16
 *     48 83 E4 F0                    and   rsp, -16                ; align CONTEXT to 16
 *
 *     31 C0                          xor   eax, eax                ; rax = 0
 *     48 89 E7                       mov   rdi, rsp                ; dest = CONTEXT base
 *     B9 9A 00 00 00                 mov   ecx, 0x9A               ; 0x9A * 8 = 0x4D0
 *     F3 48 AB                       rep stosq                     ; zero entire CONTEXT
 *
 *     C7 44 24 30 10 00 10 00        mov   dword [rsp+0x30], 0x100010   ; ContextFlags = CONTEXT_DEBUG_REGISTERS
 *
 *     48 C7 C1 FE FF FF FF           mov   rcx, -2                 ; thread handle (current thread pseudo)
 *     48 89 E2                       mov   rdx, rsp                ; CONTEXT*
 *     49 89 CA                       mov   r10, rcx                ; syscall ABI: r10 ← rcx
 *     B8 ?? ?? ?? ??                 mov   eax, <SSN>              ; build-time resolved SSN
 *     0F 05                          syscall
 *
 *     48 8B 44 24 48                 mov   rax, [rsp+0x48]         ; DR0
 *     48 0B 44 24 50                 or    rax, [rsp+0x50]         ; DR1
 *     48 0B 44 24 58                 or    rax, [rsp+0x58]         ; DR2
 *     48 0B 44 24 60                 or    rax, [rsp+0x60]         ; DR3
 *
 *     48 F7 D8                       neg   rax                     ; CF iff non-zero
 *     19 C0                          sbb   eax, eax                ; 0 or -1
 *
 *     4C 89 E4                       mov   rsp, r12                ; restore rsp
 *
 *     25 ?? ?? ?? ??                 and   eax, <mask>             ; 0 or mask
 *     31 44 24 ??                    xor   [rsp + key_disp], eax   ; corrupt key on real DR
 *
 * Real hardware, no debugger: DR0..DR3 are all zero. eax = 0 →
 * `xor [key_disp], 0` is a no-op. Real hardware, debugger has set a
 * breakpoint: at least one DR is non-zero. eax = mask → key slot is
 * corrupted → every subsequent VM dispatch decrypts wrong → first
 * dispatch jumps into garbage.
 *
 * ## Why r12 as the rsp save register
 *
 * The Windows x64 `syscall` instruction unconditionally clobbers
 * **rcx** (loaded with the saved RIP) and **r11** (loaded with the
 * saved RFLAGS) — those values do NOT survive across the syscall.
 * Every other GPR is preserved. We pick r12 because:
 *
 *   * it is preserved across syscall (unlike r11);
 *   * it is not used by any other anti-emulation check that may
 *     run before us (rdtsc / cpuid use only rax/rbx/rcx/rdx);
 *   * its original value is already saved in its VM-context slot,
 *     so clobbering it here is harmless;
 *   * the first VM dispatch reloads any base register it picks via
 *     `lea base, [rip + table]`, so even if the dispatch picks
 *     r12 as the table base, our scratch use is safely overwritten.
 *
 * ## Stack alignment
 *
 * The Windows x64 ABI requires the `CONTEXT` struct to be 16-byte
 * aligned. The entry stub's rsp may be 8- or 16-aligned depending
 * on the G7 padding draw, so we explicitly align with `and rsp, -16`
 * after subtracting an extra 16 bytes of headroom.
 *
 * ## Failure mode
 *
 * If the syscall fails (wrong SSN, kernel reject, EDR blocking the
 * sysenter), the CONTEXT remains zeroed (we cleared it before the
 * call), DR0..DR3 read as zeros, eax = 0, the XOR is a no-op. The
 * check silently degrades — the protected binary keeps working,
 * just without the DR sweep.
 *
 * ## Limitation: build-time SSN
 *
 * The SSN is hardcoded at build time from the builder host's
 * NTDLL. If the protected binary runs on a Windows build with
 * different syscall numbering, the `syscall` will hit the wrong
 * service. A future runtime Hell's Gate resolver in the entry stub
 * itself will fix this; until then, the check assumes builder and
 * target share the same Windows version.
 */

#include "mxprotector/protection/anti_tamper/check.hpp"

#include <memory>

namespace mx::anti_tamper {

class HwBreakpointSweepCheck final : public ICheck {
public:
    explicit HwBreakpointSweepCheck(uint32_t nt_get_context_thread_ssn) noexcept
        : ssn_(nt_get_context_thread_ssn)
    {}

    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        // Random non-zero corruption mask so two builds differ even
        // when they pick the same check.
        const uint32_t corruption = rng.next_u32() | 1;

        // mov r12, rsp                           49 89 E4
        // CRITICAL: NOT r11. The Windows x64 `syscall` instruction
        // clobbers BOTH rcx (gets RIP) AND r11 (gets RFLAGS), so r11
        // does NOT survive across the syscall. r12 is preserved.
        // We can clobber r12 freely here because (a) its original
        // value is in its VM-context slot, and (b) the first VM
        // dispatch reloads any base register it picks via
        // `lea base, [rip + table]`.
        e.u8(0x49); e.u8(0x89); e.u8(0xE4);

        // sub rsp, 0x4E0                         48 81 EC E0 04 00 00
        // (CONTEXT is 0x4D0; +16 of headroom for the 16-byte alignment)
        e.u8(0x48); e.u8(0x81); e.u8(0xEC);
        e.u32(0x000004E0u);

        // and rsp, -16                           48 83 E4 F0
        e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);

        // Zero entire CONTEXT (0x4D0 bytes = 0x9A qwords) via rep stosq.
        // xor eax, eax                           31 C0
        e.u8(0x31); e.u8(0xC0);
        // mov rdi, rsp                           48 89 E7
        e.u8(0x48); e.u8(0x89); e.u8(0xE7);
        // mov ecx, 0x9A                          B9 9A 00 00 00
        e.u8(0xB9); e.u32(0x0000009Au);
        // rep stosq                              F3 48 AB
        e.u8(0xF3); e.u8(0x48); e.u8(0xAB);

        // mov dword [rsp + 0x30], CONTEXT_DEBUG_REGISTERS (0x00100010)
        // C7 44 24 30 10 00 10 00
        e.u8(0xC7); e.u8(0x44); e.u8(0x24); e.u8(0x30);
        e.u32(0x00100010u);

        // mov rcx, -2  — current thread pseudo-handle (NtCurrentThread).
        // sign-extended imm32 form: 48 C7 C1 imm32
        e.u8(0x48); e.u8(0xC7); e.u8(0xC1);
        e.u32(0xFFFFFFFEu);

        // mov rdx, rsp                           48 89 E2
        e.u8(0x48); e.u8(0x89); e.u8(0xE2);

        // mov r10, rcx                           49 89 CA
        // (Windows x64 syscall ABI moves the first arg from rcx to r10
        //  because the `syscall` instruction itself clobbers rcx.)
        e.u8(0x49); e.u8(0x89); e.u8(0xCA);

        // mov eax, <SSN>                         B8 imm32
        e.u8(0xB8); e.u32(ssn_);

        // syscall                                0F 05
        e.u8(0x0F); e.u8(0x05);

        // After return:
        //   rax       = NTSTATUS (ignored — failure path leaves
        //               CONTEXT zeroed → DR=0 → no-op XOR)
        //   rcx, r11  = clobbered by syscall (RIP, RFLAGS)
        //   r12       = preserved (still holds saved rsp)
        //   CONTEXT at [rsp + 0x00 .. rsp + 0x4D0] is filled in

        // mov rax, [rsp + 0x48]                  48 8B 44 24 48      ; DR0
        e.u8(0x48); e.u8(0x8B); e.u8(0x44); e.u8(0x24); e.u8(0x48);
        // or  rax, [rsp + 0x50]                  48 0B 44 24 50      ; DR1
        e.u8(0x48); e.u8(0x0B); e.u8(0x44); e.u8(0x24); e.u8(0x50);
        // or  rax, [rsp + 0x58]                  48 0B 44 24 58      ; DR2
        e.u8(0x48); e.u8(0x0B); e.u8(0x44); e.u8(0x24); e.u8(0x58);
        // or  rax, [rsp + 0x60]                  48 0B 44 24 60      ; DR3
        e.u8(0x48); e.u8(0x0B); e.u8(0x44); e.u8(0x24); e.u8(0x60);

        // neg rax                                48 F7 D8           ; CF iff non-zero
        e.u8(0x48); e.u8(0xF7); e.u8(0xD8);
        // sbb eax, eax                           19 C0              ; 0 or -1
        e.u8(0x19); e.u8(0xC0);

        // mov rsp, r12                           4C 89 E4           ; restore rsp
        e.u8(0x4C); e.u8(0x89); e.u8(0xE4);

        // and eax, <mask32>                      25 imm32           ; 0 or mask
        e.u8(0x25); e.u32(corruption);

        // xor [rsp + key_disp], eax              31 44 24 disp8
        e.u8(0x31); e.u8(0x44); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "hw_breakpoint_sweep";
    }

private:
    const uint32_t ssn_;
};

std::unique_ptr<ICheck> make_hw_breakpoint_sweep_check(uint32_t nt_get_context_thread_ssn) {
    return std::make_unique<HwBreakpointSweepCheck>(nt_get_context_thread_ssn);
}

} // namespace mx::anti_tamper
