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
 * `syscall` instruction directly, with the SSN for
 * `NtGetContextThread` loaded from `r13d` — which the runtime
 * Hell's Gate resolver (see `hells_gate_resolver.cpp`) populates
 * once per region, immediately before the anti-tamper loop. The
 * kernel sees the real DR values and the hook never gets a chance
 * to intercept.
 *
 * If the Hell's Gate resolver failed for any reason (ntdll moved,
 * export missing, prologue hooked), it leaves `r13d = 0`. The
 * subsequent `syscall` with eax=0 ends up calling `NtAcceptConnectPort`
 * or similar — the call either fails immediately (wrong parameters)
 * or succeeds but doesn't touch our CONTEXT struct. In both cases
 * CONTEXT stays zeroed (we clear it before the syscall), the DR OR
 * reads zero, and the final XOR is a no-op. Graceful degradation.
 *
 * Emitted byte sequence (~90 bytes):
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
 *     44 89 E8                       mov   eax, r13d               ; runtime-resolved SSN
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
 * Real hardware, no debugger: all DRs zero, eax = 0, the XOR is a
 * no-op, the VM continues normally. Real hardware with even one DR
 * set: eax = mask, key slot poisoned, every subsequent VM dispatch
 * decrypts the wrong handler offset and jumps into garbage.
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
 *   * it is not used by the Hell's Gate resolver that runs
 *     immediately before us (resolver uses rbx, rdi, r8, r9, r10,
 *     r11, r13, r14, r15 — specifically avoids r12 for this
 *     reason);
 *   * its original value is already saved in its VM-context slot,
 *     so clobbering it here is harmless.
 */

#include "mxprotector/protection/anti_tamper/check.hpp"

#include <memory>

namespace mx::anti_tamper {

class HwBreakpointSweepCheck final : public ICheck {
public:
    HwBreakpointSweepCheck() = default;

    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng) const override
    {
        // Random non-zero corruption mask so two builds differ even
        // when they pick the same check.
        const uint32_t corruption = rng.next_u32() | 1;

        // mov r12, rsp                           49 89 E4
        // (Preserved across syscall; see header comment for why.)
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

        // mov eax, r13d                          44 89 E8
        // r13 holds the SSN placed there by the Hell's Gate resolver
        // that ran immediately before the anti-tamper loop. On
        // resolver failure r13 is 0 and the syscall silently degrades.
        e.u8(0x44); e.u8(0x89); e.u8(0xE8);

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
};

std::unique_ptr<ICheck> make_hw_breakpoint_sweep_check() {
    return std::make_unique<HwBreakpointSweepCheck>();
}

} // namespace mx::anti_tamper
