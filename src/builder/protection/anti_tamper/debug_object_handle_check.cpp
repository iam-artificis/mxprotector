/**
 * @file debug_object_handle_check.cpp
 * @brief G3 anti-tamper probe — queries the process debug object handle.
 *
 * `NtQueryInformationProcess(h, ProcessDebugObjectHandle = 0x1E, ...)`
 * returns the kernel HANDLE of the debug object bound to the current
 * process when one has been attached via `DebugActiveProcess` or a
 * `CREATE_SUSPENDED | DEBUG_PROCESS` launch. With no debugger the
 * call fails with `STATUS_PORT_NOT_SET (0xC0000353)` and the output
 * buffer is left untouched by the kernel. We zero the buffer
 * ourselves before the syscall, so after the call the buffer holds
 * one of two well-defined values:
 *
 *   * 0              — no debugger attached (or syscall failed; see below)
 *   * non-zero handle — debugger attached
 *
 * The detection logic XORs the buffer value into the handler-table
 * key slot through the same `neg / sbb / and mask / xor [key]`
 * pattern the HW-breakpoint check uses. A clean host leaves the key
 * untouched; an attached debugger corrupts it and the very next
 * handler dispatch decrypts to garbage — the process crashes with a
 * wild indirect branch before the debugger has a chance to step
 * into the VM body.
 *
 * ## Why this complements `hw_breakpoint_sweep`
 *
 * The two checks detect orthogonal cases:
 *
 *   * HW-breakpoint sweep reads DR0..DR3 via `NtGetContextThread`.
 *     Catches any breakpoint installed on any thread — whether by
 *     a debugger, a DBI framework, a Frida-style library, or a
 *     user-mode exception hook.
 *
 *   * Debug-object-handle check asks the kernel whether the whole
 *     process is bound to a debug port. Catches a debugger that
 *     attached via `DebugActiveProcess` but hasn't yet (or will
 *     never) set hardware breakpoints. Also fires on processes
 *     launched under a debugger from scratch with `DEBUG_PROCESS`.
 *
 * A determined attacker has to clear BOTH the DR registers (via a
 * hook on NtGetContextThread) AND the debug-object handle (via a
 * hook on NtQueryInformationProcess). Each one forces a separate
 * per-syscall hook, and the P5 per-build salted DJB2 hashes make
 * pre-installed hooks look for the wrong imports by name — the
 * attacker has to hash every ntdll export under the salt they
 * extract from the binary AND re-hook based on the match.
 *
 * ## Direct syscall, not a ntdll stub
 *
 * Identical rationale to `hw_breakpoint_check`: going through the
 * user-mode ntdll stub lets a hook patch the result on the way
 * back. We issue the raw `syscall` instruction with the SSN from
 * r13d (placed there by the Hell's Gate resolver immediately
 * before this check body). On resolver failure r13 is left at 0
 * and the subsequent syscall invokes an unrelated, usually-failing
 * service number. The buffer we cleared stays zeroed, the
 * detection XOR collapses to a no-op, and the VM runs as if the
 * check had been disabled — graceful degradation.
 *
 * ## Emitted byte sequence (~85 bytes)
 *
 *     49 89 E4                 mov    r12, rsp                 ; save rsp
 *     48 81 EC 40 00 00 00     sub    rsp, 0x40                ; 0x40-byte frame
 *     48 83 E4 F0              and    rsp, -16                 ; align
 *
 *     48 C7 44 24 30 00 00 00 00   mov  qword [rsp+0x30], 0   ; zero buf
 *     48 C7 44 24 28 00 00 00 00   mov  qword [rsp+0x28], 0   ; arg5 = NULL
 *
 *     48 C7 C1 FF FF FF FF     mov    rcx, -1                  ; NtCurrentProcess
 *     BA 1E 00 00 00           mov    edx, 0x1E                ; ProcessDebugObjectHandle
 *     4C 8D 44 24 30           lea    r8, [rsp+0x30]           ; &buf
 *     41 B9 08 00 00 00        mov    r9d, 8                   ; length
 *
 *     49 89 CA                 mov    r10, rcx                 ; syscall ABI
 *     44 89 E8                 mov    eax, r13d                ; SSN from r13
 *     0F 05                    syscall
 *
 *     48 8B 44 24 30           mov    rax, [rsp+0x30]          ; read buf
 *     48 F7 D8                 neg    rax                      ; CF iff non-zero
 *     19 C0                    sbb    eax, eax                 ; 0 or -1
 *
 *     4C 89 E4                 mov    rsp, r12                 ; restore rsp
 *
 *     25 ?? ?? ?? ??           and    eax, <mask>              ; 0 or mask
 *     31 44 24 ??              xor    [rsp + key_disp], eax    ; silent kill
 *
 * The `mov rsp, r12` lands BEFORE the final `and eax, mask` so the
 * subsequent `xor [rsp + disp8]` sees the caller's original rsp.
 * `key_disp` is always rsp-relative to the VM entry stub, so
 * restoring rsp first is required for the addressing to be valid.
 */

#include "mxprotector/protection/anti_tamper/check.hpp"
#include "mxprotector/protection/anti_tamper/syscall_scaffold.hpp"

#include <memory>

namespace mx::anti_tamper {

class DebugObjectHandleCheck final : public ICheck {
public:
    DebugObjectHandleCheck() = default;

    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng,
              const CheckContext& /*ctx*/) const override
    {
        // Per-build random non-zero corruption mask. Two builds with
        // the same check pick different masks, so a pattern that
        // matches one build's poisoned key slot doesn't help on
        // another build.
        const uint32_t corruption = rng.next_u32() | 1;

        // 0x40 bytes = 0x20 shadow + 0x08 arg5 slot + 0x08 out buffer
        //            + 0x10 padding for the `and rsp, -16` alignment.
        constexpr uint32_t kHandleFrameSize = 0x00000040u;

        emit_syscall_check_scaffold(
            e, kHandleFrameSize, key_slot_disp, corruption,
            // ---- setup ----
            [](RawEmitter& w) {
                // Zero the output buffer so the detection branch is
                // reliable even when the kernel leaves it untouched on
                // failure (which is exactly what happens for
                // STATUS_PORT_NOT_SET — the no-debugger return path).
                //
                // mov qword [rsp + 0x30], 0      48 C7 44 24 30 00 00 00 00
                w.u8(0x48); w.u8(0xC7); w.u8(0x44); w.u8(0x24); w.u8(0x30);
                w.u32(0);
                // mov qword [rsp + 0x28], 0      48 C7 44 24 28 00 00 00 00
                //   arg5 = PULONG ReturnLength = NULL.
                w.u8(0x48); w.u8(0xC7); w.u8(0x44); w.u8(0x24); w.u8(0x28);
                w.u32(0);

                // mov rcx, -1                    48 C7 C1 FF FF FF FF
                //   ProcessHandle = NtCurrentProcess pseudo-handle (-1).
                w.u8(0x48); w.u8(0xC7); w.u8(0xC1);
                w.u32(0xFFFFFFFFu);
                // mov edx, 0x1E                  BA 1E 00 00 00
                //   PROCESS_INFORMATION_CLASS::ProcessDebugObjectHandle.
                w.u8(0xBA);
                w.u32(0x0000001Eu);
                // lea r8, [rsp + 0x30]           4C 8D 44 24 30
                //   ProcessInformation → our 8-byte buffer.
                w.u8(0x4C); w.u8(0x8D); w.u8(0x44); w.u8(0x24); w.u8(0x30);
                // mov r9d, 8                     41 B9 08 00 00 00
                //   ProcessInformationLength = sizeof(HANDLE) on x64.
                w.u8(0x41); w.u8(0xB9);
                w.u32(0x00000008u);
            },
            // ---- detection ----
            //
            // After return [rsp + 0x30 .. 0x37] holds either 0 (clean)
            // or a non-zero HANDLE (debugger attached). Normalise to
            // 0 / -1 via the neg/sbb idiom. Zero-extends to rax.
            [](RawEmitter& w) {
                // mov rax, [rsp + 0x30]          48 8B 44 24 30
                w.u8(0x48); w.u8(0x8B); w.u8(0x44); w.u8(0x24); w.u8(0x30);
                // neg rax                        48 F7 D8  ; CF iff non-zero
                w.u8(0x48); w.u8(0xF7); w.u8(0xD8);
                // sbb eax, eax                   19 C0     ; 0 or -1
                w.u8(0x19); w.u8(0xC0);
            });
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "debug_object_handle";
    }

    [[nodiscard]] const char* required_syscall_name() const noexcept override {
        // G3 — the backend hashes this name under a per-build salt
        // and emits a Hell's Gate resolver that walks the PEB,
        // finds ntdll, and places the SSN in r13d before the check
        // runs.
        return "NtQueryInformationProcess";
    }
};

std::unique_ptr<ICheck> make_debug_object_handle_check() {
    return std::make_unique<DebugObjectHandleCheck>();
}

} // namespace mx::anti_tamper
