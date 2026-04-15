/**
 * @file veh_int3_trap.cpp
 * @brief G3 Phase 2 VEH INT3 trap emitter — see veh_int3_trap.hpp.
 *
 * Every instruction in the emitted block is annotated with its
 * byte layout and, where relevant, its runtime role. The layout
 * is fragile: patch slots (rel8 and rel32) are indexed into the
 * emitter buffer after each instruction is emitted, so changing
 * the byte sequence of any instruction also shifts the patch
 * offsets of everything that follows.
 */

#include "mxprotector/protection/packer/veh_int3_trap.hpp"

#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

#include <cstdint>
#include <cstring>

namespace mx::packer {

namespace {

/// Fill a 1-byte rel8 placeholder at `patch` so it branches to
/// `target`. `patch` is the offset of the rel8 byte itself; the
/// branch is taken from the byte AFTER `patch` (which is
/// `patch + 1`), matching the rel8 addressing convention used by
/// every `75`/`74`/`EB` opcode on x64.
inline void patch_rel8(RawEmitter& e, size_t patch, size_t target) noexcept {
    const int delta = static_cast<int>(target) - static_cast<int>(patch + 1);
    e.buf[patch] = static_cast<uint8_t>(static_cast<int8_t>(delta));
}

} // namespace

void emit_veh_int3_trap(RawEmitter& e, Randomizer& rng) {
    // ----------------------------------------------------------------
    // (1) jmp short .past_handler                  EB rel8
    //
    // Execution enters this block linearly from the surrounding
    // packer stub. We jump over the handler body so the instructions
    // we're about to emit aren't executed as code — they're the
    // VEH's own function body and must only be entered via the
    // kernel's KiUserCallbackDispatcher after `AddVectoredException
    // Handler` installed them.
    // ----------------------------------------------------------------
    e.u8(0xEB);
    const size_t jmp_past_handler_rel8 = e.size();
    e.u8(0x00);

    // ----------------------------------------------------------------
    // (2) .handler: LONG NTAPI VEH(PEXCEPTION_POINTERS info)
    //
    // The kernel calls this with:
    //   rcx = PEXCEPTION_POINTERS info
    //         [rcx + 0x00] = PEXCEPTION_RECORD ExceptionRecord
    //         [rcx + 0x08] = PCONTEXT          ContextRecord
    //
    // EXCEPTION_RECORD layout on x64:
    //   [rec + 0x00] DWORD  ExceptionCode
    //   [rec + 0x04] DWORD  ExceptionFlags
    //   [rec + 0x08] PEXCEPTION_RECORD ExceptionRecord (chain)
    //   [rec + 0x10] PVOID  ExceptionAddress      ← we care about this
    //   [rec + 0x18] DWORD  NumberParameters
    //   ...
    //
    // CONTEXT on x64: Rip lives at offset 0xF8.
    //
    // Return value (in eax):
    //   EXCEPTION_CONTINUE_EXECUTION = -1  (0xFFFFFFFF)
    //   EXCEPTION_CONTINUE_SEARCH    =  0
    //
    // The filter is strict: we only act on an exception whose code
    // is STATUS_BREAKPOINT (0x80000003) AND whose address matches
    // our one planted int3. Every other exception — including C++
    // `throw` (code 0xE06D7363) — gets CONTINUE_SEARCH so the
    // protected binary's own try/catch machinery stays untouched.
    // ----------------------------------------------------------------
    const size_t handler_offset = e.size();

    // mov rdx, [rcx]                               48 8B 11
    //   rdx = PEXCEPTION_RECORD*
    e.u8(0x48); e.u8(0x8B); e.u8(0x11);

    // mov eax, [rdx]                               8B 02
    //   eax = ExceptionCode (32-bit at offset 0)
    e.u8(0x8B); e.u8(0x02);

    // cmp eax, 0x80000003                          3D 03 00 00 80
    //   STATUS_BREAKPOINT
    e.u8(0x3D);
    e.u32(0x80000003u);

    // jne short .not_ours                          75 rel8 (placeholder)
    e.u8(0x75);
    const size_t jne1_rel8 = e.size();
    e.u8(0x00);

    // mov rax, [rdx + 0x10]                        48 8B 42 10
    //   rax = ExceptionAddress
    e.u8(0x48); e.u8(0x8B); e.u8(0x42); e.u8(0x10);

    // lea r9, [rip + .int3_addr - end_of_lea]      4C 8D 0D rel32
    //   Rel32 patched in once we know where the int3 landed.
    e.u8(0x4C); e.u8(0x8D); e.u8(0x0D);
    const size_t lea_r9_disp32 = e.size();
    e.u32(0);
    const size_t end_of_lea_r9 = e.size();

    // cmp rax, r9                                  4C 39 C8
    //   Are we the one planted int3? REX.W+REX.R = 0x4C, opcode 39.
    //   ModRM mod=11 reg=r9(001) rm=rax(000) → 0xC8.
    e.u8(0x4C); e.u8(0x39); e.u8(0xC8);

    // jne short .not_ours                          75 rel8 (placeholder)
    e.u8(0x75);
    const size_t jne2_rel8 = e.size();
    e.u8(0x00);

    // mov rax, [rcx + 0x08]                        48 8B 41 08
    //   rax = PCONTEXT
    e.u8(0x48); e.u8(0x8B); e.u8(0x41); e.u8(0x08);

    // add qword [rax + 0xF8], 7                    48 83 80 F8 00 00 00 07
    //   CONTEXT.Rip += 1 (int3) + 6 (junk). The sign-extended imm8
    //   form of ADD covers the +7 advance in one 8-byte instruction.
    //   ModRM mod=10 (disp32) reg=/0 (ADD) rm=rax(000) → 0x80.
    e.u8(0x48); e.u8(0x83); e.u8(0x80);
    e.u32(0x000000F8u);
    e.u8(0x07);

    // mov eax, 0xFFFFFFFF                          B8 FF FF FF FF
    //   EXCEPTION_CONTINUE_EXECUTION. The kernel re-reads CONTEXT
    //   on return, so the modified Rip takes effect.
    e.u8(0xB8);
    e.u32(0xFFFFFFFFu);

    // ret                                          C3
    e.u8(0xC3);

    // .not_ours: — exception code or address doesn't match, delegate
    //   to the next VEH / SEH chain link. This is the path that
    //   fires for every C++ `throw` in the protected binary.
    {
        const size_t not_ours_label = e.size();
        patch_rel8(e, jne1_rel8, not_ours_label);
        patch_rel8(e, jne2_rel8, not_ours_label);
    }

    // xor eax, eax                                 31 C0
    //   EXCEPTION_CONTINUE_SEARCH = 0
    e.u8(0x31); e.u8(0xC0);

    // ret                                          C3
    e.u8(0xC3);

    // .past_handler: — execution resumes from the `jmp short` at
    //   the top of this block. Patch the rel8.
    {
        const size_t past_handler_label = e.size();
        patch_rel8(e, jmp_past_handler_rel8, past_handler_label);
    }

    // ----------------------------------------------------------------
    // (3) Install the handler via ntdll!RtlAddVectoredExceptionHandler.
    //
    // Windows x64 ABI for a call: 16-aligned rsp BEFORE the call
    // instruction itself; the call pushes the return address and
    // the callee sees mod-16 == 8. We save rsp in r12, align, and
    // allocate 0x28 bytes of shadow space (the 0x20 required by the
    // ABI + 8 bytes of padding, total = 0x28 → 40 bytes, which is
    // still 8-aligned but aligns the post-call rsp correctly).
    //
    // Hell's Gate is the same address-resolver the packer already
    // uses for NtProtectVirtualMemory. On any failure path (ntdll
    // moved, prologue mismatch, export name not found) r13 comes
    // back at 0 and we skip the `call r13` entirely — the trap is
    // effectively a no-op, and the int3 planted below will crash
    // the process when it fires. That's an opt-in feature on an
    // opt-in flag, so graceful-degradation-to-crash is acceptable.
    // ----------------------------------------------------------------

    // mov r12, rsp                                 49 89 E4
    e.u8(0x49); e.u8(0x89); e.u8(0xE4);
    // and rsp, -16                                 48 83 E4 F0
    e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);
    // sub rsp, 0x28                                48 83 EC 28
    //   0x20 shadow space + 0x08 alignment pad.
    e.u8(0x48); e.u8(0x83); e.u8(0xEC); e.u8(0x28);

    // Hell's Gate address resolver → r13 = RtlAddVectoredExceptionHandler.
    // `validate_syscall_prologue=false` because this target is a
    // plain user-mode function, not an Nt* syscall stub — its
    // prologue doesn't start with `4C 8B D1 B8` and the default
    // validation would reject every lookup.
    {
        const uint32_t salt = rng.next_u32();
        const uint32_t target_hash = anti_tamper::djb2_ascii_hash_salted(
            "RtlAddVectoredExceptionHandler", salt);
        RawEmitter tmp{};
        anti_tamper::emit_hells_gate_address_resolver(
            tmp, target_hash, salt,
            /*validate_syscall_prologue=*/false);
        e.bytes(ByteView{tmp.buf.data(), tmp.buf.size()});
    }

    // test r13, r13                                4D 85 ED
    e.u8(0x4D); e.u8(0x85); e.u8(0xED);
    // jz short .skip_install                       74 rel8 (placeholder)
    e.u8(0x74);
    const size_t jz_skip_install_rel8 = e.size();
    e.u8(0x00);

    // mov ecx, 1                                   B9 01 00 00 00
    //   first = 1 → prepend (our VEH runs before any handler the
    //   C++ runtime might have installed earlier, which is what we
    //   want for breakpoint capture).
    e.u8(0xB9);
    e.u32(1u);

    // lea rdx, [rip + .handler - end_of_lea]       48 8D 15 disp32
    //   Handler address as an rip-relative offset computed at emit
    //   time. The `handler_offset` label was recorded when we
    //   finished emitting the jmp-past-handler prefix at the start
    //   of this function.
    e.u8(0x48); e.u8(0x8D); e.u8(0x15);
    {
        const size_t disp_slot = e.size();
        const size_t end_of_lea = disp_slot + 4;
        const int32_t disp = static_cast<int32_t>(handler_offset) -
                             static_cast<int32_t>(end_of_lea);
        e.u32(static_cast<uint32_t>(disp));
    }

    // call r13                                     41 FF D5
    //   RtlAddVectoredExceptionHandler(first=1, handler). On return
    //   the VEH is installed at the head of the chain.
    e.u8(0x41); e.u8(0xFF); e.u8(0xD5);

    // .skip_install: — back-patch site for the `test r13, r13; jz`.
    {
        const size_t skip_label = e.size();
        patch_rel8(e, jz_skip_install_rel8, skip_label);
    }

    // mov rsp, r12                                 4C 89 E4
    //   Restore caller rsp. From here on, the register state is
    //   whatever the Hell's Gate resolver left behind (scratch
    //   clobbered, r13 possibly zero). The surrounding cipher body
    //   rebuilds everything it needs from scratch.
    e.u8(0x4C); e.u8(0x89); e.u8(0xE4);

    // ----------------------------------------------------------------
    // (4) Planted int3 + 6 bytes of per-build random junk.
    //
    // Execution reaches this point linearly. The int3 fires, the
    // VEH (if it was installed) catches the exception, checks that
    // the address matches the lea-r9 target, advances CONTEXT.Rip
    // by 7, and resumes execution PAST the junk bytes.
    //
    // Reverse-engineering effects:
    //   * Linear disassemblers decode the 6 junk bytes as
    //     instructions, producing bogus control flow that doesn't
    //     reflect real execution.
    //   * Debuggers that swallow first-chance SEH exceptions never
    //     deliver the int3 to the VEH; execution either stalls at
    //     the int3 or the debugger auto-advances Rip by 1 into
    //     the first junk byte, which rarely decodes to a clean
    //     instruction — disrupting the reverser's workflow.
    //   * Debuggers that PASS first-chance exceptions to the
    //     program behave like clean execution (VEH runs, advances
    //     Rip). No detection in that configuration, but the
    //     static-analysis confusion still applies.
    // ----------------------------------------------------------------
    const size_t int3_offset = e.size();
    e.u8(0xCC);
    for (int i = 0; i < 6; ++i) {
        e.u8(rng.next_u8());
    }

    // Patch the `lea r9, [rip + .int3_addr]` disp32 inside the
    // handler body so r9 loads the runtime address of the int3
    // we just planted.
    {
        const int32_t disp = static_cast<int32_t>(int3_offset) -
                             static_cast<int32_t>(end_of_lea_r9);
        std::memcpy(e.buf.data() + lea_r9_disp32, &disp, sizeof(disp));
    }
}

} // namespace mx::packer
