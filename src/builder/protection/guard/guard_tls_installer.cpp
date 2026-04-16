/**
 * @file guard_tls_installer.cpp
 * @brief Byte-level emission of the runtime-guards TLS installer
 *        thunk. See guard_tls_installer.hpp for the ABI and flow.
 */

#include "mxprotector/protection/guard/guard_tls_installer.hpp"

#include <cstring>

#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"

namespace mx::guard {

GuardTlsInstallerEmit emit_guard_tls_installer(
    RawEmitter& e,
    Randomizer& rng)
{
    GuardTlsInstallerEmit out{};
    const uint32_t start = static_cast<uint32_t>(e.size());

    // =================================================================
    // Reason filter: only DLL_PROCESS_ATTACH (1) triggers the install.
    //
    //   cmp edx, 1                       83 FA 01
    //   jne .done (near, rel32)          0F 85 rel32  (patched below)
    //
    // NOTE: this MUST be a near jne (rel32), not a short one.
    // The `.done` label lives at the far end of the installer
    // (past the 155-byte Hell's Gate resolver + the 51-byte CRC
    // block + the ~15 bytes of AVEH call setup), which is well
    // beyond the ±127-byte rel8 range. An earlier commit shipped
    // this as a rel8 by mistake; the truncated byte wrapped to
    // `-32` and jumped BACKWARD into the VEH handler, producing
    // crashes on any TLS callback invocation where `reason != 1`
    // (DLL_THREAD_ATTACH, etc.). Single-threaded tests never hit
    // that branch, so the bug lay dormant until Commit 7's
    // polymorphic handler tail shifted the crash landing byte
    // into a truly invalid instruction. See that commit's message
    // for the full diagnosis.
    //
    // THREAD_ATTACH / THREAD_DETACH / PROCESS_DETACH are ignored —
    // the VEH only needs to be registered once per process lifetime,
    // and doing it on THREAD_ATTACH would install a fresh handler
    // per thread which is wasteful and noisy in EDR telemetry.
    // =================================================================
    e.u8(0x83); e.u8(0xFA); e.u8(0x01);
    e.u8(0x0F); e.u8(0x85);
    const uint32_t done_rel32_slot = static_cast<uint32_t>(e.size());
    e.u32(0);

    // =================================================================
    // Reserve shadow space + alignment for the upcoming `call r13`.
    //
    //   sub rsp, 0x28                    48 83 EC 28
    //
    // The TLS loader enters this callback with rsp mod 16 == 8 (the
    // return address just got pushed). Subtracting 0x28 brings rsp
    // back to mod 16 == 0 before the call and leaves 0x20 bytes of
    // shadow space as required by the Windows x64 ABI.
    // =================================================================
    e.u8(0x48); e.u8(0x83); e.u8(0xEC); e.u8(0x28);

    // =================================================================
    // Resolve RtlAddVectoredExceptionHandler via Hell's Gate.
    //
    // The resolver walks PEB.Ldr → ntdll exports, salted-hashes each
    // name, and compares against our precomputed target hash. On
    // match it plants the full 64-bit function address in `r13`; on
    // any failure (ntdll not found, export not found, per-build salt
    // does not match) it leaves `r13 = 0` so the install is silently
    // skipped — a degraded but non-crashing mode identical to the
    // packer reprotect block's graceful fallback.
    //
    // `RtlAddVectoredExceptionHandler` is NOT a syscall stub (it
    // doesn't start with `4C 8B D1 B8`), so we pass
    // `validate_syscall_prologue = false`. Without that, the
    // resolver would reject the match and always return 0.
    // =================================================================
    {
        const uint32_t salt = rng.next_u32();
        const uint32_t name_hash = anti_tamper::djb2_ascii_hash_salted(
            "RtlAddVectoredExceptionHandler", salt);
        anti_tamper::emit_hells_gate_address_resolver(
            e, name_hash, salt,
            /*validate_syscall_prologue=*/false);
    }

    // =================================================================
    // Skip the call if the resolver failed (r13 == 0).
    //
    //   test r13, r13                    4D 85 ED
    //   jz   .restore                    74 rel8 (patched below)
    // =================================================================
    e.u8(0x4D); e.u8(0x85); e.u8(0xED);
    e.u8(0x74);
    const uint32_t skip_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // Commit 6 — Self-CRC of the VEH handler body.
    //
    // Before installing the handler, walk its byte stream, compute
    // an FNV-1a hash, and compare against a build-time-baked
    // expected value. A mismatch means someone modified the
    // handler bytes (a reverser patched anti-debug out, an inline
    // hook landed on the prologue, etc.) and we silently skip the
    // install. The VEH is then never registered, and the first
    // guard `int3` at runtime propagates as an unhandled
    // breakpoint — the process terminates.
    //
    // The CRC walks the CURRENT in-memory bytes of the handler,
    // not the bytes at disk-image time, so this specifically
    // catches runtime-applied patches (e.g., by a loader-level
    // hook) that happen between PE mapping and TLS callback
    // execution. Static on-disk tampering also fires the check
    // because P6's stub self-hash would already have detected it
    // via its own mechanism — this is a layered defence.
    //
    //   mov r10d, 0x811C9DC5             41 BA imm32   ; hash = offset basis
    //   lea r11, [rip + rel32_handler]   4C 8D 1D rel32  ; r11 = handler start
    //   mov ecx, <size>                  B9 imm32       ; byte count (patched)
    //   mov r8d, 0x01000193              41 B8 imm32    ; FNV prime
    //   .crc_loop:
    //     movzx eax, byte [r11]          41 0F B6 03
    //     xor   r10d, eax                41 31 C2
    //     imul  r10d, r8d                45 0F AF D0
    //     inc   r11                      49 FF C3
    //     dec   ecx                      FF C9
    //     jnz   .crc_loop                75 rel8 (back-patched)
    //   cmp r10d, <expected>             41 81 FA imm32 ; expected hash
    //   jne .restore                     75 rel8 (forward patched)
    //
    // Clobbers: r8d, r10d, r11, rcx, eax, rflags. None of those
    // are live across the following `mov ecx, 1; lea rdx; call r13`
    // — the caller reinitialises rcx and rdx for the call args,
    // and r8/r10/r11 are volatile under Win64 ABI.
    // =================================================================
    e.u8(0x41); e.u8(0xBA);
    e.u32(0x811C9DC5u);  // FNV offset basis — same constant as P6 stub_self_hash

    e.u8(0x4C); e.u8(0x8D); e.u8(0x1D);
    out.crc_walk_rel32_offset = static_cast<uint32_t>(e.size() - start);
    e.u32(0);
    out.crc_walk_rel32_end_offset = static_cast<uint32_t>(e.size() - start);

    e.u8(0xB9);
    out.crc_size_imm32_offset = static_cast<uint32_t>(e.size() - start);
    e.u32(0);

    e.u8(0x41); e.u8(0xB8);
    e.u32(0x01000193u);  // FNV prime

    const uint32_t crc_loop_label = static_cast<uint32_t>(e.size());
    e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x03);   // movzx eax, byte [r11]
    e.u8(0x41); e.u8(0x31); e.u8(0xC2);                // xor r10d, eax
    e.u8(0x45); e.u8(0x0F); e.u8(0xAF); e.u8(0xD0);   // imul r10d, r8d
    e.u8(0x49); e.u8(0xFF); e.u8(0xC3);                // inc r11
    e.u8(0xFF); e.u8(0xC9);                            // dec ecx
    e.u8(0x75);                                         // jnz rel8
    const uint32_t crc_loop_back_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    {
        const int32_t jnz_end = static_cast<int32_t>(crc_loop_back_slot + 1);
        const int32_t rel8 =
            static_cast<int32_t>(crc_loop_label) - jnz_end;
        e.buf[crc_loop_back_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    e.u8(0x41); e.u8(0x81); e.u8(0xFA);                // cmp r10d, imm32
    out.crc_expected_imm32_offset = static_cast<uint32_t>(e.size() - start);
    e.u32(0);

    e.u8(0x75);                                         // jne rel8 → .restore
    const uint32_t crc_fail_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // AddVectoredExceptionHandler(1, &VehHandler)
    //
    //   mov ecx, 1                       B9 01 00 00 00     First = TRUE
    //   lea rdx, [rip + rel32_handler]   48 8D 15 rel32     Handler
    //   call r13                         41 FF D5
    //
    // RtlAddVectoredExceptionHandler exported signature (ntdll.dll):
    //   PVOID NTAPI RtlAddVectoredExceptionHandler(
    //       ULONG First,
    //       PVECTORED_EXCEPTION_HANDLER Handler)
    //
    // We pass First = 1 so our handler runs at the head of the VEH
    // chain — it must see the int3 exception before any other
    // handler downgrades or swallows it.
    // =================================================================
    e.u8(0xB9); e.u8(0x01); e.u8(0x00); e.u8(0x00); e.u8(0x00);

    e.u8(0x48); e.u8(0x8D); e.u8(0x15);
    out.handler_rel32_offset = static_cast<uint32_t>(e.size()) - start;
    e.u32(0);
    out.handler_rel32_end_offset = static_cast<uint32_t>(e.size()) - start;

    e.u8(0x41); e.u8(0xFF); e.u8(0xD5);

    // =================================================================
    // .restore: reclaim the stack frame.
    //
    //   add rsp, 0x28                    48 83 C4 28
    // =================================================================
    const uint32_t restore_label = static_cast<uint32_t>(e.size());
    e.u8(0x48); e.u8(0x83); e.u8(0xC4); e.u8(0x28);

    // =================================================================
    // .done: zero eax and return.
    //
    //   xor eax, eax                     31 C0
    //   ret                              C3
    //
    // TLS callbacks are declared `void NTAPI` so the return value is
    // ignored by the loader; we clear eax for a deterministic state
    // in case something downstream inspects it.
    // =================================================================
    const uint32_t done_label = static_cast<uint32_t>(e.size());
    e.u8(0x31); e.u8(0xC0);
    e.u8(0xC3);

    // =================================================================
    // Back-patch forward branches now that every label is known.
    //
    // `done_rel32_slot` is a 4-byte slot (near jne) — it needs
    // rel32 arithmetic. The rel8 slots (`skip_rel8_slot` and
    // `crc_fail_rel8_slot`) target `restore_label` which is at most
    // ~20 bytes after them, well within int8 range.
    // =================================================================
    auto patch_rel8 = [&](uint32_t slot, uint32_t target) {
        const int32_t rel8 =
            static_cast<int32_t>(target) - static_cast<int32_t>(slot + 1);
        e.buf[slot] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    auto patch_rel32 = [&](uint32_t slot, uint32_t target) {
        const int32_t rel32 =
            static_cast<int32_t>(target) - static_cast<int32_t>(slot + 4);
        std::memcpy(e.buf.data() + slot, &rel32, sizeof(rel32));
    };

    patch_rel32(done_rel32_slot,    done_label);
    patch_rel8 (skip_rel8_slot,     restore_label);
    patch_rel8 (crc_fail_rel8_slot, restore_label);

    return out;
}

} // namespace mx::guard
