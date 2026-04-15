/**
 * @file guard_tls_installer.cpp
 * @brief Byte-level emission of the runtime-guards TLS installer
 *        thunk. See guard_tls_installer.hpp for the ABI and flow.
 */

#include "mxprotector/protection/guard/guard_tls_installer.hpp"

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
    //   jne .done                        75 rel8  (patched below)
    //
    // THREAD_ATTACH / THREAD_DETACH / PROCESS_DETACH are ignored —
    // the VEH only needs to be registered once per process lifetime,
    // and doing it on THREAD_ATTACH would install a fresh handler
    // per thread which is wasteful and noisy in EDR telemetry.
    // =================================================================
    e.u8(0x83); e.u8(0xFA); e.u8(0x01);
    e.u8(0x75);
    const uint32_t done_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

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
    // Back-patch the forward rel8 branches now that the labels are
    // known.
    // =================================================================
    auto patch_rel8 = [&](uint32_t slot, uint32_t target) {
        const int32_t rel8 =
            static_cast<int32_t>(target) - static_cast<int32_t>(slot + 1);
        e.buf[slot] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    patch_rel8(done_rel8_slot, done_label);
    patch_rel8(skip_rel8_slot, restore_label);

    return out;
}

} // namespace mx::guard
