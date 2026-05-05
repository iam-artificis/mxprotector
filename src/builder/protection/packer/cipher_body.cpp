/**
 * @file cipher_body.cpp
 * @brief Shared RC4 decrypt body emitter — user-mode orchestration.
 *
 * Owns the high-level emission order of the user-mode cipher body:
 * G6 hash predicate → optional G3 VEH trap → polymorphic anti-debug
 * probe → P2 bias save → P6 stub-self-integrity hash → multi-layer
 * RC4 decrypt → optional Stage-3 reloc applier → reprotect block →
 * IAT wipe → P6 hash range close.
 *
 * The two largest sub-pieces have been split out for clarity and to
 * keep this file under the per-file LOC cap:
 *   * `emit_multi_layer_decrypt` — `cipher_body_multi_layer.cpp`
 *     (declared in cipher_body.hpp; reused by `driver_cipher_body.cpp`).
 *   * `emit_reprotect_block` — `cipher_body_reprotect.{hpp,cpp}`
 *     (private helper, user-mode only — drivers do not reprotect).
 *
 * See cipher_body.hpp for the public contract.
 */

#include "mxprotector/protection/packer/cipher_body.hpp"

#include "cipher_body_reprotect.hpp"

#include "mxprotector/protection/obfuscation/hash_opaque_predicate.hpp"
#include "mxprotector/protection/packer/reloc_applier.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"
#include "mxprotector/protection/packer/veh_int3_trap.hpp"

#include <cstdint>

namespace mx::packer {

namespace {

/**
 * @brief Emit the polymorphic anti-debug probe variant.
 *
 * Picks one of three Windows debugger-detection strategies at
 * build time (PEB.BeingDebugged byte, PEB.NtGlobalFlag dword,
 * KUSER_SHARED_DATA.KdDebuggerEnabled). All variants normalize
 * the result to `edx` ∈ {0, 1} and clobber rax. Callers that
 * need a preserved rax must restore it after the body.
 *
 * The bias propagates into layer 0's KSA via `mov r15d, edx`
 * (emitted by the caller right after this function returns), so
 * a non-zero bias silently garbles the final decrypt without an
 * explicit branch the reverser can patch.
 */
void emit_anti_debug_probe(RawEmitter& e, Randomizer& rng)
{
    const uint32_t adv = rng.next_range(0, 2);
    switch (adv) {
        case 0: {
            // PEB.BeingDebugged (byte at PEB+0x02) — classic.
            e.u8(0x65); e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0x25);
            e.u8(0x60); e.u8(0x00); e.u8(0x00); e.u8(0x00);  // mov rax, gs:[0x60]
            e.u8(0x0F); e.u8(0xB6); e.u8(0x40); e.u8(0x02);  // movzx eax, [rax+2]
            e.u8(0x89); e.u8(0xC2);                           // mov edx, eax
            break;
        }
        case 1: {
            // PEB.NtGlobalFlag (dword at PEB+0xBC). Under a debugger the
            // loader sets FLG_HEAP_ENABLE_TAIL_CHECK |
            // FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
            // (mask 0x70). Reduce to {0, 1} via `(val & 0x70) ? 1 : 0`.
            e.u8(0x65); e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0x25);
            e.u8(0x60); e.u8(0x00); e.u8(0x00); e.u8(0x00);  // mov rax, gs:[0x60]
            e.u8(0x8B); e.u8(0x80); e.u8(0xBC);
            e.u8(0x00); e.u8(0x00); e.u8(0x00);              // mov eax, [rax + 0xBC]
            e.u8(0x83); e.u8(0xE0); e.u8(0x70);               // and eax, 0x70
            e.u8(0x31); e.u8(0xD2);                           // xor edx, edx
            e.u8(0x85); e.u8(0xC0);                           // test eax, eax
            e.u8(0x0F); e.u8(0x95); e.u8(0xC2);               // setnz dl
            break;
        }
        default: {
            // KUSER_SHARED_DATA.KdDebuggerEnabled at 0x7FFE02D4.
            // User-mode readable page mapped at fixed VA 0x7FFE0000.
            // Bit 0x01 is set when a kernel debugger is attached; we
            // OR it with bit 0x02 for broader coverage.
            //
            // `mov rax, imm64` is 10 bytes; we need the full 64-bit addr.
            e.u8(0x48); e.u8(0xB8);                           // mov rax, imm64
            e.u8(0xD4); e.u8(0x02); e.u8(0xFE); e.u8(0x7F);
            e.u8(0x00); e.u8(0x00); e.u8(0x00); e.u8(0x00);   // 0x7FFE02D4
            e.u8(0x0F); e.u8(0xB6); e.u8(0x00);               // movzx eax, byte [rax]
            e.u8(0x83); e.u8(0xE0); e.u8(0x03);               // and eax, 0x03
            e.u8(0x31); e.u8(0xD2);                           // xor edx, edx
            e.u8(0x85); e.u8(0xC0);                           // test eax, eax
            e.u8(0x0F); e.u8(0x95); e.u8(0xC2);               // setnz dl
            break;
        }
    }
}

} // namespace

void emit_decrypt_body(RawEmitter&        e,
                       CipherBodyPatches& patches,
                       Randomizer&        rng,
                       uint32_t           section_count,
                       uint32_t           layer_count,
                       bool               enable_veh_trap,
                       bool               apply_relocs_inline)
{
    // P2 — allocate per-layer patch storage up front. The emission loop
    // below fills entries in runtime-decrypt order (N-1 first, 0 last);
    // the caller addresses each layer by its logical index and the
    // in-memory position of the per-layer LEAs is irrelevant to patching.
    patches.layers.resize(layer_count);
    for (auto& lp : patches.layers) lp.sections.reserve(section_count);

    // ----------------------------------------------------------------
    // G6 — Hash-based opaque predicate gate.
    //
    // Plant one always-true hash predicate at the very head of the
    // decrypt body, BEFORE the anti-debug probe. The predicate hashes
    // a build-time random 4-byte input through three rounds of
    // multiplication mixed with XOR and rotation, then compares the
    // result against a build-time-baked target. SAT/SMT engines that
    // try to invert the multiplicative chain to reach the false branch
    // either time out or return UNSAT, blowing up symbolic exploration
    // before anything important is reached.
    //
    // The predicate clobbers `eax` and `rflags`. That's safe here
    // because the next emitted code (anti-debug probe) starts with
    // a `mov rax, gs:[0x60]` / `mov rax, imm64` that reinitialises
    // rax cleanly, and rflags is not consumed across the probe.
    // ----------------------------------------------------------------
    {
        const obf::HashOpaqueParams hp =
            obf::randomize_hash_opaque_params(rng);
        obf::emit_hash_opaque_predicate(e, hp, rng);
    }

    // ----------------------------------------------------------------
    // G3 Phase 2 — VEH INT3 trap (opt-in, EXE-only).
    //
    // When the caller sets `enable_veh_trap`, install a Vectored
    // Exception Handler and plant an `int3 + 6 junk bytes` region
    // that the VEH skips on a clean run. The VEH reports
    // EXCEPTION_CONTINUE_SEARCH so the protected binary's own
    // top-level handlers still see real exceptions. A debugger
    // that intercepts the int3 first short-circuits the skip and
    // the runtime falls into the junk bytes.
    //
    // The trap is emitted BEFORE the anti-debug probe because the
    // Hell's Gate resolver inside the trap clobbers r15 (loop
    // counter scratch); placing it AFTER the bias save would wipe
    // the saved bias. Placing it AFTER the probe but BEFORE the
    // bias save would mean the probe still runs but the bias
    // never reaches the KSA. Putting the trap first keeps the
    // VEH-installation register footprint isolated.
    //
    // Gating is the caller's responsibility: `enable_veh_trap` must
    // only be true when `pe_type == executable` AND the user passed
    // `--anti-tamper-veh`. DLL stubs MUST NOT enable this because a
    // DLL-installed VEH outlives the DLL's unload and would leave a
    // dangling handler pointing at freed memory in the host process.
    // ----------------------------------------------------------------
    if (enable_veh_trap) {
        emit_veh_int3_trap(e, rng);
    }

    // (2) Anti-debug probe — polymorphic, leaves bias in `edx`.
    //
    // The downstream KSA seeds layer 0's `j` from this bias via the
    // `mov r15d, edx` capture below; a non-zero bias silently garbles
    // the entire decrypted output without an explicit branch the
    // reverser can patch. Variants documented in `emit_anti_debug_probe`.
    emit_anti_debug_probe(e, rng);

    // P2 — Bias carrier. `edx` holds the anti-debug bias right after
    // the probe, but we're about to clobber edx inside each layer's KSA
    // phase 2 (it's used as scratch for `mov dl, cl; and dl, 0x1F`).
    // Copy the bias into `r15d` so it survives every KSA call until
    // layer 0's phase 2 reads it back. r15 is free from here until the
    // reprotect loop reloads it with its iteration counter, which runs
    // AFTER all layers finish.
    //
    //   mov r15d, edx                           41 89 D7
    e.u8(0x41); e.u8(0x89); e.u8(0xD7);

    // ----------------------------------------------------------------
    // P6 — Stub-self-integrity hash.
    //
    // Emit the FNV-1a loop that walks the stub's own code bytes
    // `[stub_start, stub_start + hash_range_end_offset)` and leaves
    // the resulting 32-bit hash in `r14d`. Every per-layer
    // `emit_key_derivation_loop` below reads `r14d` as input to the
    // base→effective key transformation, so any tamper with the
    // hashed range (debugger INT3, anti-debug NOP patch, reprotect
    // loop hook, IAT wipe bypass, etc.) propagates through the
    // derivation into every layer's effective key and the KSA+PRGA
    // produces a diverged S-box → garbage plaintext.
    //
    // Placement rationale: the self-hash sits AFTER the VEH trap
    // (which clobbers r14 as part of the Hell's Gate resolver's
    // register budget) and AFTER `mov r15d, edx` (bias save), but
    // BEFORE `lea r8, sbox`. The self-hash inner loop loads the FNV
    // prime into `r8d` and would stomp the S-box pointer if we ran
    // it AFTER the sbox lea — by emitting it first, the subsequent
    // `lea r8, sbox` reinitialises r8 cleanly and every downstream
    // KSA read of `[r8 + ...]` is correct. Nothing between this
    // point and the first derivation loop touches r14, so the hash
    // survives every layer's setup until consumed.
    // ----------------------------------------------------------------
    patches.self_hash = emit_stub_self_hash(e);

    // (3) Multi-layer RC4 decrypt — the shared KSA + PRGA block.
    //
    // Extracted into `emit_multi_layer_decrypt` so the kernel-driver
    // cipher body can reuse it without dragging in the user-mode
    // anti-debug / Hell's Gate / reprotect / IAT-wipe machinery.
    //
    // Byte-for-byte identical to the pre-refactor inlined block. The
    // caller guarantees the usual preconditions: `r14d` has been
    // populated by `emit_stub_self_hash` just above, `r15d` carries the
    // layer-0 KSA `j` seed (anti-debug bias in user-mode, zero in the
    // driver path), and `patches.layers` is pre-sized.
    emit_multi_layer_decrypt(e, patches, section_count, layer_count);

    // (4.25) Optional Stage-3 base-relocation applier.
    //
    // Runs AFTER the innermost decrypt layer finished (every target
    // section is now plaintext) and BEFORE the reprotect loop revokes
    // WRITE — the relocated pages must stay writable while the applier
    // mutates them. The applier emits its own RIP-relative runtime-
    // base computation, so it does not depend on any state from the
    // decrypt loop; the emission order of the two blocks is the only
    // constraint.
    //
    // Enabled when the caller sets `apply_relocs_inline = true`, which
    // `PackerPass` does iff `ctx.target().is_manually_mapped()`. In
    // OS-load mode the loader has already applied relocations before
    // the stub runs and running the applier would double-apply the
    // delta; leaving the applier out also trims ~116 bytes off the
    // common-case stub.
    if (apply_relocs_inline) {
        emit_reloc_applier(e, patches.reloc_applier);
    }

    // (4.5) Reprotect decrypted sections to PAGE_EXECUTE_READ.
    //
    // The decrypt loops above wrote through every target section, so
    // the loader mapped them PAGE_EXECUTE_READWRITE. Leaving them RWX
    // at runtime is a security hazard: (a) a reverser's in-memory
    // patch doesn't need VirtualProtect first, so there's no detection
    // opportunity, and (b) the anti-tamper page_protection_sweep check
    // can't meaningfully probe our own VM blob because a legitimate
    // RWX state is indistinguishable from a tampered one. Both
    // problems disappear if we revoke WRITE after decryption finishes.
    //
    // Implementation lives in `cipher_body_reprotect.cpp` — see that
    // file for the Hell's-Gate-driven NtProtectVirtualMemory loop.
    emit_reprotect_block(e, rng, patches, section_count);

    // (5) IAT destruction: zero the Import Directory region in memory.
    // After decryption the loader has already resolved every import
    // into the IAT. Zeroing the Import Directory + ILT makes the
    // resolved addresses un-labelable by dump/reconstruction tools
    // (Scylla, IDA imports tab).
    //
    //   lea rdi, [rip + import_dir_rel32]
    //   xor eax, eax
    //   mov ecx, import_dir_size / 4
    //   rep stosd
    e.u8(0x48); e.u8(0x8D); e.u8(0x3D);  // lea rdi, [rip + rel32]
    patches.rel_to_impdir_at = static_cast<uint32_t>(e.size());
    e.u32(0);                             // placeholder rel32
    e.u8(0x31); e.u8(0xC0);               // xor eax, eax
    e.u8(0xB9);                            // mov ecx, imm32
    patches.impdir_size_at = static_cast<uint32_t>(e.size());
    e.u32(0);                             // placeholder size/4
    e.u8(0xF3); e.u8(0xAB);               // rep stosd

    // ----------------------------------------------------------------
    // P6 — Hash range end.
    //
    // The cipher body is complete. Record the end of the hashed
    // range here so the build-time driver can compute FNV-1a over
    // `[stub_start, stub_start + hash_range_end_offset)` once every
    // rel32 inside the body has been finalised and the hash count
    // imm32 has been patched. Anything the outer stub emitter
    // appends after this point — pops, stolen bytes, `jmp OEP`,
    // key blobs, sbox scratch, VM blob, reprotect table, TLS
    // callback plumbing — lives OUTSIDE the hashed range.
    // ----------------------------------------------------------------
    patches.hash_range_end_offset = static_cast<uint32_t>(e.size());
}

} // namespace mx::packer
