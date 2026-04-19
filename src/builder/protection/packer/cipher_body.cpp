/**
 * @file cipher_body.cpp
 * @brief Shared RC4 decrypt body emitter — see cipher_body.hpp.
 */

#include "mxprotector/protection/packer/cipher_body.hpp"

#include "mxprotector/protection/anti_tamper/hells_gate_resolver.hpp"
#include "mxprotector/protection/obfuscation/hash_opaque_predicate.hpp"
#include "mxprotector/protection/packer/reloc_applier.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"
#include "mxprotector/protection/packer/veh_int3_trap.hpp"

#include <cstdint>

namespace mx::packer {

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
    // a build-time random 4-byte input (loaded via a rip-relative
    // mov from inline data) through three rounds of multiplication
    // mixed with XOR and rotation, then compares the result against
    // a build-time-baked target. The "true" path falls through to
    // the anti-debug probe; the "false" path is reachable code (a
    // tiny `mov eax, junk; ret` body) that's never executed at
    // runtime but which static analysers must still decode and
    // explore.
    //
    // Effect on reverse engineering:
    //   * SAT/SMT-based symbolic engines that try to invert the hash
    //     to find an input satisfying the false branch get stuck on
    //     the multiplication chain. Most engines either time out or
    //     skip the constraint, leaving both branches "reachable" in
    //     their reachability set and inflating analysis cost.
    //   * Linear disassemblers that follow the `jne short` happily
    //     decode the false branch, see the `ret`, and assume the
    //     enclosing function ended there — confusing their callgraph
    //     view of the surrounding stub.
    //   * Concrete-evaluation engines (the strongest case) evaluate
    //     the hash forward and prune the false branch correctly.
    //     They pay a small extra cost but recover ground truth.
    //
    // The predicate clobbers `eax` and `rflags`. That's safe here
    // because the very next emission (the anti-debug probe) clobbers
    // both anyway — the variants either do `mov rax, gs:[0x60]` or
    // load `rax = imm64`, and they all rebuild `edx` from scratch
    // afterwards.
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
    // here. The handler's filter is strict: it only acts on an
    // exception whose code is STATUS_BREAKPOINT AND whose address
    // is the exact runtime VA of the planted int3. Every other
    // exception — including C++ `throw` — gets
    // EXCEPTION_CONTINUE_SEARCH so the protected binary's own
    // try/catch machinery is unaffected. See `veh_int3_trap.cpp`
    // for the full encoding and `test_exception.cpp` for the
    // compatibility smoke test.
    //
    // The trap is emitted BEFORE the anti-debug probe because the
    // Hell's Gate resolver inside the trap clobbers r15 (loop
    // counter), and the probe's bias capture into r15d happens
    // AFTER the probe — so ordering the trap first means the VEH
    // install has no register-state conflict with the downstream
    // bias save.
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

    // (2) Anti-debug — polymorphic. Each variant reads a different Windows
    //     "debugger present" indicator and normalizes the result to `edx`
    //     ∈ {0, 1}. The downstream decrypt loop uses `edx` as the key-stream
    //     start index, so a non-zero value silently garbles the entire
    //     decrypted output. No explicit jump to patch: the check is baked
    //     into the cipher.
    //
    // All variants leave edx ∈ {0, 1} and clobber rax. Callers that need
    // a preserved rax must restore it after the stub.
    //
    // Variant 0: PEB.BeingDebugged (byte at PEB+0x02) — classic.
    // Variant 1: PEB.NtGlobalFlag (dword at PEB+0xBC). Under a debugger the
    //            loader sets FLG_HEAP_ENABLE_TAIL_CHECK |
    //            FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    //            (mask 0x70). We reduce to {0, 1} via
    //            `(val & 0x70) ? 1 : 0`.
    // Variant 2: KUSER_SHARED_DATA.KdDebuggerEnabled at 0x7FFE02D4.
    //            User-mode readable page mapped at fixed VA 0x7FFE0000.
    //            Bit 0x01 is set when a kernel debugger is attached; we
    //            OR it with bit 0x02 for broader coverage.
    const uint32_t adv = rng.next_range(0, 2);
    switch (adv) {
        case 0: {
            // PEB.BeingDebugged
            e.u8(0x65); e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0x25);
            e.u8(0x60); e.u8(0x00); e.u8(0x00); e.u8(0x00);  // mov rax, gs:[0x60]
            e.u8(0x0F); e.u8(0xB6); e.u8(0x40); e.u8(0x02);  // movzx eax, [rax+2]
            e.u8(0x89); e.u8(0xC2);                           // mov edx, eax
            break;
        }
        case 1: {
            // PEB.NtGlobalFlag
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

    // (3) RC4 setup — load the shared S-box pointer.
    //
    // `r8` holds the 256-byte S-box scratch area. Every layer's KSA
    // rebuilds the full S-box from S[k]=k, so layers can share one
    // scratch region. The per-layer `lea rsi, key_K` load happens
    // inside the layer emission loop below.
    //
    //   lea r8,  [rip + sbox_rel32]  4C 8D 05 rel32
    e.u8(0x4C); e.u8(0x8D); e.u8(0x05);
    patches.rel_to_sbox_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // (3a) RC4 Key Scheduling Algorithm (KSA).
    //
    //   Phase 1 — initialise S[k] = k for k ∈ [0, 256):
    //     xor  ecx, ecx               ; k = 0
    //   .init:
    //     mov  [r8 + rcx], cl         ; S[k] = k (low byte)
    //     inc  cl                     ; k++
    //     jnz  .init                  ; wraps at 256 → exit
    //
    //   Phase 2 — mix with the key, seeded by the anti-debug bias
    //             (only on layer 0; other layers start with j = 0):
    //     xor  ecx, ecx               ; k = 0
    //     mov  ebx, r15d              ; j = bias    (layer 0 only)
    //       or  xor  ebx, ebx         ; j = 0       (outer layers)
    //   .ksa:
    //     movzx eax, byte [r8 + rcx]  ; al = S[k]
    //     mov  dl, cl                 ; dl = k
    //     and  dl, 0x1F               ; dl = k mod 32 (key length)
    //     add  bl, al                 ; j += S[k]
    //     add  bl, [rsi + rdx]        ; j += key[k mod 32]
    //     movzx edx, byte [r8 + rbx]  ; dl = S[j]
    //     mov  [r8 + rbx], al         ; S[j] = S[k]
    //     mov  [r8 + rcx], dl         ; S[k] = S[j]   (old S[j])
    //     inc  cl                     ; k++
    //     jnz  .ksa                   ; wraps at 256
    //
    //   Phase 3 — reset PRGA state:
    //     xor  r9,  r9                ; i = 0
    //     xor  r10, r10               ; j = 0

    // P2 — Emit `layer_count` cipher rounds in RUNTIME DECRYPT order
    // (N-1 first, 0 last). Layer 0 is the innermost; build-time
    // encryption applies layers in the reverse order (0, 1, ..., N-1)
    // so that runtime decryption undoes them correctly. Only layer 0's
    // KSA is exposed to the P3 VM lifter — the `ksa_block_start/end`
    // fields are filled in only when the inner iteration hits
    // `layer_idx == 0`.
    for (int32_t layer_idx = static_cast<int32_t>(layer_count) - 1;
         layer_idx >= 0; --layer_idx)
    {
        const bool is_bias_layer = (layer_idx == 0);
        LayerPatches& lp = patches.layers[layer_idx];

        // Per-layer: load this layer's RC4 key pointer. Placed BEFORE
        // the `ksa_block_start_offset` mark for layer 0 so the P3 VM
        // lift region stays register-only (no rip-relative memory).
        //
        //   lea rsi, [rip + key_K_rel32]   48 8D 35 rel32
        e.u8(0x48); e.u8(0x8D); e.u8(0x35);
        lp.rel_to_key_at = static_cast<uint32_t>(e.size());
        e.u32(0);

        // P6 — Per-layer effective-key derivation.
        //
        // `rsi` now points at this layer's 32-byte base key embedded
        // in the `.mxpack` data tail. The derivation loop reads the
        // stub integrity hash from `r14d` (set by the self-hash loop
        // above), chains it through every base-key byte with the
        // FNV-1a multiplicative step, and writes the effective key
        // back IN PLACE. After the loop `rsi` still points at the
        // key base — the emitter preserves `rsi` by iterating
        // through `rcx` — so the downstream KSA phase 2 read of
        // `[rsi + rdx]` sees the effective bytes with no extra
        // plumbing.
        //
        // Emitted OUTSIDE the `ksa_block_start/end` bracket so that
        // P3's VM lifter, which only lifts layer 0's KSA body, never
        // has to deal with the derivation code (which has no
        // corresponding VM semantics yet — it's pure native x64).
        //
        // Clobbers: eax, rcx, rdx, r9d, RFLAGS. All of those are
        // either dead at this point or about to be rewritten by
        // the following KSA phase 1/2/3 (phase 1 starts with
        // `xor ecx, ecx`, phase 3 resets `r9` to 0). `r8` (S-box
        // pointer) and `r14d` (hash carrier) are explicitly
        // preserved — see `stub_self_hash.hpp` for the contract.
        emit_key_derivation_loop(e);

        // Mark the start of the VM-liftable KSA block for layer 0.
        // Everything from here through `xor r10, r10` (PRGA state reset)
        // is pure register / r8-or-rsi-relative code — no rip-relative
        // memory operands, no syscalls, no external branches. Safe for
        // the VmLifter.
        if (is_bias_layer) {
            patches.ksa_block_start_offset = static_cast<uint32_t>(e.size());
        }

        // Phase 1: init S[k] = k.
        e.u8(0x31); e.u8(0xC9);                          // xor ecx, ecx
        const uint32_t init_loop_start = static_cast<uint32_t>(e.size());
        e.u8(0x41); e.u8(0x88); e.u8(0x0C); e.u8(0x08);  // mov [r8+rcx], cl
        e.u8(0xFE); e.u8(0xC1);                          // inc cl
        {
            const uint32_t jnz_end = static_cast<uint32_t>(e.size()) + 2;
            const int32_t  rel8    = static_cast<int32_t>(init_loop_start) -
                                     static_cast<int32_t>(jnz_end);
            e.u8(0x75);
            e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
        }

        // Phase 2: KSA mix. Seed j from the bias on layer 0, else 0.
        e.u8(0x31); e.u8(0xC9);                          // xor ecx, ecx    (k = 0)
        if (is_bias_layer) {
            // mov ebx, r15d                          44 89 FB
            //   j = saved anti-debug bias (0 normally, 1 under debugger)
            e.u8(0x44); e.u8(0x89); e.u8(0xFB);
        } else {
            // xor ebx, ebx                           31 DB
            //   j = 0 — outer layers don't care about bias, they just
            //   rebuild a deterministic S-box from their own key.
            e.u8(0x31); e.u8(0xDB);
        }
        const uint32_t ksa_loop_start = static_cast<uint32_t>(e.size());
        e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x04); e.u8(0x08); // movzx eax, [r8+rcx]
        e.u8(0x88); e.u8(0xCA);                          // mov dl, cl
        e.u8(0x80); e.u8(0xE2); e.u8(0x1F);              // and dl, 0x1F
        e.u8(0x00); e.u8(0xC3);                          // add bl, al
        e.u8(0x02); e.u8(0x1C); e.u8(0x16);              // add bl, [rsi+rdx]
        e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x14); e.u8(0x18); // movzx edx, [r8+rbx]
        e.u8(0x41); e.u8(0x88); e.u8(0x04); e.u8(0x18);  // mov [r8+rbx], al
        e.u8(0x41); e.u8(0x88); e.u8(0x14); e.u8(0x08);  // mov [r8+rcx], dl
        e.u8(0xFE); e.u8(0xC1);                          // inc cl
        {
            const uint32_t jnz_end = static_cast<uint32_t>(e.size()) + 2;
            const int32_t  rel8    = static_cast<int32_t>(ksa_loop_start) -
                                     static_cast<int32_t>(jnz_end);
            e.u8(0x75);
            e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
        }

        // Phase 3: zero the PRGA (i, j) state. Each layer restarts
        // PRGA from (0, 0) — cross-layer state sharing would require
        // matching build-time encryption to use a different initial
        // state on every layer, which gains nothing.
        e.u8(0x4D); e.u8(0x31); e.u8(0xC9);              // xor r9, r9     (i  = 0)
        e.u8(0x4D); e.u8(0x31); e.u8(0xD2);              // xor r10, r10   (j  = 0)

        // End of the VM-liftable KSA block for layer 0. The caller may
        // replace the range `[ksa_block_start_offset, ksa_block_end_offset)`
        // with a `call rel32 <vm_entry>` + NOP pad, hiding the RC4 setup
        // inside a VM region.
        if (is_bias_layer) {
            patches.ksa_block_end_offset = static_cast<uint32_t>(e.size());
        }

        // (4) Per-section decrypt loop — RC4 PRGA.
        //
        // State at entry: r8 = S-box ptr, r9b = PRGA i, r10b = PRGA j,
        //                 rdi/ecx = per-section dest ptr and length.
        //
        //   .loop:
        //     inc   r9b                           ; i++
        //     movzx eax, byte [r8 + r9]           ; al = S[i]
        //     add   r10b, al                      ; j += S[i]
        //     movzx edx, byte [r8 + r10]          ; dl = S[j]
        //     mov   [r8 + r10], al                ; S[j] = S[i]
        //     mov   [r8 + r9],  dl                ; S[i] = S[j] (swap)
        //     add   al, dl                        ; al = (S[i]+S[j]) mod 256
        //     movzx eax, al                       ; zero-extend sum
        //     mov   al, [r8 + rax]                ; K = S[sum]
        //     xor   [rdi], al                     ; decrypt one byte
        //     inc   rdi                           ; advance dst
        //     dec   ecx                           ; length--
        //     jnz   .loop
        for (uint32_t s = 0; s < section_count; ++s) {
            DecryptSection ds{};

            //   lea rdi, [rip + section_rel32]    48 8D 3D rel32
            e.u8(0x48); e.u8(0x8D); e.u8(0x3D);
            ds.patch_lea_at = static_cast<uint32_t>(e.size());
            e.u32(0);

            //   mov ecx, imm32                    B9 imm32
            e.u8(0xB9);
            ds.patch_size_at = static_cast<uint32_t>(e.size());
            e.u32(0);

            lp.sections.push_back(ds);

            const uint32_t loop_body_start = static_cast<uint32_t>(e.size());

            e.u8(0x41); e.u8(0xFE); e.u8(0xC1);                     // inc r9b
            e.u8(0x43); e.u8(0x0F); e.u8(0xB6); e.u8(0x04); e.u8(0x08); // movzx eax, [r8+r9]
            e.u8(0x41); e.u8(0x00); e.u8(0xC2);                     // add r10b, al
            e.u8(0x43); e.u8(0x0F); e.u8(0xB6); e.u8(0x14); e.u8(0x10); // movzx edx, [r8+r10]
            e.u8(0x43); e.u8(0x88); e.u8(0x04); e.u8(0x10);         // mov [r8+r10], al
            e.u8(0x43); e.u8(0x88); e.u8(0x14); e.u8(0x08);         // mov [r8+r9],  dl
            e.u8(0x00); e.u8(0xD0);                                  // add al, dl
            e.u8(0x0F); e.u8(0xB6); e.u8(0xC0);                      // movzx eax, al
            e.u8(0x41); e.u8(0x8A); e.u8(0x04); e.u8(0x00);          // mov al, [r8+rax]
            e.u8(0x30); e.u8(0x07);                                  // xor [rdi], al
            e.u8(0x48); e.u8(0xFF); e.u8(0xC7);                      // inc rdi
            e.u8(0xFF); e.u8(0xC9);                                  // dec ecx
            {
                const uint32_t jnz_end = static_cast<uint32_t>(e.size()) + 2;
                const int32_t  rel8    = static_cast<int32_t>(loop_body_start) -
                                         static_cast<int32_t>(jnz_end);
                e.u8(0x75);
                e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
            }
        }
    }

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
    // The reprotect block:
    //   1. Saves rsp to r12 and allocates a 16-aligned 0x50-byte frame.
    //   2. Emits the Hell's Gate SSN resolver targeting
    //      `NtProtectVirtualMemory` — ~155 bytes that walk the PEB,
    //      find ntdll, and leave the function address in r13.
    //   3. Skips the reprotect loop entirely on resolver failure
    //      (r13 == 0) — sections stay RWX, matching the pre-fix state.
    //   4. Sets up one-time state: rbx = ImageBase (computed
    //      rip-relative so it works for EXE and DLL), the &old_protect
    //      arg5 slot, r14 = section table, r15 = countdown.
    //   5. Loops over each (rva, size) entry, calling
    //      NtProtectVirtualMemory to revoke WRITE.
    //   6. Restores rsp from r12.

    const uint32_t reprotect_entry_count = section_count;
    patches.reprotect_entry_count = reprotect_entry_count;

    // Save rsp, align, and allocate our scratch+call frame.
    //   mov r12, rsp                 49 89 E4
    //   and rsp, -16                 48 83 E4 F0
    //   sub rsp, 0x50                48 81 EC 50 00 00 00
    //
    // After sub the frame looks like:
    //   [rsp+0x00..0x1F]  shadow space for the callee's arg1..4 homes
    //   [rsp+0x20]        arg5 slot = &old_protect_var (set once)
    //   [rsp+0x30]        base_var  (rdx target, rewritten per iter)
    //   [rsp+0x38]        size_var  (r8 target, rewritten per iter)
    //   [rsp+0x40]        old_protect_var (PULONG output)
    //
    // `and rsp, -16` ensures rsp is 16-aligned BEFORE the `call r13`
    // below — the CALL push will then leave rsp at mod16==8 inside
    // ntdll's stub, which is what the Windows x64 ABI expects.
    e.u8(0x49); e.u8(0x89); e.u8(0xE4);
    e.u8(0x48); e.u8(0x83); e.u8(0xE4); e.u8(0xF0);
    e.u8(0x48); e.u8(0x81); e.u8(0xEC);
    e.u32(0x00000050u);

    // Hell's Gate address resolver → r13 = NtProtectVirtualMemory
    // function body address. The resolver walks the PEB, finds ntdll,
    // and looks up the export by salted DJB2 hash. On failure r13 is
    // left at 0 and we skip the reprotect loop entirely.
    //
    // The per-build random salt kills the "djb2_hash → ntdll API"
    // reverse-lookup dictionary: every build folds a different 32-bit
    // constant into the hash seed, so both the `cmp eax, target_hash`
    // slot and the scan-loop initial seed slot change from build to
    // build even though the target API name is the same.
    {
        RawEmitter tmp{};
        const uint32_t salt = rng.next_u32();
        const uint32_t ntprotect_hash =
            anti_tamper::djb2_ascii_hash_salted(
                "NtProtectVirtualMemory", salt);
        anti_tamper::emit_hells_gate_address_resolver(
            tmp, ntprotect_hash, salt);
        e.bytes(ByteView{tmp.buf.data(), tmp.buf.size()});
    }

    // test r13, r13                          4D 85 ED
    e.u8(0x4D); e.u8(0x85); e.u8(0xED);
    // jz short .reprotect_done               74 rel8 (patched below)
    e.u8(0x74);
    const uint32_t patch_jz_reprotect_done = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // --- One-time setup outside the loop: ImageBase, arg5, table ---

    // rbx = our own module's runtime image base, computed rip-relative.
    // PEB.ImageBaseAddress would give the host EXE's base, which is
    // correct for executables but wrong for DLLs (we'd reprotect pages
    // inside the host's image instead of our own). The rip-relative
    // path works for both.
    //
    //   lea rbx, [rip + 0]                   48 8D 1D 00 00 00 00
    //     rbx = runtime address of the next instruction = ImageBase
    //           + stub_section_rva + `imagebase_lea_anchor_offset`.
    //   sub rbx, <imm32>                     48 81 EB imm32
    //     imm32 = stub_section_rva + imagebase_lea_anchor_offset
    //     → rbx = ImageBase (always, EXE or DLL).
    e.u8(0x48); e.u8(0x8D); e.u8(0x1D);
    e.u8(0x00); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    patches.imagebase_lea_anchor_offset = static_cast<uint32_t>(e.size());
    e.u8(0x48); e.u8(0x81); e.u8(0xEB);
    patches.imagebase_sub_imm32_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // lea rax, [rsp + 0x40]                  48 8D 44 24 40
    // mov [rsp + 0x20], rax                  48 89 44 24 20
    //   arg5 slot (pointer to old_protect_var) — constant, set once.
    e.u8(0x48); e.u8(0x8D); e.u8(0x44); e.u8(0x24); e.u8(0x40);
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x20);

    // lea r14, [rip + reprotect_table_rel32]  4C 8D 35 rel32
    //   r14 = pointer to the embedded section table. The rel32 is
    //   patched in `execute()` once the stub's section RVA and the
    //   table's offset inside the stub are final. r14 is also
    //   nonvolatile so it survives the CALL.
    e.u8(0x4C); e.u8(0x8D); e.u8(0x35);
    patches.rel_to_reprotect_table_at = static_cast<uint32_t>(e.size());
    e.u32(0);

    // mov r15d, <reprotect_entry_count>      41 BF imm32
    //   r15 = loop countdown. Nonvolatile, so the CALL won't stomp it.
    e.u8(0x41); e.u8(0xBF);
    e.u32(reprotect_entry_count);

    // --- Loop body ---

    const uint32_t loop_start = static_cast<uint32_t>(e.size());

    // test r15, r15                          4D 85 FF
    e.u8(0x4D); e.u8(0x85); e.u8(0xFF);
    // jz short .reprotect_done               74 rel8 (patched below)
    e.u8(0x74);
    const uint32_t patch_jz_loop_done = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // mov eax, [r14]                         41 8B 06
    //   rva (zero-extends to 64-bit in rax)
    e.u8(0x41); e.u8(0x8B); e.u8(0x06);
    // lea rax, [rbx + rax*1]                 48 8D 04 03
    //   rax = ImageBase + rva
    e.u8(0x48); e.u8(0x8D); e.u8(0x04); e.u8(0x03);
    // mov [rsp + 0x30], rax                  48 89 44 24 30
    //   store base_var
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x30);

    // mov eax, [r14 + 4]                     41 8B 46 04
    //   size (zero-extends)
    e.u8(0x41); e.u8(0x8B); e.u8(0x46); e.u8(0x04);
    // mov [rsp + 0x38], rax                  48 89 44 24 38
    //   store size_var
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(0x38);

    // Prepare call registers (volatile — re-set every iteration because
    // the previous CALL clobbered them):
    //   rcx = -1              (NtCurrentProcess pseudo-handle)
    //   rdx = &base_var       ([rsp + 0x30])
    //   r8  = &size_var       ([rsp + 0x38])
    //   r9d = PAGE_EXECUTE_READ (0x20)

    // mov rcx, -1                            48 C7 C1 FF FF FF FF
    e.u8(0x48); e.u8(0xC7); e.u8(0xC1);
    e.u32(0xFFFFFFFFu);
    // lea rdx, [rsp + 0x30]                  48 8D 54 24 30
    e.u8(0x48); e.u8(0x8D); e.u8(0x54); e.u8(0x24); e.u8(0x30);
    // lea r8, [rsp + 0x38]                   4C 8D 44 24 38
    e.u8(0x4C); e.u8(0x8D); e.u8(0x44); e.u8(0x24); e.u8(0x38);
    // mov r9d, 0x20                          41 B9 20 00 00 00
    e.u8(0x41); e.u8(0xB9);
    e.u32(0x00000020u);

    // call r13                               41 FF D5
    //   Invoke ntdll!NtProtectVirtualMemory. Going through the real
    //   stub means ntdll handles the Windows x64 ABI for the stack
    //   argument at [rsp+0x20] → [rsp+0x28] inside the stub, which
    //   a hand-rolled direct `syscall` from a 16-aligned rsp does
    //   not replicate correctly on Win11 with CET / shadow stack.
    e.u8(0x41); e.u8(0xFF); e.u8(0xD5);

    // add r14, 8                             49 83 C6 08
    e.u8(0x49); e.u8(0x83); e.u8(0xC6); e.u8(0x08);
    // dec r15                                49 FF CF
    e.u8(0x49); e.u8(0xFF); e.u8(0xCF);
    // jmp short .loop_start                  EB rel8
    e.u8(0xEB);
    {
        const uint32_t jmp_end = static_cast<uint32_t>(e.size()) + 1;
        const int32_t rel8 = static_cast<int32_t>(loop_start) -
                             static_cast<int32_t>(jmp_end);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));
    }

    // .reprotect_done:
    {
        const uint32_t done_at = static_cast<uint32_t>(e.size());
        e.buf[patch_jz_reprotect_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_reprotect_done + 1)));
        e.buf[patch_jz_loop_done] = static_cast<uint8_t>(
            static_cast<int8_t>(static_cast<int32_t>(done_at) -
                                static_cast<int32_t>(patch_jz_loop_done + 1)));
    }

    // Restore rsp from r12.
    // mov rsp, r12                           4C 89 E4
    e.u8(0x4C); e.u8(0x89); e.u8(0xE4);

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
