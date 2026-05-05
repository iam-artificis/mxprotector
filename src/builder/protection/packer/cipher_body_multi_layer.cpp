/**
 * @file cipher_body_multi_layer.cpp
 * @brief Shared multi-layer RC4 KSA+PRGA emitter — see cipher_body.hpp.
 *
 * Extracted from cipher_body.cpp so the user-mode and kernel-driver
 * variants share one byte-level implementation. The function lives
 * in its own translation unit to keep cipher_body.cpp focused on
 * user-mode orchestration (anti-debug probe, VEH trap, reprotect,
 * IAT wipe) and to keep this RC4 core file under the per-file LOC
 * cap. Public declaration stays in cipher_body.hpp.
 */

#include "mxprotector/protection/packer/cipher_body.hpp"

#include "mxprotector/protection/packer/stub_self_hash.hpp"

#include <cstdint>

namespace mx::packer {

void emit_multi_layer_decrypt(RawEmitter&        e,
                              CipherBodyPatches& patches,
                              uint32_t           section_count,
                              uint32_t           layer_count)
{
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
    //     add  bl, [rsi + rdx]         ; j += key[k mod 32]
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
}

} // namespace mx::packer
