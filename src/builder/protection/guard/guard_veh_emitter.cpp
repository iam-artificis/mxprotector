/**
 * @file guard_veh_emitter.cpp
 * @brief Byte-level x64 emission of the runtime-guards VEH handler.
 *
 * Commit 9a: the decrypt subroutine is extracted into a separate
 * callable blob (`guard_decrypt_unit.hpp/cpp`). The handler emits
 * two `call rel32` instructions whose rel32 slots are left as zero
 * for `GuardPass` to patch once the decrypt unit's offset in the
 * section is known.
 *
 * Handler structure (234 bytes base + 0..8 polymorphic tail):
 *
 *   * 0..21   — prologue + ExceptionCode filter + bailout tail
 *   * 22..95  — module base, fault RVA, self-hash FNV walk
 *   * 96..108 — descriptor table pointer + count
 *   * 109..131 — linear scan loop
 *   * 132..191 — entry_match (HW bp sweep + LOCK XADD + call decrypt)
 *   * 192..228 — exit_match  (LOCK XADD + call decrypt)
 *   * 229..233 — .done_success (pops + ret)
 *   * 234..    — polymorphic tail (0..8 random bytes)
 *
 * ## ABI / register use
 *
 * Clobbered volatiles: rax, rcx, rdx, r8, r9, r10, r11.
 * Saved + restored nonvolatiles: rbx, rbp, rsi, rdi.
 */

#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

#include <cstdint>
#include <cstring>

namespace mx::guard {

GuardVehEmit emit_guard_veh_handler(RawEmitter& e, Randomizer& rng) {
    GuardVehEmit out{};
    const uint32_t handler_start = static_cast<uint32_t>(e.size());

    // =================================================================
    // Prologue — save nonvolatiles.
    //   push rbx  (53)    push rbp  (55)
    //   push rsi  (56)    push rdi  (57)
    // =================================================================
    e.u8(0x53);
    e.u8(0x55);
    e.u8(0x56);
    e.u8(0x57);

    // =================================================================
    // ExceptionCode filter.
    //   mov rax, [rcx]                48 8B 01
    //   cmp dword [rax], 0x80000003   81 38 03 00 00 80
    //   je  .proceed                  74 rel8
    // Fall-through IS the bailout path — no branch needed to reach
    // continue_search.
    // =================================================================
    e.u8(0x48); e.u8(0x8B); e.u8(0x01);
    e.u8(0x81); e.u8(0x38); e.u8(0x03); e.u8(0x00); e.u8(0x00); e.u8(0x80);
    e.u8(0x74);
    const uint32_t je_proceed_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // Bailout tail — continue_search + pops + ret.
    //
    //   xor eax, eax    31 C0
    //   pop rdi         5F
    //   pop rsi         5E
    //   pop rbp         5D
    //   pop rbx         5B
    //   ret             C3
    // =================================================================
    e.u8(0x31); e.u8(0xC0);
    e.u8(0x5F);
    e.u8(0x5E);
    e.u8(0x5D);
    e.u8(0x5B);
    e.u8(0xC3);

    // =================================================================
    // .proceed — cache PCONTEXT in rbp and start real work.
    //   mov rbp, [rcx + 8]    48 8B 69 08
    // =================================================================
    const uint32_t proceed_label = static_cast<uint32_t>(e.size());
    e.u8(0x48); e.u8(0x8B); e.u8(0x69); e.u8(0x08);

    // =================================================================
    // Fault address → rdi.
    //   mov rdi, [rax + 0x10]    48 8B 78 10
    // =================================================================
    e.u8(0x48); e.u8(0x8B); e.u8(0x78); e.u8(0x10);

    // =================================================================
    // Module base → rbx.
    //   lea rbx, [rip + 0]       48 8D 1D 00 00 00 00
    //   sub rbx, <imm32>         48 81 EB imm32
    //
    // The caller patches the imm32 with the RVA of the byte right
    // after the `lea`, so at runtime `rbx_after_lea - imm32 = 0 +
    // module_base`.
    // =================================================================
    e.u8(0x48); e.u8(0x8D); e.u8(0x1D);
    e.u8(0x00); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    out.module_base_lea_anchor_offset =
        static_cast<uint32_t>(e.size()) - handler_start;

    e.u8(0x48); e.u8(0x81); e.u8(0xEB);
    out.module_base_sub_imm32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);

    // =================================================================
    // Convert fault address to fault_rva.
    //   sub rdi, rbx             48 29 DF
    // =================================================================
    e.u8(0x48); e.u8(0x29); e.u8(0xDF);

    // =================================================================
    // Commit 8 — self-hash walk over handler body.
    //
    // Compute FNV-1a over the handler's own byte stream and leave
    // the result in `r11d`. The decrypt_body subroutine uses r11d
    // as a 4-byte rolling XOR mask over the stored per-guard key
    // so that the "real" key (used for body encryption at build
    // time) is never materialized in the descriptor table. An
    // attacker with a memory dump sees the descriptor's stored
    // key + the plaintext handler bytes, but must:
    //
    //   1. Identify the FNV walk (not obvious in a sea of handler
    //      instructions)
    //   2. Correctly determine the hashed byte range
    //   3. Compute the same hash offline
    //   4. XOR the stored key to recover the real key
    //
    // Side benefit: any runtime tamper of the handler bytes
    // changes r11d → wrong mask → wrong key → decrypt to garbage.
    // This complements Commit 6's installer-time self-CRC with a
    // per-invocation integrity check that doesn't bail out (to
    // avoid giving the attacker a clear "tamper detected" signal)
    // but silently garbles decryption.
    //
    //   mov r11d, 0x811C9DC5      41 BB imm32       FNV init
    //   lea r10, [rip + 0]        4C 8D 15 00000000 cursor
    //   sub r10, <imm32>          49 81 EA imm32    → handler start
    //   mov ecx, <size>           B9 imm32          byte count
    //   mov r8d, 0x01000193       41 B8 imm32       FNV prime
    //   .hw:
    //     movzx eax, byte [r10]   41 0F B6 02       (3 bytes)
    //     xor r11d, eax           41 31 C3          (3)
    //     imul r11d, r8d          45 0F AF D8       (4)
    //     inc r10                 49 FF C2          (3)
    //     dec ecx                 FF C9             (2)
    //     jnz .hw                 75 rel8           (2)
    // =================================================================
    e.u8(0x41); e.u8(0xBB);
    e.u32(0x811C9DC5u);

    e.u8(0x4C); e.u8(0x8D); e.u8(0x15);
    e.u8(0x00); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    out.self_hash_lea_anchor_offset =
        static_cast<uint32_t>(e.size()) - handler_start;

    e.u8(0x49); e.u8(0x81); e.u8(0xEA);
    out.self_hash_sub_imm32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);

    e.u8(0xB9);
    out.self_hash_size_imm32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);

    e.u8(0x41); e.u8(0xB8);
    e.u32(0x01000193u);

    const uint32_t hw_loop_start = static_cast<uint32_t>(e.size());
    e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x02);   // movzx eax, [r10]
    e.u8(0x41); e.u8(0x31); e.u8(0xC3);                // xor r11d, eax
    e.u8(0x45); e.u8(0x0F); e.u8(0xAF); e.u8(0xD8);   // imul r11d, r8d
    e.u8(0x49); e.u8(0xFF); e.u8(0xC2);                // inc r10
    e.u8(0xFF); e.u8(0xC9);                            // dec ecx
    e.u8(0x75);                                         // jnz .hw
    {
        const uint32_t slot = static_cast<uint32_t>(e.size());
        e.u8(0x00);
        const int32_t rel8 =
            static_cast<int32_t>(hw_loop_start) -
            static_cast<int32_t>(slot + 1);
        e.buf[slot] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    // =================================================================
    // Descriptor table pointer + count.
    //   lea rsi, [rip + rel32]   48 8D 35 rel32
    //   mov r8d, imm32           41 B8 imm32
    // =================================================================
    e.u8(0x48); e.u8(0x8D); e.u8(0x35);
    out.descriptor_table_rel32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);
    out.descriptor_table_rel32_end_offset =
        static_cast<uint32_t>(e.size()) - handler_start;

    e.u8(0x41); e.u8(0xB8);
    out.descriptor_count_imm32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);

    // =================================================================
    // .loop — linear scan of the descriptor table.
    //
    //   .loop:
    //     test r8d, r8d                    45 85 C0
    //     jz   .bailout (rel8)             74 rel8
    //     cmp  dword [rsi], edi            39 3E
    //     je   .entry_match                74 rel8
    //     cmp  dword [rsi + 4], edi        39 7E 04
    //     je   .exit_match                 74 rel8
    //     add  rsi, 64                     48 83 C6 40
    //     dec  r8d                         41 FF C8
    //     jmp  .loop                       EB rel8
    //
    // The bailout rel8 goes backward to the `xor eax, eax` in the
    // bailout tail (above, near offset 15). Distance fits comfortably
    // inside an int8 delta.
    // =================================================================
    const uint32_t bailout_label = static_cast<uint32_t>(e.size() - handler_start);
    // bailout_label is actually the offset of the `xor eax, eax`
    // above. Recompute: the `je_proceed_slot` is at the rel8 slot
    // of the `je .proceed`, and the bailout starts one byte after
    // that. xor eax, eax is emitted right after.
    //
    // To avoid computing it from the slot, we remember it when we
    // emitted it. Redo: emit location of xor eax, eax = je_proceed_slot + 1.
    const uint32_t bailout_target = je_proceed_slot + 1;  // xor eax, eax
    (void)bailout_label;

    const uint32_t loop_start = static_cast<uint32_t>(e.size());

    e.u8(0x45); e.u8(0x85); e.u8(0xC0);
    e.u8(0x74);
    const uint32_t jz_bailout_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x39); e.u8(0x3E);
    e.u8(0x74);
    const uint32_t je_entry_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x39); e.u8(0x7E); e.u8(0x04);
    e.u8(0x74);
    const uint32_t je_exit_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x48); e.u8(0x83); e.u8(0xC6); e.u8(0x40);  // add rsi, 64
    e.u8(0x41); e.u8(0xFF); e.u8(0xC8);              // dec r8d
    e.u8(0xEB);
    const uint32_t jmp_loop_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    {
        const int32_t jmp_end = static_cast<int32_t>(jmp_loop_slot + 1);
        const int32_t rel8    = static_cast<int32_t>(loop_start) - jmp_end;
        e.buf[jmp_loop_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    // =================================================================
    // .entry_match
    //
    // Commit 4 anti-debug: hardware-breakpoint sweep BEFORE doing any
    // state change or decryption. If any of the four debug-address
    // registers (Dr0..Dr3 at CONTEXT offsets 0x48/0x50/0x58/0x60)
    // hold a non-zero value, the thread has at least one HW bp armed
    // — a strong signal that a reverser is attached and single-
    // stepping into the guard. Bail out via the existing fall-through
    // bailout tail (continue_search + pops + ret) without touching
    // the open_count or the body bytes. This leaves the body fully
    // encrypted at rest and pushes the unhandled int3 onwards, which
    // typically terminates the process.
    //
    // The HW bp sweep only runs on CONFIRMED guard int3 events, so a
    // debugger breaking on an UNRELATED hw bp does not interfere
    // with our bailout path.
    //
    //   mov rax, [rbp + 0x48]            48 8B 45 48     ; Dr0
    //   or  rax, [rbp + 0x50]            48 0B 45 50     ; | Dr1
    //   or  rax, [rbp + 0x58]            48 0B 45 58     ; | Dr2
    //   or  rax, [rbp + 0x60]            48 0B 45 60     ; | Dr3
    //   test rax, rax                    48 85 C0
    //   jnz  .bailout_tail               75 rel8
    //
    // Fall-through into the decrypt/set-Rip block on the clean path.
    //
    // Then:
    //   mov eax, 1                       B8 01 00 00 00
    //   lock xadd [rsi + 0x14], eax      F0 0F C1 46 14
    //   test eax, eax                    85 C0
    //   jnz .entry_skip_decrypt          75 rel8
    //   call .decrypt_body (rel32)       E8 rel32
    //
    //   .entry_skip_decrypt:
    //   mov eax, [rsi + 8]               8B 46 08
    //   add rax, rbx                     48 01 D8
    //   mov [rbp + 0xF8], rax            48 89 85 F8 00 00 00
    //   mov eax, -1                      B8 FF FF FF FF
    //   jmp .done_success                EB rel8
    // =================================================================
    const uint32_t entry_match_label = static_cast<uint32_t>(e.size());

    // HW breakpoint sweep (Commit 4) — Dr0 | Dr1 | Dr2 | Dr3.
    e.u8(0x48); e.u8(0x8B); e.u8(0x45); e.u8(0x48);  // mov rax, [rbp + 0x48]
    e.u8(0x48); e.u8(0x0B); e.u8(0x45); e.u8(0x50);  // or rax, [rbp + 0x50]
    e.u8(0x48); e.u8(0x0B); e.u8(0x45); e.u8(0x58);  // or rax, [rbp + 0x58]
    e.u8(0x48); e.u8(0x0B); e.u8(0x45); e.u8(0x60);  // or rax, [rbp + 0x60]
    e.u8(0x48); e.u8(0x85); e.u8(0xC0);              // test rax, rax
    e.u8(0x75);                                       // jnz rel8 → bailout_tail
    const uint32_t hw_bp_bailout_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0xB8); e.u8(0x01); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    e.u8(0xF0); e.u8(0x0F); e.u8(0xC1); e.u8(0x46); e.u8(0x14);
    e.u8(0x85); e.u8(0xC0);
    e.u8(0x75);
    const uint32_t entry_skip_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    e.u8(0xE8);
    const uint32_t entry_call_rel32_slot = static_cast<uint32_t>(e.size());
    e.u32(0);
    const uint32_t entry_skip_label = static_cast<uint32_t>(e.size());

    e.u8(0x8B); e.u8(0x46); e.u8(0x08);
    e.u8(0x48); e.u8(0x01); e.u8(0xD8);
    e.u8(0x48); e.u8(0x89); e.u8(0x85);
    e.u8(0xF8); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);
    e.u8(0xEB);
    const uint32_t entry_done_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // .exit_match
    //
    //   mov eax, -1                      B8 FF FF FF FF
    //   lock xadd [rsi + 0x14], eax      F0 0F C1 46 14
    //   cmp eax, 1                       83 F8 01
    //   jne .exit_skip_reencrypt         75 rel8
    //   call .decrypt_body               E8 rel32
    //
    //   .exit_skip_reencrypt:
    //   mov eax, [rsi + 12]              8B 46 0C
    //   add rax, rbx                     48 01 D8
    //   mov [rbp + 0xF8], rax            48 89 85 F8 00 00 00
    //   mov eax, -1                      B8 FF FF FF FF
    //   ; fall through to .done_success
    // =================================================================
    const uint32_t exit_match_label = static_cast<uint32_t>(e.size());

    e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);
    e.u8(0xF0); e.u8(0x0F); e.u8(0xC1); e.u8(0x46); e.u8(0x14);
    e.u8(0x83); e.u8(0xF8); e.u8(0x01);
    e.u8(0x75);
    const uint32_t exit_skip_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    e.u8(0xE8);
    const uint32_t exit_call_rel32_slot = static_cast<uint32_t>(e.size());
    e.u32(0);
    const uint32_t exit_skip_label = static_cast<uint32_t>(e.size());

    e.u8(0x8B); e.u8(0x46); e.u8(0x0C);
    e.u8(0x48); e.u8(0x01); e.u8(0xD8);
    e.u8(0x48); e.u8(0x89); e.u8(0x85);
    e.u8(0xF8); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);

    // =================================================================
    // .done_success — shared success tail.
    //
    //   pop rdi    5F
    //   pop rsi    5E
    //   pop rbp    5D
    //   pop rbx    5B
    //   ret        C3
    // =================================================================
    const uint32_t done_success_label = static_cast<uint32_t>(e.size());
    e.u8(0x5F);
    e.u8(0x5E);
    e.u8(0x5D);
    e.u8(0x5B);
    e.u8(0xC3);

    // =================================================================
    // Back-patch forward rel8 jumps. The two `call decrypt_body`
    // rel32 slots are LEFT AS ZERO — the caller (GuardPass) patches
    // them once the separately-emitted decrypt unit's offset in the
    // section is known (Commit 9a extraction).
    // =================================================================
    auto patch_rel8 = [&](uint32_t slot, uint32_t target) {
        const int32_t rel8 =
            static_cast<int32_t>(target) - static_cast<int32_t>(slot + 1);
        e.buf[slot] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    patch_rel8(je_proceed_slot,          proceed_label);
    patch_rel8(jz_bailout_slot,          bailout_target);
    patch_rel8(je_entry_slot,            entry_match_label);
    patch_rel8(je_exit_slot,             exit_match_label);
    patch_rel8(hw_bp_bailout_rel8_slot,  bailout_target);
    patch_rel8(entry_skip_rel8_slot,     entry_skip_label);
    patch_rel8(entry_done_rel8_slot,     done_success_label);
    patch_rel8(exit_skip_rel8_slot,      exit_skip_label);

    out.entry_call_decrypt_rel32_offset =
        entry_call_rel32_slot - handler_start;
    out.exit_call_decrypt_rel32_offset =
        exit_call_rel32_slot - handler_start;

    // =================================================================
    // Commit 7 — Per-build polymorphic random tail.
    //
    // Append 0..kGuardVehMaxTailJunk random bytes AFTER the
    // handler's final `ret` in `.done_success`. These bytes are
    // never executed but change the handler's CRC and byte stream
    // per build, breaking signature matching.
    // =================================================================
    const uint32_t tail_len = rng.next_range(0, kGuardVehMaxTailJunk);
    for (uint32_t i = 0; i < tail_len; ++i) {
        e.u8(rng.next_u8());
    }

    return out;
}

} // namespace mx::guard
