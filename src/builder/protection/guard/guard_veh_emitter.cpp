/**
 * @file guard_veh_emitter.cpp
 * @brief Byte-level x64 emission of the runtime-guards VEH handler.
 *        See guard_veh_emitter.hpp for the ABI and semantics.
 *
 * Commit 3b adds at-rest body encryption and concurrent-thread
 * reference counting to the Commit 3a scaffold. The handler body
 * is 209 bytes of position-independent code organised as:
 *
 *   * 0..21  — prologue + ExceptionCode filter + bailout tail.
 *     The fall-through after the filter IS the bailout path:
 *     `xor eax, eax` + pops + `ret`. The success path takes a
 *     forward `je` to skip over it.
 *
 *   * 22..59 — compute module base via rip-relative lea/sub,
 *     convert fault address to RVA, load descriptor table
 *     pointer + count.
 *
 *   * 60..82 — linear scan loop that matches the fault RVA
 *     against `[rsi + 0]` (entry) and `[rsi + 4]` (exit).
 *
 *   * 83..121 — entry_match: `LOCK XADD [rsi + 0x14], +1`; if
 *     the old count was 0 call `.decrypt_body`. Set
 *     `CONTEXT.Rip = body_start_va`, eax = -1, jmp forward
 *     into the shared success tail.
 *
 *   * 122..159 — exit_match: `LOCK XADD [rsi + 0x14], -1`; if
 *     the old count was 1 (new == 0) call `.decrypt_body` which
 *     re-encrypts the body because XOR is self-inverse. Set
 *     `CONTEXT.Rip = return_va`, eax = -1, fall through to the
 *     shared success tail.
 *
 *   * 160..164 — `.done_success`: pops + ret, reached from
 *     entry_match via forward jmp and from exit_match via
 *     fall-through.
 *
 *   * 165..208 — `.decrypt_body` subroutine. XORs the body range
 *     (at `[rbx + [rsi + 8]]`, length `[rsi + 0x10]`) with the
 *     32-byte key at `[rsi + 0x18]`, cycling every 32 bytes.
 *     Called from both entry_match and exit_match; because XOR
 *     is self-inverse, the same loop encrypts on the way in and
 *     decrypts on the way out (or vice versa).
 *
 * The ref-counter handles concurrent re-entry from multiple
 * threads: if thread A is already inside the guard, thread B's
 * entry sees count=1 and skips decryption (bytes are already
 * plaintext). Thread B's exit sees count=2→1 and skips
 * re-encryption. Only the LAST thread out re-encrypts.
 *
 * ## ABI / register use
 *
 * Clobbered volatiles: rax, rcx, rdx, r8, r9, r10, r11.
 * Saved + restored nonvolatiles: rbx, rbp, rsi, rdi.
 *
 * `rbp` caches `PCONTEXT` across the whole body so entry_match
 * and exit_match can `mov [rbp + 0xF8], rax` without re-loading
 * from rcx each time. `rbx` caches the module base. `rsi` holds
 * the current descriptor pointer during the loop and is
 * preserved across the `.decrypt_body` call. `rdi` holds the
 * fault RVA (unused after the match but still live until the
 * loop terminates).
 *
 * The `.decrypt_body` subroutine clobbers rax/rcx/rdx/r9 and
 * preserves rsi/rbx/rbp/rdi/r8 — the caller only needs rsi and
 * rbx after the call, both of which survive.
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
    // .decrypt_body — XOR-cipher pass over the guard body.
    //
    //   mov edx, [rsi + 8]            8B 56 08       body_start_rva
    //   add rdx, rbx                  48 01 DA       body_va
    //   mov ecx, [rsi + 0x10]         8B 4E 10       body_size
    //   xor r9d, r9d                  45 31 C9       key index
    //   test ecx, ecx                 85 C9
    //   jz .decrypt_done              74 rel8
    //   .decrypt_loop:
    //     movzx eax, byte [rsi + r9 + 0x18]   42 0F B6 44 0E 18
    //     xor [rdx], al                       30 02
    //     inc rdx                             48 FF C2
    //     inc r9d                             41 FF C1
    //     cmp r9d, 32                         41 83 F9 20
    //     jb .no_wrap                         72 rel8 (+3 to skip xor)
    //     xor r9d, r9d                        45 31 C9
    //   .no_wrap:
    //     dec ecx                             FF C9
    //     jnz .decrypt_loop                   75 rel8
    //   .decrypt_done:
    //     ret                                 C3
    //
    // Clobbers: rax, rcx, rdx, r9.
    // Preserves: rsi, rbx, rbp, rdi, r8.
    // =================================================================
    const uint32_t decrypt_body_label = static_cast<uint32_t>(e.size());

    e.u8(0x8B); e.u8(0x56); e.u8(0x08);
    e.u8(0x48); e.u8(0x01); e.u8(0xDA);
    e.u8(0x8B); e.u8(0x4E); e.u8(0x10);
    e.u8(0x45); e.u8(0x31); e.u8(0xC9);
    e.u8(0x85); e.u8(0xC9);
    e.u8(0x74);
    const uint32_t decrypt_done_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    const uint32_t decrypt_loop_label = static_cast<uint32_t>(e.size());
    e.u8(0x42); e.u8(0x0F); e.u8(0xB6); e.u8(0x44); e.u8(0x0E); e.u8(0x18);
    e.u8(0x30); e.u8(0x02);
    e.u8(0x48); e.u8(0xFF); e.u8(0xC2);
    e.u8(0x41); e.u8(0xFF); e.u8(0xC1);
    e.u8(0x41); e.u8(0x83); e.u8(0xF9); e.u8(0x20);
    // jb .no_wrap (skip the next 3-byte `xor r9d, r9d`)
    e.u8(0x72); e.u8(0x03);
    e.u8(0x45); e.u8(0x31); e.u8(0xC9);
    // .no_wrap:
    e.u8(0xFF); e.u8(0xC9);
    e.u8(0x75);
    const uint32_t decrypt_loop_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    {
        const int32_t end = static_cast<int32_t>(decrypt_loop_rel8_slot + 1);
        const int32_t rel8 =
            static_cast<int32_t>(decrypt_loop_label) - end;
        e.buf[decrypt_loop_rel8_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    const uint32_t decrypt_done_label = static_cast<uint32_t>(e.size());
    e.u8(0xC3);

    // =================================================================
    // Back-patch every forward rel8 and the two `call` rel32s.
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

    patch_rel8(je_proceed_slot,          proceed_label);
    patch_rel8(jz_bailout_slot,          bailout_target);
    patch_rel8(je_entry_slot,            entry_match_label);
    patch_rel8(je_exit_slot,             exit_match_label);
    patch_rel8(hw_bp_bailout_rel8_slot,  bailout_target);
    patch_rel8(entry_skip_rel8_slot,     entry_skip_label);
    patch_rel8(entry_done_rel8_slot,     done_success_label);
    patch_rel8(exit_skip_rel8_slot,      exit_skip_label);
    patch_rel8(decrypt_done_rel8_slot,   decrypt_done_label);
    patch_rel32(entry_call_rel32_slot,   decrypt_body_label);
    patch_rel32(exit_call_rel32_slot,    decrypt_body_label);

    // =================================================================
    // Commit 7 — Per-build polymorphic random tail.
    //
    // Append 0..kGuardVehMaxTailJunk random bytes AFTER the final
    // `ret` inside `.decrypt_body`. These bytes are never executed
    // (every control-flow path through the handler ends with a
    // `ret`), but they:
    //
    //   * Change the handler's total byte length per build, which
    //     shifts every downstream rel32 / imm32 patch in the
    //     `.mxguard` section (descriptor table rel32 from the
    //     handler, the TLS installer's handler_rel32 and
    //     crc_walk_rel32, the installer's crc_size_imm32, and
    //     the TLS callback VA computed by `GuardPass`).
    //
    //   * Change the CRC that the TLS installer's self-check
    //     compares against (Commit 6 pins the expected value at
    //     build time over the FULL handler byte range including
    //     this tail, so runtime verification still matches).
    //
    //   * Break naive byte-signature matching across builds —
    //     two builds of the same source binary will have
    //     different handler hashes and different .mxguard byte
    //     streams.
    //
    // The tail's bytes are drawn uniformly from `rng.next_u8()`.
    // It is the ONLY randomness source inside the handler proper
    // (other than what GuardPass already contributes via per-
    // guard XOR keys and per-page junk tails).
    // =================================================================
    const uint32_t tail_len = rng.next_range(0, kGuardVehMaxTailJunk);
    for (uint32_t i = 0; i < tail_len; ++i) {
        e.u8(rng.next_u8());
    }

    return out;
}

} // namespace mx::guard
