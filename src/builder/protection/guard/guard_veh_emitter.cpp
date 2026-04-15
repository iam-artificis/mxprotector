/**
 * @file guard_veh_emitter.cpp
 * @brief Byte-level x64 emission of the runtime-guards VEH handler.
 *        See guard_veh_emitter.hpp for the ABI and semantics.
 *
 * The handler is 125 bytes of position-independent code. Every rel8
 * branch inside the body is baked at emit time from fixed instruction
 * offsets — the handler's shape is constant, so the math below never
 * depends on external inputs. Unit tests in
 * `tests/unit/guard_veh_emitter_test.cpp` assert the exact byte
 * pattern + patch-site offsets so any accidental insn-size change
 * trips immediately.
 */

#include "mxprotector/protection/guard/guard_veh_emitter.hpp"

#include <cstdint>

namespace mx::guard {

GuardVehEmit emit_guard_veh_handler(RawEmitter& e) {
    GuardVehEmit out{};
    const uint32_t handler_start = static_cast<uint32_t>(e.size());

    // =================================================================
    // Prologue — save nonvolatiles the body uses.
    //
    //   push rbx    (53)
    //   push rsi    (56)
    //   push rdi    (57)
    // =================================================================
    e.u8(0x53);
    e.u8(0x56);
    e.u8(0x57);

    // =================================================================
    // Exception-code filter.
    //
    //   mov rax, [rcx]                   48 8B 01
    //     rax = PEXCEPTION_RECORD
    //   cmp dword [rax], 0x80000003      81 38 03 00 00 80
    //     STATUS_BREAKPOINT
    //   jne .continue_search             75 rel8
    //
    // If the fault is not an int3, bail out immediately with
    // EXCEPTION_CONTINUE_SEARCH — every other exception (C++ throw,
    // access violation, etc.) must flow through the rest of the
    // VEH chain unmodified so user code still works correctly.
    // =================================================================
    e.u8(0x48); e.u8(0x8B); e.u8(0x01);
    e.u8(0x81); e.u8(0x38); e.u8(0x03); e.u8(0x00); e.u8(0x00); e.u8(0x80);
    e.u8(0x75);
    const uint32_t bailout_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // Load fault address into rdi.
    //
    //   mov rdi, [rax + 0x10]            48 8B 78 10
    //     ExceptionAddress field of EXCEPTION_RECORD (offset 0x10 on
    //     x64: ExceptionCode(4) + ExceptionFlags(4) +
    //     ExceptionRecord*(8) = 16).
    // =================================================================
    e.u8(0x48); e.u8(0x8B); e.u8(0x78); e.u8(0x10);

    // =================================================================
    // Compute module base into rbx.
    //
    //   lea rbx, [rip + 0]               48 8D 1D 00 00 00 00
    //     rbx = handler_start + module_base_lea_anchor_offset
    //   sub rbx, <imm32>                 48 81 EB imm32
    //     imm32 = handler_start + module_base_lea_anchor_offset
    //     → rbx = module_base
    //
    // The `lea rbx, [rip + 0]` emits a zero rel32 because that's
    // exactly what we want: it resolves to the rip-after-lea value,
    // which equals `handler_rva + <byte offset of the next insn>`.
    // The caller patches `module_base_sub_imm32_offset` with the
    // exact RVA of the byte right after the LEA, so that
    // `current_rip - imm32 = 0 + module_base`.
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
    // Convert fault address to RVA.
    //
    //   sub rdi, rbx                     48 29 DF
    //     rdi = fault_rva
    // =================================================================
    e.u8(0x48); e.u8(0x29); e.u8(0xDF);

    // =================================================================
    // Load descriptor table base into rsi.
    //
    //   lea rsi, [rip + rel32]           48 8D 35 rel32
    // =================================================================
    e.u8(0x48); e.u8(0x8D); e.u8(0x35);
    out.descriptor_table_rel32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);
    out.descriptor_table_rel32_end_offset =
        static_cast<uint32_t>(e.size()) - handler_start;

    // =================================================================
    // Load descriptor count into r8d.
    //
    //   mov r8d, imm32                   41 B8 imm32
    // =================================================================
    e.u8(0x41); e.u8(0xB8);
    out.descriptor_count_imm32_offset =
        static_cast<uint32_t>(e.size()) - handler_start;
    e.u32(0);

    // =================================================================
    // Linear scan loop.
    //
    // .loop:
    //   test r8d, r8d                    45 85 C0
    //   jz   .continue_search            74 rel8
    //   cmp  dword [rsi], edi            39 3E
    //   je   .entry_match                74 rel8
    //   cmp  dword [rsi + 4], edi        39 7E 04
    //   je   .exit_match                 74 rel8
    //   add  rsi, 16                     48 83 C6 10
    //   dec  r8d                         41 FF C8
    //   jmp  .loop                       EB rel8
    // =================================================================
    const uint32_t loop_start = static_cast<uint32_t>(e.size());

    e.u8(0x45); e.u8(0x85); e.u8(0xC0);
    e.u8(0x74);
    const uint32_t loop_zero_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x39); e.u8(0x3E);
    e.u8(0x74);
    const uint32_t entry_match_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x39); e.u8(0x7E); e.u8(0x04);
    e.u8(0x74);
    const uint32_t exit_match_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    e.u8(0x48); e.u8(0x83); e.u8(0xC6); e.u8(0x10);
    e.u8(0x41); e.u8(0xFF); e.u8(0xC8);
    e.u8(0xEB);
    const uint32_t loop_back_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);
    // Back-patch the loop → loop_start jmp immediately so we don't
    // have to carry loop_start around to the post-emit fixups below.
    {
        const uint32_t jmp_end = loop_back_rel8_slot + 1;
        const int32_t  rel8    = static_cast<int32_t>(loop_start) -
                                 static_cast<int32_t>(jmp_end);
        e.buf[loop_back_rel8_slot] =
            static_cast<uint8_t>(static_cast<int8_t>(rel8));
    }

    // =================================================================
    // .entry_match:
    //   mov eax, [rsi + 8]               8B 46 08       ; body_start_rva
    //   add rax, rbx                     48 01 D8       ; += module_base
    //   mov rdx, [rcx + 8]               48 8B 51 08    ; PCONTEXT
    //   mov [rdx + 0xF8], rax            48 89 82 F8 00 00 00
    //                                                    CONTEXT.Rip = body_start_va
    //   mov eax, -1                      B8 FF FF FF FF ; CONTINUE_EXECUTION
    //   jmp .done                        EB rel8
    // =================================================================
    const uint32_t entry_match_label = static_cast<uint32_t>(e.size());

    e.u8(0x8B); e.u8(0x46); e.u8(0x08);
    e.u8(0x48); e.u8(0x01); e.u8(0xD8);
    e.u8(0x48); e.u8(0x8B); e.u8(0x51); e.u8(0x08);
    e.u8(0x48); e.u8(0x89); e.u8(0x82);
    e.u8(0xF8); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);
    e.u8(0xEB);
    const uint32_t entry_done_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // .exit_match:
    //   mov eax, [rsi + 12]              8B 46 0C       ; return_rva
    //   add rax, rbx                     48 01 D8
    //   mov rdx, [rcx + 8]               48 8B 51 08
    //   mov [rdx + 0xF8], rax            48 89 82 F8 00 00 00
    //   mov eax, -1                      B8 FF FF FF FF
    //   jmp .done                        EB rel8
    // =================================================================
    const uint32_t exit_match_label = static_cast<uint32_t>(e.size());

    e.u8(0x8B); e.u8(0x46); e.u8(0x0C);
    e.u8(0x48); e.u8(0x01); e.u8(0xD8);
    e.u8(0x48); e.u8(0x8B); e.u8(0x51); e.u8(0x08);
    e.u8(0x48); e.u8(0x89); e.u8(0x82);
    e.u8(0xF8); e.u8(0x00); e.u8(0x00); e.u8(0x00);
    e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);
    e.u8(0xEB);
    const uint32_t exit_done_rel8_slot = static_cast<uint32_t>(e.size());
    e.u8(0x00);

    // =================================================================
    // .continue_search:
    //   xor eax, eax                     31 C0
    //   ; fall through into .done
    // =================================================================
    const uint32_t continue_search_label = static_cast<uint32_t>(e.size());
    e.u8(0x31); e.u8(0xC0);

    // =================================================================
    // .done:
    //   pop rdi                          5F
    //   pop rsi                          5E
    //   pop rbx                          5B
    //   ret                              C3
    // =================================================================
    const uint32_t done_label = static_cast<uint32_t>(e.size());
    e.u8(0x5F);
    e.u8(0x5E);
    e.u8(0x5B);
    e.u8(0xC3);

    // =================================================================
    // Back-patch forward rel8 branches now that every label is known.
    // =================================================================
    auto patch_rel8 = [&](uint32_t slot, uint32_t target) {
        const int32_t rel8 =
            static_cast<int32_t>(target) - static_cast<int32_t>(slot + 1);
        e.buf[slot] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    patch_rel8(bailout_rel8_slot,       continue_search_label);
    patch_rel8(loop_zero_rel8_slot,     continue_search_label);
    patch_rel8(entry_match_rel8_slot,   entry_match_label);
    patch_rel8(exit_match_rel8_slot,    exit_match_label);
    patch_rel8(entry_done_rel8_slot,    done_label);
    patch_rel8(exit_done_rel8_slot,     done_label);

    return out;
}

} // namespace mx::guard
