/**
 * @file x64_inner_vm.cpp
 * @brief [BUILDER, x64] Inner VM runtime emitter (G2 nested VM).
 *
 * Produces the 64-byte inner-VM runtime block described in
 * `x64_inner_vm.hpp`. Every byte is hand-assembled and
 * cross-referenced against the layout diagram in the header; the
 * final `assert(size == kInnerVmRuntimeSize)` catches any
 * accidental drift.
 *
 * Flag propagation: the three terminal handlers
 * (`iadd_exit`/`isub_exit`/`ixor_exit`) execute their ALU op
 * DIRECTLY against `[rsi]` and then `ret` to the outer handler.
 * No dispatcher loop runs between the ALU and the return, so the
 * ALU's rflags are the ones the outer handler's tail dispatch
 * sees and stores into `vflags`. Any design that routes through a
 * dispatch-loop `inc r12` or `add rax, r13` between the ALU and
 * the return would clobber the guest flags and break downstream
 * `vjcc` handlers — the earlier G4 dead-opcode attempt ran into
 * exactly this and had to be reverted.
 *
 * Layout (offsets inside the emitted block):
 *
 *   +0   lea  r13, [rip + handler_table_disp32]   (7 bytes)
 *   +7   .loop:  movzx eax, byte [r12]            (5)
 *   +12         inc   r12                          (3)
 *   +15         mov   eax, [r13 + rax*4 + 0]       (5)
 *   +20         movsxd rax, eax                    (3)
 *   +23         add   rax, r13                     (3)
 *   +26         jmp   rax                          (2)
 *   +28  H_iload_src:  mov rax, [rdi]; jmp .loop   (5)
 *   +33  H_iadd_exit:  add [rsi], rax; ret         (4)
 *   +37  H_isub_exit:  sub [rsi], rax; ret         (4)
 *   +41  H_ixor_exit:  xor [rsi], rax; ret         (4)
 *   +45  padding                                    (3, 0xCC)
 *   +48  handler_table: 4 × int32                   (16)
 *   +64  end
 */

#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace mx::vm::x64 {

namespace {

// Hard-coded layout offsets — every jump distance, table base, and
// handler-table entry below is derived from these. If the byte-level
// shape of any chunk changes, update the constant(s) AND the
// dependent computations in `emit_inner_vm_runtime`.
constexpr size_t kOffDispatcherStart = 0;
constexpr size_t kOffLoopStart       = 7;    // right after `lea r13, ...`
constexpr size_t kOffDispatcherEnd   = 28;   // after `jmp rax`
constexpr size_t kOffHIloadSrc       = 28;
constexpr size_t kOffHIaddExit       = 33;
constexpr size_t kOffHIsubExit       = 37;
constexpr size_t kOffHIxorExit       = 41;
constexpr size_t kOffHandlersEnd     = 45;
constexpr size_t kOffPaddingEnd      = 48;   // 4-byte aligned
constexpr size_t kOffHandlerTable    = 48;

static_assert(kOffHandlersEnd + 3 == kOffPaddingEnd,
              "expected exactly 3 bytes of padding between handlers and table");

} // anonymous namespace

size_t emit_inner_vm_runtime(RawEmitter& e) {
    const size_t blob_base = e.size();

    // ------------------------------------------------------------------
    // Dispatcher prologue + fetch/dispatch loop.
    //
    // There is no sentinel byte and no `.done:` branch — the terminal
    // handlers below `ret` directly instead of looping back, so the
    // dispatcher's last meaningful flag-clobber is `add rax, r13`
    // right before `jmp rax` to the next handler. The terminal ALU
    // op then overwrites those flags with the guest-ALU result.
    // ------------------------------------------------------------------

    // [+0]  lea r13, [rip + handler_table_disp32]
    //
    //   REX.W|R (0x4C) + 0x8D + ModRM(mod=00 reg=r13&7=101 rm=101=rip-rel)
    //   disp32 = handler_table_offset - (lea_end = +7)
    //
    //   r13 is encoded with REX.R = 1 and ModRM.reg = 5.
    constexpr int32_t lea_disp32 =
        static_cast<int32_t>(kOffHandlerTable) - 7;
    static_assert(lea_disp32 == 41, "handler table must sit at offset 48");
    e.u8(0x4C); e.u8(0x8D); e.u8(0x2D);
    e.u32(static_cast<uint32_t>(lea_disp32));

    // [+7]  .loop:  movzx eax, byte [r12]
    //
    //   REX.B (0x41) + 0x0F B6 + ModRM(mod=00 reg=eax=000 rm=100=SIB) = 0x04
    //   SIB(scale=00 index=100=none base=r12&7=100) = 0x24
    //
    //   [r12] always needs a SIB byte because the low 3 bits of r12
    //   are 100 — which is the ModRM "SIB follows" escape.
    e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x04); e.u8(0x24);

    // [+12] inc r12
    //
    //   REX.W|B (0x49) + 0xFF + ModRM(11 000 100 = 0xC4)
    e.u8(0x49); e.u8(0xFF); e.u8(0xC4);

    // [+15] mov eax, [r13 + rax*4 + 0]
    //
    //   REX.B (0x41, r13 base) + 0x8B + ModRM(01 000 100 = 0x44, SIB)
    //   SIB(scale=10 ×4, index=rax=000, base=r13&7=101) = 0x85
    //   disp8 = 0 (required because base=r13 with mod=00 would mean
    //             "disp32, no base" per the SIB escape rule).
    e.u8(0x41); e.u8(0x8B); e.u8(0x44); e.u8(0x85); e.u8(0x00);

    // [+20] movsxd rax, eax
    //
    //   REX.W (0x48) + 0x63 + ModRM(11 000 000 = 0xC0)
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // [+23] add rax, r13
    //
    //   REX.W|R (0x4C, r13 as source reg-field) + 0x01 +
    //   ModRM(mod=11 reg=r13&7=101 rm=rax=000) = 0xE8
    e.u8(0x4C); e.u8(0x01); e.u8(0xE8);

    // [+26] jmp rax
    //
    //   0xFF /4 + ModRM(11 100 000 = 0xE0)
    e.u8(0xFF); e.u8(0xE0);

    assert(e.size() - blob_base == kOffDispatcherEnd);

    // ------------------------------------------------------------------
    // [+28] H_iload_src:  mov r14, [rdi];  jmp .loop
    //
    //   mov r64, r/m64:   REX.W|R + 0x8B + ModRM
    //   For `mov r14, [rdi]`: REX = W|R = 0x4C, opcode = 0x8B,
    //   ModRM = 00 (mod) 110 (reg=r14&7=6) 111 (rm=rdi=7) = 0x37
    //
    //   Body = 3 bytes, jmp .loop = 2 bytes, total = 5.
    //
    //   r14 is used as the "inner src register" to avoid clobbering
    //   rax — which the dispatcher loop uses as its opcode / table-
    //   index / handler-address scratch. If we kept the src value in
    //   rax, the very next dispatcher iteration's `movzx eax, byte
    //   [r12]` would overwrite it, and the terminal handler would
    //   add the handler address to the destination slot. (That was
    //   the first-pass bug — 48-bit pointer results everywhere.)
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIloadSrc);
    e.u8(0x4C); e.u8(0x8B); e.u8(0x37);
    {
        constexpr int8_t rel8 =
            static_cast<int8_t>(static_cast<int32_t>(kOffLoopStart) -
                                static_cast<int32_t>(kOffHIloadSrc + 5));
        static_assert(rel8 == -26, "iload_src jmp distance");
        e.u8(0xEB); e.u8(static_cast<uint8_t>(rel8));
    }

    // ------------------------------------------------------------------
    // [+33] H_iadd_exit:  add [rsi], r14;  ret
    //
    //   `add r/m64, r64`:  REX.W|R + 0x01 + ModRM
    //   For `add [rsi], r14`: REX = W|R = 0x4C, opcode = 0x01,
    //   ModRM = 00 (mod) 110 (reg=r14&7=6) 110 (rm=rsi=6) = 0x36
    //
    //   rflags after the add reflects the guest ALU result. `ret`
    //   preserves them, and the outer handler's tail dispatch saves
    //   them straight into the VM `vflags` slot — downstream
    //   `vjcc` handlers see the correct guest ZF/SF/CF/OF/PF.
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIaddExit);
    e.u8(0x4C); e.u8(0x01); e.u8(0x36);
    e.u8(0xC3);

    // ------------------------------------------------------------------
    // [+37] H_isub_exit:  sub [rsi], r14;  ret
    //   `sub r/m64, r64`: 4C 29 36
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIsubExit);
    e.u8(0x4C); e.u8(0x29); e.u8(0x36);
    e.u8(0xC3);

    // ------------------------------------------------------------------
    // [+41] H_ixor_exit:  xor [rsi], r14;  ret
    //   `xor r/m64, r64`: 4C 31 36
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIxorExit);
    e.u8(0x4C); e.u8(0x31); e.u8(0x36);
    e.u8(0xC3);

    assert(e.size() - blob_base == kOffHandlersEnd);

    // ------------------------------------------------------------------
    // [+45] 3-byte padding so the int32 handler table lands 4-aligned.
    // ------------------------------------------------------------------
    e.u8(0xCC); e.u8(0xCC); e.u8(0xCC);
    assert(e.size() - blob_base == kOffPaddingEnd);

    // ------------------------------------------------------------------
    // [+48] Handler table: 4 × signed int32 offsets, each stored as
    // `handler_offset - kOffHandlerTable`, so the dispatcher's
    // `movsxd rax, eax; add rax, r13` yields the absolute handler
    // address.
    // ------------------------------------------------------------------
    constexpr int32_t kTableEntries[4] = {
        static_cast<int32_t>(kOffHIloadSrc) - static_cast<int32_t>(kOffHandlerTable),
        static_cast<int32_t>(kOffHIaddExit) - static_cast<int32_t>(kOffHandlerTable),
        static_cast<int32_t>(kOffHIsubExit) - static_cast<int32_t>(kOffHandlerTable),
        static_cast<int32_t>(kOffHIxorExit) - static_cast<int32_t>(kOffHandlerTable),
    };
    static_assert(kTableEntries[0] == -20);
    static_assert(kTableEntries[3] == -7);
    for (int32_t entry : kTableEntries) {
        e.u32(static_cast<uint32_t>(entry));
    }

    assert(e.size() - blob_base == kInnerVmRuntimeSize);
    return blob_base + kOffDispatcherStart;  // entry point offset
}

} // namespace mx::vm::x64
