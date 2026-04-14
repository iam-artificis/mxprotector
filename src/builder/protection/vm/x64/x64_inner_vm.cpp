/**
 * @file x64_inner_vm.cpp
 * @brief [BUILDER, x64] Inner VM runtime emitter (G2 extended scope).
 *
 * Produces the 152-byte inner-VM runtime block described in
 * `x64_inner_vm.hpp`. Every byte is hand-assembled and
 * cross-referenced against the layout diagram in the header; the
 * final `assert(size == kInnerVmRuntimeSize)` catches any accidental
 * drift.
 *
 * Flag propagation uses a live host register (`rcx`) as the rflags
 * carrier between the guest ALU and `iret`. The dispatch loop and
 * all non-ALU handlers leave `rcx` untouched, so the last ALU to
 * run leaves its correct guest flags in `rcx`, and `iret` does
 * `push rcx; popfq; ret` to restore them before returning to the
 * outer handler.
 *
 * The runtime lives in the .mxvm code section which is R+X but NOT
 * writable — an earlier attempt at an 8-byte in-runtime flag scratch
 * (`pop qword [r13+disp]`) faulted on first use for this reason.
 * That's why the scratch has to be a register.
 *
 * Register convention inside handler bodies:
 *   r14 = accumulator  (holds dst, then `dst op src` after the ALU)
 *   r15 = rhs operand  (holds src value, right-hand side of the ALU)
 *   rcx = flag carrier (holds saved rflags between ALU and iret)
 *   r12 = inner VPC
 *   r13 = handler-table base
 *   rax = dispatcher scratch (clobbered every dispatch cycle)
 *
 * The r14/r15 split matters for non-commutative ops: `sub r14, r15`
 * = dst - src matches the outer VM's `sub_rr` semantics. First-pass
 * had these reversed and sub_rr produced `src - dst` — see git
 * history for the triage trail.
 *
 * Layout (offsets inside the emitted block):
 *
 *   +0   lea  r13, [rip + handler_table_disp32]     (7)
 *   +7   .loop:  movzx eax, byte [r12]              (5)
 *   +12         inc   r12                            (3)
 *   +15         mov   eax, [r13 + rax*4 + 0]         (5)
 *   +20         movsxd rax, eax                      (3)
 *   +23         add   rax, r13                       (3)
 *   +26         jmp   rax                            (2)
 *   +28  H_iload_src        : mov r15, [rdi]; jmp .loop           (5)
 *   +33  H_iload_dst        : mov r14, [rsi]; jmp .loop           (5)
 *   +38  H_istore_dst       : mov [rsi], r14; jmp .loop           (5)
 *   +43  H_iadd_rr          : add r14, r15; pushfq; pop rcx; jmp  (7)
 *   +50  H_isub_rr          : sub r14, r15; pushfq; pop rcx; jmp  (7)
 *   +57  H_ixor_rr          : xor r14, r15; pushfq; pop rcx; jmp  (7)
 *   +64  H_iand_rr          : and r14, r15; pushfq; pop rcx; jmp  (7)
 *   +71  H_ior_rr           : or  r14, r15; pushfq; pop rcx; jmp  (7)
 *   +78  H_iret             : push rcx; popfq; ret                (3)
 *   +81  H_iload_src_accum  : mov r14, [rdi]; jmp .loop           (5)
 *   +86  H_iret_noflag      : ret                                 (1)
 *   +87  H_inot_r14         : not r14; jmp .loop                  (5)
 *   +92  H_ineg_r14         : neg r14; pushfq; pop rcx; jmp .loop (7)
 *   +99  padding                                                  (1, 0xCC)
 *   +100 handler_table : 13 × int32                              (52)
 *   +152 end
 */

#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>

namespace mx::vm::x64 {

namespace {

// Hard-coded layout offsets. Every jump distance, table base, and
// handler-table entry below is derived from these. If the byte-level
// shape of any chunk changes, update the constant(s) AND the
// dependent computations in `emit_inner_vm_runtime`.
constexpr size_t kOffDispatcherStart = 0;
constexpr size_t kOffLoopStart       = 7;     // right after `lea r13, ...`
constexpr size_t kOffDispatcherEnd   = 28;    // after `jmp rax`

constexpr size_t kOffHIloadSrc       = 28;
constexpr size_t kOffHIloadDst       = 33;
constexpr size_t kOffHIstoreDst      = 38;
constexpr size_t kOffHIaddRr         = 43;
constexpr size_t kOffHIsubRr         = 50;
constexpr size_t kOffHIxorRr         = 57;
constexpr size_t kOffHIandRr         = 64;
constexpr size_t kOffHIorRr          = 71;
constexpr size_t kOffHIret           = 78;
constexpr size_t kOffHIloadSrcAccum  = 81;
constexpr size_t kOffHIretNoFlag     = 86;
constexpr size_t kOffHInotR14        = 87;
constexpr size_t kOffHInegR14        = 92;
constexpr size_t kOffHandlersEnd     = 99;
constexpr size_t kOffPaddingEnd      = 100;  // 4-byte aligned

constexpr size_t kOffHandlerTable    = 100;
constexpr size_t kOffRuntimeEnd      = 152;

static_assert(kOffHandlersEnd + 1 == kOffPaddingEnd,
              "expected exactly 1 byte of padding between handlers and table");
static_assert(kOffHandlerTable + 13 * 4 == kOffRuntimeEnd,
              "handler table is 13 × int32, ends the block");
static_assert(kOffRuntimeEnd == kInnerVmRuntimeSize,
              "runtime size constant must match layout end");

// Emit a short `jmp .loop` (2 bytes) from the current position back
// to the dispatcher loop. `body_end` is the offset of the byte
// AFTER the jmp instruction (used to compute rel8).
void emit_jmp_loop_rel8(RawEmitter& e, size_t body_end) {
    const int32_t rel = static_cast<int32_t>(kOffLoopStart) -
                        static_cast<int32_t>(body_end);
    assert(rel >= -128 && rel <= 127);
    e.u8(0xEB);
    e.u8(static_cast<uint8_t>(static_cast<int8_t>(rel)));
}

} // anonymous namespace

size_t emit_inner_vm_runtime(RawEmitter& e) {
    const size_t blob_base = e.size();

    // ------------------------------------------------------------------
    // [+0..+28] Dispatcher prologue + fetch/dispatch loop.
    //
    // Last rflags-clobber before jumping into a handler is `add rax,
    // r13` — all ALU handlers re-clobber rflags on their first op
    // anyway, and `iret` reloads them from `rcx`, so nothing here
    // is load-bearing for flag propagation. `rcx` is NOT touched by
    // anything in this loop.
    // ------------------------------------------------------------------

    // [+0] lea r13, [rip + handler_table_disp32]
    //
    //   REX.W|R (0x4C) + 0x8D + ModRM(mod=00 reg=r13&7=101 rm=101=rip-rel)
    //   disp32 = kOffHandlerTable - (end of LEA = +7)
    constexpr int32_t lea_disp32 =
        static_cast<int32_t>(kOffHandlerTable) - 7;
    static_assert(lea_disp32 == 93, "handler table must sit at offset 100");
    e.u8(0x4C); e.u8(0x8D); e.u8(0x2D);
    e.u32(static_cast<uint32_t>(lea_disp32));

    // [+7] .loop: movzx eax, byte [r12]
    //
    //   REX.B (0x41) + 0x0F B6 + ModRM(00 000 100 = 0x04) + SIB(00 100 100 = 0x24)
    //   [r12] needs SIB because r12's low 3 bits are 100 (SIB-escape).
    e.u8(0x41); e.u8(0x0F); e.u8(0xB6); e.u8(0x04); e.u8(0x24);

    // [+12] inc r12
    //
    //   REX.W|B (0x49) + 0xFF + ModRM(11 000 100 = 0xC4)
    e.u8(0x49); e.u8(0xFF); e.u8(0xC4);

    // [+15] mov eax, [r13 + rax*4 + 0]
    //
    //   REX.B (0x41, r13 base) + 0x8B + ModRM(01 000 100 = 0x44, SIB)
    //   SIB(scale=10 ×4, index=rax=000, base=r13&7=101) = 0x85
    //   disp8 = 0 (required because r13 with mod=00 means "disp32, no base")
    e.u8(0x41); e.u8(0x8B); e.u8(0x44); e.u8(0x85); e.u8(0x00);

    // [+20] movsxd rax, eax
    //
    //   REX.W (0x48) + 0x63 + ModRM(11 000 000 = 0xC0)
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // [+23] add rax, r13
    //
    //   REX.W|R (0x4C) + 0x01 + ModRM(11 101 000 = 0xE8)
    e.u8(0x4C); e.u8(0x01); e.u8(0xE8);

    // [+26] jmp rax
    //
    //   0xFF /4 + ModRM(11 100 000 = 0xE0)
    e.u8(0xFF); e.u8(0xE0);

    assert(e.size() - blob_base == kOffDispatcherEnd);

    // ------------------------------------------------------------------
    // [+28] H_iload_src: mov r15, [rdi]; jmp .loop
    //
    // r15 is the "rhs operand" register — the source value is the
    // right-hand side of non-commutative ops like `sub r14, r15`
    // (= dst - src, which is the outer VM's sub_rr semantics). For
    // commutative ops (add/xor/and/or) the order is irrelevant.
    //
    //   REX.W|R (0x4C) + 0x8B + ModRM(00 111 111 = 0x3F)
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIloadSrc);
    e.u8(0x4C); e.u8(0x8B); e.u8(0x3F);
    emit_jmp_loop_rel8(e, kOffHIloadSrc + 5);

    // ------------------------------------------------------------------
    // [+33] H_iload_dst: mov r14, [rsi]; jmp .loop
    //
    // r14 is the "accumulator" — holds the dst value before the ALU,
    // then the result after. istore_dst writes r14 back to [rsi].
    //
    //   REX.W|R (0x4C) + 0x8B + ModRM(00 110 110 = 0x36)
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIloadDst);
    e.u8(0x4C); e.u8(0x8B); e.u8(0x36);
    emit_jmp_loop_rel8(e, kOffHIloadDst + 5);

    // ------------------------------------------------------------------
    // [+38] H_istore_dst: mov [rsi], r14; jmp .loop
    //
    //   mov r/m64, r64: REX.W|R (0x4C) + 0x89 + ModRM(00 110 110 = 0x36)
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIstoreDst);
    e.u8(0x4C); e.u8(0x89); e.u8(0x36);
    emit_jmp_loop_rel8(e, kOffHIstoreDst + 5);

    // ------------------------------------------------------------------
    // ALU r-r handlers. Each is:
    //   <3 bytes ALU `op r14, r15`>     REX.W|R|B=0x4D + opcode + ModRM=0xFE
    //   <1 byte pushfq>                 0x9C
    //   <1 byte pop rcx>                0x59   (pop r64 = 58+rq, rcx rq=1)
    //   <2 bytes jmp .loop>             0xEB rel8
    // = 7 bytes total.
    //
    // ModRM 0xFE = 11 111 110: mod=11 (reg-direct), reg=r15&7=111,
    // rm=r14&7=110 → destination r14, source r15. Opcode differs per op:
    //   add 0x01   sub 0x29   xor 0x31   and 0x21   or 0x09
    //
    // The `pop rcx` is a plain opcode (0x59) with no REX prefix —
    // rcx is a low register, so it encodes into the opcode byte
    // directly (pop r64 = 58 + reg_num, rcx=1, → 0x59).
    // ------------------------------------------------------------------

    auto emit_alu_tail = [&](size_t handler_offset) {
        e.u8(0x9C);  // pushfq
        e.u8(0x59);  // pop rcx
        // jmp .loop, body_end = handler_offset + 3 (alu) + 1 (pushfq) + 1 (pop rcx) + 2 (jmp)
        emit_jmp_loop_rel8(e, handler_offset + 7);
    };

    // [+43] H_iadd_rr: add r14, r15; save→rcx; jmp .loop
    assert(e.size() - blob_base == kOffHIaddRr);
    e.u8(0x4D); e.u8(0x01); e.u8(0xFE);
    emit_alu_tail(kOffHIaddRr);

    // [+50] H_isub_rr: sub r14, r15; save→rcx; jmp .loop
    assert(e.size() - blob_base == kOffHIsubRr);
    e.u8(0x4D); e.u8(0x29); e.u8(0xFE);
    emit_alu_tail(kOffHIsubRr);

    // [+57] H_ixor_rr: xor r14, r15; save→rcx; jmp .loop
    assert(e.size() - blob_base == kOffHIxorRr);
    e.u8(0x4D); e.u8(0x31); e.u8(0xFE);
    emit_alu_tail(kOffHIxorRr);

    // [+64] H_iand_rr: and r14, r15; save→rcx; jmp .loop
    assert(e.size() - blob_base == kOffHIandRr);
    e.u8(0x4D); e.u8(0x21); e.u8(0xFE);
    emit_alu_tail(kOffHIandRr);

    // [+71] H_ior_rr: or r14, r15; save→rcx; jmp .loop
    assert(e.size() - blob_base == kOffHIorRr);
    e.u8(0x4D); e.u8(0x09); e.u8(0xFE);
    emit_alu_tail(kOffHIorRr);

    // ------------------------------------------------------------------
    // [+78] H_iret: push rcx; popfq; ret
    //
    //   push rcx = 0x51 (push r64 = 50+rq, rcx rq=1)
    //   popfq    = 0x9D
    //   ret      = 0xC3
    //
    // `ret` preserves rflags, so the flags we just loaded from rcx
    // carry straight through to the outer handler's tail dispatch,
    // which saves them to `vflags`.
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIret);
    e.u8(0x51); e.u8(0x9D); e.u8(0xC3);

    // ------------------------------------------------------------------
    // [+81] H_iload_src_accum: mov r14, [rdi]; jmp .loop
    //
    //   REX.W|R (0x4C) + 0x8B + ModRM(00 110 111 = 0x37)
    //
    // Same encoding as `mov r14, [rdi]` — loads the src slot value
    // directly into the accumulator. Used by `mov_rr` lifts where
    // no rhs operand is needed.
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIloadSrcAccum);
    e.u8(0x4C); e.u8(0x8B); e.u8(0x37);
    emit_jmp_loop_rel8(e, kOffHIloadSrcAccum + 5);

    // ------------------------------------------------------------------
    // [+86] H_iret_noflag: ret
    //
    // `mov_rr` and other flag-transparent lifts use this instead of
    // `iret` — it returns without the `push rcx; popfq` pair, so
    // `rflags` exits the inner VM exactly as it entered. This
    // matches V0 `mov_rr`'s flag behavior (flag-transparent at the
    // inner-VM boundary).
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHIretNoFlag);
    e.u8(0xC3);

    // ------------------------------------------------------------------
    // [+87] H_inot_r14: not r14; jmp .loop
    //
    //   not r/m64: REX.W|B + 0xF7 + ModRM(/2)
    //   For `not r14`: REX = 0x49, opcode 0xF7,
    //   ModRM(mod=11 reg=010 rm=r14&7=110) = 11 010 110 = 0xD6
    //
    // x86 `not` does NOT touch rflags — this handler deliberately
    // does NOT save to rcx, matching real hardware semantics. `not_r`
    // lifts pair this with `iret_noflag` to keep the inner-VM round
    // trip flag-transparent, exactly like V0 `not_r`.
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHInotR14);
    e.u8(0x49); e.u8(0xF7); e.u8(0xD6);
    emit_jmp_loop_rel8(e, kOffHInotR14 + 5);

    // ------------------------------------------------------------------
    // [+92] H_ineg_r14: neg r14; pushfq; pop rcx; jmp .loop
    //
    //   neg r/m64: REX.W|B + 0xF7 + ModRM(/3)
    //   For `neg r14`: REX = 0x49, opcode 0xF7,
    //   ModRM(mod=11 reg=011 rm=r14&7=110) = 11 011 110 = 0xDE
    //
    // Unlike `not`, x86 `neg` DOES set rflags (CF=(operand != 0),
    // plus SF/ZF/OF/PF from the result). `neg_r` lifts pair this
    // with the regular `iret` so the saved rcx value is the one
    // the outer tail dispatch writes to vflags.
    // ------------------------------------------------------------------
    assert(e.size() - blob_base == kOffHInegR14);
    e.u8(0x49); e.u8(0xF7); e.u8(0xDE);
    e.u8(0x9C);                                         // pushfq
    e.u8(0x59);                                         // pop rcx
    emit_jmp_loop_rel8(e, kOffHInegR14 + 7);

    assert(e.size() - blob_base == kOffHandlersEnd);

    // ------------------------------------------------------------------
    // [+87] 1 byte padding so the int32 handler table lands 4-aligned.
    // ------------------------------------------------------------------
    e.u8(0xCC);
    assert(e.size() - blob_base == kOffPaddingEnd);

    // ------------------------------------------------------------------
    // [+100] Handler table: 13 × signed int32 offsets, each stored as
    // `handler_offset - kOffHandlerTable`, so the dispatcher's
    // `movsxd rax, eax; add rax, r13` yields the absolute handler
    // address. Indices MUST match InnerVmOp enum values.
    // ------------------------------------------------------------------
    constexpr int32_t kTableEntries[13] = {
        static_cast<int32_t>(kOffHIloadSrc)       - static_cast<int32_t>(kOffHandlerTable),  // 0x00
        static_cast<int32_t>(kOffHIloadDst)       - static_cast<int32_t>(kOffHandlerTable),  // 0x01
        static_cast<int32_t>(kOffHIstoreDst)      - static_cast<int32_t>(kOffHandlerTable),  // 0x02
        static_cast<int32_t>(kOffHIaddRr)         - static_cast<int32_t>(kOffHandlerTable),  // 0x03
        static_cast<int32_t>(kOffHIsubRr)         - static_cast<int32_t>(kOffHandlerTable),  // 0x04
        static_cast<int32_t>(kOffHIxorRr)         - static_cast<int32_t>(kOffHandlerTable),  // 0x05
        static_cast<int32_t>(kOffHIandRr)         - static_cast<int32_t>(kOffHandlerTable),  // 0x06
        static_cast<int32_t>(kOffHIorRr)          - static_cast<int32_t>(kOffHandlerTable),  // 0x07
        static_cast<int32_t>(kOffHIret)           - static_cast<int32_t>(kOffHandlerTable),  // 0x08
        static_cast<int32_t>(kOffHIloadSrcAccum)  - static_cast<int32_t>(kOffHandlerTable),  // 0x09
        static_cast<int32_t>(kOffHIretNoFlag)     - static_cast<int32_t>(kOffHandlerTable),  // 0x0A
        static_cast<int32_t>(kOffHInotR14)        - static_cast<int32_t>(kOffHandlerTable),  // 0x0B
        static_cast<int32_t>(kOffHInegR14)        - static_cast<int32_t>(kOffHandlerTable),  // 0x0C
    };
    static_assert(kTableEntries[0]  == -72, "iload_src table entry");
    static_assert(kTableEntries[8]  == -22, "iret table entry");
    static_assert(kTableEntries[9]  == -19, "iload_src_accum table entry");
    static_assert(kTableEntries[10] == -14, "iret_noflag table entry");
    static_assert(kTableEntries[11] == -13, "inot_r14 table entry");
    static_assert(kTableEntries[12] == -8,  "ineg_r14 table entry");
    for (int32_t entry : kTableEntries) {
        e.u32(static_cast<uint32_t>(entry));
    }

    assert(e.size() - blob_base == kInnerVmRuntimeSize);
    return blob_base + kOffDispatcherStart;  // entry point offset
}

} // namespace mx::vm::x64
