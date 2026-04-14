/**
 * @file x64_inner_vm.hpp
 * @brief [BUILDER, x64] Inner VM runtime — nested dispatch layer under the main VM.
 *
 * G2 (nested VM) extended scope. The outer VM's r-r ALU handlers
 * (`add_rr`, `sub_rr`, `xor_rr`, and soon `and_rr`/`or_rr`/`mov_rr`)
 * can be emitted in a "nested" variant whose body hands the
 * arithmetic off to a second, tiny threaded-code interpreter
 * instead of executing the op as a straight x64 sequence. The inner
 * VM has its own instruction set, its own dispatcher, its own
 * handler table, and its own register convention — completely
 * independent of the outer VM. A reverser who has already cracked
 * the outer dispatch now sees outer-handler bodies whose tail is
 * `call inner_vm_entry; <tail dispatch>` and has to crack a second
 * dispatch layer before reading any guest arithmetic.
 *
 * ## ISA
 *
 * Multi-step threaded interpreter. Handlers share the host register
 * context with the outer handler that invoked them:
 *
 *   `rsi`  — dst slot address                      (set by outer)
 *   `rdi`  — src slot address                      (set by outer)
 *   `r11`  — OUTER VPC                             (never touch)
 *   `r12`  — inner VPC                             (advanced by dispatch loop)
 *   `r13`  — inner handler-table pointer           (rip-relative LEA)
 *   `r14`  — inner "accumulator"                   (holds dst, then result)
 *   `r15`  — inner "rhs operand"                   (holds src value)
 *   `rcx`  — flag-save register                    (holds saved rflags)
 *   `rax`  — dispatcher scratch                    (clobbered every step)
 *   flags  — must hold guest-ALU result on return via `iret`
 *
 * The r14/r15 split (accumulator/rhs) matters for non-commutative
 * ops. `sub r14, r15` = r14 - r15 = dst - src, which matches the
 * outer VM's `sub_rr` semantics `[dst] -= [src]`. For commutative
 * ops (add/xor/and/or) the split is irrelevant but we keep the
 * convention for consistency.
 *
 * r14/r15 are chosen explicitly — `rax` CANNOT be used to hold inner
 * values across dispatch steps because the dispatch loop clobbers it
 * on every iteration (opcode fetch → table index → handler address).
 * An earlier first-pass bug used `rax` for the inner src and ended up
 * adding the handler address into the destination slot. See commit
 * history for the 48-bit-pointer fiasco; see the `### Уроки` section
 * of G2 in ROADMAP.md for the full trap list.
 *
 * Opcodes (1 byte each, zero operands):
 *
 *   0x00 iload_src         r15 <- [rdi]                   ; rhs = src
 *   0x01 iload_dst         r14 <- [rsi]                   ; accum = dst
 *   0x02 istore_dst        [rsi] <- r14                   ; dst = accum
 *   0x03 iadd_rr           r14 <- r14 + r15;  rcx <- rflags
 *   0x04 isub_rr           r14 <- r14 - r15;  rcx <- rflags
 *   0x05 ixor_rr           r14 <- r14 ^ r15;  rcx <- rflags
 *   0x06 iand_rr           r14 <- r14 & r15;  rcx <- rflags
 *   0x07 ior_rr            r14 <- r14 | r15;  rcx <- rflags
 *   0x08 iret              rflags <- rcx;  ret to outer handler
 *   0x09 iload_src_accum   r14 <- [rdi]    ; src goes straight into accum
 *   0x0A iret_noflag       ret (rflags untouched)
 *   0x0B inot_r14          r14 <- ~r14     (rflags untouched)
 *   0x0C ineg_r14          r14 <- -r14;  rcx <- rflags
 *   0x0D itake_branch      r11 <- r11 + r15  (advance outer VPC; for vjcc V2)
 *
 * ## Flag propagation (scheme 2 — flag live in host reg rcx)
 *
 * Every ALU opcode that produces guest flags saves `rflags` into
 * `rcx` via `pushfq; pop rcx`. The dispatch loop between ALU and
 * `iret` clobbers `rflags` freely — it doesn't matter, because the
 * last ALU to run has already stashed the correct flags in `rcx`,
 * and the dispatch loop never touches `rcx`. `iret` restores
 * `rflags` via `push rcx; popfq; ret`, and `ret` preserves `rflags`
 * so the outer handler's tail dispatch sees them in its
 * `emit_vflags_store`.
 *
 * Why `rcx` in particular:
 *   1. It is the first host-reg emit_vmreg_addr_rsi_from_rcx
 *      consumes (`shl rcx, 3; lea rsi, [rsp+rcx*1]`) and is not
 *      read by anything the outer handler does BETWEEN `lea rsi`
 *      and the `call rel32 inner_vm_entry`. So the inner VM is free
 *      to clobber it from that point on.
 *   2. The outer handler's tail dispatch after the inner VM call
 *      re-fetches everything from memory; it never relies on `rcx`
 *      carrying any specific value.
 *   3. The dispatch loop uses only `rax` as scratch, never `rcx`,
 *      so `rcx` survives every dispatch step untouched.
 *
 * This replaces the original terminal-producer scheme (used by the
 * initial 4-opcode G2 iteration), which did the ALU op directly
 * against `[rsi]` and returned immediately to preserve flags. That
 * approach is limited to 1-ALU bytecodes; the rcx-live scheme
 * handles arbitrary-length inner programs with at most one guest-ALU
 * result at a time. (An earlier attempt tried to stash flags in an
 * 8-byte slot at the end of this runtime block, but the .mxvm
 * section is R+X without W, so `pop qword [r13+disp]` faulted on
 * first use — see commit history for the debug trail.)
 *
 * **Rule for the lifter**: the LAST flag-producing ALU in the inner
 * bytecode must be the one that leaves the desired guest flags in
 * `rcx`. Since every ALU writes `rcx`, this is satisfied by the
 * natural `[...; i{alu}_rr; istore_dst; iret]` pattern — store/ret
 * don't touch `rcx`.
 *
 * ## Lifted bytecodes
 *
 *   add_rr  → [iload_src, iload_dst, iadd_rr, istore_dst, iret]  (5 bytes)
 *   sub_rr  → [iload_src, iload_dst, isub_rr, istore_dst, iret]
 *   xor_rr  → [iload_src, iload_dst, ixor_rr, istore_dst, iret]
 *   and_rr  → [iload_src, iload_dst, iand_rr, istore_dst, iret]
 *   or_rr   → [iload_src, iload_dst, ior_rr,  istore_dst, iret]
 *   mov_rr  → [iload_src_accum, istore_dst, iret_noflag]         (3 bytes)
 *   not_r   → [iload_dst, inot_r14, istore_dst, iret_noflag]     (4 bytes)
 *   neg_r   → [iload_dst, ineg_r14, istore_dst, iret]            (4 bytes)
 *   vjcc    → [itake_branch, iret_noflag]                        (2 bytes, taken path only)
 *
 * `mov_rr` and `not_r` use `iret_noflag` because both are
 * flag-transparent on real x86 (`mov` and `not` do not touch
 * rflags). `neg_r` DOES set rflags on real x86, so it uses the
 * regular `iret` which restores the ALU's saved flags from `rcx`.
 *
 * `vjcc` is unusual: the outer wrapper still performs the native
 * condition test in x64, then conditionally calls into the inner
 * VM only on the taken path. The inner bytecode just does
 * `add r11, r15; ret` — advancing the outer VPC by the pre-loaded
 * `r15 = rel32` offset. `iret_noflag` keeps the outer vflags
 * untouched (the cc test itself clobbered them, but the next tail
 * dispatch saves the post-test flags anyway, which is what V0 does
 * as well).
 *
 * ## Runtime shape
 *
 * `emit_inner_vm_runtime` produces a self-contained 160-byte block:
 *
 *   +0   dispatcher:
 *          lea r13, [rip + handler_table_disp32]   (7 bytes)
 *        .loop:
 *          movzx eax, byte [r12]                   (5)
 *          inc   r12                                (3)
 *          mov   eax, [r13 + rax*4 + 0]             (5)
 *          movsxd rax, eax                          (3)
 *          add   rax, r13                           (3)
 *          jmp   rax                                (2)
 *
 *   +28  H_iload_src        : mov r15, [rdi];           jmp .loop  (5)
 *   +33  H_iload_dst        : mov r14, [rsi];           jmp .loop  (5)
 *   +38  H_istore_dst       : mov [rsi], r14;           jmp .loop  (5)
 *   +43  H_iadd_rr          : add r14, r15; save→rcx;   jmp .loop  (7)
 *   +50  H_isub_rr          : sub r14, r15; save→rcx;   jmp .loop  (7)
 *   +57  H_ixor_rr          : xor r14, r15; save→rcx;   jmp .loop  (7)
 *   +64  H_iand_rr          : and r14, r15; save→rcx;   jmp .loop  (7)
 *   +71  H_ior_rr           : or  r14, r15; save→rcx;   jmp .loop  (7)
 *   +78  H_iret             : push rcx; popfq;          ret        (3)
 *   +81  H_iload_src_accum  : mov r14, [rdi];           jmp .loop  (5)
 *   +86  H_iret_noflag      : ret                                  (1)
 *   +87  H_inot_r14         : not r14;                  jmp .loop  (5)
 *   +92  H_ineg_r14         : neg r14; save→rcx;        jmp .loop  (7)
 *   +99  H_itake_branch     : add r11, r15;             jmp .loop  (5)
 *   +104 handler_table : 14 × int32 (handler_off - table_off)     (56)
 *   +160 end
 *
 * Flag save/restore byte-level:
 *
 *   ALU tail (4 bytes): pushfq  (9C)
 *                       pop rcx (59)
 *                       jmp .loop (EB rel8)
 *   iret body (3 bytes): push rcx (51)
 *                        popfq    (9D)
 *                        ret      (C3)
 *
 * Every intra-runtime jump is a short rel8 back to `.loop`, and the
 * LEA is rip-relative — the block remains position-independent with
 * zero external patches beyond the outer-handler `call rel32
 * inner_vm_entry` slots that the backend collects and fixes up
 * after runtime emit.
 *
 * Note: the runtime lives in the .mxvm code section which is R+X
 * (no write permission). That's why the rflags scratch has to be a
 * host register, not a memory slot inside the runtime block.
 *
 * ## Callee ABI
 *
 * Entry: the outer handler must have set up
 *   - `rsi` = dst slot address
 *   - `rdi` = src slot address
 *   - `r12` = pointer to the inner bytecode (exactly 5 bytes, ending
 *             with `iret`)
 * and called `inner_vm_entry` via a plain `call rel32` (so the
 * terminal `iret`'s `ret` pops the return address cleanly and
 * execution resumes at the outer handler's tail dispatch).
 *
 * The inner VM is allowed to clobber `rax`, `rcx`, `rdx`, `r12`,
 * `r13`, `r14`, `r15`, and `rflags`. On return via `iret`, `rflags`
 * matches what a direct V0 `add/sub/xor/and/or r/m64, r64` would
 * have produced (the guest ALU result). The outer handler's tail
 * dispatch saves those flags into `vflags`, so downstream `vjcc`
 * handlers see the correct guest condition codes.
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstddef>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::vm::x64 {

/// Inner VM opcodes. See file header for semantics.
///
/// The values below are the **identity** (canonical) opcode bytes —
/// the ones a fresh build uses by default. Per-build randomization
/// permutes them into `InnerVmIsa::to_byte` (see below), so the byte
/// `0x03` a wrapper emits in one build may be `0x07` in another. The
/// enum values are stable across builds; the byte values are not.
///
/// When indexing into arrays sized by `kInnerVmOpCount`, cast the
/// enum value to `uint8_t` directly — it doubles as the "logical
/// index" and never changes.
enum class InnerVmOp : uint8_t {
    iload_src       = 0x00,  ///< r15 <- [rdi]        (rhs = src)
    iload_dst       = 0x01,  ///< r14 <- [rsi]        (accum = dst)
    istore_dst      = 0x02,  ///< [rsi] <- r14
    iadd_rr         = 0x03,  ///< r14 <- r14 + r15; rcx <- rflags
    isub_rr         = 0x04,  ///< r14 <- r14 - r15; rcx <- rflags
    ixor_rr         = 0x05,  ///< r14 <- r14 ^ r15; rcx <- rflags
    iand_rr         = 0x06,  ///< r14 <- r14 & r15; rcx <- rflags
    ior_rr          = 0x07,  ///< r14 <- r14 | r15; rcx <- rflags
    iret            = 0x08,  ///< rflags <- rcx; ret
    iload_src_accum = 0x09,  ///< r14 <- [rdi]        (for flag-transparent mov)
    iret_noflag     = 0x0A,  ///< ret (rflags untouched)
    inot_r14        = 0x0B,  ///< r14 <- ~r14         (rflags untouched; x86 `not` is flag-transparent)
    ineg_r14        = 0x0C,  ///< r14 <- -r14;  rcx <- rflags
    itake_branch    = 0x0D,  ///< r11 <- r11 + r15    (vjcc taken path: advance outer VPC by rel32)
};

/// Total number of defined `InnerVmOp` values. Handler table size
/// and `InnerVmIsa::to_byte` length both derive from this.
inline constexpr size_t kInnerVmOpCount = 14;

/// Per-build permutation of inner VM opcode byte values.
///
/// Two builds of the same input produce two different `InnerVmIsa`
/// instances, and their inner bytecodes therefore look completely
/// different at the byte level — even though the logical meaning
/// (`iload_src`, `iadd_rr`, `iret`, ...) is the same. A reverser
/// who has reverse-engineered build A's opcode-to-semantic map
/// cannot reuse that map on build B without starting over.
///
/// `to_byte[static_cast<uint8_t>(InnerVmOp::foo)]` is the byte
/// value the wrapper must emit in the inline bytecode for `foo`,
/// and the corresponding handler table slot (at position =
/// that byte) points at `foo`'s handler body.
///
/// The identity permutation — where `to_byte[i] == i` — reproduces
/// the canonical, fully-predictable runtime. Unit tests use it;
/// production always uses a random instance.
struct InnerVmIsa {
    std::array<uint8_t, kInnerVmOpCount> to_byte{};

    /// Look up the byte value assigned to a logical opcode.
    [[nodiscard]] constexpr uint8_t byte_of(InnerVmOp op) const noexcept {
        return to_byte[static_cast<uint8_t>(op)];
    }
};

/// Identity ISA — `to_byte[i] == i` for every opcode. Useful for
/// deterministic tests and as the reference layout documented in
/// `x64_inner_vm.cpp`'s hand-assembled runtime comments.
[[nodiscard]] InnerVmIsa make_identity_inner_vm_isa() noexcept;

/// Random ISA — Fisher–Yates shuffle of the identity permutation
/// using `rng`. Every production build calls this exactly once per
/// VM blob and threads the result through `emit_inner_vm_runtime`
/// and every `emit_handler_*_nested` wrapper.
[[nodiscard]] InnerVmIsa make_random_inner_vm_isa(Randomizer& rng);

/// Size of the emitted inner VM runtime, in bytes.
///
/// Breakdown:
///   28 bytes dispatcher (lea r13 + fetch/decode/dispatch loop)
///   76 bytes handler bodies (5+5+5+5*7+3+5+1+5+7+5)
///    0 bytes padding (handlers end at +104, already 4-aligned)
///   56 bytes handler table (14 × int32 relative offsets)
inline constexpr size_t kInnerVmRuntimeSize = 160;

/// Emit the inner VM runtime (dispatcher + 13 handlers + handler
/// table) into `e`. Returns the offset of the dispatcher entry
/// point relative to the start of the emitted bytes — callers add
/// this to their absolute blob offset to get the inner VM entry's
/// in-blob address for rel32 patching.
///
/// `isa` controls which byte value the handler table entry uses for
/// each logical opcode. Physical handler body offsets are fixed and
/// do not depend on `isa` — only the table entry ordering does. An
/// identity ISA reproduces the canonical byte-for-byte layout
/// documented in the `x64_inner_vm.cpp` layout comment.
///
/// The emitted runtime is position-independent: every intra-runtime
/// branch is either a short rel8 `jmp` back to the dispatch loop or
/// the rip-relative `lea r13, handler_table` at the dispatcher
/// prologue. No external patches are required beyond the outer
/// handler's `call rel32 inner_vm_entry`, which the backend fixes
/// up after this runtime is emitted.
[[nodiscard]] size_t emit_inner_vm_runtime(RawEmitter& e, const InnerVmIsa& isa);

} // namespace mx::vm::x64
