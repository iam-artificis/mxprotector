/**
 * @file x64_inner_vm.hpp
 * @brief [BUILDER, x64] Inner VM — nested dispatch layer under the main VM.
 *
 * G2 (nested VM). A subset of the outer VM handlers — today only the
 * register-register ALU forms of `add_rr`, `sub_rr`, and `xor_rr` —
 * can be emitted in a "nested" variant whose body hands off the
 * arithmetic to a second, tiny bytecode interpreter instead of
 * executing it as a straight sequence of x64 instructions. The inner
 * VM has its own instruction set, its own dispatcher, and its own
 * handler table, all independent of the outer VM. A reverser who has
 * already cracked the outer VM now sees outer-handler bodies whose
 * implementation is "call inner_vm_entry(bc)" and has to crack a
 * second dispatch layer before they can read the guest arithmetic.
 *
 * ## ISA
 *
 * The inner VM is a zero-operand threaded interpreter. It shares its
 * register context with the outer handler that invoked it:
 *
 *   `rsi`  — destination slot address (set by outer handler)
 *   `rdi`  — source      slot address (set by outer handler)
 *   `r14`  — "inner src register": holds the source slot value
 *            between `iload_src` and one of the terminal ALU
 *            opcodes. MUST NOT be rax/rdx/rcx — the dispatcher
 *            loop below clobbers those for its own bookkeeping
 *            (opcode fetch → table index → handler address).
 *            A past bug used `rax` and silently added the handler
 *            address to the destination slot instead of the src
 *            value — see the commit history for the 48-bit
 *            pointer fiasco.
 *   `r11`  — outer VPC (do not touch)
 *   `r12`  — inner VPC
 *   `r13`  — inner handler-table pointer
 *   flags  — must hold the guest-ALU result on return
 *
 * Opcodes (1 byte each, no operands):
 *
 *   0x00 iload_src   r14  <- [rdi];             jmp dispatcher loop
 *   0x01 iadd_exit   [rsi] <- [rsi] + r14;     ret to outer handler
 *   0x02 isub_exit   [rsi] <- [rsi] - r14;     ret to outer handler
 *   0x03 ixor_exit   [rsi] <- [rsi] ^ r14;     ret to outer handler
 *
 * There is no separate "store" or "exit" opcode. The three terminal
 * ALU opcodes do the store-in-place AND return, so the `add`'s flags
 * are the last thing to touch `rflags` before `ret`. `ret` itself
 * preserves `rflags`, and the outer handler's tail-dispatch runs
 * `emit_vflags_store` immediately afterward — so the guest's ZF/SF/
 * CF/OF/PF all end up in the outer VM's `vflags` slot unchanged.
 * This is the only way to route rflags through a nested layer
 * without either stashing them on the stack (which bloats every
 * handler) or losing them to the dispatcher's `inc r12` /
 * `add rax, r13` side effects.
 *
 * ## Lifted bytecodes
 *
 *   add_rr → [iload_src, iadd_exit]   — 2 bytes
 *   sub_rr → [iload_src, isub_exit]
 *   xor_rr → [iload_src, ixor_exit]
 *
 * Since the terminal opcode produces the final answer + flags and
 * returns directly, there is no need for a trailing sentinel byte.
 *
 * ## Runtime shape
 *
 * `emit_inner_vm_runtime` produces a self-contained 64-byte block:
 *
 *   +0  dispatcher:
 *         lea r13, [rip + handler_table_disp32]
 *       .loop:
 *         movzx eax, byte [r12]
 *         inc r12
 *         mov  eax, [r13 + rax*4]
 *         movsxd rax, eax
 *         add rax, r13
 *         jmp rax
 *
 *   +28 H_iload_src :  mov rax, [rdi]; jmp .loop
 *   +33 H_iadd_exit :  add [rsi], rax; ret
 *   +37 H_isub_exit :  sub [rsi], rax; ret
 *   +41 H_ixor_exit :  xor [rsi], rax; ret
 *   +45 padding to 4-byte alignment (3 bytes of 0xCC)
 *   +48 handler_table: 4 × int32 (handler_offset - table_offset)
 *   +64 end
 *
 * Every jmp back to the dispatch loop is a short rel8, the LEA is
 * rip-relative forward, and the handler table holds signed 32-bit
 * deltas that the dispatcher sign-extends and adds to r13. The
 * block is therefore position-independent with zero external
 * patches.
 *
 * ## Callee ABI
 *
 * Entry: the outer handler must have set up
 *   - `rsi` = dst slot address
 *   - `rdi` = src slot address
 *   - `r12` = pointer to the inner bytecode (exactly 2 bytes
 *             terminating with one of the `_exit` opcodes)
 * and called `inner_vm_entry` via a plain `call rel32` (so the
 * terminal handler's `ret` pops the return address cleanly).
 *
 * The inner VM is allowed to clobber `rax`, `rdx`, `r13`, and
 * `rflags` — but the FINAL `rflags` it leaves behind must match
 * what the outer-handler V0 body would have produced (i.e. the
 * guest ALU result), because the outer's tail dispatch saves them
 * straight to `vflags`. The byte-level layout above guarantees
 * this as long as no non-ALU instruction runs between the
 * terminal ALU op and the `ret`.
 */

#pragma once

#include <cstdint>
#include <cstddef>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::vm::x64 {

/// Inner VM opcodes. See file header for semantics.
enum class InnerVmOp : uint8_t {
    iload_src  = 0x00,  ///< rax = [rdi]; continue dispatch
    iadd_exit  = 0x01,  ///< [rsi] += rax; ret (flags = ALU result)
    isub_exit  = 0x02,  ///< [rsi] -= rax; ret
    ixor_exit  = 0x03,  ///< [rsi] ^= rax; ret
};

/// Size of the emitted inner VM runtime, in bytes.
///
/// Breakdown:
///   28 bytes dispatcher (lea r13 + fetch/decode/dispatch loop)
///   17 bytes handler bodies
///    3 bytes padding to 4-byte align the handler table
///   16 bytes handler table (4 × int32 relative offsets)
inline constexpr size_t kInnerVmRuntimeSize = 64;

/// Emit the inner VM runtime (dispatcher + 4 handlers + handler
/// table) into `e`. Returns the offset of the dispatcher entry
/// point relative to the start of the emitted bytes — callers add
/// this to their absolute blob offset to get the inner VM entry's
/// in-blob address for rel32 patching.
///
/// The emitted runtime is position-independent: every intra-
/// runtime branch is either a short rel8 `jmp` back to the
/// dispatch loop or the rip-relative `lea r13, handler_table`
/// at the dispatcher prologue. No external patches are required.
[[nodiscard]] size_t emit_inner_vm_runtime(RawEmitter& e);

} // namespace mx::vm::x64
