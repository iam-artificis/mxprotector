/**
 * @file x64_inner_vm_wrappers.hpp
 * @brief [BUILDER, x64] Outer-handler bodies that dispatch into the G2 inner VM.
 *
 * Each "nested" variant of an outer handler is emitted by one of the
 * functions declared here. The shape is always the same:
 *
 *   1. Fetch this handler's operand bytes from the outer bytecode
 *      stream (via `emit_fetch_*`, see `x64_handlers.hpp`).
 *   2. Compute `rsi` / `rdi` as pointers to the dst / src slot on the
 *      outer VM's stack frame (via `emit_vmreg_addr_*`).
 *   3. Invoke the inner VM runtime with a fixed, inlined inner
 *      bytecode describing the operation to perform. This is the
 *      part these wrappers own.
 *
 * Step 3 is factored into `emit_inner_vm_call` below, which every
 * wrapper in this module calls. Adding a new nested variant (e.g. a
 * `mov_rr` lift) therefore means only picking a 1-line inner
 * bytecode sequence and reusing the operand-fetch helpers; it does
 * NOT mean re-implementing the LEA + jmp + call + patch-offset
 * dance.
 *
 * This is the open/closed point for G2: new outer handlers get a
 * small wrapper function here; the runtime (`x64_inner_vm.cpp`) and
 * the backend patch loop (`x64_vm_backend.cpp`) only need to know
 * the inner bytecode to use.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/vm/x64/x64_inner_vm.hpp"

namespace mx::vm::x64 {

/**
 * @brief Emit the shared "call into inner VM" tail.
 *
 * Layout emitted (all position-independent, no external patches
 * beyond the rel32 call site):
 *
 *   lea r12, [rip + 2]        ; 7 bytes — r12 ← start of inline bytecode
 *   jmp  +N                   ; 2 bytes — skip over the inline bytecode
 *   <bytecode ... >           ; N bytes — inline inner VM program
 *   call rel32 inner_vm_entry ; 5 bytes — rel32 patched by backend
 *
 * `bytecode` is a sequence of **logical** inner VM opcodes (as
 * `InnerVmOp` values). Each one is translated through `isa.to_byte`
 * before being emitted, so the byte that actually lands in the
 * blob depends on the current build's ISA permutation. This is the
 * single place where the logical-to-byte translation happens —
 * every nested wrapper calls this instead of emitting raw bytes.
 *
 * @param e
 *   RawEmitter to append to.
 * @param isa
 *   Active inner-VM ISA permutation for this build.
 * @param bytecode
 *   Pointer to the logical inner VM bytecode. Caller is responsible
 *   for the terminating `iret` / `iret_noflag` opcode.
 * @param bytecode_len
 *   Number of opcodes (== emitted bytes) in `bytecode`. Must fit in
 *   a short rel8 jump (≤ 127 — in practice we stay well under 16).
 * @param call_rel32_patch_out
 *   Receives the absolute in-blob offset of the rel32 operand of
 *   the `call` instruction. The backend uses this offset to patch
 *   the rel32 after `emit_inner_vm_runtime` has been called and
 *   the inner VM entry offset is known.
 */
void emit_inner_vm_call(RawEmitter& e,
                        const InnerVmIsa& isa,
                        const InnerVmOp* bytecode,
                        size_t bytecode_len,
                        size_t& call_rel32_patch_out);

// ---------------------------------------------------------------------------
// Nested variants of individual outer handlers.
// ---------------------------------------------------------------------------
//
// Every function here fetches its operands, computes slot addresses,
// and emits an inline inner bytecode followed by `call rel32
// inner_vm_entry`. The `call_rel32_patch_out` parameter is the offset
// the backend must fix up once the inner VM runtime's entry offset
// is known (the inner VM block is emitted AFTER all outer handlers).

// ---------------------------------------------------------------------------
// Nested wrappers. Every function takes the active `InnerVmIsa`
// permutation for the current build; the wrappers use it when
// emitting the inline inner bytecode so the actual bytes that
// hit the blob are build-specific.
// ---------------------------------------------------------------------------

/**
 * @brief `add_rr` / `sub_rr` / `xor_rr` / `and_rr` / `or_rr` nested V2.
 *
 * Logical inline bytecode (5 opcodes):
 *   [iload_src, iload_dst, alu_inner_op, istore_dst, iret]
 *
 * @param alu_inner_op
 *   One of `InnerVmOp::iadd_rr` / `isub_rr` / `ixor_rr` / `iand_rr`
 *   / `ior_rr`.
 */
void emit_handler_alu_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, const InnerVmIsa& isa,
                                InnerVmOp alu_inner_op,
                                size_t& call_rel32_patch_out);

/**
 * @brief `mov_rr` nested V2.
 *
 * Logical inline bytecode (3 opcodes):
 *   [iload_src_accum, istore_dst, iret_noflag]
 *
 * `iload_src_accum` loads `[rdi]` directly into r14 (the
 * accumulator), which is what `istore_dst` subsequently writes to
 * `[rsi]`. `iret_noflag` matches V0 `mov_rr`'s flag-transparent
 * behavior — x86 `mov` does not touch rflags.
 */
void emit_handler_mov_rr_nested(RawEmitter& e, int32_t key_disp,
                                bool rolling, const InnerVmIsa& isa,
                                size_t& call_rel32_patch_out);

/**
 * @brief `not_r` nested V2.
 *
 * Logical inline bytecode (4 opcodes):
 *   [iload_dst, inot_r14, istore_dst, iret_noflag]
 *
 * `inot_r14` toggles every bit of the accumulator r14. x86 `not`
 * is flag-transparent, so we pair with `iret_noflag` — final
 * rflags match V0 `not_r` (whatever the addr-compute shl produced).
 */
void emit_handler_not_r_nested(RawEmitter& e, int32_t key_disp,
                               bool rolling, const InnerVmIsa& isa,
                               size_t& call_rel32_patch_out);

/**
 * @brief `neg_r` nested V2.
 *
 * Logical inline bytecode (4 opcodes):
 *   [iload_dst, ineg_r14, istore_dst, iret]
 *
 * `ineg_r14` negates r14 and saves the resulting rflags to rcx
 * (unlike `not`, x86 `neg` is flag-producing). The terminal
 * `iret` restores those flags via `push rcx; popfq; ret` so the
 * outer tail dispatch writes correct guest flags to `vflags`.
 */
void emit_handler_neg_r_nested(RawEmitter& e, int32_t key_disp,
                               bool rolling, const InnerVmIsa& isa,
                               size_t& call_rel32_patch_out);

/**
 * @brief `add_ri32` / `sub_ri32` / `xor_ri32` / `and_ri32` / `or_ri32`
 *        nested V2.
 *
 * Semantics: `[dst] <op>= sign_extend(imm32)`. Outer wrapper uses
 * `emit_fetch_dword` to decrypt the imm32 into `eax`, then does
 * `movsxd r15, eax` to preload the inner VM's "rhs operand"
 * register. Inner bytecode reuses the regular r-r ALU handlers
 * without any imm-loading opcode.
 *
 * Logical inline bytecode (4 opcodes):
 *   [iload_dst, alu_inner_op, istore_dst, iret]
 *
 * @param alu_inner_op
 *   One of `InnerVmOp::iadd_rr` / `isub_rr` / `ixor_rr` / `iand_rr`
 *   / `ior_rr`.
 */
void emit_handler_alu_ri32_nested(RawEmitter& e, int32_t key_disp,
                                  bool rolling, const InnerVmIsa& isa,
                                  InnerVmOp alu_inner_op,
                                  size_t& call_rel32_patch_out);

/**
 * @brief `mov_ri32` nested V2.
 *
 * Semantics: `[dst] = sign_extend(imm32)`. x86 `mov` is
 * flag-transparent, so the inner bytecode terminates with
 * `iret_noflag`.
 *
 * Approach: outer wrapper decrypts imm32 into `eax`, does `movsxd
 * r14, eax` to place the value directly into the accumulator, and
 * the inner bytecode just stores + returns.
 *
 * Logical inline bytecode (2 opcodes):
 *   [istore_dst, iret_noflag]
 */
void emit_handler_mov_ri32_nested(RawEmitter& e, int32_t key_disp,
                                  bool rolling, const InnerVmIsa& isa,
                                  size_t& call_rel32_patch_out);

} // namespace mx::vm::x64
