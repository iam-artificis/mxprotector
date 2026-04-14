/**
 * @file x64_handlers.hpp
 * @brief [BUILDER, x64] Handler bodies, fetch helpers and tail dispatch.
 *
 * Each VM opcode (`add_rr`, `mov_ri32`, `vjcc`, ...) maps to one or
 * more `emit_handler_*` functions in this header that emit the body
 * of a single handler. Bodies share three building blocks:
 *
 *   - **rolling-key fetch helpers** (`emit_fetch_*`) that read 1, 4 or
 *     8 bytes from the bytecode stream while updating the rolling key;
 *
 *   - **vmreg address helpers** (`emit_vmreg_addr_*`) that turn a
 *     fetched slot index into an absolute pointer into the VM stack
 *     context;
 *
 *   - **`emit_tail_dispatch`** appended at the end of every handler
 *     to fetch the next opcode, decrypt it via the encrypted handler
 *     table, and indirect-branch.
 *
 * `pick_table_base_reg`, `pick_dispatch_shape`, `pick_*_variant` are
 * the per-build polymorphism dials that drive how each handler ends.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::vm::x64 {

// Forward-declared here so `emit_handler_vjcc` can take an optional
// `const InnerVmIsa*` without pulling `x64_inner_vm.hpp` into every
// translation unit that only emits non-nested handler bodies.
struct InnerVmIsa;

// ----------------------------------------------------------------------------
// Bytecode fetch helpers
// ----------------------------------------------------------------------------

/// Fetch one byte into `dst_reg` (0..3 — rax/rcx/rdx/rbx), decrypt with
/// the rolling key. When `rolling` is true the key byte is updated
/// after decryption (stream cipher); when false the key stays constant
/// (used in regions containing virtual branches).
void emit_fetch_byte(RawEmitter& e, uint8_t dst_reg, int32_t key_disp,
                     bool rolling = true);

void emit_fetch_dword(RawEmitter& e, int32_t key_disp, bool rolling = true);
void emit_fetch_qword(RawEmitter& e, int32_t key_disp, bool rolling = true);

/// Fetch two operand bytes: cl = dst_idx, dl = src_idx (each masked 0x0F).
void emit_fetch_2_operand_bytes(RawEmitter& e, int32_t key_disp, bool rolling = true);

/// Fetch one operand byte: cl = dst_idx (masked).
void emit_fetch_1_operand_byte(RawEmitter& e, int32_t key_disp, bool rolling = true);

// ----------------------------------------------------------------------------
// VM-reg address helpers
// ----------------------------------------------------------------------------

/// `rsi = rsp + rcx * 8` — address of `ctx[reg_idx]`.
void emit_vmreg_addr_rsi_from_rcx(RawEmitter& e);

/// `rdi = rsp + rdx * 8` — address of `ctx[reg_idx]`.
void emit_vmreg_addr_rdi_from_rdx(RawEmitter& e);

// ----------------------------------------------------------------------------
// Junk / dispatch polymorphism
// ----------------------------------------------------------------------------

/// Emit a random junk prologue of 0..max_bytes NOPs at the current
/// position. Each handler entry uses one to break signature matches
/// on the handler prologue.
void emit_junk_prologue(RawEmitter& e, Randomizer& rng, uint32_t max_bytes = 8);

/// Indirect-branch shape used by the tail dispatch.
enum class DispatchShape : uint8_t {
    JmpReg     = 0,   ///< jmp <table_base>
    PushRegRet = 1,   ///< push <table_base>; ret
    kCount     = 2
};

[[nodiscard]] DispatchShape pick_dispatch_shape(Randomizer& rng);

/// Pick a GPR to use as the table base in the tail dispatch. Excludes
/// rax (holds the decrypted opcode) and r11 (vpc).
[[nodiscard]] uint8_t pick_table_base_reg(Randomizer& rng);

// ----------------------------------------------------------------------------
// Tail dispatch
// ----------------------------------------------------------------------------

struct TailDispatchPatch {
    size_t rel32_offset;     ///< offset of the rel32 inside `lea reg, [rip+rel32]`
    size_t instruction_end;  ///< byte just after the rel32
};

/// Emit the tail dispatch stub. Returns the rel32 patch the caller
/// must fix up once the handler-table offset is known.
///
/// `imagebase_key_disp >= 0` selects the ImageBase-derived key path:
/// the decrypt step reads the table key from `[rsp + imagebase_key_disp]`
/// instead of carrying it as an imm32, so the literal key never appears
/// anywhere in the VM blob.
TailDispatchPatch emit_tail_dispatch(RawEmitter& e, int32_t key_disp,
                                     bool rolling,
                                     bool save_rflags,
                                     std::vector<size_t>& table_key_patches,
                                     uint32_t vflags_key,
                                     uint32_t vflags_rol,
                                     int32_t rflags_disp,
                                     Randomizer* rng,
                                     int32_t imagebase_key_disp = -1);

// ----------------------------------------------------------------------------
// Handler bodies
// ----------------------------------------------------------------------------

void emit_handler_mov_rr(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_alu_rr(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr);
void emit_handler_add_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_sub_rr_neg(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_xor_rr_mba(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_imul_rr(RawEmitter& e, int32_t key_disp, bool rolling);

// ---- G4 handler-id polymorphism: alternative variants ----
//
// Each of these produces the exact same VM-observable effect as the
// corresponding `mov_rr` / `and_rr` / `or_rr` / `not_r` / `neg_r`
// handler, but with a different x64 byte sequence. The backend picks
// one variant per bytecode instruction at encoding time, so two
// consecutive `and_rr` ops can be served by two unrelated-looking
// handler bodies with different opcodes, register use, and lengths.
// A reverser can no longer recover the guest opcode table by matching
// one "canonical" body to one VmOp.

/// `mov_rr` V1: `push qword [src]; pop qword [dst]`.
/// Same net effect as V0's `mov rax, [src]; mov [dst], rax`, but uses
/// stack-micro-ops and leaves no trace in a scratch register.
void emit_handler_mov_rr_pushpop(RawEmitter& e, int32_t key_disp, bool rolling);

/// `and_rr` V1: De Morgan's law — `x & y ≡ ~(~x | ~y)`.
/// Materialises the operands into rax/rdx, negates both, OR's them,
/// negates the result, and stores. 10 bytes of ALU vs. V0's 3-byte
/// direct `and`, and touches a completely different set of opcodes.
void emit_handler_and_rr_demorgan(RawEmitter& e, int32_t key_disp, bool rolling);

/// `or_rr` V1: De Morgan's law — `x | y ≡ ~(~x & ~y)`.
/// Mirror of the AND variant above.
void emit_handler_or_rr_demorgan(RawEmitter& e, int32_t key_disp, bool rolling);

/// `not_r` V1: `xor qword [slot], -1`.
/// Same bitwise result as V0's `not [slot]` but encodes as an XOR
/// against an imm32 of `0xFFFFFFFF` (sign-extended), producing a
/// visibly different instruction.
void emit_handler_not_r_xor(RawEmitter& e, int32_t key_disp, bool rolling);

/// `neg_r` V1: two's-complement identity — `-x ≡ ~x + 1`.
/// Encoded as `not [slot]; inc qword [slot]`, so the trace looks like
/// a NOT+INC pair instead of the atomic NEG of V0.
void emit_handler_neg_r_notinc(RawEmitter& e, int32_t key_disp, bool rolling);

// G2 nested-VM wrappers (emit_handler_*_nested) have moved to
// `x64_inner_vm_wrappers.hpp`. Include that header instead if you
// need to emit an outer-handler variant that dispatches through the
// inner VM.

void emit_handler_mov_ri32(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_mov_ri64(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_alu_ri32(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr);

void emit_handler_unary(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op);
void emit_handler_shift(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op);

void emit_handler_vjmp(RawEmitter& e, int32_t key_disp, bool rolling);

/// VJCC handler emit.
///
/// If `isa` is non-null, the taken-path body is emitted as a nested-
/// VM call (`mov r15, rax; lea r12; jmp; bc; call rel32 inner_vm_entry`)
/// instead of the direct `add r11, rax`. `inner_vm_call_patch_out`
/// then receives the in-blob offset of the rel32 operand of that
/// `call` instruction so the backend can fix it up once the inner VM
/// runtime's entry offset is known. Passing `isa == nullptr` keeps
/// the V0 direct form (no patch needed, `inner_vm_call_patch_out`
/// is ignored).
void emit_handler_vjcc(RawEmitter& e, int32_t key_disp, bool rolling,
                       uint8_t cc, uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp, Randomizer& rng,
                       const InnerVmIsa* isa = nullptr,
                       size_t* inner_vm_call_patch_out = nullptr);

// ----------------------------------------------------------------------------
// Specialized handlers (G1 — Virtual CPU per-build handler specialisation)
//
// A specialised handler hard-codes a specific (op, dst_vreg, src_vreg) tuple
// at emit time. The bytecode for an instruction that matches such a tuple
// then carries ONLY the handler_id (1 byte) — no operand bytes. This:
//
//   * shrinks the bytecode for matching instructions from 3 bytes to 1;
//   * makes the bytecode VARIABLE-LENGTH per instruction, so a static
//     disassembler that assumes a fixed 1+operand_size encoding cannot
//     even tell where the next instruction starts;
//   * adds K extra distinct handler bodies per build, each with its own
//     hard-coded `[rsp + slot*8]` disps — different from the generic
//     handler's `shl/lea/[rsi]` operand-fetch shape.
//
// Specialised handlers always use disp8 (slot disps ≤ 120). They never
// touch the rolling-key slot because the `Specialization` generator
// excludes the per-region junk slot.
// ----------------------------------------------------------------------------

/// Specialised mov_rr: emit
///     mov rax, [rsp + src_disp]
///     mov [rsp + dst_disp], rax
/// Both displacements MUST fit in disp8 (caller ensures slot ≤ 15).
void emit_handler_mov_rr_specialized(RawEmitter& e,
                                     uint8_t dst_disp, uint8_t src_disp);

/// Specialised r-r ALU: emit
///     mov rax, [rsp + src_disp]
///     OP  [rsp + dst_disp], rax
/// where `op_mr` is the ALU r/m, r opcode byte (add=01, sub=29, xor=31,
/// and=21, or=09).
void emit_handler_alu_rr_specialized(RawEmitter& e, uint8_t op_mr,
                                     uint8_t dst_disp, uint8_t src_disp);

} // namespace mx::vm::x64
