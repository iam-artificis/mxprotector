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

void emit_handler_mov_ri32(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_mov_ri64(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_alu_ri32(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t op_mr);

void emit_handler_unary(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op);
void emit_handler_shift(RawEmitter& e, int32_t key_disp, bool rolling, uint8_t sub_op);

void emit_handler_vjmp(RawEmitter& e, int32_t key_disp, bool rolling);
void emit_handler_vjcc(RawEmitter& e, int32_t key_disp, bool rolling,
                       uint8_t cc, uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp, Randomizer& rng);

} // namespace mx::vm::x64
