/**
 * @file x64_emitters.hpp
 * @brief [BUILDER, x64] Atomic byte-level encoders for the VM runtime.
 *
 * The x64 backend is built from many tiny instruction-encoder helpers
 * — `emit_push_reg`, `emit_lea_reg_rip_rel32`, etc. — each of which
 * appends a single x86-64 instruction (or a small fixed group) to a
 * `RawEmitter`. They are deliberately simple: no label resolution, no
 * higher-level abstractions, no operand parsing. Higher-level
 * mechanics (vEFLAGS, handler dispatch, handler bodies) compose them.
 *
 * Lives under `mxprotector/protection/vm/x64/` so a future Arm64
 * backend can sit alongside in `arm64/` without colliding. All
 * symbols are in `mx::vm::x64` namespace.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::vm::x64 {

// --- Memory / scratch encoders ------------------------------------------

/// `movzx r32, byte ptr [base + disp]` — load 1 byte zero-extended.
void emit_movzx_r32_byte_mem(RawEmitter& e, uint8_t dst_reg,
                              uint8_t base_reg, int32_t disp);

/// `xor reg8_low, byte ptr [rsp + disp]` — 1-byte XOR with stack slot.
void emit_xor_r8l_rsp_disp(RawEmitter& e, uint8_t reg, int32_t disp);

/// `xor byte ptr [rsp + disp], reg8_low` — 1-byte XOR back into stack slot.
void emit_xor_rsp_disp_r8l(RawEmitter& e, uint8_t reg, int32_t disp);

// --- Register / control-flow encoders -----------------------------------

void emit_inc_r11(RawEmitter& e);

/// `lea r11, [rip + rel32]` — returns the file offset of the rel32
/// placeholder so the caller can patch it once the target is known.
[[nodiscard]] size_t emit_lea_r11_rip_rel32(RawEmitter& e);

/// `lea <reg>, [rip + rel32]` for any GPR 0..15.
[[nodiscard]] size_t emit_lea_reg_rip_rel32(RawEmitter& e, uint8_t reg);

void emit_ud2(RawEmitter& e);
void emit_ret(RawEmitter& e);
void emit_pushfq(RawEmitter& e);
void emit_popfq(RawEmitter& e);
void emit_push_reg(RawEmitter& e, uint8_t reg);
void emit_pop_reg(RawEmitter& e, uint8_t reg);

/// Patch a rel32 placeholder so it jumps from `instruction_end` to `target`.
void patch_rel32(ByteBuffer& buf, size_t patch_offset,
                 size_t instruction_end, size_t target_offset);

// --- Indirect-branch dispatch helpers -----------------------------------

/// `jmp <reg>` for any GPR 0..15.
void emit_jmp_reg(RawEmitter& e, uint8_t reg);

/// `mov eax, dword [base + rax*4]` for any GPR base 0..15.
void emit_mov_eax_from_base_rax4(RawEmitter& e, uint8_t base);

/// `add <base>, rax` for any GPR base 0..15.
void emit_add_base_rax(RawEmitter& e, uint8_t base);

/// Multi-byte NOP run of length `size` (1..15) using Intel canonical forms.
void emit_nop_run(RawEmitter& e, uint8_t size);

// --- Stack-relative scratch helpers (eax/rax for vEFLAGS code) ----------

void emit_mov_rsp_disp_rax(RawEmitter& e, int32_t disp);
void emit_mov_eax_rsp_disp(RawEmitter& e, int32_t disp);
void emit_xor_eax_imm32(RawEmitter& e, uint32_t imm);
void emit_rol_eax_imm8(RawEmitter& e, uint8_t imm);
void emit_ror_eax_imm8(RawEmitter& e, uint8_t imm);

/// 32-bit rotate-right by `n` (mod 32). Pure arithmetic helper; emitted
/// nowhere — used by the vEFLAGS encoders to pre-compute rotated keys.
[[nodiscard]] uint32_t ror32(uint32_t v, uint32_t n) noexcept;

} // namespace mx::vm::x64
