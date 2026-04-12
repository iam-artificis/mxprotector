/**
 * @file vm_runtime_gen.cpp
 * @brief [BUILDER] VmRuntimeGenerator — threaded-code VM with rolling-key stream cipher.
 *
 * Architecture (per build, per region):
 *
 *   entry_stub:
 *     pushfq                              ; save rflags
 *     push r15..rax                       ; save 15 GPRs (rsp skipped)
 *     push rax                            ; JUNK push — reserves rolling-key scratch slot
 *     mov byte ptr [rsp + 0], INITIAL_KEY ; seed rolling key
 *     lea r11, [rip + bytecode]           ; vpc
 *     <inline fetch-and-dispatch tail>    ; jump to first handler via handler_table
 *
 *   handler_N:
 *     <operand fetches via rolling key>
 *     <body (ALU / memory / native)>
 *     <inline fetch-and-dispatch tail>    ; jump to NEXT handler via handler_table
 *
 *   exit_handler:
 *     pop  rax..r15  (skip rsp)
 *     add  rsp, 8                          ; discard junk/key slot
 *     popfq
 *     ret
 *
 *   handler_table:
 *     int32[total_handlers]               ; each entry = handler_offset - table_offset
 *     (used by every tail-dispatch via `movsxd rax, [rcx + rax*4]; add rcx, rax; jmp rcx`)
 *
 *   bytecode:
 *     stream-encrypted with rolling key:
 *       enc[i] = plain[i] ^ key[i]
 *       key[i+1] = key[i] ^ plain[i]
 *     Initial key = INITIAL_KEY (per-build random byte).
 *
 * VM stack layout after entry (rsp = caller_rsp - 144):
 *
 *   [rsp +   0] = rolling key byte (lives in the junk push slot)
 *   [rsp +   8] = rax  (vm_reg 0)
 *   [rsp +  16] = rcx  (vm_reg 1)
 *   [rsp +  24] = rdx
 *   [rsp +  32] = rbx
 *   [rsp +  40] = rbp  (rsp/idx 4 is skipped — unused)
 *   [rsp +  48] = rsi
 *   [rsp +  56] = rdi
 *   [rsp +  64] = r8
 *   [rsp +  72] = r9
 *   [rsp +  80] = r10
 *   [rsp +  88] = r11  (the *saved* r11; live vpc is in the physical r11)
 *   [rsp +  96] = r12
 *   [rsp + 104] = r13
 *   [rsp + 112] = r14
 *   [rsp + 120] = r15
 *   [rsp + 128] = rflags
 *   [rsp + 136] = CALL return address (back to caller instruction stream)
 *
 * The native-escape handler additionally `sub rsp, 16` to reserve a vpc save
 * slot, then `add rsp, 160` around the raw native bytes so the instruction sees
 * the caller's frame. Context loads/stores during native use [rsp + 16 + offset].
 *
 * Per-build randomization:
 *   - INITIAL_KEY (non-zero)
 *   - handler_id permutation (VmOp → handler_id)
 *   - NO central dispatcher (threaded code — every handler ends with a
 *     `lea rcx, [rip + table]; movsxd rax, [rcx+rax*4]; add rcx, rax; jmp rcx`
 *     so the reverser cannot see a single dispatch point in IDA's CFG)
 */

#include "mxprotector/protection/vm/vm_runtime_gen.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <numeric>

namespace mx::vm {

namespace {

// ============================================================================
// Stack layout constants (must match entry prologue below)
// ============================================================================

/// VM-reg index → byte offset within the saved context (relative to rsp).
/// All 16 slots are allocated on stack (slot 4 is the rsp slot and doubles as
/// the rolling-key scratch — no VM op references it directly). A uniform
/// `idx * 8` mapping lets handlers compute ctx addresses with a single LEA.
constexpr std::array<int32_t, 16> kVmRegOffset = {
    0,    // 0  RAX
    8,    // 1  RCX
    16,   // 2  RDX
    24,   // 3  RBX
    32,   // 4  RSP — dummy slot, unused by ops, host of rolling key byte
    40,   // 5  RBP
    48,   // 6  RSI
    56,   // 7  RDI
    64,   // 8  R8
    72,   // 9  R9
    80,   // 10 R10
    88,   // 11 R11  (saved r11; live vpc is in the physical r11)
    96,   // 12 R12
    104,  // 13 R13
    112,  // 14 R14
    120,  // 15 R15
};

constexpr int32_t kRollingKeyDisp    = 32;   ///< key byte at [rsp + 32] (slot 4)
constexpr int32_t kRflagsOffset      = 128;  ///< rflags at [rsp + 128]
constexpr int32_t kContextSize       = 136;  ///< 16*8 (regs) + rflags(8) = 136

/// Frame shift between the caller's rsp (at CALL time) and vm_rsp inside a
/// native handler after `sub rsp, 16` (vpc scratch). Used to restore the
/// caller's rsp for the native instruction body.
///
///   8 (ret)  + 8 (rflags)  + 128 (16 regs)  + 16 (native scratch)  =  160
constexpr int32_t kNativeFrameShift = 160;

// ============================================================================
// RawEmitter — tiny byte buffer with pos tracking
// ============================================================================

struct RawEmitter {
    ByteBuffer buf;

    void u8(uint8_t b) { buf.push_back(b); }
    void u16(uint16_t v) { u8(static_cast<uint8_t>(v)); u8(static_cast<uint8_t>(v >> 8)); }
    void u32(uint32_t v) {
        u8(static_cast<uint8_t>(v));
        u8(static_cast<uint8_t>(v >> 8));
        u8(static_cast<uint8_t>(v >> 16));
        u8(static_cast<uint8_t>(v >> 24));
    }
    void u64(uint64_t v) {
        u32(static_cast<uint32_t>(v));
        u32(static_cast<uint32_t>(v >> 32));
    }
    void bytes(ByteView data) {
        buf.insert(buf.end(), data.begin(), data.end());
    }
    size_t size() const noexcept { return buf.size(); }
};

// ============================================================================
// Atomic x64 encoders
// ============================================================================

/// movzx r32, byte ptr [base + disp]    (0F B6 /r)
void emit_movzx_r32_byte_mem(RawEmitter& e, uint8_t dst_reg,
                              uint8_t base_reg, int32_t disp)
{
    const bool rex_r = dst_reg >= 8;
    const bool rex_b = base_reg >= 8;
    if (rex_b || rex_r) {
        uint8_t rex = 0x40;
        if (rex_r) rex |= 0x04;
        if (rex_b) rex |= 0x01;
        e.u8(rex);
    }
    e.u8(0x0F);
    e.u8(0xB6);

    const uint8_t dst3  = dst_reg & 0x07;
    const uint8_t base3 = base_reg & 0x07;
    const bool needs_sib = (base3 == 4);  // RSP/R12 encode requires SIB
    const bool base_is_rbp = (base3 == 5); // RBP/R13: disp=0 needs disp8

    if (disp == 0 && !base_is_rbp) {
        e.u8(static_cast<uint8_t>((0 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (dst3 << 3) | (needs_sib ? 4 : base3)));
        if (needs_sib) e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

/// xor reg8_low, byte ptr [rsp + disp]   (32 /r)
/// For reg 4..7 (SPL/BPL/SIL/DIL) and reg 8..15, force a REX prefix.
void emit_xor_r8l_rsp_disp(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);  // REX.R
    } else if (reg >= 4) {
        e.u8(0x40);  // empty REX to force SPL/BPL/SIL/DIL (we only use 0..3 anyway)
    }
    e.u8(0x32);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

/// xor byte ptr [rsp + disp], reg8_low   (30 /r)
void emit_xor_rsp_disp_r8l(RawEmitter& e, uint8_t reg, int32_t disp) {
    if (reg >= 8) {
        e.u8(0x44);
    } else if (reg >= 4) {
        e.u8(0x40);
    }
    e.u8(0x30);

    const uint8_t reg3 = reg & 0x07;
    if (disp == 0) {
        e.u8(static_cast<uint8_t>((0 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
    } else if (disp >= -128 && disp <= 127) {
        e.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
    } else {
        e.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
        e.u8(0x24);
        e.u32(static_cast<uint32_t>(disp));
    }
}

void emit_inc_r11(RawEmitter& e) {
    // inc r11 = 49 FF C3
    e.u8(0x49); e.u8(0xFF); e.u8(0xC3);
}

size_t emit_lea_r11_rip_rel32(RawEmitter& e) {
    // lea r11, [rip + rel32]  = 4C 8D 1D rel32
    e.u8(0x4C); e.u8(0x8D); e.u8(0x1D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

size_t emit_lea_rcx_rip_rel32(RawEmitter& e) {
    // lea rcx, [rip + rel32]  = 48 8D 0D rel32
    e.u8(0x48); e.u8(0x8D); e.u8(0x0D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

void emit_ud2(RawEmitter& e) { e.u8(0x0F); e.u8(0x0B); }
void emit_ret(RawEmitter& e) { e.u8(0xC3); }
void emit_pushfq(RawEmitter& e) { e.u8(0x9C); }
void emit_popfq(RawEmitter& e) { e.u8(0x9D); }

void emit_push_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x50 + (reg & 0x07));
}
void emit_pop_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x58 + (reg & 0x07));
}

/// add rsp, imm32  — uses full imm32 form for any displacement
void emit_add_rsp_imm32(RawEmitter& e, int32_t imm) {
    // 48 81 C4 imm32
    e.u8(0x48); e.u8(0x81); e.u8(0xC4); e.u32(static_cast<uint32_t>(imm));
}

/// sub rsp, imm32
void emit_sub_rsp_imm32(RawEmitter& e, int32_t imm) {
    // 48 81 EC imm32
    e.u8(0x48); e.u8(0x81); e.u8(0xEC); e.u32(static_cast<uint32_t>(imm));
}

/// Patch a rel32 placeholder so it jumps from `instruction_end` to `target`.
void patch_rel32(ByteBuffer& buf, size_t patch_offset, size_t instruction_end,
                 size_t target_offset)
{
    const auto rel = static_cast<int32_t>(
        static_cast<int64_t>(target_offset) - static_cast<int64_t>(instruction_end));
    std::memcpy(buf.data() + patch_offset, &rel, sizeof(int32_t));
}

// ============================================================================
// Rolling-key fetch helpers
// ============================================================================
//
// Each fetch:
//    1) movzx r32, byte [r11]           — load encrypted byte
//    2) xor r8_low, [rsp + keyDisp]     — decrypt with current key
//    3) xor [rsp + keyDisp], r8_low     — update key ^= decrypted_byte
//    4) inc r11                         — advance vpc
//
// After step 2, the low 8 bits of the destination register hold the plain
// byte; the upper bits are zero (from the movzx).

/// Fetch one byte into dst_reg (0..3 — rax/rcx/rdx/rbx), decrypt with key.
/// When `rolling` is true the key byte is updated after decryption (stream
/// cipher). When false the key stays constant (static XOR — used for regions
/// containing virtual branches where key-state synchronisation at branch
/// targets is non-trivial).
void emit_fetch_byte(RawEmitter& e, uint8_t dst_reg, int32_t key_disp,
                     bool rolling = true) {
    emit_movzx_r32_byte_mem(e, dst_reg, 11, 0);
    emit_xor_r8l_rsp_disp(e, dst_reg, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, dst_reg, key_disp);
    }
    emit_inc_r11(e);
}

/// Fetch 4 bytes into eax (little-endian), key-decrypted.
void emit_fetch_dword(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 4; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x09); e.u8(0xC8);
    }
}

/// Fetch 8 bytes into rax (little-endian), key-decrypted.
void emit_fetch_qword(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 0 /*rax*/, key_disp, rolling);
    for (int i = 1; i < 8; ++i) {
        emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
        e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(static_cast<uint8_t>(i * 8));
        e.u8(0x48); e.u8(0x09); e.u8(0xC8);
    }
}

/// Fetch two operand bytes: cl = dst_idx, dl = src_idx (masked 0x0F).
void emit_fetch_2_operand_bytes(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
    emit_fetch_byte(e, 2 /*rdx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE2); e.u8(0x0F);
}

/// Fetch one operand byte: cl = dst_idx (masked).
void emit_fetch_1_operand_byte(RawEmitter& e, int32_t key_disp, bool rolling = true) {
    emit_fetch_byte(e, 1 /*rcx*/, key_disp, rolling);
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
}

// ============================================================================
// VM-reg address helpers: compute &ctx[reg_idx] into rsi/rdi
// ============================================================================

/// rsi = rsp + rcx * 8 (ctx[reg_idx])
///   shl rcx, 3                     48 C1 E1 03
///   lea rsi, [rsp + rcx*1]         48 8D 34 0C  (mod=00, SIB: scale=0, idx=rcx, base=rsp)
void emit_vmreg_addr_rsi_from_rcx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x34); e.u8(0x0C);
}

/// rdi = rsp + rdx * 8 (ctx[reg_idx])
///   shl rdx, 3                     48 C1 E2 03
///   lea rdi, [rsp + rdx*1]         48 8D 3C 14
void emit_vmreg_addr_rdi_from_rdx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE2); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x14);
}

// ============================================================================
// Tail dispatch (inlined at end of each handler): fetch next opcode via
// rolling key, look up handler in the handler_table, jump.
// ============================================================================

struct TailDispatchPatch {
    size_t rel32_offset;      ///< offset of the rel32 inside `lea rcx, [rip+rel32]`
    size_t instruction_end;   ///< byte just after the rel32
};

/// Emits the tail dispatch stub. Caller must collect the returned patch and
/// fix it up to point at the handler_table once the table offset is known.
TailDispatchPatch emit_tail_dispatch(RawEmitter& e, int32_t key_disp,
                                     bool rolling = true,
                                     bool save_rflags = false) {
    // Optionally save CPU rflags into the VM context BEFORE clobbering them
    // with the fetch logic (movzx/xor). This is the single collection point
    // for flag preservation — every handler's body has just finished, and the
    // CPU flags still reflect the last ALU/native operation.
    if (save_rflags) {
        // pushfq; pop rax; mov [rsp + kRflagsOffset], rax
        e.u8(0x9C); e.u8(0x58);
        e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24);
        e.u8(static_cast<uint8_t>(kRflagsOffset & 0xFF));
        e.u8(static_cast<uint8_t>((kRflagsOffset >> 8) & 0xFF));
        e.u8(static_cast<uint8_t>((kRflagsOffset >> 16) & 0xFF));
        e.u8(static_cast<uint8_t>((kRflagsOffset >> 24) & 0xFF));
    }

    emit_movzx_r32_byte_mem(e, 0 /*rax*/, 11, 0);
    emit_xor_r8l_rsp_disp(e, 0, key_disp);
    if (rolling) {
        emit_xor_rsp_disp_r8l(e, 0, key_disp);
    }
    emit_inc_r11(e);

    // lea rcx, [rip + rel32]       — rel32 patched to point at handler_table
    const auto patch_off = emit_lea_rcx_rip_rel32(e);
    const auto patch_end = e.size();

    // movsxd rax, dword [rcx + rax*4]   48 63 04 81
    e.u8(0x48); e.u8(0x63); e.u8(0x04); e.u8(0x81);
    // add rcx, rax                       48 01 C1
    e.u8(0x48); e.u8(0x01); e.u8(0xC1);
    // jmp rcx                            FF E1
    e.u8(0xFF); e.u8(0xE1);

    return {patch_off, patch_end};
}

// ============================================================================
// Specific handlers (ALU / logic / shift / mov / etc.)
// ============================================================================

void emit_handler_mov_rr(RawEmitter& e, int32_t key_disp) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]   48 8B 07
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // mov [rsi], rax   48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/// Generic r-r ALU using dst-memory addressing and op_mr opcode
/// (add=01, sub=29, xor=31, and=21, or=09).
void emit_handler_alu_rr(RawEmitter& e, int32_t key_disp, uint8_t op_mr) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // OP [rsi], rax     48 op_mr 06
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

// ---------------------------------------------------------------------------
// MBA variants — mathematically equivalent alternative encodings that look
// nothing like the straightforward ALU form in a decompiler. Chosen at
// encode time per instruction to defeat simple opcode-table recovery.
// ---------------------------------------------------------------------------

/// ADD variant: x + y ≡ (x ^ y) + 2 * (x & y)
void emit_handler_add_rr_mba(RawEmitter& e, int32_t key_disp) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // rdx = x = [rsi]          48 8B 16
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);
    // rcx = rdx                48 89 D1
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);
    // rcx = x & y              48 21 C1
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);
    // rcx = 2 * (x & y)        48 D1 E1
    e.u8(0x48); e.u8(0xD1); e.u8(0xE1);
    // rdx = x ^ y              48 31 C2
    e.u8(0x48); e.u8(0x31); e.u8(0xC2);
    // rdx = (x^y) + 2*(x&y)    48 01 CA
    e.u8(0x48); e.u8(0x01); e.u8(0xCA);
    // [rsi] = rdx              48 89 16
    e.u8(0x48); e.u8(0x89); e.u8(0x16);
}

/// SUB variant: x - y ≡ x + (-y)
void emit_handler_sub_rr_neg(RawEmitter& e, int32_t key_disp) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // neg rax              48 F7 D8
    e.u8(0x48); e.u8(0xF7); e.u8(0xD8);
    // add [rsi], rax       48 01 06
    e.u8(0x48); e.u8(0x01); e.u8(0x06);
}

/// XOR variant: x ^ y ≡ (x | y) - (x & y)
void emit_handler_xor_rr_mba(RawEmitter& e, int32_t key_disp) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // rax = y = [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // rdx = x = [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x16);
    // rcx = rdx                48 89 D1
    e.u8(0x48); e.u8(0x89); e.u8(0xD1);
    // rcx = x & y              48 21 C1
    e.u8(0x48); e.u8(0x21); e.u8(0xC1);
    // rdx = x | y              48 09 C2
    e.u8(0x48); e.u8(0x09); e.u8(0xC2);
    // rdx = (x|y) - (x&y)      48 29 CA
    e.u8(0x48); e.u8(0x29); e.u8(0xCA);
    // [rsi] = rdx              48 89 16
    e.u8(0x48); e.u8(0x89); e.u8(0x16);
}

void emit_handler_imul_rr(RawEmitter& e, int32_t key_disp) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // imul rax, [rdi]
    e.u8(0x48); e.u8(0x0F); e.u8(0xAF); e.u8(0x07);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri32(RawEmitter& e, int32_t key_disp) {
    emit_fetch_1_operand_byte(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp);
    // movsxd rax, eax   48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_mov_ri64(RawEmitter& e, int32_t key_disp) {
    emit_fetch_1_operand_byte(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_qword(e, key_disp);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

void emit_handler_alu_ri32(RawEmitter& e, int32_t key_disp, uint8_t op_mr) {
    emit_fetch_1_operand_byte(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_fetch_dword(e, key_disp);
    // movsxd rax, eax
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // OP [rsi], rax
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

/// not/neg [rsi]  (/2 for not, /3 for neg)
void emit_handler_unary(RawEmitter& e, int32_t key_disp, uint8_t sub_op) {
    emit_fetch_1_operand_byte(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    // 48 F7 /sub_op,rm=6(rsi)
    e.u8(0x48); e.u8(0xF7);
    e.u8(static_cast<uint8_t>((sub_op << 3) | 0x06));
}

void emit_handler_shift(RawEmitter& e, int32_t key_disp, uint8_t sub_op) {
    emit_fetch_2_operand_bytes(e, key_disp);
    emit_vmreg_addr_rsi_from_rcx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // mov cl, dl         88 D1
    e.u8(0x88); e.u8(0xD1);
    // OP rax, cl         48 D3 /sub_op
    e.u8(0x48); e.u8(0xD3);
    e.u8(static_cast<uint8_t>(0xC0 | (sub_op << 3)));
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

// ---------------------------------------------------------------------------
// RFLAGS save — needed so VJCC can read flags set by prior ALU handlers
// ---------------------------------------------------------------------------

/// Save current CPU rflags into the VM context slot so that a subsequent
/// VJCC handler can evaluate branch conditions. Called at the END of every
/// handler body that may modify arithmetic flags (ADD, SUB, XOR, AND, OR,
/// IMUL, NOT, NEG, SHL, SHR, SAR, ROL, ROR and native escape).
void emit_save_rflags_to_ctx(RawEmitter& e) {
    // pushfq          9C
    e.u8(0x9C);
    // pop rax         58
    e.u8(0x58);
    // mov [rsp + kRflagsOffset], rax
    // kRflagsOffset = 128: needs disp32 form.
    // 48 89 84 24 80 00 00 00
    e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24);
    e.u8(static_cast<uint8_t>(kRflagsOffset & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 8) & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 16) & 0xFF));
    e.u8(static_cast<uint8_t>((kRflagsOffset >> 24) & 0xFF));
}

// ---------------------------------------------------------------------------
// VJMP / VJCC handlers
// ---------------------------------------------------------------------------

/// VJMP (unconditional virtual branch).
/// Operand layout: [rel32]. After fetching, r11 already points past rel32.
/// Handler adds rel32 to r11 so the next tail dispatch reads from the target.
void emit_handler_vjmp(RawEmitter& e, int32_t key_disp, bool rolling) {
    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    // movsxd rax, eax     48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // add r11, rax         4C 01 C3 — wait: add r11, rax = 49 01 C3
    // Actually: ADD r/m64, r64 → REX.WB + 01 /r.  r11 = rm, rax = reg
    // ModRM: mod=11, reg=0(rax), rm=3(r11&7) → C3.  REX = 49 (W+B)
    e.u8(0x49); e.u8(0x01); e.u8(0xC3);
}

/// VJCC (conditional virtual branch) with condition `cc` baked in at emit time.
/// Operand layout: [rel32] (cc byte is NOT in bytecode — the handler_id itself
/// encodes the condition through the variant system). Handler loads saved RFLAGS,
/// evaluates the condition, and if taken adjusts r11 by rel32.
///
/// @param cc  x86 condition code (0..0xF): 0=O,1=NO,2=B,3=NB,4=E,5=NE,...
void emit_handler_vjcc(RawEmitter& e, int32_t key_disp, bool rolling,
                       uint8_t cc) {
    emit_fetch_dword(e, key_disp, rolling);      // eax = rel32
    // movsxd rax, eax
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);

    // Load the saved RFLAGS from ctx into the CPU:
    //   pushfq                             9C
    //   push qword [rsp + kRflagsOffset + 8]
    //     (the +8 accounts for our pushfq which shifted rsp down)
    //     For kRflagsOffset=128: disp = 128+8 = 136 > 127 → disp32
    //     48 FF 34 24 — push [rsp] wrong.
    //     push [rsp+disp32]: FF B4 24 disp32
    //   popfq
    //   48 83 C4 08 — add rsp, 8 (discard the saved rflags copy)
    //   (CPU flags now reflect saved RFLAGS; rsp back to pre-pushfq position)
    //
    // Wait — simpler: swap current flags with saved:
    //   pushfq                              save current CPU flags
    //   mov rcx, [rsp + kRflagsOffset + 8]  load saved rflags (+8 for pushfq)
    //   push rcx                            push it
    //   popfq                               restore saved flags to CPU
    //   (now CPU has user's flags; original CPU flags are at [rsp])
    //
    //   <test condition via Jcc>
    //
    //   popfq                               restore original CPU flags

    // pushfq          9C
    e.u8(0x9C);
    // mov rcx, [rsp + 128 + 8]  = [rsp + 136]
    // 48 8B 8C 24 88 00 00 00   (mod=10, reg=1(rcx), rm=4(SIB), SIB=0x24, disp32=136)
    e.u8(0x48); e.u8(0x8B); e.u8(0x8C); e.u8(0x24);
    const int32_t rflags_disp = kRflagsOffset + 8;
    e.u8(static_cast<uint8_t>(rflags_disp & 0xFF));
    e.u8(static_cast<uint8_t>((rflags_disp >> 8) & 0xFF));
    e.u8(static_cast<uint8_t>((rflags_disp >> 16) & 0xFF));
    e.u8(static_cast<uint8_t>((rflags_disp >> 24) & 0xFF));
    // push rcx         51
    e.u8(0x51);
    // popfq            9D   — CPU flags = saved rflags
    e.u8(0x9D);

    // Jcc_short taken_label — rel8 forward (we emit 2 bytes: 0x70+cc, rel8).
    // The not-taken path is: popfq + tail_dispatch (below). The taken path is:
    // popfq + add r11, rax + tail_dispatch.
    //
    // not-taken (next instruction): popfq
    //   size of popfq = 1
    //   + jmp rel8 to skip taken block — 2 bytes
    //   total not-taken body: 3 bytes
    //
    // taken (after jcc): popfq + add r11, rax
    //   popfq = 1
    //   add r11, rax = 3
    //   total: 4 bytes
    //
    // Jcc: 0x70+cc, rel8 = offset to taken_label from jcc_end.
    //   jcc_end = current + 2
    //   not_taken: popfq(1) + jmp rel8(2) = 3 bytes
    //   taken_label is at jcc_end + 3
    //   rel8 = 3 → Jcc lands 3 bytes ahead

    e.u8(static_cast<uint8_t>(0x70 + cc));
    e.u8(0x03);  // skip the not-taken path (popfq + jmp 4)

    // NOT TAKEN path:
    // popfq            9D
    e.u8(0x9D);
    // jmp short +4     EB 04   — skip the taken-path body (popfq + add r11, rax = 4 bytes)
    e.u8(0xEB); e.u8(0x04);

    // TAKEN path:
    // popfq            9D
    e.u8(0x9D);
    // add r11, rax     49 01 C3
    e.u8(0x49); e.u8(0x01); e.u8(0xC3);

    // Both paths converge here → tail dispatch follows (emitted by caller).
}

} // anonymous namespace

// ============================================================================
// VmRuntimeGenerator::generate — main entry
// ============================================================================

namespace {

/// How many handler variants each canonical VmOp emits. Ops with multiple
/// variants have two (or more) mathematically equivalent emission forms; the
/// encoder picks one at random per instruction to defeat simple opcode-table
/// recovery.
constexpr uint8_t variant_count_for(VmOp op) {
    switch (op) {
        case VmOp::add_rr:
        case VmOp::sub_rr:
        case VmOp::xor_rr:
            return 2;
        case VmOp::vjcc:
            return 16;   // one handler per x86 condition code (0..F)
        default:
            return 1;
    }
}

} // anonymous namespace

MxResult<VmRuntime> VmRuntimeGenerator::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng)
{
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "VmRuntimeGenerator: empty VM instruction list"));
    }

    // ------------------------------------------------------------------------
    // Step 1 — per-build randomization: opcode handler_id permutation, handler
    // variant assignment, initial rolling key.
    // ------------------------------------------------------------------------
    VmOpcodeMap map{};
    do { map.opcode_xor_key = rng.next_u8(); } while (map.opcode_xor_key == 0);
    const uint8_t initial_key = map.opcode_xor_key;

    const uint32_t native_count = static_cast<uint32_t>(std::count_if(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) { return v.op == VmOp::native; }));

    // Total generic variant slots (sum of variants across all canonical VmOps).
    uint32_t generic_variant_total = 0;
    for (uint32_t i = 0; i < kVmOpCount; ++i) {
        generic_variant_total += variant_count_for(static_cast<VmOp>(i));
    }

    const uint32_t total_handlers = generic_variant_total + native_count;
    if (total_handlers > 255) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            std::format("VmRuntimeGenerator: too many handlers ({} > 255)",
                total_handlers)));
    }
    map.total_handlers = total_handlers;

    // Shuffle handler_id assignment across the entire slot space.
    std::vector<uint8_t> slots(total_handlers);
    std::iota(slots.begin(), slots.end(), static_cast<uint8_t>(0));
    std::shuffle(slots.begin(), slots.end(), rng.engine());

    // variant_handler_ids[op] = list of handler_ids (one per variant).
    std::vector<std::vector<uint8_t>> variant_handler_ids(kVmOpCount);
    {
        uint32_t idx = 0;
        for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
            const uint32_t vcount = variant_count_for(static_cast<VmOp>(opi));
            variant_handler_ids[opi].reserve(vcount);
            for (uint32_t v = 0; v < vcount; ++v) {
                variant_handler_ids[opi].push_back(slots[idx++]);
            }
            // Keep VmOpcodeMap's "canonical" id for compatibility: it stores
            // the FIRST variant's id. Encoders normally bypass this and pick
            // a random variant directly from variant_handler_ids.
            map.generic_handler_id[opi] = variant_handler_ids[opi].front();
        }
    }

    std::vector<uint8_t> native_handler_ids;
    native_handler_ids.reserve(native_count);
    for (uint32_t i = generic_variant_total; i < total_handlers; ++i) {
        native_handler_ids.push_back(slots[i]);
    }

    // ------------------------------------------------------------------------
    // Step 2 — build plain bytecode stream, then stream-encrypt with rolling
    // key. The encryption walks bytes in fetch order (opcode, operands, next
    // opcode, ...) so the runtime decryption order matches.
    // ------------------------------------------------------------------------
    ByteBuffer bytecode_plain;
    bytecode_plain.reserve(instructions.size() * 4);

    uint32_t next_native_idx = 0;
    std::vector<uint32_t> native_handler_of_insn(instructions.size(), UINT32_MAX);

    // --- Phase 1: compute bytecode size per instruction to get offsets. ---
    // We need offsets BEFORE encoding because vjmp/vjcc rel32 depends on the
    // target instruction's bytecode offset.
    auto insn_bc_size = [](const VmInstruction& vi) -> uint32_t {
        // 1 byte for handler_id + operand bytes
        return 1 + vm_op_operand_size(vi.op);
    };

    std::vector<uint32_t> bc_offset(instructions.size() + 1);
    bc_offset[0] = 0;
    for (size_t i = 0; i < instructions.size(); ++i) {
        bc_offset[i + 1] = bc_offset[i] + insn_bc_size(instructions[i]);
    }
    const uint32_t exit_bc_offset = bc_offset.back(); // offset of the terminal exit opcode

    // --- Phase 2: encode bytecode. ---
    auto push32 = [&](int32_t v) {
        const auto u = static_cast<uint32_t>(v);
        bytecode_plain.push_back(static_cast<uint8_t>(u & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
        bytecode_plain.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
    };

    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& vi = instructions[i];
        uint8_t handler_id;
        if (vi.op == VmOp::native) {
            handler_id = native_handler_ids[next_native_idx];
            native_handler_of_insn[i] = next_native_idx;
            ++next_native_idx;
        } else if (vi.op == VmOp::vjcc) {
            // vjcc uses a per-CC variant: variant index = branch_cc.
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(VmOp::vjcc)];
            handler_id = variants[vi.branch_cc];
        } else {
            const auto& variants = variant_handler_ids[static_cast<uint32_t>(vi.op)];
            const uint32_t v = (variants.size() > 1)
                ? rng.next_range(0, static_cast<uint32_t>(variants.size() - 1))
                : 0u;
            handler_id = variants[v];
        }

        bytecode_plain.push_back(handler_id);

        switch (vi.op) {
            case VmOp::mov_rr:
            case VmOp::add_rr:
            case VmOp::sub_rr:
            case VmOp::xor_rr:
            case VmOp::and_rr:
            case VmOp::or_rr:
            case VmOp::imul_rr:
                bytecode_plain.push_back(vi.dst);
                bytecode_plain.push_back(vi.src);
                break;

            case VmOp::mov_ri32:
            case VmOp::add_ri32:
            case VmOp::sub_ri32:
            case VmOp::xor_ri32:
            case VmOp::and_ri32:
            case VmOp::or_ri32:
                bytecode_plain.push_back(vi.dst);
                push32(vi.imm32);
                break;

            case VmOp::mov_ri64:
                bytecode_plain.push_back(vi.dst);
                for (int b = 0; b < 8; ++b)
                    bytecode_plain.push_back(
                        static_cast<uint8_t>((vi.imm64 >> (b * 8)) & 0xFF));
                break;

            case VmOp::not_r:
            case VmOp::neg_r:
                bytecode_plain.push_back(vi.dst);
                break;

            case VmOp::shl_ri:
            case VmOp::shr_ri:
            case VmOp::sar_ri:
            case VmOp::rol_ri:
            case VmOp::ror_ri:
                bytecode_plain.push_back(vi.dst);
                bytecode_plain.push_back(vi.shift_count);
                break;

            case VmOp::vjmp: {
                // rel32 = target_bc_offset - next_insn_bc_offset
                const auto target_off = bc_offset[vi.branch_target_insn];
                const auto next_off   = bc_offset[i + 1];
                push32(static_cast<int32_t>(target_off) -
                       static_cast<int32_t>(next_off));
                break;
            }

            case VmOp::vjcc: {
                // Operand: [rel32]. The CC is baked into the handler variant.
                const auto target_off = bc_offset[vi.branch_target_insn];
                const auto next_off   = bc_offset[i + 1];
                push32(static_cast<int32_t>(target_off) -
                       static_cast<int32_t>(next_off));
                break;
            }

            case VmOp::native:
            case VmOp::exit:
            case VmOp::count_:
                break;
        }
    }

    // Terminal exit opcode.
    bytecode_plain.push_back(
        variant_handler_ids[static_cast<uint32_t>(VmOp::exit)][0]);

    // Detect whether the instruction list contains any virtual branches.
    // If it does, we fall back to static XOR encryption (all bytes XOR'd with
    // the same key) because branch targets would need key-state checkpoints
    // that complicate the first-pass design. Straight-line regions keep the
    // stronger rolling-key cipher.
    const bool has_branches = std::any_of(
        instructions.begin(), instructions.end(),
        [](const VmInstruction& v) {
            return v.op == VmOp::vjmp || v.op == VmOp::vjcc;
        });
    const bool rolling = !has_branches;

    // Bytecode encryption: rolling-key or static XOR.
    if (rolling) {
        uint8_t key = initial_key;
        for (auto& b : bytecode_plain) {
            const uint8_t plain = b;
            b = static_cast<uint8_t>(plain ^ key);
            key ^= plain;
        }
    } else {
        for (auto& b : bytecode_plain) {
            b ^= initial_key;
        }
    }

    // ------------------------------------------------------------------------
    // Step 3 — emit the runtime blob:
    //   [entry_stub][handlers ...][handler_table][bytecode]
    // ------------------------------------------------------------------------
    RawEmitter rt;

    // Patch-records collected during emission.
    struct TablePatch {
        size_t rel32_offset;
        size_t instruction_end;
    };
    std::vector<TablePatch> table_patches;

    // ---- Entry stub ----------------------------------------------------------
    const size_t entry_offset = rt.size();

    emit_pushfq(rt);
    // 16 register pushes. Slot 4 (vm_reg[RSP]) is a dummy `push rax` — no
    // VM op references it, so its contents don't matter; we reuse its first
    // byte as the rolling-key scratch.
    constexpr uint8_t push_order[] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7 /*rdi*/, 6 /*rsi*/, 5 /*rbp*/,
        0 /*dummy for slot 4 (rsp)*/,
        3 /*rbx*/, 2 /*rdx*/, 1 /*rcx*/, 0 /*rax*/
    };
    for (uint8_t r : push_order) {
        emit_push_reg(rt, r);
    }

    // Seed the rolling key inside slot 4 (rsp dummy):
    //   mov byte [rsp + 32], initial_key    C6 44 24 20 ib
    rt.u8(0xC6); rt.u8(0x44); rt.u8(0x24); rt.u8(0x20); rt.u8(initial_key);

    // lea r11, [rip + bytecode_rel32]
    const size_t entry_bc_patch = emit_lea_r11_rip_rel32(rt);
    const size_t entry_bc_patch_end = rt.size();

    // Inline first dispatch (same shape as handler tails): fetch opcode,
    // decrypt, update key, look up handler via table, jump.
    const auto entry_tail = emit_tail_dispatch(rt, kRollingKeyDisp, rolling);
    table_patches.push_back({entry_tail.rel32_offset, entry_tail.instruction_end});

    // ---- Handler emission ----------------------------------------------------
    // For each handler_id we record its starting offset so we can fill the
    // handler_table at the end.
    std::vector<size_t> handler_offset_by_id(total_handlers, SIZE_MAX);

    auto begin_handler = [&](uint8_t handler_id) {
        handler_offset_by_id[handler_id] = rt.size();
    };

    auto end_handler_tail = [&]() {
        const auto p = emit_tail_dispatch(rt, kRollingKeyDisp, rolling,
                                          has_branches);
        table_patches.push_back({p.rel32_offset, p.instruction_end});
    };

    // Emit one body for (op, variant_index). Returns true if a tail dispatch
    // should be appended after the body. The VmOp::exit variant emits its own
    // ret and returns false.
    auto emit_op_variant = [&](VmOp op, uint32_t variant) -> bool {
        switch (op) {
            case VmOp::mov_rr:   emit_handler_mov_rr(rt, kRollingKeyDisp);             return true;

            case VmOp::add_rr:
                if (variant == 0) emit_handler_alu_rr(rt, kRollingKeyDisp, 0x01);
                else              emit_handler_add_rr_mba(rt, kRollingKeyDisp);
                return true;

            case VmOp::sub_rr:
                if (variant == 0) emit_handler_alu_rr(rt, kRollingKeyDisp, 0x29);
                else              emit_handler_sub_rr_neg(rt, kRollingKeyDisp);
                return true;

            case VmOp::xor_rr:
                if (variant == 0) emit_handler_alu_rr(rt, kRollingKeyDisp, 0x31);
                else              emit_handler_xor_rr_mba(rt, kRollingKeyDisp);
                return true;

            case VmOp::and_rr:   emit_handler_alu_rr(rt, kRollingKeyDisp, 0x21);       return true;
            case VmOp::or_rr:    emit_handler_alu_rr(rt, kRollingKeyDisp, 0x09);       return true;
            case VmOp::imul_rr:  emit_handler_imul_rr(rt, kRollingKeyDisp);            return true;

            case VmOp::mov_ri32: emit_handler_mov_ri32(rt, kRollingKeyDisp);           return true;
            case VmOp::add_ri32: emit_handler_alu_ri32(rt, kRollingKeyDisp, 0x01);     return true;
            case VmOp::sub_ri32: emit_handler_alu_ri32(rt, kRollingKeyDisp, 0x29);     return true;
            case VmOp::xor_ri32: emit_handler_alu_ri32(rt, kRollingKeyDisp, 0x31);     return true;
            case VmOp::and_ri32: emit_handler_alu_ri32(rt, kRollingKeyDisp, 0x21);     return true;
            case VmOp::or_ri32:  emit_handler_alu_ri32(rt, kRollingKeyDisp, 0x09);     return true;

            case VmOp::mov_ri64: emit_handler_mov_ri64(rt, kRollingKeyDisp);           return true;

            case VmOp::not_r:    emit_handler_unary(rt, kRollingKeyDisp, 2);           return true;
            case VmOp::neg_r:    emit_handler_unary(rt, kRollingKeyDisp, 3);           return true;

            case VmOp::shl_ri:   emit_handler_shift(rt, kRollingKeyDisp, 4);           return true;
            case VmOp::shr_ri:   emit_handler_shift(rt, kRollingKeyDisp, 5);           return true;
            case VmOp::sar_ri:   emit_handler_shift(rt, kRollingKeyDisp, 7);           return true;
            case VmOp::rol_ri:   emit_handler_shift(rt, kRollingKeyDisp, 0);           return true;
            case VmOp::ror_ri:   emit_handler_shift(rt, kRollingKeyDisp, 1);           return true;

            case VmOp::vjmp:
                emit_handler_vjmp(rt, kRollingKeyDisp, rolling);
                return true;

            case VmOp::vjcc:
                emit_handler_vjcc(rt, kRollingKeyDisp, rolling,
                                  static_cast<uint8_t>(variant));
                return true;

            case VmOp::native:
                // Generic native slot is never invoked — each native insn gets
                // its own handler. Trap with ud2 (no tail).
                emit_ud2(rt);
                return false;

            case VmOp::exit: {
                // Exit: pop 4 regs, skip dummy slot 4, pop rest, popfq, ret.
                // Pops mirror the push order in reverse (first popped = lowest
                // address = last pushed). The push order was:
                //   r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rbp,
                //   dummy(slot4), rbx, rdx, rcx, rax
                // => last pushed = rax at [rsp+0], then rcx at [rsp+8], rdx,
                //    rbx, dummy, rbp, rsi, rdi, r8..r15.
                emit_pop_reg(rt, 0);  // rax
                emit_pop_reg(rt, 1);  // rcx
                emit_pop_reg(rt, 2);  // rdx
                emit_pop_reg(rt, 3);  // rbx
                // Skip slot 4 (rsp dummy / rolling key):
                //   add rsp, 8       48 83 C4 08
                rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4); rt.u8(0x08);
                emit_pop_reg(rt, 5);  // rbp
                emit_pop_reg(rt, 6);  // rsi
                emit_pop_reg(rt, 7);  // rdi
                for (uint8_t r = 8; r <= 15; ++r) emit_pop_reg(rt, r);
                emit_popfq(rt);
                emit_ret(rt);
                return false;  // no tail dispatch — we return to the caller
            }
            case VmOp::count_:
                return false;
        }
        return false;
    };

    // Generic handlers: emit every variant of every canonical VmOp.
    for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
        const auto op = static_cast<VmOp>(opi);
        const auto& variants = variant_handler_ids[opi];
        for (uint32_t v = 0; v < variants.size(); ++v) {
            begin_handler(variants[v]);
            const bool needs_tail = emit_op_variant(op, v);
            if (needs_tail) {
                end_handler_tail();
            }
        }
    }

    // Per-instruction native handlers — one per VmOp::native insn.
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].op != VmOp::native) continue;
        const uint8_t hid = native_handler_ids[native_handler_of_insn[i]];
        begin_handler(hid);

        // sub rsp, 16   — reserve scratch for vpc save
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xEC); rt.u8(0x10);
        // mov [rsp], r11   — save vpc
        rt.u8(0x4C); rt.u8(0x89); rt.u8(0x1C); rt.u8(0x24);

        // Reload native regs from ctx. After `sub rsp, 16` the ctx lives at
        // [rsp + 16 + kVmRegOffset[reg]]. Slot 4 (rsp dummy / rolling-key)
        // is skipped — no native reg maps to it.
        struct RegLoad { uint8_t native_reg; int32_t offset; };
        const RegLoad loads[] = {
            {0,  16 + 0},    {1,  16 + 8},   {2,  16 + 16},  {3,  16 + 24},
            /* slot 4 (rsp dummy) skipped */
            {5,  16 + 40},   {6,  16 + 48},  {7,  16 + 56},
            {8,  16 + 64},   {9,  16 + 72},  {10, 16 + 80},
            {11, 16 + 88},   // r11 (will overwrite vpc — saved above)
            {12, 16 + 96},   {13, 16 + 104}, {14, 16 + 112}, {15, 16 + 120},
        };

        auto emit_mem_mov = [&](uint8_t opcode, uint8_t reg, int32_t disp) {
            // opcode=0x8B (load) or 0x89 (store)
            uint8_t rex = 0x48 | ((reg >= 8) ? 0x04 : 0x00);
            rt.u8(rex);
            rt.u8(opcode);
            const uint8_t reg3 = reg & 0x07;
            if (disp >= -128 && disp <= 127) {
                rt.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u8(static_cast<uint8_t>(static_cast<int8_t>(disp)));
            } else {
                rt.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u32(static_cast<uint32_t>(disp));
            }
        };

        for (const auto& l : loads) emit_mem_mov(0x8B, l.native_reg, l.offset);

        // Restore CPU flags from ctx so flag-dependent native instructions
        // (CMOV, ADC, SBB, etc.) see the correct state:
        //   push qword [rsp + 16 + kRflagsOffset]    FF B4 24 disp32
        //   popfq                                     9D
        {
            const int32_t rf_disp = 16 + kRflagsOffset;
            rt.u8(0xFF); rt.u8(0xB4); rt.u8(0x24);
            rt.u32(static_cast<uint32_t>(rf_disp));
            rt.u8(0x9D);
        }

        // Shift rsp to caller frame via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(kNativeFrameShift));

        // Execute native bytes (sees correct GPRs, flags, and caller frame).
        rt.bytes(ByteView{
            instructions[i].native_bytes.data(),
            instructions[i].native_bytes.size()});

        // Shift rsp back via LEA (flag-preserving).
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0xA4); rt.u8(0x24);
        rt.u32(static_cast<uint32_t>(-kNativeFrameShift));

        // Save CPU flags after native execution into ctx so the NEXT
        // handler (or VJCC) sees the correct flags:
        //   pushfq                                 9C
        //   pop qword [rsp + 16 + kRflagsOffset]  8F 84 24 disp32
        {
            const int32_t rf_disp = 16 + kRflagsOffset;
            rt.u8(0x9C);
            rt.u8(0x8F); rt.u8(0x84); rt.u8(0x24);
            rt.u32(static_cast<uint32_t>(rf_disp));
        }

        // Save all native regs back to ctx
        for (const auto& l : loads) emit_mem_mov(0x89, l.native_reg, l.offset);

        // Restore vpc: mov r11, [rsp]    4C 8B 1C 24
        rt.u8(0x4C); rt.u8(0x8B); rt.u8(0x1C); rt.u8(0x24);
        // lea rsp, [rsp + 16]    48 8D 64 24 10  (flags-preserving)
        rt.u8(0x48); rt.u8(0x8D); rt.u8(0x64); rt.u8(0x24); rt.u8(0x10);

        end_handler_tail();
    }

    // ---- Handler table -------------------------------------------------------
    // Align to 4 bytes so the 32-bit entries are naturally aligned.
    while (rt.size() % 4 != 0) rt.u8(0xCC);
    const size_t handler_table_offset = rt.size();
    for (uint32_t h = 0; h < total_handlers; ++h) {
        rt.u32(0);  // placeholder, patched below
    }

    // ---- Bytecode ------------------------------------------------------------
    while (rt.size() % 8 != 0) rt.u8(0xCC);
    const size_t bytecode_offset = rt.size();
    rt.bytes(ByteView{bytecode_plain.data(), bytecode_plain.size()});

    // ------------------------------------------------------------------------
    // Step 4 — patch all rel32s and the handler_table entries.
    // ------------------------------------------------------------------------

    // Entry → bytecode (via lea r11, [rip + rel32])
    patch_rel32(rt.buf, entry_bc_patch, entry_bc_patch_end, bytecode_offset);

    // All tail-dispatch lea rcx, [rip + rel32] → handler_table
    for (const auto& p : table_patches) {
        patch_rel32(rt.buf, p.rel32_offset, p.instruction_end, handler_table_offset);
    }

    // handler_table entries: each = handler_offset - table_offset (int32 LE)
    for (uint32_t h = 0; h < total_handlers; ++h) {
        if (handler_offset_by_id[h] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("VmRuntimeGenerator: handler id {} not emitted", h)));
        }
        const auto rel = static_cast<int32_t>(
            static_cast<int64_t>(handler_offset_by_id[h]) -
            static_cast<int64_t>(handler_table_offset));
        std::memcpy(rt.buf.data() + handler_table_offset + h * 4, &rel, 4);
    }

    VmRuntime result;
    result.blob = std::move(rt.buf);
    result.entry_offset   = static_cast<uint32_t>(entry_offset);
    result.bytecode_offset = static_cast<uint32_t>(bytecode_offset);
    result.bytecode_size   = static_cast<uint32_t>(bytecode_plain.size());
    result.handler_count   = total_handlers;
    result.opcode_map      = map;
    return result;
}

} // namespace mx::vm
