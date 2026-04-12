/**
 * @file vm_runtime_gen.cpp
 * @brief [BUILDER] Реализация VmRuntimeGenerator — x64 emission всего VM runtime.
 *
 * Архитектура runtime:
 *
 *   entry:
 *     pushfq                        ; save rflags
 *     push r15..rax                 ; save all GPRs (15 pushes, rsp skipped)
 *     lea r11, [rip + bytecode]     ; vpc = bytecode stream
 *     jmp dispatcher
 *
 *   dispatcher:
 *     movzx eax, byte ptr [r11]     ; fetch opcode
 *     xor al, KEY                    ; decrypt
 *     inc r11                        ; advance
 *     cmp al, h_0 / je handler_0
 *     cmp al, h_1 / je handler_1
 *     ...
 *     ud2                             ; unknown
 *
 *   handler_N:
 *     <operation on vm_regs in stack>
 *     jmp dispatcher
 *
 *   exit_handler:
 *     pop rax..r15                    ; restore all (15 pops)
 *     popfq
 *     ret                              ; back to caller (past JMP+fill)
 *
 * VM reg idx → stack offset mapping (after 15 pushes):
 *   0 rax=0, 1 rcx=8, 2 rdx=16, 3 rbx=24, 4 rsp=SKIP, 5 rbp=32,
 *   6 rsi=40, 7 rdi=48, 8 r8=56, 9 r9=64, 10 r10=72, 11 r11=80,
 *   12 r12=88, 13 r13=96, 14 r14=104, 15 r15=112, rflags=120
 *
 * Stack offset = offset_table[vm_reg_idx].
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

/**
 * @brief Маппинг VM reg idx (0..15) → смещение в VM-контексте (стэк).
 * RSP (idx=4) не хранится в контексте — не используется generic ops.
 */
constexpr std::array<int32_t, 16> kVmRegOffset = {
    0,    // 0  RAX
    8,    // 1  RCX
    16,   // 2  RDX
    24,   // 3  RBX
    -1,   // 4  RSP — запрещён
    32,   // 5  RBP
    40,   // 6  RSI
    48,   // 7  RDI
    56,   // 8  R8
    64,   // 9  R9
    72,   // 10 R10
    80,   // 11 R11  — в runtime'е нативный R11 = vpc, но при NATIVE escape восстанавливаем из контекста
    88,   // 12 R12
    96,   // 13 R13
    104,  // 14 R14
    112,  // 15 R15
};

constexpr int32_t kRflagsOffset = 120;
constexpr int32_t kContextSize  = 128;  ///< 15 regs × 8 + rflags = 128 (выровнен на 16)

/**
 * @brief Помощник, который ПИШЕТ сырые байты в буфер.
 * Всё что не поддерживается X86CodeEmitter, эмитим вручную.
 */
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
// Атомарные encoders для инструкций, которых нет в X86CodeEmitter
// ============================================================================

// movzx r32, byte ptr [base + disp]
// 0F B6 /r  ; REX.B if base>=8
void emit_movzx_r32_byte_mem(RawEmitter& e, uint8_t dst_reg,
                              uint8_t base_reg, int32_t disp)
{
    const bool rex_b = base_reg >= 8;
    const bool rex_r = dst_reg >= 8;
    if (rex_b || rex_r) {
        uint8_t rex = 0x40;
        if (rex_r) rex |= 0x04;
        if (rex_b) rex |= 0x01;
        e.u8(rex);
    }
    e.u8(0x0F);
    e.u8(0xB6);

    const uint8_t dst3 = dst_reg & 0x07;
    const uint8_t base3 = base_reg & 0x07;
    const bool needs_sib = (base3 == 4); // RSP/R12
    const bool base_is_rbp = (base3 == 5); // RBP/R13 — disp=0 требует disp8

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

// xor al, imm8: 34 imm8
void emit_xor_al_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0x34);
    e.u8(imm);
}

// inc r11 (REX.WB + FF /0): 49 FF C3
void emit_inc_r11(RawEmitter& e) {
    e.u8(0x49);
    e.u8(0xFF);
    e.u8(0xC3);
}

// add r11, imm8: 49 83 C3 imm8
void emit_add_r11_imm8(RawEmitter& e, int8_t imm) {
    e.u8(0x49);
    e.u8(0x83);
    e.u8(0xC3);
    e.u8(static_cast<uint8_t>(imm));
}

// lea r11, [rip + rel32]: 4C 8D 1D rel32
// Returns patch offset of the rel32 for later fixup.
size_t emit_lea_r11_rip_rel32(RawEmitter& e) {
    e.u8(0x4C);
    e.u8(0x8D);
    e.u8(0x1D);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

// mov r64, [rsp + rcx*8] : 48 8B 04 CC
// Encoded with SIB scale=3 (×8), index=rcx/rdx/etc, base=rsp(4)
// We emit for reg ∈ {rax, rcx, rdx} usually. Helper only for reg=rax.

// mov rax, [rsp + rdx*8]   48 8B 04 D4
void emit_mov_rax_rsp_rdx8(RawEmitter& e) {
    e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0xD4);
}

// mov rax, [rsp + rcx*8]   48 8B 04 CC
void emit_mov_rax_rsp_rcx8(RawEmitter& e) {
    e.u8(0x48); e.u8(0x8B); e.u8(0x04); e.u8(0xCC);
}

// mov [rsp + rcx*8], rax   48 89 04 CC
void emit_mov_rsp_rcx8_rax(RawEmitter& e) {
    e.u8(0x48); e.u8(0x89); e.u8(0x04); e.u8(0xCC);
}

// mov [rsp + rcx*8], rdx   48 89 14 CC
void emit_mov_rsp_rcx8_rdx(RawEmitter& e) {
    e.u8(0x48); e.u8(0x89); e.u8(0x14); e.u8(0xCC);
}

// mov rax, [rsp + disp8] (no SIB needed, RSP is base): 48 8B 44 24 disp8
void emit_mov_rax_rsp_disp8(RawEmitter& e, int8_t disp) {
    e.u8(0x48); e.u8(0x8B); e.u8(0x44); e.u8(0x24); e.u8(static_cast<uint8_t>(disp));
}
void emit_mov_rax_rsp_disp32(RawEmitter& e, int32_t disp) {
    e.u8(0x48); e.u8(0x8B); e.u8(0x84); e.u8(0x24); e.u32(static_cast<uint32_t>(disp));
}
void emit_mov_rsp_disp8_rax(RawEmitter& e, int8_t disp) {
    e.u8(0x48); e.u8(0x89); e.u8(0x44); e.u8(0x24); e.u8(static_cast<uint8_t>(disp));
}
void emit_mov_rsp_disp32_rax(RawEmitter& e, int32_t disp) {
    e.u8(0x48); e.u8(0x89); e.u8(0x84); e.u8(0x24); e.u32(static_cast<uint32_t>(disp));
}

// cmp al, imm8: 3C imm8
void emit_cmp_al_imm8(RawEmitter& e, uint8_t imm) {
    e.u8(0x3C);
    e.u8(imm);
}

// jmp rel32: E9 rel32
size_t emit_jmp_rel32(RawEmitter& e) {
    e.u8(0xE9);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

// jcc rel32 (0F 80+cc rel32)
size_t emit_jcc_rel32(RawEmitter& e, uint8_t cc) {
    e.u8(0x0F);
    e.u8(0x80 + cc);
    const auto patch = e.size();
    e.u32(0);
    return patch;
}

// ud2 (invalid): 0F 0B
void emit_ud2(RawEmitter& e) { e.u8(0x0F); e.u8(0x0B); }

// ret: C3
void emit_ret(RawEmitter& e) { e.u8(0xC3); }

// pushfq / popfq: 9C / 9D
void emit_pushfq(RawEmitter& e) { e.u8(0x9C); }
void emit_popfq(RawEmitter& e) { e.u8(0x9D); }

// push r: 50+r (no REX) or 41 50+(r-8)
void emit_push_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x50 + (reg & 0x07));
}
void emit_pop_reg(RawEmitter& e, uint8_t reg) {
    if (reg >= 8) e.u8(0x41);
    e.u8(0x58 + (reg & 0x07));
}

// Helper: patch a rel32 at `patch_offset` so it jumps from `instruction_end`
// to `target_offset`.
void patch_rel32(ByteBuffer& buf, size_t patch_offset, size_t instruction_end,
                 size_t target_offset)
{
    const auto rel = static_cast<int32_t>(
        static_cast<int64_t>(target_offset) - static_cast<int64_t>(instruction_end));
    std::memcpy(buf.data() + patch_offset, &rel, sizeof(int32_t));
}

// ============================================================================
// Handler generation helpers (ALU/logic on vm_regs in stack)
// ============================================================================

/**
 * @brief Эмитит prologue handler'а:
 *   movzx ecx, byte [r11]          ; dst_idx (operand byte 0)
 *   movzx edx, byte [r11+1]        ; src_idx (operand byte 1)
 *   xor cl, opkey                  ; decrypt (optional — operand bytes also encrypted)
 *   xor dl, opkey
 *   add r11, 2
 */
void emit_handler_load_2bytes(RawEmitter& e, uint8_t key) {
    // movzx ecx, byte [r11]         -> 41 0F B6 0B
    emit_movzx_r32_byte_mem(e, 1 /*rcx*/, 11 /*r11*/, 0);
    // movzx edx, byte [r11+1]       -> 41 0F B6 53 01
    emit_movzx_r32_byte_mem(e, 2 /*rdx*/, 11 /*r11*/, 1);
    // xor cl, key  : 80 F1 key  (REX not needed for cl)
    if (key != 0) {
        e.u8(0x80); e.u8(0xF1); e.u8(key);
        e.u8(0x80); e.u8(0xF2); e.u8(key);
    }
    // and cl, 0x0F  : 80 E1 0F — на всякий случай ограничиваем 4 битами
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
    e.u8(0x80); e.u8(0xE2); e.u8(0x0F);
    // add r11, 2
    emit_add_r11_imm8(e, 2);
}

/**
 * @brief Эмитит prologue для 1-операндного handler'а:
 *   movzx ecx, byte [r11]; xor cl,key; and cl,0x0F; inc r11
 */
void emit_handler_load_1byte(RawEmitter& e, uint8_t key) {
    emit_movzx_r32_byte_mem(e, 1, 11, 0);
    if (key != 0) {
        e.u8(0x80); e.u8(0xF1); e.u8(key);
    }
    e.u8(0x80); e.u8(0xE1); e.u8(0x0F);
    emit_inc_r11(e);
}

/**
 * @brief Прыжок обратно в dispatcher (заглушка, патчится после)
 * @return Патч-оффсет rel32
 */
size_t emit_jmp_to_dispatcher(RawEmitter& e) {
    return emit_jmp_rel32(e);
}

/**
 * @brief Читает 4 байта из bytecode stream в eax, расшифровывает key.
 *   mov eax, [r11]    41 8B 03
 *   xor eax, key32    35 imm32
 *   add r11, 4        49 83 C3 04
 * Возвращает расширенный rax с расшифрованным 32-бит imm.
 */
void emit_load_imm32_eax(RawEmitter& e, uint8_t key) {
    // mov eax, dword ptr [r11]   41 8B 03
    e.u8(0x41); e.u8(0x8B); e.u8(0x03);
    // xor eax, imm32 (каждый байт ^ key → 4 байта key ^ key ^ key ^ key)
    if (key != 0) {
        const uint32_t k32 = static_cast<uint32_t>(key) |
                             (static_cast<uint32_t>(key) << 8) |
                             (static_cast<uint32_t>(key) << 16) |
                             (static_cast<uint32_t>(key) << 24);
        e.u8(0x35); e.u32(k32);
    }
    // add r11, 4
    emit_add_r11_imm8(e, 4);
}

/**
 * @brief Читает 8 байт из bytecode stream в rax, расшифровывает key.
 *   mov rax, [r11]    49 8B 03    -- wait, that's 49 8B 03
 */
void emit_load_imm64_rax(RawEmitter& e, uint8_t key) {
    // mov rax, qword ptr [r11]   49 8B 03 (REX.WB, 8B /r, ModRM 00 000 011 = 03)
    e.u8(0x49); e.u8(0x8B); e.u8(0x03);
    if (key != 0) {
        // mov rdx, key8_replicated — build 64-bit key and xor
        const uint64_t k64 =
            static_cast<uint64_t>(key) * 0x0101010101010101ULL;
        // mov rdx, imm64  48 BA imm64
        e.u8(0x48); e.u8(0xBA); e.u64(k64);
        // xor rax, rdx   48 31 D0
        e.u8(0x48); e.u8(0x31); e.u8(0xD0);
    }
    // add r11, 8
    e.u8(0x49); e.u8(0x83); e.u8(0xC3); e.u8(0x08);
}

/**
 * @brief Вспомогательный: загружает адрес vm_regs[rcx] в rsi
 *   shl rcx, 3       48 C1 E1 03
 *   lea rsi, [rsp + rcx]   48 8D 34 0C  (SIB scale=0 ×1, index=rcx, base=rsp)
 */
void emit_vmreg_addr_rsi_from_rcx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE1); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x34); e.u8(0x0C);
}

/**
 * @brief Аналогично, но для rdx → rdi.
 *   shl rdx, 3       48 C1 E2 03
 *   lea rdi, [rsp + rdx]    48 8D 3C 14
 */
void emit_vmreg_addr_rdi_from_rdx(RawEmitter& e) {
    e.u8(0x48); e.u8(0xC1); e.u8(0xE2); e.u8(0x03);
    e.u8(0x48); e.u8(0x8D); e.u8(0x3C); e.u8(0x14);
}

// ============================================================================
// Specific handlers
// ============================================================================

/**
 * @brief Handler h_mov_rr: vm[dst] = vm[src]
 *   load 2 operand bytes (cl=dst, dl=src)
 *   rsi = &vm[dst], rdi = &vm[src]
 *   mov rax, [rdi]; mov [rsi], rax
 */
void emit_handler_mov_rr(RawEmitter& e, uint8_t key) {
    emit_handler_load_2bytes(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]   48 8B 07
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // mov [rsi], rax   48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/**
 * @brief Generic emitter для r-r ALU (add/sub/xor/and/or) через dst-addressing.
 *   rsi = &vm[dst], rdi = &vm[src]
 *   mov rax, [rdi]             load src value
 *   op_opcode [rsi], rax       apply to dst memory
 *
 * opcode_rm_r это байт opcode "OP r/m64, r64"  (add=0x01, sub=0x29, xor=0x31, and=0x21, or=0x09)
 */
void emit_handler_alu_rr(RawEmitter& e, uint8_t key, uint8_t op_mr) {
    emit_handler_load_2bytes(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rdi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x07);
    // OP [rsi], rax  ->  48 op_mr 06  (ModRM mod=0 reg=rax rm=rsi)
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

/**
 * @brief imul dst,src особая форма: imul r64,r/m64 = 0F AF /r
 *   mov rax, [rsi] ; mov rdx, [rdi] ; imul rax, rdx ; mov [rsi], rax
 */
void emit_handler_imul_rr(RawEmitter& e, uint8_t key) {
    emit_handler_load_2bytes(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_vmreg_addr_rdi_from_rdx(e);
    // mov rax, [rsi]  48 8B 06
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // imul rax, [rdi]  48 0F AF 07
    e.u8(0x48); e.u8(0x0F); e.u8(0xAF); e.u8(0x07);
    // mov [rsi], rax  48 89 06
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/**
 * @brief Handler h_mov_ri32: vm[dst] = sxt(imm32)
 *   load 1 operand (cl=dst), load imm32 into eax (zero-ext rax)
 *   НО: mov r64, sxt(imm32) НЕ zero-ext! Нужно знак-расширить.
 *   Проще: movsxd rax, eax  48 63 C0
 *   Затем store rax в [rsi]
 */
void emit_handler_mov_ri32(RawEmitter& e, uint8_t key) {
    emit_handler_load_1byte(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_load_imm32_eax(e, key);
    // movsxd rax, eax   48 63 C0
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/**
 * @brief Handler h_mov_ri64: vm[dst] = imm64
 */
void emit_handler_mov_ri64(RawEmitter& e, uint8_t key) {
    emit_handler_load_1byte(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_load_imm64_rax(e, key);
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

/**
 * @brief Generic ALU r-imm32 (add/sub/xor/and/or):
 *   opcode_81_ext — /0 add, /5 sub, /4 and, /1 or, /6 xor
 *   emit: load 1 byte dst, rsi=&dst, load imm32 eax, sxt to rax,
 *   op [rsi], rax using opcode_mr form.
 */
void emit_handler_alu_ri32(RawEmitter& e, uint8_t key, uint8_t op_mr) {
    emit_handler_load_1byte(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    emit_load_imm32_eax(e, key);
    // movsxd rax, eax
    e.u8(0x48); e.u8(0x63); e.u8(0xC0);
    // OP [rsi], rax   48 op_mr 06
    e.u8(0x48); e.u8(op_mr); e.u8(0x06);
}

/**
 * @brief Unary: not [rsi] / neg [rsi]
 *   48 F7 /2 06  for not
 *   48 F7 /3 06  for neg
 */
void emit_handler_unary(RawEmitter& e, uint8_t key, uint8_t sub_op) {
    emit_handler_load_1byte(e, key);
    emit_vmreg_addr_rsi_from_rcx(e);
    // OP qword ptr [rsi]
    // ModRM mod=0 reg=sub_op rm=6(rsi) → (sub_op << 3) | 6
    e.u8(0x48); e.u8(0xF7);
    e.u8(static_cast<uint8_t>((sub_op << 3) | 0x06));
}

/**
 * @brief Shift handlers: dst=cl(reg idx), count=dl
 *   load 2 bytes (cl=dst idx, dl=count)
 *   rsi = &vm[dst]
 *   mov rax, [rsi]
 *   mov cl, dl
 *   op rax, cl   (48 D3 /ext)
 *   mov [rsi], rax
 *
 * Problem: shl uses cl as shift count, but cl was holding dst_idx. After
 * we computed rsi from rcx, we can reuse cl (but we cleared via shl rcx,3).
 * Better: emit load_2bytes but preserve the count in rdx, use dl as count,
 * then copy dl → cl BEFORE shift.
 */
void emit_handler_shift(RawEmitter& e, uint8_t key, uint8_t sub_op) {
    emit_handler_load_2bytes(e, key);
    // rsi = &vm[dst]
    emit_vmreg_addr_rsi_from_rcx(e);
    // mov rax, [rsi]
    e.u8(0x48); e.u8(0x8B); e.u8(0x06);
    // mov cl, dl       88 D1
    e.u8(0x88); e.u8(0xD1);
    // OP rax, cl       48 D3 /ext (C0 + ext*8)
    e.u8(0x48); e.u8(0xD3);
    e.u8(static_cast<uint8_t>(0xC0 | (sub_op << 3)));
    // mov [rsi], rax
    e.u8(0x48); e.u8(0x89); e.u8(0x06);
}

} // anonymous namespace

// ============================================================================
// VmRuntimeGenerator::generate — главный метод
// ============================================================================

MxResult<VmRuntime> VmRuntimeGenerator::generate(
    const std::vector<VmInstruction>& instructions,
    Randomizer& rng)
{
    if (instructions.empty()) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            "VmRuntimeGenerator: пустой список VM инструкций"));
    }

    // ========================================================================
    // Шаг 1: рандомизируем opcode map (канон VmOp → handler_id)
    // + XOR-ключ (ненулевой) для stream encryption.
    // ========================================================================
    VmOpcodeMap map{};
    // opcode_xor_key = non-zero random byte
    do { map.opcode_xor_key = rng.next_u8(); } while (map.opcode_xor_key == 0);

    // Сколько handlers всего: generic (по одному на каждый VmOp, кроме exit) +
    //                        уникальный handler на каждый native insn + 1 exit
    // Для простоты: generic = kVmOpCount (включая exit, который будет handler 0 в canon),
    //                и каждый native получает свой handler.
    // handler_id пространство: [0, total_handlers)
    const uint32_t native_count =
        static_cast<uint32_t>(std::count_if(
            instructions.begin(), instructions.end(),
            [](const VmInstruction& v) { return v.op == VmOp::native; }));
    const uint32_t total_handlers = kVmOpCount + native_count;
    if (total_handlers > 255) {
        return std::unexpected(MxError(
            ProtectionErrorCode::vm_translation_error,
            std::format("VmRuntimeGenerator: слишком много handlers ({} > 255)",
                total_handlers)));
    }
    map.total_handlers = total_handlers;

    // Shuffle assignment for generic handlers (kVmOpCount slots out of total_handlers)
    std::vector<uint8_t> slots(total_handlers);
    std::iota(slots.begin(), slots.end(), static_cast<uint8_t>(0));
    std::shuffle(slots.begin(), slots.end(), rng.engine());

    for (uint32_t i = 0; i < kVmOpCount; ++i) {
        map.generic_handler_id[i] = slots[i];
    }
    // Остальные slots[kVmOpCount..] → native handler slots (по порядку первого появления)
    std::vector<uint8_t> native_handler_ids;
    native_handler_ids.reserve(native_count);
    for (uint32_t i = kVmOpCount; i < total_handlers; ++i) {
        native_handler_ids.push_back(slots[i]);
    }

    // ========================================================================
    // Шаг 2: собираем bytecode stream (до шифрования)
    // ========================================================================
    ByteBuffer bytecode_plain;
    bytecode_plain.reserve(instructions.size() * 4);

    uint32_t next_native_idx = 0;
    std::vector<uint32_t> native_handler_of_insn(instructions.size(), UINT32_MAX);

    for (size_t i = 0; i < instructions.size(); ++i) {
        const auto& vi = instructions[i];
        uint8_t handler_id;
        if (vi.op == VmOp::native) {
            handler_id = native_handler_ids[next_native_idx];
            native_handler_of_insn[i] = next_native_idx;
            ++next_native_idx;
        } else {
            handler_id = map.generic_handler_id[static_cast<uint32_t>(vi.op)];
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
                {
                    const uint32_t u = static_cast<uint32_t>(vi.imm32);
                    bytecode_plain.push_back(static_cast<uint8_t>(u & 0xFF));
                    bytecode_plain.push_back(static_cast<uint8_t>((u >> 8) & 0xFF));
                    bytecode_plain.push_back(static_cast<uint8_t>((u >> 16) & 0xFF));
                    bytecode_plain.push_back(static_cast<uint8_t>((u >> 24) & 0xFF));
                }
                break;

            case VmOp::mov_ri64:
                bytecode_plain.push_back(vi.dst);
                for (int b = 0; b < 8; ++b) {
                    bytecode_plain.push_back(static_cast<uint8_t>(
                        (vi.imm64 >> (b * 8)) & 0xFF));
                }
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

            case VmOp::native:
            case VmOp::exit:
            case VmOp::count_:
                // no operand bytes in stream for native (bytes are inlined in handler)
                // no operand bytes for exit
                break;
        }
    }

    // Append terminal exit opcode
    bytecode_plain.push_back(map.generic_handler_id[static_cast<uint32_t>(VmOp::exit)]);

    // Encrypt bytecode stream in-place with XOR key
    for (auto& b : bytecode_plain) {
        b = encrypt_byte(b, map.opcode_xor_key);
    }

    // ========================================================================
    // Шаг 3: эмитим runtime blob
    //   [entry][dispatcher][handlers][bytecode]
    // ========================================================================
    RawEmitter rt;

    // --- Entry ---
    const size_t entry_offset = rt.size();
    emit_pushfq(rt);
    // push r15..rax (15 pushes in reverse order, so last push = rax at [rsp+0])
    constexpr uint8_t push_order[] = {
        15, 14, 13, 12, 11, 10, 9, 8, 7 /*rdi*/, 6 /*rsi*/, 5 /*rbp*/,
        3 /*rbx*/, 2 /*rdx*/, 1 /*rcx*/, 0 /*rax*/
    };
    for (uint8_t r : push_order) {
        emit_push_reg(rt, r);
    }
    // lea r11, [rip + bytecode_rel32]
    const size_t entry_bc_patch = emit_lea_r11_rip_rel32(rt);
    // jmp dispatcher
    const size_t entry_disp_patch = emit_jmp_rel32(rt);

    // --- Dispatcher ---
    const size_t dispatcher_offset = rt.size();

    // movzx eax, byte [r11]        41 0F B6 03
    emit_movzx_r32_byte_mem(rt, 0 /*rax*/, 11, 0);
    // xor al, key
    emit_xor_al_imm8(rt, map.opcode_xor_key);
    // inc r11
    emit_inc_r11(rt);

    // For each handler_id, emit `cmp al, id; je handler_offset`
    // We build the handlers AFTER the dispatcher, so we track patch offsets.
    struct HandlerPatch {
        uint8_t handler_id;
        size_t  je_patch;     // offset of the rel32 in the je inside dispatcher
        size_t  je_end;
    };
    std::vector<HandlerPatch> dispatcher_patches;
    dispatcher_patches.reserve(total_handlers);

    // Per-build dispatch order randomization: shuffle the CMP/JE chain so that
    // the physical order of handler comparisons doesn't reveal handler IDs.
    std::vector<uint8_t> dispatch_order(total_handlers);
    std::iota(dispatch_order.begin(), dispatch_order.end(), static_cast<uint8_t>(0));
    std::shuffle(dispatch_order.begin(), dispatch_order.end(), rng.engine());

    for (const uint8_t h : dispatch_order) {
        emit_cmp_al_imm8(rt, h);
        const auto patch = emit_jcc_rel32(rt, 0x04 /*je*/);
        dispatcher_patches.push_back({h, patch, rt.size()});

        // Inject a few junk no-side-effect bytes occasionally between entries
        // to break up the uniform cmp/je pattern for static analyzers.
        if ((rng.next_u32() & 0x3) == 0) {
            // emit multi-byte NOP (66 0F 1F 44 00 00 — 6-byte nop)
            rt.u8(0x66); rt.u8(0x0F); rt.u8(0x1F); rt.u8(0x44); rt.u8(0x00); rt.u8(0x00);
        }
    }
    // Fallthrough = ud2 (invalid opcode trap)
    emit_ud2(rt);

    // --- Handlers ---
    std::vector<size_t> handler_offset_by_id(total_handlers, SIZE_MAX);
    std::vector<size_t> handler_jmp_patches;  // all jmp-to-dispatcher patches (global)
    std::vector<size_t> handler_jmp_ends;
    std::vector<size_t> exit_ret_patches;      // exit handler does ret — no dispatcher jump

    // Helper to emit a handler wrapper (offset + jmp dispatcher patch)
    auto begin_handler = [&](uint8_t handler_id) {
        handler_offset_by_id[handler_id] = rt.size();
    };
    auto end_handler_goto_dispatcher = [&]() {
        const auto patch = emit_jmp_to_dispatcher(rt);
        handler_jmp_patches.push_back(patch);
        handler_jmp_ends.push_back(rt.size());
    };

    // Generic handlers (kVmOpCount штук)
    for (uint32_t opi = 0; opi < kVmOpCount; ++opi) {
        const auto op = static_cast<VmOp>(opi);
        const uint8_t hid = map.generic_handler_id[opi];
        begin_handler(hid);

        const uint8_t key = map.opcode_xor_key;
        switch (op) {
            case VmOp::mov_rr:
                emit_handler_mov_rr(rt, key); break;
            case VmOp::add_rr:
                emit_handler_alu_rr(rt, key, 0x01); break;
            case VmOp::sub_rr:
                emit_handler_alu_rr(rt, key, 0x29); break;
            case VmOp::xor_rr:
                emit_handler_alu_rr(rt, key, 0x31); break;
            case VmOp::and_rr:
                emit_handler_alu_rr(rt, key, 0x21); break;
            case VmOp::or_rr:
                emit_handler_alu_rr(rt, key, 0x09); break;
            case VmOp::imul_rr:
                emit_handler_imul_rr(rt, key); break;

            case VmOp::mov_ri32:
                emit_handler_mov_ri32(rt, key); break;
            case VmOp::add_ri32:
                emit_handler_alu_ri32(rt, key, 0x01); break;
            case VmOp::sub_ri32:
                emit_handler_alu_ri32(rt, key, 0x29); break;
            case VmOp::xor_ri32:
                emit_handler_alu_ri32(rt, key, 0x31); break;
            case VmOp::and_ri32:
                emit_handler_alu_ri32(rt, key, 0x21); break;
            case VmOp::or_ri32:
                emit_handler_alu_ri32(rt, key, 0x09); break;

            case VmOp::mov_ri64:
                emit_handler_mov_ri64(rt, key); break;

            case VmOp::not_r:
                emit_handler_unary(rt, key, 2); break;  // /2
            case VmOp::neg_r:
                emit_handler_unary(rt, key, 3); break;  // /3

            case VmOp::shl_ri:
                emit_handler_shift(rt, key, 4); break;  // /4
            case VmOp::shr_ri:
                emit_handler_shift(rt, key, 5); break;  // /5
            case VmOp::sar_ri:
                emit_handler_shift(rt, key, 7); break;  // /7
            case VmOp::rol_ri:
                emit_handler_shift(rt, key, 0); break;  // /0
            case VmOp::ror_ri:
                emit_handler_shift(rt, key, 1); break;  // /1

            case VmOp::native: {
                // Generic "native" handler (shouldn't be invoked; each native insn has own handler)
                emit_ud2(rt);
                break;
            }
            case VmOp::exit: {
                // Exit: pop all regs and ret
                constexpr uint8_t pop_order[] = {
                    0 /*rax*/, 1 /*rcx*/, 2 /*rdx*/, 3 /*rbx*/, 5 /*rbp*/,
                    6 /*rsi*/, 7 /*rdi*/, 8, 9, 10, 11, 12, 13, 14, 15
                };
                for (uint8_t r : pop_order) emit_pop_reg(rt, r);
                emit_popfq(rt);
                emit_ret(rt);
                continue;  // no jmp dispatcher
            }
            case VmOp::count_:
                break;
        }

        if (op != VmOp::exit && op != VmOp::native) {
            end_handler_goto_dispatcher();
        }
    }

    // Native handlers — по одному на каждый native insn
    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].op != VmOp::native) continue;
        const uint8_t hid = native_handler_ids[native_handler_of_insn[i]];
        begin_handler(hid);

        // --- Native handler body ---
        // 1) Save vpc (r11) to scratch slot [rsp + ctx_size + 8_ret_addr]
        //    But we don't have a scratch slot. Use a fresh push/pop? We can't
        //    push because that shifts stack offsets used by entry context mapping.
        //    Instead: save r11 into a SAFE unused vm_reg slot? RSP slot (offset 24 for RBX!)
        //    Actually slot 4 (RSP) is unused by generic ops — we can use it.
        //    But then native insn might reference rsp... which we forbade.
        //    Wait — vm_reg[4] (RSP) slot doesn't exist in our layout: we skipped it!
        //    Our layout: rbp at offset 32. There's NO rsp slot in the save area.
        //    We need a genuine scratch slot. Let's reserve one extra qword just
        //    before the context via `sub rsp, 8; restore later`. That changes
        //    offsets though.
        //
        //    Alternative: use vm_reg[RSI] (offset 40) — but native insn might use rsi.
        //    There's no free slot.
        //
        //    Best: inside the native handler itself, use a LOCAL 'sub rsp, 16' /
        //    'add rsp, 16' wrapper to reserve temporary scratch.
        //
        //    BUT that shifts all vm_reg offsets by +16 during the handler's body,
        //    and the save/restore below must use the shifted offsets.
        //
        //    Let me just do it:
        //
        //    sub rsp, 16            ; reserve scratch
        //    mov [rsp], r11         ; save vpc
        //    ; now ctx regs start at [rsp + 16], so all offsets shift +16
        //    mov rax, [rsp + 16 + offset(RAX)]
        //    ; ... (reload all native regs from ctx)
        //    ; note: r11 ctx value is loaded here; we'll restore vpc from [rsp] after
        //    <native bytes>
        //    ; save all regs BACK to ctx (still at [rsp + 16 + ...])
        //    mov [rsp + 16 + ...], rax
        //    ; ...
        //    mov r11, [rsp]          ; restore vpc
        //    add rsp, 16             ; release scratch
        //    jmp dispatcher

        // Emit:
        //  sub rsp, 16   ->  48 83 EC 10
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xEC); rt.u8(0x10);
        //  mov [rsp], r11  ->  4C 89 1C 24
        rt.u8(0x4C); rt.u8(0x89); rt.u8(0x1C); rt.u8(0x24);

        // Reload native registers from ctx (at [rsp + 16 + offset[i]])
        // For each VM reg that maps to a native GPR (skipping RSP idx 4 — no entry):
        struct RegLoad { uint8_t native_reg; int32_t offset; };
        const RegLoad loads[] = {
            {0, 16 + 0},   {1, 16 + 8},   {2, 16 + 16},  {3, 16 + 24},
            /* RSP skipped */
            {5, 16 + 32},  {6, 16 + 40},  {7, 16 + 48},
            {8, 16 + 56},  {9, 16 + 64},  {10, 16 + 72},
            {11, 16 + 80}, // r11 (will overwrite vpc — that's why we saved)
            {12, 16 + 88}, {13, 16 + 96}, {14, 16 + 104}, {15, 16 + 112},
        };

        for (const auto& l : loads) {
            // mov reg, [rsp + disp]
            // REX.W [+ R if reg>=8] [+ B for base=rsp (none needed — rsp is base, no REX.B)]
            // REX = 48 + (reg>=8 ? 4 : 0) = 48 or 4C
            uint8_t rex = 0x48 | ((l.native_reg >= 8) ? 0x04 : 0x00);
            rt.u8(rex);
            rt.u8(0x8B);
            // ModRM: mod depends on disp, reg = l.native_reg & 7, rm = 100 (SIB)
            const uint8_t reg3 = l.native_reg & 0x07;
            if (l.offset >= -128 && l.offset <= 127) {
                rt.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24); // SIB: scale=0 index=4(none) base=rsp
                rt.u8(static_cast<uint8_t>(static_cast<int8_t>(l.offset)));
            } else {
                rt.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u32(static_cast<uint32_t>(l.offset));
            }
        }

        // Adjust rsp so the native instruction sees the caller's frame.
        // Layout at this point (relative to caller-rsp at CALL vm_entry):
        //   [caller_rsp - 8]   = return address (CALL)
        //   [caller_rsp - 16]  = rflags (pushfq)
        //   [caller_rsp - 16 - 120] = 15 saved regs (last push = rax at lowest)
        //   [caller_rsp - 136 - 16] = scratch (sub rsp, 16)
        // So current rsp = caller_rsp - 152. To make [rsp+X] access caller's
        // frame again, we need `add rsp, 152` before and `sub rsp, 152` after.
        constexpr int32_t kNativeFrameShift = 152;
        // add rsp, 152     48 81 C4 98 00 00 00
        rt.u8(0x48); rt.u8(0x81); rt.u8(0xC4);
        rt.u32(static_cast<uint32_t>(kNativeFrameShift));

        // Execute native bytes
        rt.bytes(ByteView{
            instructions[i].native_bytes.data(),
            instructions[i].native_bytes.size()});

        // sub rsp, 152     48 81 EC 98 00 00 00
        rt.u8(0x48); rt.u8(0x81); rt.u8(0xEC);
        rt.u32(static_cast<uint32_t>(kNativeFrameShift));

        // Save all native regs back to ctx (store form)
        for (const auto& l : loads) {
            uint8_t rex = 0x48 | ((l.native_reg >= 8) ? 0x04 : 0x00);
            rt.u8(rex);
            rt.u8(0x89);
            const uint8_t reg3 = l.native_reg & 0x07;
            if (l.offset >= -128 && l.offset <= 127) {
                rt.u8(static_cast<uint8_t>((1 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u8(static_cast<uint8_t>(static_cast<int8_t>(l.offset)));
            } else {
                rt.u8(static_cast<uint8_t>((2 << 6) | (reg3 << 3) | 4));
                rt.u8(0x24);
                rt.u32(static_cast<uint32_t>(l.offset));
            }
        }

        // Restore vpc from scratch slot: mov r11, [rsp]   ->  4C 8B 1C 24
        rt.u8(0x4C); rt.u8(0x8B); rt.u8(0x1C); rt.u8(0x24);
        // add rsp, 16      48 83 C4 10
        rt.u8(0x48); rt.u8(0x83); rt.u8(0xC4); rt.u8(0x10);

        end_handler_goto_dispatcher();
    }

    // --- Bytecode ---
    // Align to 8 bytes for nicer layout (optional)
    while (rt.size() % 8 != 0) rt.u8(0xCC);
    const size_t bytecode_offset = rt.size();
    rt.bytes(ByteView{bytecode_plain.data(), bytecode_plain.size()});

    // ========================================================================
    // Шаг 4: patching
    // ========================================================================

    // entry → dispatcher
    patch_rel32(rt.buf, entry_disp_patch, entry_disp_patch + 4, dispatcher_offset);
    // entry → bytecode (via lea r11, [rip+rel32])
    patch_rel32(rt.buf, entry_bc_patch, entry_bc_patch + 4, bytecode_offset);
    // dispatcher → each handler
    for (const auto& hp : dispatcher_patches) {
        if (handler_offset_by_id[hp.handler_id] == SIZE_MAX) {
            return std::unexpected(MxError(
                ProtectionErrorCode::vm_translation_error,
                std::format("VmRuntimeGenerator: handler id {} не сгенерирован",
                    hp.handler_id)));
        }
        patch_rel32(rt.buf, hp.je_patch, hp.je_end,
                    handler_offset_by_id[hp.handler_id]);
    }
    // handlers → dispatcher (jmp at end of each generic/native handler)
    for (size_t i = 0; i < handler_jmp_patches.size(); ++i) {
        patch_rel32(rt.buf, handler_jmp_patches[i], handler_jmp_ends[i],
                    dispatcher_offset);
    }

    VmRuntime result;
    result.blob = std::move(rt.buf);
    result.entry_offset = static_cast<uint32_t>(entry_offset);
    result.bytecode_offset = static_cast<uint32_t>(bytecode_offset);
    result.bytecode_size = static_cast<uint32_t>(bytecode_plain.size());
    result.handler_count = total_handlers;
    result.opcode_map = map;
    return result;
}

} // namespace mx::vm
