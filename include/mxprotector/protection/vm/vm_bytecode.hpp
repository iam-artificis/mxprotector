/**
 * @file vm_bytecode.hpp
 * @brief [BUILDER] VM bytecode — определения опкодов и инструкций VM.
 *
 * Каждая VM-инструкция = 1 байт handler-индекса + фиксированное количество
 * операндных байт, определяемое каноническим опкодом. Handler-индекс
 * отличается от канонического опкода: mapping рандомизируется при каждой сборке.
 *
 * Байткод + операндные байты XOR-шифруются stream-ключом (opcode_xor_key).
 */

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "mxprotector/core/types.hpp"

namespace mx::vm {

/**
 * @brief Канонические VM-опкоды (до permutation).
 *
 * Полностью покрывают linear straight-line ALU-код. Для всего остального
 * используется VmOp::native — handler выполняет инлайн сырые байты инструкции.
 */
enum class VmOp : uint8_t {
    mov_rr = 0,   ///< mov vm[dst], vm[src]           operands: [dst,src]
    add_rr,       ///< add vm[dst], vm[src]           operands: [dst,src]
    sub_rr,       ///< sub vm[dst], vm[src]           operands: [dst,src]
    xor_rr,       ///< xor vm[dst], vm[src]           operands: [dst,src]
    and_rr,       ///< and vm[dst], vm[src]           operands: [dst,src]
    or_rr,        ///< or  vm[dst], vm[src]           operands: [dst,src]
    imul_rr,      ///< imul vm[dst], vm[src]          operands: [dst,src]

    mov_ri32,     ///< mov vm[dst], sxt(imm32)        operands: [dst,imm32]
    add_ri32,     ///< add vm[dst], sxt(imm32)        operands: [dst,imm32]
    sub_ri32,     ///< sub vm[dst], sxt(imm32)        operands: [dst,imm32]
    xor_ri32,     ///< xor vm[dst], sxt(imm32)        operands: [dst,imm32]
    and_ri32,     ///< and vm[dst], sxt(imm32)        operands: [dst,imm32]
    or_ri32,      ///< or  vm[dst], sxt(imm32)        operands: [dst,imm32]

    mov_ri64,     ///< mov vm[dst], imm64             operands: [dst,imm64]

    not_r,        ///< not vm[dst]                    operands: [dst]
    neg_r,        ///< neg vm[dst]                    operands: [dst]

    shl_ri,       ///< shl vm[dst], imm8              operands: [dst,count]
    shr_ri,       ///< shr vm[dst], imm8              operands: [dst,count]
    sar_ri,       ///< sar vm[dst], imm8              operands: [dst,count]
    rol_ri,       ///< rol vm[dst], imm8              operands: [dst,count]
    ror_ri,       ///< ror vm[dst], imm8              operands: [dst,count]

    // Virtual control-flow — VM branches within its own bytecode stream.
    // Operand is a signed 4-byte offset relative to the byte AFTER the operand
    // (i.e., the next opcode position), plus a 1-byte key-checkpoint that
    // reseeds the rolling key at the target so branch paths converge correctly.
    vjmp,         ///< unconditional bytecode jump   operands: [rel32, key_ckpt]
    vjcc,         ///< conditional bytecode jump     operands: [cc, rel32, key_ckpt]

    native,       ///< execute inlined native bytes   no operand bytes (handler is specialized)
    exit,         ///< restore ctx & return           no operand bytes

    // G4 dead opcode. Zero operands, empty handler body. Inserted
    // by the encoder at random positions between real instructions
    // to defeat static bytecode analysis (static recovery now has
    // to distinguish "live" from "dead" opcode bytes without running
    // the VM). The handler is flag-transparent by construction —
    // the body is empty, and the tail dispatch is emitted inline
    // with save_rflags=false so it never touches vflags.
    dead,

    // G4 opaque branch. 4-byte rel32-shaped operand, no actual
    // branching. Handler fetches the 4 bytes (advancing r11) and
    // falls through without ever adding the rel32 to r11. Looks
    // like a `vjmp` at the byte level — a reverser parsing the
    // encrypted bytecode linearly sees a handler_id followed by
    // 4 operand bytes and has to trace into the handler body to
    // discover that the rel32 is never added to the VPC. Paired
    // with encoder-side insertion of "dead bytecode" past the fake
    // target, it makes static recovery of the real control flow
    // significantly harder.
    opq_branch,

    count_        ///< sentinel
};

constexpr uint32_t kVmOpCount = static_cast<uint32_t>(VmOp::count_);

/**
 * @brief Возвращает размер операндных байт для опкода (native/exit = 0).
 */
[[nodiscard]] constexpr uint8_t vm_op_operand_size(VmOp op) noexcept {
    switch (op) {
        case VmOp::mov_rr:
        case VmOp::add_rr:
        case VmOp::sub_rr:
        case VmOp::xor_rr:
        case VmOp::and_rr:
        case VmOp::or_rr:
        case VmOp::imul_rr:
            return 2;

        case VmOp::mov_ri32:
        case VmOp::add_ri32:
        case VmOp::sub_ri32:
        case VmOp::xor_ri32:
        case VmOp::and_ri32:
        case VmOp::or_ri32:
            return 1 + 4;

        case VmOp::mov_ri64:
            return 1 + 8;

        case VmOp::not_r:
        case VmOp::neg_r:
            return 1;

        case VmOp::shl_ri:
        case VmOp::shr_ri:
        case VmOp::sar_ri:
        case VmOp::rol_ri:
        case VmOp::ror_ri:
            return 2;

        case VmOp::vjmp:
            return 4;           // rel32 only (static XOR for branched regions)

        case VmOp::vjcc:
            return 4;           // rel32 only (CC is baked into handler variant)

        case VmOp::native:
        case VmOp::exit:
        case VmOp::dead:
            return 0;

        case VmOp::opq_branch:
            return 4;           // rel32-shaped operand (never actually added to r11)

        case VmOp::count_:
            return 0;
    }
    return 0;
}

/**
 * @brief Одна VM-инструкция, полученная при лифтинге x64 → bytecode.
 */
struct VmInstruction {
    VmOp     op = VmOp::exit;
    uint8_t  dst = 0;             ///< VM reg index [0..15]
    uint8_t  src = 0;             ///< VM reg index [0..15]
    uint8_t  shift_count = 0;     ///< для shift/rot
    int32_t  imm32 = 0;           ///< 32-бит immediate
    uint64_t imm64 = 0;           ///< 64-бит immediate
    ByteBuffer native_bytes;      ///< для VmOp::native — сырые байты x64 инструкции
    Va       original_va = 0;     ///< для диагностики

    // Virtual control-flow (vjmp / vjcc)
    uint8_t  branch_cc = 0;       ///< x86 condition code for vjcc (0x0..0xF)
    uint32_t branch_target_insn = 0; ///< index into VmInstruction array (resolved by lifter)
};

/**
 * @brief Per-build рандомизация: handler-индексы для каждого опкода и XOR-ключ.
 *
 * Handler-индексы — перестановка [0..N) где N = количество handlers в регионе.
 * В регионе: kVmOpCount generic handlers + native_count специальных.
 */
struct VmOpcodeMap {
    std::array<uint8_t, kVmOpCount> generic_handler_id{};  ///< VmOp → handler_id
    uint8_t opcode_xor_key = 0;                             ///< stream XOR key (non-zero)
    uint32_t total_handlers = 0;                            ///< всего handlers (generic + native)
};

} // namespace mx::vm
