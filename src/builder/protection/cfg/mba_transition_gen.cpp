/**
 * @file mba_transition_gen.cpp
 * @brief [BUILDER] Реализация генератора MBA-обфусцированных state-переходов.
 *
 * @details Генерирует цепочку 32-битных x86 инструкций (add, sub, xor, not, rol, ror),
 *          трансформирующую state-регистр из текущего состояния в целевое.
 *
 *          Все инструкции эмитируются БЕЗ REX.W (32-битный режим операндов),
 *          что обеспечивает zero-extension в 64-битном режиме.
 *          Для расширенных регистров (r8-r15) используется REX.B.
 *
 *          Encoding (32-bit mode, ModRM reg-imm):
 *          - ADD r32, imm32: [REX.B] 81 /0 id
 *          - SUB r32, imm32: [REX.B] 81 /5 id
 *          - XOR r32, imm32: [REX.B] 81 /6 id
 *          - NOT r32:        [REX.B] F7 /2
 *          - ROL r32, imm8:  [REX.B] C1 /0 ib
 *          - ROR r32, imm8:  [REX.B] C1 /1 ib
 */

#include "mxprotector/protection/cfg/mba_transition_gen.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

#include <bit>

namespace mx {

MbaTransitionGenerator::MbaTransitionGenerator(Architecture arch)
    : arch_(arch)
{}

uint32_t MbaTransitionGenerator::rotl32(uint32_t value, uint32_t count) noexcept {
    count &= 31;
    if (count == 0) return value;
    return (value << count) | (value >> (32 - count));
}

uint32_t MbaTransitionGenerator::rotr32(uint32_t value, uint32_t count) noexcept {
    count &= 31;
    if (count == 0) return value;
    return (value >> count) | (value << (32 - count));
}

void MbaTransitionGenerator::emit_op_32bit(
    ByteBuffer& out, OpType type, uint32_t constant, x86::Reg reg) const
{
    const uint8_t reg_num = static_cast<uint8_t>(reg);
    const bool needs_rex_b = (reg_num >= 8);
    const uint8_t rm_3bit = reg_num & 0x07;

    auto emit_rex_b = [&]() {
        if (needs_rex_b) {
            out.push_back(0x41); // REX.B
        }
    };

    auto emit_modrm = [&](uint8_t reg_field) {
        out.push_back(x86::make_modrm(3, reg_field, rm_3bit));
    };

    auto emit_imm32 = [&](uint32_t imm) {
        out.push_back(static_cast<uint8_t>(imm & 0xFF));
        out.push_back(static_cast<uint8_t>((imm >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>((imm >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((imm >> 24) & 0xFF));
    };

    switch (type) {
        case OpType::add_imm:
            emit_rex_b();
            out.push_back(0x81);
            emit_modrm(0); // /0
            emit_imm32(constant);
            break;

        case OpType::sub_imm:
            emit_rex_b();
            out.push_back(0x81);
            emit_modrm(5); // /5
            emit_imm32(constant);
            break;

        case OpType::xor_imm:
            emit_rex_b();
            out.push_back(0x81);
            emit_modrm(6); // /6
            emit_imm32(constant);
            break;

        case OpType::not_op:
            emit_rex_b();
            out.push_back(0xF7);
            emit_modrm(2); // /2
            break;

        case OpType::rol_imm: {
            const uint8_t count = static_cast<uint8_t>(constant & 31);
            emit_rex_b();
            if (count == 1) {
                out.push_back(0xD1);
                emit_modrm(0); // /0
            } else {
                out.push_back(0xC1);
                emit_modrm(0); // /0
                out.push_back(count);
            }
            break;
        }

        case OpType::ror_imm: {
            const uint8_t count = static_cast<uint8_t>(constant & 31);
            emit_rex_b();
            if (count == 1) {
                out.push_back(0xD1);
                emit_modrm(1); // /1
            } else {
                out.push_back(0xC1);
                emit_modrm(1); // /1
                out.push_back(count);
            }
            break;
        }
    }
}

ByteBuffer MbaTransitionGenerator::generate(
    uint32_t current_state,
    uint32_t next_state,
    x86::Reg state_reg,
    Randomizer& rng,
    bool state_preserved)
{
    current_state = sanitize_state_id(current_state);
    next_state = sanitize_state_id(next_state);

    // Forward synthesis: state_reg already holds current_state at entry
    // (if state_preserved == true). Generate chain_len-1 random ops accumulating
    // a running value; the final XOR closes the gap so the total chain transforms
    // current_state → next_state without re-loading the register via MOV.
    //
    // Property: when state_preserved is true, next_state is a deterministic
    // function of BOTH current_state AND the (build-time-fixed) chain. A decoder
    // must simulate the full arithmetic per block instead of just reading
    // `mov reg, NEXT_STATE`.
    //
    // When state_preserved is false (block clobbers state_reg, e.g. via CALL),
    // we fall back to loading `required_input` first, then applying the chain.
    const uint32_t chain_len = rng.next_range(6, 12);

    std::vector<ChainOp> chain;
    chain.reserve(chain_len);

    const uint32_t start_value = state_preserved ? current_state : rng.next_u32();
    uint32_t value = start_value;

    for (uint32_t i = 0; i + 1 < chain_len; ++i) {
        const auto op_idx = rng.next_range(0, 5);
        ChainOp op;

        switch (op_idx) {
            case 0: {
                uint32_t K = rng.next_u32() | 1;
                op = {OpType::add_imm, K};
                value += K;
                break;
            }
            case 1: {
                uint32_t K = rng.next_u32() | 1;
                op = {OpType::sub_imm, K};
                value -= K;
                break;
            }
            case 2: {
                uint32_t K = rng.next_u32();
                op = {OpType::xor_imm, K};
                value ^= K;
                break;
            }
            case 3: {
                op = {OpType::not_op, 0};
                value = ~value;
                break;
            }
            case 4: {
                uint32_t K = rng.next_range(1, 31);
                op = {OpType::rol_imm, K};
                value = rotl32(value, K);
                break;
            }
            case 5: {
                uint32_t K = rng.next_range(1, 31);
                op = {OpType::ror_imm, K};
                value = rotr32(value, K);
                break;
            }
            default:
                break;
        }

        chain.push_back(op);
    }

    // Final XOR: closes the gap so `value ^ correction == next_state`.
    const uint32_t correction = value ^ next_state;
    chain.push_back(ChainOp{OpType::xor_imm, correction});

    ByteBuffer result;
    result.reserve(chain_len * 7 + 7);

    if (!state_preserved) {
        // Fallback: load start_value (random seed) into state_reg via
        // MOV r32, imm32 (REX.B + B8+rd + imm32, zero-extends to 64-bit).
        const uint8_t reg_num = static_cast<uint8_t>(state_reg);
        if (reg_num >= 8) {
            result.push_back(0x41); // REX.B
        }
        result.push_back(static_cast<uint8_t>(0xB8 + (reg_num & 0x07)));
        result.push_back(static_cast<uint8_t>(start_value & 0xFF));
        result.push_back(static_cast<uint8_t>((start_value >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>((start_value >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((start_value >> 24) & 0xFF));
    }

    // Emit the chain directly onto state_reg. When state_preserved,
    // state_reg starts at current_state; after the chain it equals next_state.
    for (const auto& op : chain) {
        emit_op_32bit(result, op.type, op.constant, state_reg);
    }

    return result;
}

} // namespace mx
