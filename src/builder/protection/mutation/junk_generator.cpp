/**
 * @file junk_generator.cpp
 * @brief [BUILDER] Реализация генератора мёртвого кода (junk code) x86/x64.
 *
 * @details Генерирует NOP-эквивалентные последовательности машинного кода:
 *          push/pop, self-canceling арифметика, flag-safe операции.
 *          Каждый паттерн не изменяет состояние процессора (регистры, флаги,
 *          стек, память остаются без изменений после выполнения паттерна).
 *
 * @note Паттерны рандомизируются: регистры, значения и типы выбираются случайно.
 *       Минимальный размер паттерна — 2 байта (push/pop r64 без REX).
 */

#include "mxprotector/protection/mutation/junk_generator.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx {

// ============================================================================
// generate — основной метод генерации junk заданного размера
// ============================================================================

ByteBuffer JunkGenerator::generate(size_t desired_size, Randomizer& rng) const {
    if (desired_size == 0) return {};

    ByteBuffer result;
    result.reserve(desired_size);

    while (result.size() < desired_size) {
        const size_t remaining = desired_size - result.size();

        if (remaining < 2) {
            auto nop = x86::make_nop(static_cast<uint8_t>(remaining));
            result.insert(result.end(), nop.begin(), nop.end());
            break;
        }

        auto pattern = generate_single_pattern(rng);

        if (pattern.size() > remaining) {
            auto nop = x86::make_nop(static_cast<uint8_t>(remaining));
            result.insert(result.end(), nop.begin(), nop.end());
            break;
        }

        result.insert(result.end(), pattern.begin(), pattern.end());
    }

    return result;
}

// ============================================================================
// generate_single_pattern — один случайный junk-паттерн
// ============================================================================

ByteBuffer JunkGenerator::generate_single_pattern(Randomizer& rng) const {
    const uint32_t choice = rng.next_range(0, 6);

    switch (choice) {
        case 0:  return gen_push_pop(rng);
        case 1:  return gen_self_canceling_arithmetic(rng);
        case 2:  return gen_flag_safe_arithmetic(rng);
        case 3:  return gen_dead_mov(rng);
        case 4:  return gen_xchg_pair(rng);
        case 5:  return gen_double_not(rng);
        default: return gen_double_bswap(rng);
    }
}

// ============================================================================
// gen_push_pop — PUSH reg; POP reg (2 или 4 байта)
// ============================================================================

ByteBuffer JunkGenerator::gen_push_pop(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 7));

    ByteBuffer result;

    if (arch_ == Architecture::x64 && rng.next_bool(0.3)) {
        const uint8_t ext_reg = static_cast<uint8_t>(rng.next_range(0, 7));
        result.push_back(0x41);
        result.push_back(static_cast<uint8_t>(0x50 + ext_reg));
        result.push_back(0x41);
        result.push_back(static_cast<uint8_t>(0x58 + ext_reg));
    } else {
        result.push_back(static_cast<uint8_t>(0x50 + reg));
        result.push_back(static_cast<uint8_t>(0x58 + reg));
    }

    return result;
}

// ============================================================================
// gen_self_canceling_arithmetic — ADD+SUB или XOR+XOR (4–6 байт)
// ============================================================================

ByteBuffer JunkGenerator::gen_self_canceling_arithmetic(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 5));
    if (reg == 4) return gen_push_pop(rng);

    const uint8_t imm = static_cast<uint8_t>(rng.next_range(1, 127));
    const uint32_t variant = rng.next_range(0, 1);

    ByteBuffer result;

    if (variant == 0) {
        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 0, reg));
        result.push_back(imm);

        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 5, reg));
        result.push_back(imm);
    } else {
        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 6, reg));
        result.push_back(imm);

        result.push_back(0x83);
        result.push_back(x86::make_modrm(3, 6, reg));
        result.push_back(imm);
    }

    return result;
}

// ============================================================================
// gen_flag_safe_arithmetic — PUSHFQ + dead арифметика + POPFQ (x64 only)
// ============================================================================

ByteBuffer JunkGenerator::gen_flag_safe_arithmetic(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 5));
    if (reg == 4) return gen_push_pop(rng);

    const uint8_t imm = static_cast<uint8_t>(rng.next_range(1, 127));

    ByteBuffer result;

    result.push_back(0x9C);

    result.push_back(static_cast<uint8_t>(0x50 + reg));

    result.push_back(0x83);
    result.push_back(x86::make_modrm(3, 0, reg));
    result.push_back(imm);

    result.push_back(0x83);
    result.push_back(x86::make_modrm(3, 5, reg));
    result.push_back(imm);

    result.push_back(static_cast<uint8_t>(0x58 + reg));

    result.push_back(0x9D);

    return result;
}

// ============================================================================
// gen_dead_mov — MOV reg, reg (NOP-эквивалент для 32-bit, 2 байта)
// ============================================================================

ByteBuffer JunkGenerator::gen_dead_mov(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 7));
    if (reg == 4 || reg == 5) return gen_push_pop(rng);

    ByteBuffer result;

    if (arch_ == Architecture::x64) {
        result.push_back(0x48);
        result.push_back(0x89);
        result.push_back(x86::make_modrm(3, reg, reg));
    } else {
        result.push_back(0x89);
        result.push_back(x86::make_modrm(3, reg, reg));
    }

    return result;
}

// ============================================================================
// gen_xchg_pair — XCHG reg1,reg2; XCHG reg1,reg2 (полный NOP-эквивалент, 4 байта)
// ============================================================================

ByteBuffer JunkGenerator::gen_xchg_pair(Randomizer& rng) const {
    uint8_t reg1 = static_cast<uint8_t>(rng.next_range(0, 5));
    uint8_t reg2 = static_cast<uint8_t>(rng.next_range(0, 5));
    if (reg1 == 4) reg1 = 6;
    if (reg2 == 4) reg2 = 7;
    if (reg1 == reg2) reg2 = (reg1 + 1) % 4;

    ByteBuffer result;
    result.push_back(0x87);
    result.push_back(x86::make_modrm(3, reg1, reg2));
    result.push_back(0x87);
    result.push_back(x86::make_modrm(3, reg1, reg2));
    return result;
}

// ============================================================================
// gen_double_not — NOT reg; NOT reg (identity, 4 байта)
// ============================================================================

ByteBuffer JunkGenerator::gen_double_not(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 5));
    if (reg == 4) return gen_push_pop(rng);

    ByteBuffer result;
    result.push_back(0xF7);
    result.push_back(x86::make_modrm(3, 2, reg));
    result.push_back(0xF7);
    result.push_back(x86::make_modrm(3, 2, reg));
    return result;
}

// ============================================================================
// gen_double_bswap — BSWAP reg; BSWAP reg (identity, 4 байта)
// ============================================================================

ByteBuffer JunkGenerator::gen_double_bswap(Randomizer& rng) const {
    const uint8_t reg = static_cast<uint8_t>(rng.next_range(0, 5));
    if (reg == 4) return gen_push_pop(rng);

    ByteBuffer result;
    result.push_back(0x0F);
    result.push_back(static_cast<uint8_t>(0xC8 + reg));
    result.push_back(0x0F);
    result.push_back(static_cast<uint8_t>(0xC8 + reg));
    return result;
}

} // namespace mx
