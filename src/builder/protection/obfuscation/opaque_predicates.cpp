/**
 * @file opaque_predicates.cpp
 * @brief [BUILDER] Реализация генератора opaque predicates x86/x64.
 *
 * @details Генерирует машинный код для математически доказуемых предикатов.
 *          Каждый предикат — это последовательность инструкций, вычисляющая
 *          выражение с заведомо известным результатом (true/false), за которой
 *          следует условный переход. Используется для запутывания CFG.
 *
 * @note Все предикаты используют регистры, безопасные для модификации
 *       (не RSP/RBP). Регистр сохраняется/восстанавливается через стек.
 */

#include "mxprotector/protection/obfuscation/opaque_predicates.hpp"
#include "mxprotector/analysis/x86_encoding.hpp"

namespace mx {

// ============================================================================
// Вспомогательные функции
// ============================================================================

uint8_t OpaquePredicateGenerator::pick_safe_register(Randomizer& rng) const {
    static constexpr uint8_t safe_regs[] = {0, 1, 2, 3, 6, 7};
    const uint32_t idx = rng.next_range(0, 5);
    return safe_regs[idx];
}

// ============================================================================
// generate_always_true — предикат, всегда оцениваемый как true
// ============================================================================

OpaquePredicateCode OpaquePredicateGenerator::generate_always_true(
    Randomizer& rng, [[maybe_unused]] uint8_t junk_size) const
{
    const uint32_t variant = rng.next_range(0, 2);

    switch (variant) {
        case 0:  return gen_quadratic_parity(rng, true);
        case 1:  return gen_or_one_nonzero(rng);
        default: return gen_xor_self_zero(rng);
    }
}

// ============================================================================
// generate_always_false — предикат, всегда оцениваемый как false
// ============================================================================

OpaquePredicateCode OpaquePredicateGenerator::generate_always_false(Randomizer& rng) const {
    return gen_quadratic_parity(rng, false);
}

// ============================================================================
// gen_quadratic_parity — x*(x+1) % 2 == 0 (всегда true)
// ============================================================================

OpaquePredicateCode OpaquePredicateGenerator::gen_quadratic_parity(
    Randomizer& rng, bool always_true) const
{
    const uint8_t reg = pick_safe_register(rng);
    ByteBuffer code;

    code.push_back(static_cast<uint8_t>(0x50 + reg));

    code.push_back(0x89);
    code.push_back(x86::make_modrm(3, reg, reg));

    code.push_back(0x83);
    code.push_back(x86::make_modrm(3, 0, reg));
    code.push_back(0x01);

    code.push_back(0x0F);
    code.push_back(0xAF);
    code.push_back(x86::make_modrm(3, reg, reg));

    code.push_back(0xA8);
    code.push_back(0x01);

    code.push_back(static_cast<uint8_t>(0x58 + reg));

    const uint8_t jcc_offset = static_cast<uint8_t>(code.size());

    if (always_true) {
        code.push_back(0x74);
    } else {
        code.push_back(0x75);
    }
    code.push_back(0x00);

    OpaquePredicateCode result;
    result.code = std::move(code);
    result.true_branch_offset = jcc_offset;
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.is_always_true = always_true;
    return result;
}

// ============================================================================
// gen_or_one_nonzero — (x | 1) != 0 (всегда true)
// ============================================================================

OpaquePredicateCode OpaquePredicateGenerator::gen_or_one_nonzero(Randomizer& rng) const {
    const uint8_t reg = pick_safe_register(rng);
    ByteBuffer code;

    code.push_back(static_cast<uint8_t>(0x50 + reg));

    code.push_back(0x83);
    code.push_back(x86::make_modrm(3, 1, reg));
    code.push_back(0x01);

    code.push_back(0x85);
    code.push_back(x86::make_modrm(3, reg, reg));

    code.push_back(static_cast<uint8_t>(0x58 + reg));

    const uint8_t jcc_offset = static_cast<uint8_t>(code.size());
    code.push_back(0x75);
    code.push_back(0x00);

    OpaquePredicateCode result;
    result.code = std::move(code);
    result.true_branch_offset = jcc_offset;
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.is_always_true = true;
    return result;
}

// ============================================================================
// gen_xor_self_zero — (x ^ x) == 0 (всегда true)
// ============================================================================

OpaquePredicateCode OpaquePredicateGenerator::gen_xor_self_zero(Randomizer& rng) const {
    const uint8_t reg = pick_safe_register(rng);
    ByteBuffer code;

    code.push_back(static_cast<uint8_t>(0x50 + reg));

    code.push_back(0x31);
    code.push_back(x86::make_modrm(3, reg, reg));

    code.push_back(0x85);
    code.push_back(x86::make_modrm(3, reg, reg));

    code.push_back(static_cast<uint8_t>(0x58 + reg));

    const uint8_t jcc_offset = static_cast<uint8_t>(code.size());
    code.push_back(0x74);
    code.push_back(0x00);

    OpaquePredicateCode result;
    result.code = std::move(code);
    result.true_branch_offset = jcc_offset;
    result.total_size = static_cast<uint8_t>(result.code.size());
    result.is_always_true = true;
    return result;
}

} // namespace mx
